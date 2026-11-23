package clientcore

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// Connection manages the HTTPS transport to the server.
// Unlike v1 which used a persistent TCP connection, v2 uses
// independent HTTPS requests with retry and backoff.
const runtimeTrafficAnalyzerEnabled = false

type Connection struct {
	transport       *Transport
	fingerprint     *Fingerprinter
	behavior        *BehaviorEngine
	cipher          *Cipher
	masker          *Masker
	analyzer        *Analyzer
	buffer          *Buffer
	psk             []byte
	transportKey    []byte
	transportMu     sync.RWMutex
	serverAddr      string
	serverDialAddr  string
	protocol        string
	dohDomain       string
	routePrefix     string
	dnsListenAddr   string
	fingerprintMode string
	dnsProxy        *DNSProxy
	interceptor     PacketInjector
	connected       atomic.Bool
	stopChan        chan struct{}
	stopOnce        sync.Once
	nonIPv4Warn     sync.Once
	profile         *ProfileManager

	// TLS pin for self-signed / pinned deployments.
	tlsCertSHA256 []byte

	// REALITY settings
	realityServerPubKey     []byte
	verifyServerCertificate bool
}

// PacketInjector abstracts inbound packet injection for platform adapters.
// Windows adapter may use WinDivert; Android adapter may write into TUN.
type PacketInjector interface {
	InjectInboundPacket(raw []byte) error
}

// NewConnection creates a new Connection manager.
func NewConnection(address string, dialAddress string, psk []byte, protocol string, routePrefix string, dohDomain string, dnsListenAddr string, fingerprintMode string, buffer *Buffer, reconnectInterval int, analyzer *Analyzer, pm *ProfileManager, tlsCertSHA256 []byte, realityPubKey []byte, verifyServerCertificate bool, transportKeys ...[]byte) *Connection {
	transportKey := psk
	if len(transportKeys) > 0 {
		transportKey = transportKeys[0]
	}
	return &Connection{
		psk:                     psk,
		transportKey:            transportKey,
		serverAddr:              address,
		serverDialAddr:          dialAddress,
		protocol:                normalizeProtocol(protocol),
		dohDomain:               dohDomain,
		routePrefix:             routePrefix,
		dnsListenAddr:           dnsListenAddr,
		fingerprintMode:         normalizeFingerprintMode(fingerprintMode),
		buffer:                  buffer,
		analyzer:                analyzer,
		stopChan:                make(chan struct{}),
		profile:                 pm,
		tlsCertSHA256:           tlsCertSHA256,
		realityServerPubKey:     realityPubKey,
		verifyServerCertificate: verifyServerCertificate,
	}
}

// Connect initializes the HTTPS transport and behavior engine.
func (c *Connection) Connect() error {
	// Initialize fingerprinter
	c.fingerprint = NewFingerprinter(c.fingerprintMode)
	LogState("connection", "TLS fingerprint initialized")

	// Initialize transport
	nextTransport := NewTransport(c.serverAddr, c.serverDialAddr, c.psk, c.fingerprint, c.protocol, c.routePrefix, c.dohDomain, c.tlsCertSHA256, c.realityServerPubKey, c.verifyServerCertificate, c.transportKey)
	c.transportMu.Lock()
	c.transport = nextTransport
	c.transportMu.Unlock()

	// Establish a fresh cryptographic session before any carrier worker starts.
	if err := c.transport.Sync(); err != nil {
		c.transport.Close()
		return err
	}
	cipher := c.transport.InnerCipher()
	if cipher == nil {
		c.transport.Close()
		return fmt.Errorf("session negotiation did not install an inner cipher")
	}
	c.cipher = cipher

	c.connected.Store(true)
	LogState("connection", "connected via HTTPS")

	return nil
}

// Start begins the connection and behavior engine.
func (c *Connection) Start() {
	if c.transport == nil {
		// Try initial connection
		if err := c.Connect(); err != nil {
			LogOperationalFailure("connection", "initial connection failed", err)
			go c.retryLoop()
			return
		}
	}

	if runtimeTrafficAnalyzerEnabled && c.analyzer == nil {
		c.analyzer = NewAnalyzer()
	} else if !runtimeTrafficAnalyzerEnabled {
		c.analyzer = nil
	}
	c.masker = NewMasker(c.analyzer, c.cipher, c.profile, c.psk)

	// Create and start behavior engine
	c.behavior = NewBehaviorEngine(c.transport, c.cipher, c.masker, c.handleInboundPacket, c.profile, c.psk)
	c.behavior.Start()

	// Flush buffered packets
	packets := c.buffer.Flush()
	if len(packets) > 0 {
		LogState("connection", "flushing buffered packets")
		if err := c.SendBatch(packets); err != nil {
			LogOperationalFailure("connection", "buffer flush failed", err)
		}
	}
	// Start DNS proxy to tunnel system DNS through HTTPS.
	// This prevents DNS queries from leaking to the ISP.
	if c.dnsListenAddr != "" {
		c.dnsProxy = NewDNSProxy(c.dnsListenAddr, c.transport)
		if err := c.dnsProxy.Start(); err != nil {
			LogOperationalFailure("dns-proxy", "start failed", err)
			c.dnsProxy = nil
		}
	}
}

// Stop shuts down all components.
func (c *Connection) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopChan)
	})
	if c.behavior != nil {
		c.behavior.Stop()
		c.behavior = nil
	}
	if c.transport != nil {
		c.transport.Close()
		c.transport = nil
	}
	if c.dnsProxy != nil {
		c.dnsProxy.Stop()
		c.dnsProxy = nil
	}
	c.connected.Store(false)
}

// Send queues one packet for encrypted transmission.
func (c *Connection) Send(data []byte) error {
	return c.SendBatch([][]byte{data})
}

// SendBatch queues multiple packets for encrypted transmission.
func (c *Connection) SendBatch(batch [][]byte) error {
	if len(batch) == 0 {
		return nil
	}

	// Server tunnel path is IPv4-only at the moment. Drop non-IPv4 packets
	// here so they do not waste bandwidth and flood server logs.
	filtered := batch[:0]
	droppedNonIPv4 := 0
	for _, data := range batch {
		if len(data) == 0 {
			continue
		}
		if data[0]>>4 != 4 {
			droppedNonIPv4++
			continue
		}
		filtered = append(filtered, data)
	}
	if droppedNonIPv4 > 0 {
		c.nonIPv4Warn.Do(func() {
			LogRateLimitedEvent("connection", "non-IPv4 packets dropped by IPv4-only tunnel")
		})
	}
	if len(filtered) == 0 {
		return nil
	}

	if c.behavior != nil && c.connected.Load() {
		// Packets are encrypted when the behavior engine forms the write
		// they travel in; see Masker.SealBatch.
		c.behavior.EnqueueBatchData(c.masker.PadBatch(filtered))
		return nil
	}

	// Buffer for later
	for _, data := range filtered {
		if len(data) == 0 {
			continue
		}
		c.buffer.Add(data)
	}
	return nil
}

// IsConnected returns whether the transport is operational.
func (c *Connection) IsConnected() bool {
	return c.connected.Load() && c.transport != nil && c.transport.IsOperational()
}

// SetInterceptor sets packet injector used for inbound tunnel packets.
func (c *Connection) SetInterceptor(i PacketInjector) {
	c.interceptor = i
}

func (c *Connection) handleInboundPacket(raw []byte) {
	if len(raw) == 0 {
		return
	}
	// Downlink packets are padded by the server (padPacketBinary); strip the
	// padding back to the raw IP packet. Fall back to the bytes as-is if this is
	// an un-padded payload (e.g. a legacy server) so the tunnel still works.
	if unp, ok := unpadPacketBinary(raw); ok {
		raw = unp
	}
	if c.interceptor == nil {
		LogRateLimitedEvent("connection", "inbound packet dropped because interceptor is unavailable")
		return
	}
	if err := c.interceptor.InjectInboundPacket(raw); err != nil {
		LogOperationalFailure("connection", "inbound packet injection failed", err)
		return
	}
	if runtimeTrafficAnalyzerEnabled && c.analyzer != nil {
		c.analyzer.Analyze(len(raw), false)
	}
}

// retryLoop attempts to reconnect with exponential backoff.
func (c *Connection) retryLoop() {
	backoff := 5 * time.Second
	maxBackoff := 2 * time.Minute

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		// Add jitter: ±30%
		jitter := time.Duration(float64(backoff) * (0.7 + rand.Float64()*0.6))
		time.Sleep(jitter)

		if err := c.Connect(); err != nil {
			LogOperationalFailure("connection", "reconnect attempt failed", err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Success — start the engine
		c.Start()
		return
	}
}

// GetTransportStats returns transport statistics for GUI display.
func (c *Connection) GetTransportStats() (requests, sent, recv int64, fp string, behavior string, shield string) {
	if c.transport != nil {
		requests, sent, recv = c.transport.Stats()
		shield = c.transport.CurrentShieldDomain()
	}
	if c.fingerprint != nil {
		fp = c.fingerprint.GetCurrentName()
	}
	if c.behavior != nil {
		behavior = string(c.behavior.GetMode())
	} else {
		behavior = "—"
	}
	return
}

// GetAckBatchStats returns outer-carrier ACK coalescing counters.
func (c *Connection) GetAckBatchStats() AckBatchStats {
	if c == nil || c.transport == nil {
		return AckBatchStats{}
	}
	return c.transport.AckBatchStats()
}

// PSKHex returns the PSK as hex string.
func (c *Connection) PSKHex() string {
	return hex.EncodeToString(c.psk)
}
