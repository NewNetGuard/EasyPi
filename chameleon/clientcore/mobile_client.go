package clientcore

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"chameleon/shared"
)

// MobileClient is a gomobile-friendly wrapper over the client core.
// It accepts outbound packets from platform code (e.g. Android VpnService TUN)
// and exposes inbound packets via PullPacket().
type MobileClient struct {
	mu sync.Mutex

	cfg         *Config
	conn        *Connection
	injector    *packetQueueInjector
	profile     *ProfileManager
	profilePath string
	started     bool
	connectedAt time.Time     // when the tunnel was last started
	sessionStop chan struct{} // closed only by StopClient; ends superviseSession
}

const (
	// A run of 401 answers this long means the server no longer knows the
	// session (for example after a server restart); the old keys cannot recover.
	sessionRejectionGrace = 3 * time.Second
	// Renegotiation attempts are spaced at least this far apart.
	sessionRebuildInterval = 10 * time.Second
)

// Seams for superviseSession; tests replace them to avoid a live server.
var (
	sessionSupervisorTick   = time.Second
	buildSessionConnection  = buildMobileConnection
	connectSessionWithRetry = connectWithRetries
	startSessionConnection  = func(c *Connection) { c.Start() }
	stopSessionConnection   = func(c *Connection) { c.Stop() }
)

// packetQueueInjector stores inbound packets produced by the tunnel.
type packetQueueInjector struct {
	ch      chan []byte
	maxSize int
}

func newPacketQueueInjector(maxSize int) *packetQueueInjector {
	if maxSize < 1 {
		maxSize = 256
	}
	return &packetQueueInjector{
		ch:      make(chan []byte, maxSize),
		maxSize: maxSize,
	}
}

func (q *packetQueueInjector) InjectInboundPacket(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}

	select {
	case q.ch <- raw:
		return nil
	default:
	}

	// Drop oldest under sustained pressure and accept latest packet.
	select {
	case <-q.ch:
	default:
	}
	select {
	case q.ch <- raw:
	default:
	}
	return nil
}

func (q *packetQueueInjector) Pop() []byte {
	select {
	case packet := <-q.ch:
		return packet
	default:
		return nil
	}
}

func (q *packetQueueInjector) PopBatch(maxPackets, maxBytes int) [][]byte {
	if maxPackets < 1 {
		maxPackets = 1
	}
	if maxBytes < 1 {
		maxBytes = 64 * 1024
	}

	batch := make([][]byte, 0, maxPackets)
	totalBytes := 0

	for len(batch) < maxPackets {
		var packet []byte
		select {
		case packet = <-q.ch:
		default:
			return batch
		}

		if len(packet) == 0 || len(packet) > 0xFFFF {
			continue
		}

		perItem := 2 + len(packet)
		if len(batch) > 0 && totalBytes+perItem > maxBytes {
			// Return current batch; keep packet for next pull by pushing it back best-effort.
			select {
			case q.ch <- packet:
			default:
			}
			return batch
		}

		batch = append(batch, packet)
		totalBytes += perItem
		if totalBytes >= maxBytes {
			return batch
		}
	}

	return batch
}

func (q *packetQueueInjector) Len() int {
	return len(q.ch)
}

// NewMobileClient creates a mobile wrapper instance.
func NewMobileClient() *MobileClient {
	return &MobileClient{
		profilePath: "profile-mobile.json",
	}
}

var errInvalidIPv4Packet = errors.New("invalid ipv4 packet")

func normalizeIPv4Packet(raw []byte) ([]byte, error) {
	if len(raw) < 20 {
		return nil, errInvalidIPv4Packet
	}
	if raw[0]>>4 != 4 {
		return nil, errInvalidIPv4Packet
	}

	ihl := int(raw[0]&0x0F) * 4
	if ihl < 20 || len(raw) < ihl {
		return nil, errInvalidIPv4Packet
	}

	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen < ihl || totalLen > len(raw) {
		return nil, errInvalidIPv4Packet
	}

	return raw[:totalLen], nil
}

// SetProfilePath sets file path for persisted traffic profile.
func (m *MobileClient) SetProfilePath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path = strings.TrimSpace(path)
	if path != "" {
		m.profilePath = path
	}
}

// SetConfigJSON applies client config from JSON.
// Returns empty string on success, otherwise error text.
func (m *MobileClient) SetConfigJSON(configJSON string) string {
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "config parse failed"
	}
	cfg.Protocol = normalizeProtocol(cfg.Protocol)
	if cfg.BufferSize < 1 {
		cfg.BufferSize = 1000
	}
	if cfg.ReconnectInterval < 1 {
		cfg.ReconnectInterval = 5
	}
	if strings.TrimSpace(cfg.ServerAddress) == "" {
		return "server_address is required"
	}
	if dialAddress := strings.TrimSpace(cfg.ServerDialAddress); dialAddress != "" {
		host, port, err := net.SplitHostPort(dialAddress)
		ip := net.ParseIP(host)
		portNumber, portErr := strconv.Atoi(port)
		if err != nil || ip == nil || ip.To4() == nil || portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "server_dial_address must be an IPv4 address with a valid port"
		}
		if port != "443" && normalizeSHA256Hex(cfg.BootstrapCertSHA256) == "" {
			return "non-standard tunnel ports require an exact certificate pin"
		}
		cfg.ServerDialAddress = net.JoinHostPort(ip.To4().String(), port)
	}
	if strings.TrimSpace(cfg.PSKKey) == "" {
		return "psk_key is required"
	}
	psk, err := hex.DecodeString(cfg.PSKKey)
	if err != nil || len(psk) != 32 {
		return "psk_key must be 32-byte hex"
	}
	if cfg.RealityServerPublicKey != "" {
		pub, err := hex.DecodeString(strings.TrimSpace(cfg.RealityServerPublicKey))
		if err != nil || len(pub) != 32 {
			return "reality_server_public_key must be 32-byte hex"
		}
		if strings.ToLower(strings.TrimSpace(cfg.RealityShieldPreset)) != "ip" {
			return "only IP Shield is supported"
		}
		if strings.TrimSpace(cfg.RealityShieldDomain) != "" {
			return "IP Shield must not configure an unrelated shield domain"
		}
		if !cfg.VerifyServerCertificate {
			return "IP Shield requires server certificate verification"
		}
	}
	if _, err := decodeSHA256Pin(cfg.BootstrapCertSHA256); err != nil {
		return "bootstrap certificate pin is invalid"
	}
	cfg.BootstrapCertSHA256 = normalizeSHA256Hex(cfg.BootstrapCertSHA256)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = &cfg
	return ""
}

// StartClient starts the transport/behavior engine.
// Returns empty string on success, otherwise error text.
func (m *MobileClient) StartClient() string {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return ""
	}
	if m.cfg == nil {
		m.mu.Unlock()
		return "config not set"
	}
	cfg := *m.cfg
	profilePath := m.profilePath
	m.mu.Unlock()

	profile := NewProfileManager(profilePath)
	injector := newPacketQueueInjector(32768)
	conn, problem := buildMobileConnection(cfg, profile, injector)
	if problem != "" {
		return problem
	}
	if err := connectWithRetries(conn, 24*time.Second); err != nil {
		return "connect failed (" + operationalErrorClass(err) + ")"
	}

	conn.Start()

	stop := make(chan struct{})
	m.mu.Lock()
	m.conn = conn
	m.injector = injector
	m.profile = profile
	m.started = true
	m.connectedAt = time.Now()
	m.sessionStop = stop
	m.mu.Unlock()
	go m.superviseSession(stop, cfg)
	return ""
}

// buildMobileConnection validates the configuration and creates an
// unconnected Connection that delivers inbound packets to injector.
func buildMobileConnection(cfg Config, profile *ProfileManager, injector *packetQueueInjector) (*Connection, string) {
	pskBytes, err := hex.DecodeString(cfg.PSKKey)
	if err != nil || len(pskBytes) != 32 {
		return nil, "invalid psk_key"
	}

	var realityPubKey []byte
	if cfg.RealityServerPublicKey != "" {
		pub, err := hex.DecodeString(strings.TrimSpace(cfg.RealityServerPublicKey))
		if err != nil || len(pub) != 32 {
			return nil, "invalid reality_server_public_key"
		}
		// Pass raw server public key; transport derives marker once.
		realityPubKey = pub
	}

	tlsCertSHA256, err := decodeSHA256Pin(cfg.BootstrapCertSHA256)
	if err != nil {
		return nil, "bootstrap certificate pin is invalid"
	}

	transportKey := pskBytes
	if cfg.TransportKey != "" {
		transportKey, err = hex.DecodeString(cfg.TransportKey)
		if err != nil || len(transportKey) != 32 {
			return nil, "invalid transport_key"
		}
	}
	routePrefix := shared.DeriveRoutePrefix(transportKey)
	conn := NewConnection(
		cfg.ServerAddress,
		cfg.ServerDialAddress,
		pskBytes,
		cfg.Protocol,
		routePrefix,
		cfg.DoHDomain,
		"", // Android path should avoid local DNS proxy auto-config.
		cfg.FingerprintMode,
		NewBuffer(cfg.BufferSize),
		cfg.ReconnectInterval,
		NewAnalyzer(),
		profile,
		tlsCertSHA256,
		realityPubKey,
		cfg.VerifyServerCertificate,
		transportKey,
	)
	conn.SetInterceptor(injector)
	return conn, ""
}

// connectWithRetries performs the session handshake with bounded, jittered
// retries inside the given time budget.
func connectWithRetries(conn *Connection, budget time.Duration) error {
	var connectErr error
	deadline := time.Now().Add(budget)
	for attempt := 0; attempt < 4; attempt++ {
		connectErr = conn.Connect()
		if connectErr == nil {
			return nil
		}
		if attempt == 3 || time.Now().After(deadline) {
			break
		}

		// Exponential backoff with jitter, but bounded by the deadline.
		baseMs := 250 << min(attempt, 3)
		wait := time.Duration(baseMs+rand.Intn(220)) * time.Millisecond
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		if wait > remain {
			wait = remain
		}
		time.Sleep(wait)
	}
	return connectErr
}

// superviseSession renegotiates when the server has rejected the active
// session (401 only, never a plain network failure). The replacement is a
// complete new Connection, so every component uses the new keys; it is
// swapped in only after its handshake succeeded, and the old connection is
// stopped right after the swap so its loops never run alongside the new ones.
// A failed handshake keeps the old connection (whose traffic stays inside the
// tunnel) and is retried no sooner than sessionRebuildInterval later.
func (m *MobileClient) superviseSession(stop <-chan struct{}, cfg Config) {
	ticker := time.NewTicker(sessionSupervisorTick)
	defer ticker.Stop()
	var lastAttempt time.Time
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		m.mu.Lock()
		current := m.conn
		profile := m.profile
		injector := m.injector
		m.mu.Unlock()
		if current == nil || current.SessionRejectedFor() < sessionRejectionGrace {
			continue
		}
		if !lastAttempt.IsZero() && time.Since(lastAttempt) < sessionRebuildInterval {
			continue
		}
		lastAttempt = time.Now()
		LogState("client", "server rejected the session; renegotiating")

		next, problem := buildSessionConnection(cfg, profile, injector)
		if problem != "" {
			LogRateLimitedEvent("client", "session renegotiation configuration rejected")
			continue
		}
		if err := connectSessionWithRetry(next, 8*time.Second); err != nil {
			stopSessionConnection(next)
			LogOperationalFailure("client", "session renegotiation failed", err)
			continue
		}
		startSessionConnection(next)

		m.mu.Lock()
		select {
		case <-stop:
			m.mu.Unlock()
			stopSessionConnection(next)
			return
		default:
		}
		if m.conn != current {
			m.mu.Unlock()
			stopSessionConnection(next)
			continue
		}
		m.conn = next
		m.connectedAt = time.Now()
		m.mu.Unlock()
		stopSessionConnection(current)
		LogState("client", "session renegotiated")
	}
}

// StopClient stops the tunnel engine.
func (m *MobileClient) StopClient() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessionStop != nil {
		close(m.sessionStop)
		m.sessionStop = nil
	}
	if m.conn != nil {
		m.conn.Stop()
		m.conn = nil
	}
	m.injector = nil
	m.profile = nil
	m.started = false
}

// PushPacket sends one raw IP packet into the tunnel.
// Returns empty string on success, otherwise error text.
func (m *MobileClient) PushPacket(raw []byte) string {
	m.mu.Lock()
	conn := m.conn
	started := m.started
	m.mu.Unlock()

	if !started || conn == nil {
		return "client is not started"
	}
	if len(raw) == 0 {
		return ""
	}
	normalized, err := normalizeIPv4Packet(raw)
	if err != nil {
		return ""
	}
	if err := conn.Send(normalized); err != nil {
		return "send failed (" + operationalErrorClass(err) + ")"
	}
	return ""
}

// PushPacketBatchWithLen sends a framed batch of outbound packets.
// Frame format: [2-byte big-endian length][packet bytes] repeated.
// Only first n bytes of batch are processed.
func (m *MobileClient) PushPacketBatchWithLen(batch []byte, n int) string {
	m.mu.Lock()
	conn := m.conn
	started := m.started
	m.mu.Unlock()

	if !started || conn == nil {
		return "client is not started"
	}
	if len(batch) == 0 || n <= 0 {
		return ""
	}
	if n > len(batch) {
		n = len(batch)
	}
	batch = batch[:n]

	packets := make([][]byte, 0, 64)
	off := 0
	for off+2 <= len(batch) {
		plen := int(binary.BigEndian.Uint16(batch[off : off+2]))
		off += 2
		if plen <= 0 || off+plen > len(batch) {
			break
		}

		rawPacket := batch[off : off+plen]
		normalized, err := normalizeIPv4Packet(rawPacket)
		if err == nil {
			packets = append(packets, normalized)
		}
		off += plen
	}
	if len(packets) == 0 {
		return ""
	}

	if err := conn.SendBatch(packets); err != nil {
		return "batch send failed (" + operationalErrorClass(err) + ")"
	}
	return ""
}

// PushPacketBatch sends the whole framed buffer.
func (m *MobileClient) PushPacketBatch(batch []byte) string {
	return m.PushPacketBatchWithLen(batch, len(batch))
}

// PullPacket returns next inbound raw IP packet from tunnel.
// If queue is empty, returns nil.
func (m *MobileClient) PullPacket() []byte {
	m.mu.Lock()
	injector := m.injector
	m.mu.Unlock()
	if injector == nil {
		return nil
	}
	return injector.Pop()
}

// WaitPacket returns the next inbound packet or nil when the wait expires.
func (m *MobileClient) WaitPacket(timeoutMillis int) []byte {
	m.mu.Lock()
	injector := m.injector
	m.mu.Unlock()
	if injector == nil {
		return nil
	}
	if packet := injector.Pop(); packet != nil || timeoutMillis <= 0 {
		return packet
	}
	timer := time.NewTimer(time.Duration(min(timeoutMillis, 1000)) * time.Millisecond)
	defer timer.Stop()
	select {
	case packet := <-injector.ch:
		return packet
	case <-timer.C:
		return nil
	}
}

func encodePacketBatch(batch [][]byte) []byte {
	if len(batch) == 0 {
		return nil
	}
	total := 0
	for _, pkt := range batch {
		if len(pkt) == 0 || len(pkt) > 0xFFFF {
			continue
		}
		total += 2 + len(pkt)
	}
	if total == 0 {
		return nil
	}

	out := make([]byte, total)
	off := 0
	for _, pkt := range batch {
		if len(pkt) == 0 || len(pkt) > 0xFFFF {
			continue
		}
		binary.BigEndian.PutUint16(out[off:off+2], uint16(len(pkt)))
		off += 2
		copy(out[off:off+len(pkt)], pkt)
		off += len(pkt)
	}
	if off == 0 {
		return nil
	}
	return out[:off]
}

// PullPacketBatch returns multiple inbound packets encoded as
// [2-byte big-endian length][packet bytes] repeated.
func (m *MobileClient) PullPacketBatch(maxPackets int, maxBytes int) []byte {
	m.mu.Lock()
	injector := m.injector
	m.mu.Unlock()
	if injector == nil {
		return nil
	}
	batch := injector.PopBatch(maxPackets, maxBytes)
	return encodePacketBatch(batch)
}

// PendingPackets returns number of queued inbound packets.
func (m *MobileClient) PendingPackets() int {
	m.mu.Lock()
	injector := m.injector
	m.mu.Unlock()
	if injector == nil {
		return 0
	}
	return injector.Len()
}

// IsStarted reports whether tunnel loop is running.
func (m *MobileClient) IsStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

// StatusJSON is the live-status struct mirrors the desktop GUI Status.
type StatusJSON struct {
	Connected             bool   `json:"connected"`
	Uptime                string `json:"uptime"`
	BytesSent             int64  `json:"bytes_sent"`
	BytesRecv             int64  `json:"bytes_recv"`
	RequestCount          int64  `json:"request_count"`
	Fingerprint           string `json:"fingerprint"`
	Behavior              string `json:"behavior"`
	TransportMode         string `json:"transport_mode"`
	TCPStreams            bool   `json:"tcp_streams"` // server offers TCP streams on this connection
	ShieldDomain          string `json:"shield_domain"`
	ServerAddr            string `json:"server_addr"`
	AckSequencesQueued    uint64 `json:"ack_sequences_queued"`
	AckSequencesConfirmed uint64 `json:"ack_sequences_confirmed"`
	AckPiggybackWrites    uint64 `json:"ack_piggyback_writes"`
	AckTimerWrites        uint64 `json:"ack_timer_writes"`
	AckThresholdWrites    uint64 `json:"ack_threshold_writes"`
	AckForcedWrites       uint64 `json:"ack_forced_writes"`
	H2FramesObserved      uint64 `json:"h2_frames_observed"`
	H2InitialConnUpdates  uint64 `json:"h2_initial_connection_updates"`
	H2ReactiveConnUpdates uint64 `json:"h2_reactive_connection_updates"`
	H2StreamUpdates       uint64 `json:"h2_stream_updates"`
	H2WindowCreditBytes   uint64 `json:"h2_window_credit_bytes"`
}

// GetStats returns a JSON string with live tunnel statistics.
// Returns empty string on error.
func (m *MobileClient) GetStats() string {
	m.mu.Lock()
	conn := m.conn
	started := m.started
	connectedAt := m.connectedAt
	cfg := m.cfg
	m.mu.Unlock()

	st := StatusJSON{Connected: started && conn != nil && conn.IsConnected()}
	if cfg != nil {
		st.ServerAddr = cfg.ServerAddress
	}
	if started && conn != nil {
		d := time.Since(connectedAt)
		h := int(d.Hours())
		mi := int(d.Minutes()) % 60
		s := int(d.Seconds()) % 60
		st.Uptime = fmt.Sprintf("%02d:%02d:%02d", h, mi, s)

		requests, sent, recv, fp, behavior, shield := conn.GetTransportStats()
		st.RequestCount = requests
		st.BytesSent = sent
		st.BytesRecv = recv
		st.Fingerprint = fp
		st.Behavior = behavior
		st.ShieldDomain = shield
		st.TCPStreams = conn.TCPStreamsAvailable()
		ackStats := conn.GetAckBatchStats()
		st.AckSequencesQueued = ackStats.SequencesQueued
		st.AckSequencesConfirmed = ackStats.SequencesConfirmed
		st.AckPiggybackWrites = ackStats.PiggybackWrites
		st.AckTimerWrites = ackStats.TimerWrites
		st.AckThresholdWrites = ackStats.ThresholdWrites
		st.AckForcedWrites = ackStats.ForcedWrites
		h2Stats := shared.CurrentH2FlowControlStats()
		st.H2FramesObserved = h2Stats.Frames
		st.H2InitialConnUpdates = h2Stats.InitialConnectionUpdates
		st.H2ReactiveConnUpdates = h2Stats.ReactiveConnectionUpdates
		st.H2StreamUpdates = h2Stats.StreamUpdates
		st.H2WindowCreditBytes = h2Stats.CreditBytes

		if cfg != nil && cfg.DoHDomain != "" {
			st.TransportMode = "Asymmetric: HTTPS send + DoH receive"
		} else {
			st.TransportMode = "HTTPS bidirectional"
		}
	}

	b, err := json.Marshal(st)
	if err != nil {
		return ""
	}
	return string(b)
}

// SendTestPacket sends a test data packet through the tunnel.
// Returns empty string on success, otherwise error text.
func (m *MobileClient) SendTestPacket() string {
	m.mu.Lock()
	conn := m.conn
	started := m.started
	m.mu.Unlock()

	if !started || conn == nil {
		return "client not started"
	}

	// Build test payload same as desktop GUI.
	randomData := make([]byte, 64)
	rand.Read(randomData)
	testData := []byte(fmt.Sprintf("CHAMELEON_TEST:%x", randomData))

	if err := conn.Send(testData); err != nil {
		return "send failed (" + operationalErrorClass(err) + ")"
	}
	return ""
}

// GetProfileStats returns current in-memory profile stats as JSON. Runtime
// profile learning and persistence are disabled, so this API must never read a
// caller-selected path or expose a legacy activity file.
func (m *MobileClient) GetProfileStats() string {
	m.mu.Lock()
	pm := m.profile
	m.mu.Unlock()

	if pm != nil {
		stats := pm.GetStats()
		data, err := json.Marshal(stats)
		if err != nil {
			return "{}"
		}
		return string(data)
	}

	return "{}"
}

// ResetProfile resets only the in-memory placeholder. It deliberately never
// removes a caller-selected file path.
func (m *MobileClient) ResetProfile() string {
	m.mu.Lock()
	pm := m.profile
	m.mu.Unlock()

	if pm != nil {
		pm.Reset()
	}
	return ""
}

// _ is a compile-time check that shared is imported.
var _ = shared.DeriveRoutePrefix

// ResolveDNS uses the already authenticated, inner-encrypted Chameleon path.
// There is deliberately no direct-network fallback when this path is down.
func (m *MobileClient) ResolveDNS(query []byte) ([]byte, error) {
	m.mu.Lock()
	conn := m.conn
	m.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("Chameleon is not running")
	}
	conn.transportMu.RLock()
	transport := conn.transport
	conn.transportMu.RUnlock()
	if transport == nil {
		return nil, fmt.Errorf("Chameleon transport unavailable")
	}
	return transport.ResolveDNS(query)
}
