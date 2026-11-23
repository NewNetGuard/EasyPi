package main

import (
	"bufio"
	"chameleon/shared"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	tlsRecordHeaderLen = 5
	// TLS 1.3 permits 2^14 bytes of plaintext plus up to 256 bytes of
	// expansion. Keep the full RFC allowance bounded before allocating a
	// per-connection reader.
	maxTLSRecordPayload = (1 << 14) + 256
	maxClientHelloPeek  = tlsRecordHeaderLen + maxTLSRecordPayload
	defaultPreAuthLimit = 256
	defaultPreAuthPerIP = 32
	probeIdleTimeout    = 30 * time.Second
	probeMaxDuration    = 2 * time.Minute
)

// RealityListener is a wrapper around net.Listener that peeks at incoming
// connections to distinguish between Chameleon clients and regular probes.
type RealityListener struct {
	net.Listener
	shieldDomain  string
	probeMode     string
	probeTarget   string
	serverPubKey  []byte
	psk           []byte
	chameleonChan chan net.Conn
	stopChan      chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
	admission     chan struct{}
	perIPMu       sync.Mutex
	perIP         map[string]int
	maxPerIP      int
	rejectLogMu   sync.Mutex
	lastRejectLog time.Time
}

// PrefixConn is a net.Conn wrapper that returns a peeked buffer before
// reading from the underlying connection.
type PrefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *PrefixConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

// NewRealityListener creates a new listener that intercepts connections.
func NewRealityListener(
	l net.Listener,
	shieldDomain, probeMode, probeTarget string,
	serverPubKey, psk []byte,
	maxPreAuth, maxPreAuthPerIP int,
) *RealityListener {
	if maxPreAuth <= 0 {
		maxPreAuth = defaultPreAuthLimit
	}
	if maxPreAuthPerIP <= 0 {
		maxPreAuthPerIP = defaultPreAuthPerIP
	}
	if maxPreAuthPerIP > maxPreAuth {
		maxPreAuthPerIP = maxPreAuth
	}
	rl := &RealityListener{
		Listener:      l,
		shieldDomain:  shieldDomain,
		probeMode:     probeMode,
		probeTarget:   probeTarget,
		serverPubKey:  serverPubKey,
		psk:           psk,
		chameleonChan: make(chan net.Conn, 100),
		stopChan:      make(chan struct{}),
		admission:     make(chan struct{}, maxPreAuth),
		perIP:         make(map[string]int),
		maxPerIP:      maxPreAuthPerIP,
	}
	go rl.acceptLoop()
	return rl
}

func (rl *RealityListener) acceptLoop() {
	for {
		conn, err := rl.Listener.Accept()
		if err != nil {
			select {
			case <-rl.stopChan:
				return
			default:
				logOperationalFailure("reality", "accept failed", err)
				continue
			}
		}

		ip, ok := rl.tryAdmit(conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		rl.wg.Add(1)
		go func() {
			defer rl.wg.Done()
			defer rl.release(ip)
			rl.handleNewConn(conn)
		}()
	}
}

func (rl *RealityListener) tryAdmit(conn net.Conn) (string, bool) {
	select {
	case rl.admission <- struct{}{}:
	default:
		rl.logRejected()
		return "", false
	}

	ip := sourceQuotaKey(remoteHost(conn.RemoteAddr().String()))
	if ip == "" {
		<-rl.admission
		return "", false
	}
	rl.perIPMu.Lock()
	if rl.perIP[ip] >= rl.maxPerIP {
		rl.perIPMu.Unlock()
		<-rl.admission
		rl.logRejected()
		return "", false
	}
	rl.perIP[ip]++
	rl.perIPMu.Unlock()
	return ip, true
}

func (rl *RealityListener) release(ip string) {
	rl.perIPMu.Lock()
	if rl.perIP[ip] <= 1 {
		delete(rl.perIP, ip)
	} else {
		rl.perIP[ip]--
	}
	rl.perIPMu.Unlock()
	<-rl.admission
}

func (rl *RealityListener) logRejected() {
	rl.rejectLogMu.Lock()
	defer rl.rejectLogMu.Unlock()
	if time.Since(rl.lastRejectLog) >= 5*time.Second {
		logRateLimitedEvent("reality", "connection rejected by pre-authentication limit")
		rl.lastRejectLog = time.Now()
	}
}

func (rl *RealityListener) handleNewConn(conn net.Conn) {
	// Set a short deadline for the ClientHello peek.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReaderSize(conn, maxClientHelloPeek)
	peeked, err := peekTLSClientHello(reader)
	if err != nil {
		logOperationalFailure("reality", "client hello inspection failed", err)
		conn.Close()
		return
	}

	// Reset deadline for whatever path we take.
	conn.SetReadDeadline(time.Time{})

	// Detect if this is a Chameleon client.
	// We search for the per-connection marker in the peeked buffer.
	isChameleon := false
	if len(peeked) > 64 {
		// In TLS, the SessionID starts after the Random field.
		// Random is 32 bytes, starting at offset 11 of ClientHello.
		// SessionID length is at 43.
		// If length is 32, SessionID is [44:76].
		// We slide a 32-byte window (16-byte marker + 16-byte nonce) over the
		// range where the SessionID might be (usually between 44 and 200) and
		// verify each candidate against the server pubkey + PSK. Only the true
		// SessionID authenticates (false-positive odds ~2^-128 per offset).
		searchRange := peeked
		if len(searchRange) > 200 {
			searchRange = searchRange[:200]
		}

		for i := 40; i < len(searchRange)-32; i++ {
			if shared.DetectMarker(searchRange[i:], rl.serverPubKey, rl.psk) {
				isChameleon = true
				break
			}
		}
	}

	prefixed := &PrefixConn{
		Conn:   conn,
		reader: reader,
	}

	if isChameleon {
		// Route to our local TLS server.
		select {
		case rl.chameleonChan <- prefixed:
		case <-rl.stopChan:
			prefixed.Close()
		default:
			logRateLimitedEvent("reality", "connection dropped because admission queue is full")
			prefixed.Close()
		}
	} else {
		// Not a Chameleon client — a probe or a stray visitor. Act like a real
		// REALITY front: transparently TCP-proxy the connection to the REAL site
		// named in the ClientHello's SNI (falling back to the configured shield).
		// The prober then completes a genuine TLS handshake with that site — real
		// cert, real content — so we look like a reverse proxy / CDN in front of
		// it. Production IP Shield configurations route probes only to the local
		// cover endpoint; the SNI proxy branch remains for config-file migration tests.
		target := rl.targetForProbe(peeked)
		if target == "" {
			prefixed.Close()
			return
		}
		rl.proxyTo(prefixed, target)
	}
}

// peekTLSClientHello waits for exactly one TLS record, rather than a fixed byte
// count. A fixed-size Peek delays valid short ClientHellos until the read
// deadline and gives active probes a stable timing signature.
func peekTLSClientHello(reader *bufio.Reader) ([]byte, error) {
	header, err := reader.Peek(tlsRecordHeaderLen)
	if err != nil {
		return nil, err
	}
	if header[0] != 0x16 || header[1] != 0x03 {
		// Preserve non-TLS input for the cover endpoint. Five bytes are enough to
		// classify it without waiting for an arbitrary buffer size.
		return header, nil
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen == 0 || recordLen > maxTLSRecordPayload {
		return nil, fmt.Errorf("invalid TLS ClientHello record length %d", recordLen)
	}
	return reader.Peek(tlsRecordHeaderLen + recordLen)
}

func (rl *RealityListener) targetForProbe(clientHello []byte) string {
	if rl.probeMode == "local" {
		if isLoopbackTarget(rl.probeTarget) {
			return rl.probeTarget
		}
		return ""
	}
	target := rl.shieldDomain
	if sni := parseClientHelloSNI(clientHello); sni != "" {
		if resolved, ok := resolveProxyTarget(sni); ok {
			target = resolved
		}
	}
	return target
}

func isLoopbackTarget(target string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// proxyTo transparently relays a non-Chameleon connection to target (host:port)
// so probes see the real site behind the SNI they used.
func (rl *RealityListener) proxyTo(client net.Conn, target string) {
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logOperationalFailure("reality", "cover proxy connection failed", err)
		return
	}
	defer upstream.Close()

	client = &idleDeadlineConn{Conn: client, idle: probeIdleTimeout}
	upstream = &idleDeadlineConn{Conn: upstream, idle: probeIdleTimeout}
	timer := time.AfterFunc(probeMaxDuration, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer timer.Stop()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}

type idleDeadlineConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *idleDeadlineConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

// isPublicIP reports whether ip is a routable public address. SSRF guard for the
// SNI-following probe proxy: never relay to loopback / private / link-local hosts.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

// resolveProxyTarget validates an SNI hostname and, if it resolves to a public
// address, returns "<ip>:443" to relay a probe to. ok=false for IP-literal SNIs,
// malformed names, or anything resolving only to non-public IPs (SSRF guard); the
// caller then falls back to the configured shield.
func resolveProxyTarget(host string) (string, bool) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return "", false
	}
	if strings.ContainsAny(host, " \t\r\n/\\@:") {
		return "", false
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", false
	}
	for _, ip := range ips {
		if isPublicIP(ip) {
			return net.JoinHostPort(ip.String(), "443"), true
		}
	}
	return "", false
}

// parseClientHelloSNI extracts the server_name (SNI) from a raw TLS ClientHello.
// Best-effort and fully bounds-checked; returns "" if absent or the buffer is
// truncated before the SNI extension.
func parseClientHelloSNI(b []byte) string {
	// TLS record: content_type(1)=0x16 handshake, version(2), length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	hs := b[5:]
	// Handshake header: msg_type(1)=0x01 ClientHello, length(3)
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	p := hs[4:]
	// client_version(2) + random(32)
	if len(p) < 34 {
		return ""
	}
	p = p[34:]
	// session_id
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return ""
	}
	p = p[1+int(p[0]):]
	// cipher_suites
	if len(p) < 2 {
		return ""
	}
	n := int(p[0])<<8 | int(p[1])
	if len(p) < 2+n {
		return ""
	}
	p = p[2+n:]
	// compression_methods
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return ""
	}
	p = p[1+int(p[0]):]
	// extensions block
	if len(p) < 2 {
		return ""
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) > extLen {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		etype := int(p[0])<<8 | int(p[1])
		elen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < elen {
			return "" // truncated (peek cut the ClientHello short)
		}
		if etype == 0x0000 { // server_name
			sn := p[:elen]
			if len(sn) < 2 {
				return ""
			}
			listLen := int(sn[0])<<8 | int(sn[1])
			sn = sn[2:]
			if len(sn) > listLen {
				sn = sn[:listLen]
			}
			for len(sn) >= 3 {
				ntype := sn[0]
				nlen := int(sn[1])<<8 | int(sn[2])
				sn = sn[3:]
				if len(sn) < nlen {
					return ""
				}
				if ntype == 0x00 { // host_name
					return string(sn[:nlen])
				}
				sn = sn[nlen:]
			}
			return ""
		}
		p = p[elen:]
	}
	return ""
}

// Accept returns a connection that was identified as a Chameleon client.
func (rl *RealityListener) Accept() (net.Conn, error) {
	select {
	case conn := <-rl.chameleonChan:
		return conn, nil
	case <-rl.stopChan:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close shuts down the listener.
func (rl *RealityListener) Close() error {
	var err error
	rl.stopOnce.Do(func() {
		close(rl.stopChan)
		err = rl.Listener.Close()
	})
	return err
}
