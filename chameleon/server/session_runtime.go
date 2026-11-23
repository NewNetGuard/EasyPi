package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxPendingDownlinkPackets   = 2048
	maxPendingDownlinkBytes     = 4 * 1024 * 1024
	downlinkBatchPacketBudget   = 512
	downlinkBatchByteBudget     = 1 * 1024 * 1024
	maxDownlinkSequenceResume   = 1 << 48
	defaultMaxSessions          = 100
	defaultMaxSessionRequests   = 8
	defaultMaxSessionsPerSource = 8
	maxOutboxPackets            = 2048
	// A reconnect from another subscriber network may replace an old source
	// binding after the previous path has stopped proving liveness. This delay
	// prevents two simultaneously active holders from bouncing one session
	// between networks while keeping ordinary Wi-Fi/mobile roaming responsive.
	sessionSourceHandoverDelay = 5 * time.Second
)

type pendingDownlinkFrame struct {
	sequence  uint64
	payload   []byte
	encrypted []byte
}

// clientSession tracks per-client state for long-poll responses.
type clientSession struct {
	mu         sync.Mutex
	outbox     chan []byte // encrypted data to send back to client via poll
	lastSeen   atomic.Int64
	activeHTTP atomic.Int32
	source     string
	clientIP   net.IP
	clientPort uint16
	relay      *udpRelay

	// DoH fallback support
	cfClient *CloudflareClient
	dohQueue chan []byte
	dohStop  chan struct{}

	downlinkOwnerMu sync.Mutex
	// downlinkTakeover asks a fallback poll that holds downlinkOwnerMu while it
	// waits for data to return at once, so an arriving stream is not held up to
	// the poll's 30 s timeout.
	downlinkTakeover chan struct{}
	tcpStreams       atomic.Int32 // open TCP streams of this session
	carrierMu        sync.Mutex
	carrierCancel    context.CancelFunc
	carrierEpoch     uint64
	carrierInstance  string
	downlinkMu       sync.Mutex
	downlinkNext     uint64
	downlinkPending  []pendingDownlinkFrame
	downlinkBytes    int
	downlinkAcked    chan struct{}

	cryptoMu        sync.RWMutex
	cryptoSessionID string
	cipher          *Cipher
	allowedIP       net.IP
	credentialID    string
	packetDemasker  *Demasker
}

type udpRelay struct {
	conn     *net.UDPConn
	upstream *net.UDPAddr
	done     chan struct{}
}

func (r *udpRelay) close() {
	select {
	case <-r.done:
		return
	default:
		close(r.done)
		_ = r.conn.Close()
	}
}

var (
	sessions               = make(map[string]*clientSession)
	sessionsMu             sync.Mutex
	sessionLimit                 = defaultMaxSessions
	sessionRequestLimit    int32 = defaultMaxSessionRequests
	sessionsPerSourceLimit       = defaultMaxSessionsPerSource
	ipToSess                     = make(map[string]*clientSession)
	ipToSessMu             sync.RWMutex

	kernelTun *kernelTunnel
	prismLink *prismLinkServer
	// Global CF client
	cfClient *CloudflareClient
)

func configureSessionLimits(maxSessions, maxRequestsPerSession, maxSessionsPerSource int) {
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	if maxRequestsPerSession <= 0 {
		maxRequestsPerSession = defaultMaxSessionRequests
	}
	if maxSessionsPerSource <= 0 {
		maxSessionsPerSource = defaultMaxSessionsPerSource
	}
	sessionsMu.Lock()
	sessionLimit = maxSessions
	sessionRequestLimit = int32(maxRequestsPerSession)
	sessionsPerSourceLimit = maxSessionsPerSource
	sessionsMu.Unlock()
}

// sourceQuotaKey groups address rotation within one ordinary subscriber prefix.
// In particular, temporary IPv6 addresses must not create independent quota
// buckets. IPv4 /24 and IPv6 /48 are deliberately coarser than a host address.
func sourceQuotaKey(source string) string {
	address, err := netip.ParseAddr(source)
	if err != nil {
		return ""
	}
	address = address.Unmap().WithZone("")
	prefixBits := 48
	if address.Is4() {
		prefixBits = 24
	} else if address.IsLoopback() {
		prefixBits = 128 // ::/48 would hide that the source is the local frontend
	}
	return netip.PrefixFrom(address, prefixBits).Masked().String()
}

// perSourceQuotaApplies reports whether a quota key names a subscriber
// network. A loopback source is the local frontend (nginx, the Mobile Link
// relay) that every client reaches the backend through: counting it as one
// network let any eight devices lock all others out. Sessions behind it stay
// bounded by authentication (one live instance per credential) and the
// server-wide session limit.
func perSourceQuotaApplies(sourceKey string) bool {
	prefix, err := netip.ParsePrefix(sourceKey)
	return err != nil || !prefix.Addr().IsLoopback()
}

func getSession(clientID, source string) *clientSession {
	source = sourceQuotaKey(source)
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	s, ok := sessions[clientID]
	if ok && source == "" {
		return nil
	}
	if ok && s.source != source {
		lastSeen := time.Unix(0, s.lastSeen.Load())
		if time.Since(lastSeen) < sessionSourceHandoverDelay {
			return nil
		}
		if perSourceQuotaApplies(source) {
			sourceSessions := 0
			for _, existing := range sessions {
				if existing != s && existing.source == source {
					sourceSessions++
				}
			}
			if sourceSessions >= sessionsPerSourceLimit {
				logRateLimitedEvent("server", "session move refused: per-source session limit reached")
				return nil
			}
		}
		resetSessionNetworkPath(s)
		s.source = source
		logRateLimitedEvent("server", "authenticated client session moved to a new network")
	}
	if !ok {
		retireIdleInstancesLocked(clientID, time.Now(), 0)
		if len(sessions) >= sessionLimit {
			logRateLimitedEvent("server", "new session refused: session limit reached")
			return nil
		}
		if source == "" {
			return nil
		}
		if perSourceQuotaApplies(source) {
			sourceSessions := 0
			for _, existing := range sessions {
				if existing.source == source {
					sourceSessions++
				}
			}
			if sourceSessions >= sessionsPerSourceLimit {
				logRateLimitedEvent("server", "new session refused: per-source session limit reached")
				return nil
			}
		}
		s = newClientSession()
		s.source = source
		sessions[clientID] = s

		// Start DoH sender only as fallback when Cloudflare is configured.
		if s.cfClient != nil && s.cfClient.Domain != "" {
			s.dohQueue = make(chan []byte, 64)
			s.dohStop = make(chan struct{})
			go s.dohSenderLoop()
		}
	}
	s.touch()
	return s
}

func newClientSession() *clientSession {
	s := &clientSession{
		outbox:           make(chan []byte, maxOutboxPackets),
		cfClient:         cfClient,
		downlinkAcked:    make(chan struct{}, 1),
		downlinkTakeover: make(chan struct{}, 1),
	}
	s.touch()
	return s
}

// acquireDownlinkForStream takes downlink ownership for the persistent stream.
// A fallback poll that currently owns it is asked to finish first; it gives
// up ownership before taking any data, so nothing is lost or reordered.
func (s *clientSession) acquireDownlinkForStream(ctx context.Context) bool {
	if s.downlinkOwnerMu.TryLock() {
		s.clearDownlinkTakeover()
		return true
	}
	select {
	case s.downlinkTakeover <- struct{}{}:
	default:
	}
	acquired := make(chan struct{})
	go func() {
		s.downlinkOwnerMu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		s.clearDownlinkTakeover()
		return true
	case <-ctx.Done():
		// The lock is still taken by the goroutine above; release it as soon as
		// it is obtained so the next owner is not blocked by this request.
		go func() {
			<-acquired
			s.downlinkOwnerMu.Unlock()
		}()
		return false
	}
}

func (s *clientSession) clearDownlinkTakeover() {
	select {
	case <-s.downlinkTakeover:
	default:
	}
}

func (s *clientSession) beginTCPStream() bool {
	for {
		open := s.tcpStreams.Load()
		if open >= maxTCPStreamsPerSession {
			return false
		}
		if s.tcpStreams.CompareAndSwap(open, open+1) {
			s.touch()
			return true
		}
	}
}

func (s *clientSession) endTCPStream() {
	s.touch()
	s.tcpStreams.Add(-1)
}

// busy reports work in flight: tunnel requests or open TCP streams. Busy
// sessions are never retired or discarded as idle.
func (s *clientSession) busy() bool {
	return s.activeHTTP.Load() != 0 || s.tcpStreams.Load() != 0
}

func (s *clientSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *clientSession) bindCrypto(session *cryptoSession) bool {
	if session == nil || session.cipher == nil {
		return false
	}
	s.cryptoMu.Lock()
	changed := s.cryptoSessionID != "" && s.cryptoSessionID != session.id
	s.cryptoSessionID = session.id
	s.cipher = session.cipher
	s.allowedIP = append(net.IP(nil), session.allowedIP...)
	s.credentialID = session.clientID
	if len(session.packetPSK) > 0 && s.packetDemasker == nil {
		s.packetDemasker = NewDemasker(session.packetPSK)
	}
	s.cryptoMu.Unlock()
	return changed
}

func (s *clientSession) currentCipher() *Cipher {
	s.cryptoMu.RLock()
	defer s.cryptoMu.RUnlock()
	return s.cipher
}

func (s *clientSession) clearCrypto() {
	s.cryptoMu.Lock()
	s.cryptoSessionID = ""
	s.cipher = nil
	s.allowedIP = nil
	s.credentialID = ""
	if s.packetDemasker != nil {
		s.packetDemasker.Stop()
		s.packetDemasker = nil
	}
	s.cryptoMu.Unlock()
}

func (s *clientSession) revokeCarrier() {
	s.carrierMu.Lock()
	cancel := s.carrierCancel
	s.carrierCancel = nil
	s.carrierInstance = ""
	s.carrierEpoch++
	s.carrierMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func revokeClientRuntime(clientID string) {
	sessionsMu.Lock()
	session := sessions[clientID]
	sessionsMu.Unlock()
	if session == nil {
		return
	}
	session.revokeCarrier()
	session.resetClientEpoch()
	session.clearCrypto()
}

// replaceCarrier gives the newest authenticated CONNECT request ownership of
// the downlink. A client process can disappear without the previous HTTP/2
// stream reaching the server promptly (for example during a Wi-Fi handover).
// Cancelling that stale handler prevents the replacement from waiting forever
// on downlinkOwnerMu.
func (s *clientSession) replaceCarrier(parent context.Context, instance string) (context.Context, func(), bool) {
	ctx, cancel := context.WithCancel(parent)
	s.carrierMu.Lock()
	previous := s.carrierCancel
	newClientEpoch := s.carrierInstance != "" && s.carrierInstance != instance
	s.carrierInstance = instance
	s.carrierEpoch++
	epoch := s.carrierEpoch
	s.carrierCancel = cancel
	s.carrierMu.Unlock()
	if previous != nil {
		previous()
	}
	return ctx, func() {
		cancel()
		s.carrierMu.Lock()
		if s.carrierEpoch == epoch {
			s.carrierCancel = nil
		}
		s.carrierMu.Unlock()
	}, newClientEpoch
}

func (s *clientSession) resetClientEpoch() {
	resetSessionNetworkPath(s)
	s.downlinkMu.Lock()
	s.downlinkNext = 0
	s.downlinkPending = nil
	s.downlinkBytes = 0
	s.downlinkMu.Unlock()
	for {
		select {
		case <-s.outbox:
		default:
			return
		}
	}
}

func (s *clientSession) tryBeginRequest() (func(), bool) {
	for {
		active := s.activeHTTP.Load()
		if active >= sessionRequestLimit {
			return nil, false
		}
		if s.activeHTTP.CompareAndSwap(active, active+1) {
			s.touch()
			return func() {
				s.touch()
				s.activeHTTP.Add(-1)
			}, true
		}
	}
}

func cloneDownlinkPayload(payload []byte) []byte {
	cloned := make([]byte, len(payload))
	copy(cloned, payload)
	return cloned
}

func (s *clientSession) reserveDownlinkBatch(batch [][]byte, cipher *Cipher) ([]pendingDownlinkFrame, error) {
	s.downlinkMu.Lock()
	defer s.downlinkMu.Unlock()

	reserved := make([]pendingDownlinkFrame, 0, len(batch))
	// The reserved frames are written as one batch; a retransmission later
	// resends them with the same padding.
	stepUp := serverBatchStepUp(batch)
	for _, payload := range batch {
		if len(payload) == 0 {
			continue
		}
		padded := serverPadPacketInBatch(payload, stepUp)
		encrypted, err := cipher.Encrypt(padded)
		if err != nil {
			return nil, fmt.Errorf("encrypt reserved downlink packet: %w", err)
		}
		s.downlinkNext++
		frame := pendingDownlinkFrame{
			sequence:  s.downlinkNext,
			payload:   cloneDownlinkPayload(payload),
			encrypted: encrypted,
		}
		s.downlinkPending = append(s.downlinkPending, frame)
		s.downlinkBytes += len(frame.payload)
		reserved = append(reserved, frame)
	}
	return reserved, nil
}

func (s *clientSession) pendingDownlinkSnapshot(maxPackets, maxBytes int) []pendingDownlinkFrame {
	s.downlinkMu.Lock()
	defer s.downlinkMu.Unlock()

	result := make([]pendingDownlinkFrame, 0, min(maxPackets, len(s.downlinkPending)))
	total := 0
	for _, frame := range s.downlinkPending {
		if len(result) >= maxPackets || (len(result) > 0 && total+len(frame.payload) > maxBytes) {
			break
		}
		result = append(result, pendingDownlinkFrame{
			sequence:  frame.sequence,
			payload:   cloneDownlinkPayload(frame.payload),
			encrypted: cloneDownlinkPayload(frame.encrypted),
		})
		total += len(frame.payload)
	}
	return result
}

func (s *clientSession) acknowledgeDownlink(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	s.downlinkMu.Lock()
	defer s.downlinkMu.Unlock()
	if sequence > s.downlinkNext {
		// A server restart loses the in-memory sequence cursor while an already
		// authenticated client can still reconnect with its cumulative ACK. Only
		// an otherwise pristine session may resume that cursor; pending data can
		// never be skipped by this path.
		if s.downlinkNext == 0 && len(s.downlinkPending) == 0 && sequence <= maxDownlinkSequenceResume {
			s.downlinkNext = sequence
			return true
		}
		return false
	}
	removed := 0
	for removed < len(s.downlinkPending) && s.downlinkPending[removed].sequence <= sequence {
		s.downlinkBytes -= len(s.downlinkPending[removed].payload)
		removed++
	}
	if removed == 0 {
		return true
	}
	copy(s.downlinkPending, s.downlinkPending[removed:])
	s.downlinkPending = s.downlinkPending[:len(s.downlinkPending)-removed]
	select {
	case s.downlinkAcked <- struct{}{}:
	default:
	}
	return true
}

func (s *clientSession) waitDownlinkCapacity(ctx context.Context) bool {
	for {
		s.downlinkMu.Lock()
		available := len(s.downlinkPending) < maxPendingDownlinkPackets &&
			s.downlinkBytes < maxPendingDownlinkBytes
		available = available &&
			len(s.downlinkPending) <= maxPendingDownlinkPackets-downlinkBatchPacketBudget &&
			s.downlinkBytes <= maxPendingDownlinkBytes-downlinkBatchByteBudget
		s.downlinkMu.Unlock()
		if available {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-s.downlinkAcked:
		}
	}
}

// dohSenderLoop sends fallback copies via Cloudflare DoH.
func (s *clientSession) dohSenderLoop() {
	if s.cfClient == nil || s.dohQueue == nil || s.dohStop == nil {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var pending []byte
	retries := 0
	for {
		select {
		case <-s.dohStop:
			return
		case <-ticker.C:
			if pending == nil {
				select {
				case pending = <-s.dohQueue:
				case <-s.dohStop:
					return
				default:
					continue
				}
			}

			if err := s.cfClient.PublishData(pending); err != nil {
				logOperationalFailure("doh-sender", "publish failed", err)
				retries++
				if retries >= 3 {
					logRateLimitedEvent("doh-sender", "payload dropped after retry limit")
					pending = nil
					retries = 0
				}
				continue
			}
			pending = nil
			retries = 0
		}
	}
}

func enqueueDoHFallback(s *clientSession, data []byte) {
	if s == nil || s.dohQueue == nil {
		return
	}
	cipher := s.currentCipher()
	if cipher == nil {
		return
	}
	padded := serverPadPacketBinary(data)
	clone, err := cipher.Encrypt(padded)
	if err != nil {
		logOperationalFailure("doh-sender", "encryption failed", err)
		return
	}
	select {
	case s.dohQueue <- clone:
	default:
		logRateLimitedEvent("doh-sender", "fallback payload dropped because queue is full")
	}
}

func closeSession(s *clientSession) {
	s.revokeCarrier()
	resetSessionNetworkPath(s)
	s.mu.Lock()
	if s.dohStop != nil {
		close(s.dohStop)
		s.dohStop = nil
	}
	s.mu.Unlock()
	s.downlinkMu.Lock()
	s.downlinkPending = nil
	s.downlinkBytes = 0
	s.downlinkMu.Unlock()
	s.clearCrypto()
}

// resetSessionNetworkPath discards state tied to the previous client network
// while preserving unacknowledged downlink data across a legitimate roam.
func resetSessionNetworkPath(s *clientSession) {
	s.mu.Lock()
	clientIP := cloneIPv4(s.clientIP)
	s.clientIP = nil
	s.clientPort = 0
	if s.relay != nil {
		s.relay.close()
		s.relay = nil
	}
	s.mu.Unlock()
	unregisterClientIP(s, clientIP)
}

func cleanupSessions() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cleanupSessionsAt(time.Now())
	}
}

// previousInstanceGrace is how long an idle session of an earlier client
// instance is kept once a newer instance of the same credential exists.
const previousInstanceGrace = 30 * time.Second

// credentialOfRuntime returns the credential part of a "credential:instance"
// session key, or "" for keys that do not carry an instance.
func credentialOfRuntime(runtimeID string) string {
	credential, _, found := strings.Cut(runtimeID, ":")
	if !found {
		return ""
	}
	return credential
}

// retireIdleInstancesLocked frees sessions that earlier instances of the same
// credential no longer use. A device runs one client at a time; a restart or
// a session renegotiation starts a new instance and the old one is gone.
// Keeping such sessions for the 10-minute idle timeout let a few restarts fill
// the per-source quota, which behind nginx every client shares (they all reach
// the backend from loopback), and new sessions were then refused. Sessions with
// requests or TCP streams in flight are kept; the periodic cleanup retires them once idle.
// minIdle is how long a session must have been idle (zero: any idle session).
// sessionsMu must be held.
func retireIdleInstancesLocked(runtimeID string, now time.Time, minIdle time.Duration) {
	credential := credentialOfRuntime(runtimeID)
	if credential == "" {
		return
	}
	for key, existing := range sessions {
		if key == runtimeID || credentialOfRuntime(key) != credential || existing.busy() {
			continue
		}
		if now.Sub(time.Unix(0, existing.lastSeen.Load())) < minIdle {
			continue
		}
		logRateLimitedEvent("server", "retired idle session of a previous client instance")
		closeSession(existing)
		delete(sessions, key)
	}
}

func cleanupSessionsAt(now time.Time) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	// Earlier instances that were still busy when their successor arrived.
	newest := map[string]string{}
	newestSeen := map[string]int64{}
	for key, s := range sessions {
		credential := credentialOfRuntime(key)
		if credential == "" {
			continue
		}
		if seen := s.lastSeen.Load(); newest[credential] == "" || seen > newestSeen[credential] {
			newest[credential], newestSeen[credential] = key, seen
		}
	}
	for _, key := range newest {
		retireIdleInstancesLocked(key, now, previousInstanceGrace)
	}
	for clientID, s := range sessions {
		lastSeen := time.Unix(0, s.lastSeen.Load())
		if !s.busy() && now.Sub(lastSeen) > 10*time.Minute {
			logRateLimitedEvent("server", "discarded stale inactive session")
			closeSession(s)
			delete(sessions, clientID)
		}
	}
}
