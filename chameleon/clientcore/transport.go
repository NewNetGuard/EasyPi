package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/shared"
)

const (
	maxBinaryFrameSize  = 4 * 1024 * 1024
	maxPollBatchPackets = shared.InnerReplayWindow
)

// Transport handles HTTPS communication with the Chameleon server.
type Transport struct {
	serverURL      string
	psk            []byte
	transportKey   []byte
	fingerprint    *Fingerprinter
	client         *http.Client
	streamClient   *http.Client
	clientID       string
	clientInstance string
	mu             sync.RWMutex
	requestCount   int64
	bytesSent      int64
	bytesRecv      int64
	pendingMu      sync.Mutex
	pendingRx      [][]byte
	protocol       string
	serverAddr     string
	serverDialAddr string
	dohClient      *DohClient
	prefix         string // PSK-derived route prefix
	realityPub     []byte // server X25519 public key; non-empty ⇒ REALITY mode (marker derived per-connection)
	tlsCertSHA256  []byte
	shieldDomain   string
	innerCipher    *Cipher
	sessionID      string
	sessionAuthKey []byte
	streamKey      []byte // seeds per-stream keys of TCP streams

	// Precomputed route paths (prefix applied at construction time).
	routePush   string
	routePoll   string
	routeStream string
	routeUpload string
	routeSync   string
	routeTCP    string

	streamEnabled     bool
	streamRx          chan []byte
	streamLive        int32
	downlinkReorderMu sync.Mutex
	downlinkReorder   map[uint64][]byte

	uplinkEnabled bool
	uplinkFrames  chan [][]byte
	uplinkLive    int32
	uplinkGate    sync.RWMutex

	ctx       context.Context
	cancelCtx context.CancelFunc
	closeOnce sync.Once

	epochCtx        context.Context
	epochCancel     context.CancelFunc
	epochGeneration uint64
	// Open TCP streams per epoch generation (see retireEpoch).
	epochStreamMu  sync.Mutex
	epochStreams   map[uint64]*epochStreamGroup
	epochRefreshMu sync.Mutex
	epochPolicyMu  sync.Mutex
	epochPolicy    transportEpochPolicy

	verifyServerCertificate bool
	recordShapeEnabled      atomic.Bool
	epochAckEnabled         atomic.Bool
	connectCarrierEnabled   atomic.Bool
	workersOnce             sync.Once
	downlinkSequence        atomic.Uint64
	downlinkAck             atomic.Uint64
	downlinkAckNotify       chan struct{}
	downlinkAckQueued       atomic.Uint64
	downlinkAckConfirmed    atomic.Uint64
	downlinkAckPiggyback    atomic.Uint64
	downlinkAckTimer        atomic.Uint64
	downlinkAckThreshold    atomic.Uint64
	downlinkAckForced       atomic.Uint64
	uploadDrain             chan uploadDrainRequest
	sessionRejectedSince    atomic.Int64 // unix nanos of the first 401 in the current run; 0 = accepted
	tcpStreamEnabled        atomic.Bool  // server advertised TCP streams on sync
	tcpStreamShaped         atomic.Bool  // server also accepts shaped stream frames
}

func (t *Transport) InnerCipher() *Cipher {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.innerCipher
}

var errPollAuth = errors.New("poll authentication failed")

// NewTransport creates the HTTPS/HTTP2 transport. The public endpoint is
// also the TLS identity; Chameleon deliberately does not impersonate unrelated
// domains whose DNS, certificate and network ownership would be inconsistent.
func NewTransport(serverAddr string, serverDialAddr string, psk []byte, fp *Fingerprinter, protocol string, routePrefix string, dohDomain string, tlsCertSHA256 []byte, realityPubKey []byte, verifyServerCertificate bool, transportKeys ...[]byte) *Transport {
	protocol = normalizeProtocol(protocol)
	shieldDomain := ""
	if verifyServerCertificate || len(tlsCertSHA256) > 0 {
		shieldDomain = serverAddr
	}
	profile := fp.GetProfile()

	// A PSK represents one installation identity. The server derives the same
	// value and rejects caller-selected IDs, preventing session-quota evasion.
	clientID := shared.ClientIDForPSK(psk)
	instanceNonce := make([]byte, 16)
	if _, err := rand.Read(instanceNonce); err != nil {
		panic("secure random source unavailable")
	}
	clientInstance := hex.EncodeToString(instanceNonce)

	// REALITY mode is driven by the raw server public key: dialUTLS derives a
	// fresh per-connection marker from (realityPubKey, psk, nonce) at handshake
	// time, so nothing is precomputed here.
	markerKey := psk
	if len(transportKeys) > 0 {
		markerKey = transportKeys[0]
	}
	transport := CreateTLSTransport(profile, serverAddr, serverDialAddr, realityPubKey, markerKey, shieldDomain, tlsCertSHA256, verifyServerCertificate)
	client := &http.Client{
		Transport: transport,
		Timeout:   35 * time.Second,
	}
	// A timeout-free client shares this HTTP/2 transport with control requests.
	// Uplink and downlink therefore become streams on the same ordinary TLS
	// connection instead of creating two short-lived connections per cycle.
	streamClient := &http.Client{Transport: transport}

	baseURL := fmt.Sprintf("https://%s", serverAddr)
	ctx, cancel := context.WithCancel(context.Background())
	epochCtx, epochCancel := context.WithCancel(ctx)

	t := &Transport{
		serverURL:               baseURL,
		psk:                     append([]byte(nil), psk...),
		transportKey:            append([]byte(nil), markerKey...),
		fingerprint:             fp,
		clientID:                clientID,
		clientInstance:          clientInstance,
		client:                  client,
		streamClient:            streamClient,
		protocol:                protocol,
		serverAddr:              serverAddr,
		serverDialAddr:          serverDialAddr,
		prefix:                  routePrefix,
		realityPub:              realityPubKey,
		tlsCertSHA256:           tlsCertSHA256,
		shieldDomain:            shieldDomain,
		verifyServerCertificate: verifyServerCertificate,
		routePush:               baseURL + shared.RouteForPrefix(routePrefix, shared.EndpointSuffixPush),
		routePoll:               baseURL + shared.RouteForPrefix(routePrefix, shared.EndpointSuffixPoll),
		routeStream:             baseURL + shared.RouteForPrefix(routePrefix, shared.EndpointSuffixStream),
		routeUpload:             baseURL + shared.RouteForPrefix(routePrefix, shared.EndpointSuffixUpload),
		routeSync:               baseURL + shared.RouteForPrefix(routePrefix, shared.EndpointSuffixSync),
		routeTCP:                baseURL + shared.RouteForPrefix(routePrefix, shared.EndpointSuffixTCP),
		ctx:                     ctx,
		cancelCtx:               cancel,
		epochCtx:                epochCtx,
		epochCancel:             epochCancel,
		epochGeneration:         1,
		epochPolicy:             newTransportEpochPolicy(time.Now()),
		downlinkAckNotify:       make(chan struct{}, 1),
		uploadDrain:             make(chan uploadDrainRequest),
		downlinkReorder:         make(map[uint64][]byte),
	}

	if dohDomain != "" {
		t.dohClient = NewDohClient(dohDomain, fp)
		LogState("transport", "DoH fallback enabled")
	}

	if t.protocol == "http2" && t.dohClient == nil {
		t.streamEnabled = true
		t.streamRx = make(chan []byte, 65536)
	}
	if t.protocol == "http2" {
		t.uplinkEnabled = true
		t.uplinkFrames = make(chan [][]byte, 4096)
	}

	return t
}

func (t *Transport) onRequest() {
	atomic.AddInt64(&t.requestCount, 1)
}

// generateAuth creates an authenticator bound to one active crypto session and
// to this request method and path.
func (t *Transport) generateAuth(req *http.Request) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	nonceHex := hex.EncodeToString(nonce)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	t.mu.RLock()
	sessionID := t.sessionID
	authKey := append([]byte(nil), t.sessionAuthKey...)
	t.mu.RUnlock()
	if sessionID == "" || len(authKey) == 0 {
		return ""
	}
	mac := shared.ComputeSessionRequestMAC(
		authKey,
		timestamp,
		nonceHex,
		t.clientID,
		sessionID,
		req.Method,
		requestPath(req),
	)
	return fmt.Sprintf("Bearer %s:%s:%s:%s:%s", hex.EncodeToString(mac), timestamp, nonceHex, t.clientID, sessionID)
}

// Session setup requests open every carrier connection. Without a query their
// size was the same on every connection; a cache-busting parameter of random
// length, as web applications add to API calls, removes that constant. The
// server routes and authenticates by path only, so the query changes nothing
// it checks.
const (
	sessionQueryMinLength = 6
	sessionQueryMaxLength = 40
	sessionQueryAlphabet  = "0123456789abcdefghijklmnopqrstuvwxyz"
)

func withCacheBuster(rawURL string) string {
	length := sessionQueryMinLength + mathrand.IntN(sessionQueryMaxLength-sessionQueryMinLength+1)
	token := make([]byte, length)
	for i := range token {
		token[i] = sessionQueryAlphabet[mathrand.IntN(len(sessionQueryAlphabet))]
	}
	return rawURL + "?_=" + string(token)
}

func requestPath(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// addBrowserHeaders adds headers coherent with the TLS identity selected at startup.
func (t *Transport) addBrowserHeaders(req *http.Request) {
	profile := t.fingerprint.GetProfile()

	req.Header.Set("User-Agent", profile.UA)
	req.Header.Set("Accept", "application/octet-stream,text/plain,*/*")
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	if len(profile.SecChUa) > 0 {
		req.Header.Set("Sec-Ch-Ua", profile.SecChUa)
		req.Header.Set("Sec-Ch-Ua-Mobile", profile.SecChUaMobile)
		req.Header.Set("Sec-Ch-Ua-Platform", profile.SecChUaPlatform)
	}

	req.Header.Set("Origin", t.serverURL)
	req.Header.Set("Referer", t.serverURL+"/")
	req.Header.Set(shared.RecordShapeHeader, shared.RecordShapeVersion)
	if t.epochAckEnabled.Load() {
		req.Header.Set(shared.EpochAckHeader, shared.EpochAckVersion)
	}
}

func (t *Transport) addHeaders(req *http.Request) {
	t.addBrowserHeaders(req)
	if auth := t.generateAuth(req); auth != "" {
		req.Header.Set("Authorization", auth)
	}
}

func (t *Transport) addConnectHeaders(req *http.Request) {
	profile := t.fingerprint.GetProfile()
	if auth := t.generateAuth(req); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	req.Header.Set("User-Agent", profile.UA)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set(shared.RecordShapeHeader, shared.RecordShapeVersion)
	req.Header.Set(shared.EpochAckHeader, shared.EpochAckVersion)
	req.Header.Set(shared.ClientInstanceHeader, t.clientInstance)
}

func (t *Transport) startHTTP2Workers() {
	if t.protocol != "http2" {
		return
	}
	t.workersOnce.Do(func() {
		// One connection carries both directions, as a browser does with a
		// single HTTP/2 connection per origin.
		if t.connectCarrierEnabled.Load() && t.streamEnabled && t.epochAckEnabled.Load() {
			go t.connectLoop()
			LogState("transport", "bidirectional CONNECT carrier enabled")
		} else {
			if t.streamEnabled {
				go t.streamLoop()
				LogState("transport", "downlink binary stream enabled")
			}
			if t.uplinkEnabled {
				go t.uploadLoop()
				LogState("transport", "uplink binary stream enabled")
			}
		}
		go t.epochLoop()
	})
}

func (t *Transport) popPendingRx() []byte {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()

	if len(t.pendingRx) == 0 {
		return nil
	}
	data := t.pendingRx[0]
	t.pendingRx = t.pendingRx[1:]
	return data
}

func (t *Transport) pushPendingRx(batch [][]byte) {
	if len(batch) == 0 {
		return
	}
	t.pendingMu.Lock()
	t.pendingRx = append(t.pendingRx, batch...)
	t.pendingMu.Unlock()
}

func encodeBinaryBatch(batch [][]byte) ([]byte, int64) {
	total := 0
	var payloadBytes int64
	for _, item := range batch {
		if len(item) == 0 {
			continue
		}
		total += 4 + len(item)
		payloadBytes += int64(len(item))
	}
	if total == 0 {
		return nil, 0
	}

	out := make([]byte, total)
	off := 0
	for _, item := range batch {
		if len(item) == 0 {
			continue
		}
		binary.BigEndian.PutUint32(out[off:off+4], uint32(len(item)))
		off += 4
		copy(out[off:off+len(item)], item)
		off += len(item)
	}
	return out, payloadBytes
}

type decodedBinaryFrame struct {
	payload  []byte
	sequence uint64
}

func decodeBinaryBatch(raw []byte) ([][]byte, error) {
	frames, err := decodeBinaryFrames(raw)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0, len(frames))
	for _, frame := range frames {
		result = append(result, frame.payload)
	}
	return result, nil
}

func decodeBinaryFrames(raw []byte) ([]decodedBinaryFrame, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	result := make([]decodedBinaryFrame, 0, 32)
	off := 0
	for off+4 <= len(raw) {
		wireLength := binary.BigEndian.Uint32(raw[off : off+4])
		off += 4
		paddingFrame := wireLength&shared.BinaryPaddingFrameFlag != 0
		sequenceFrame := wireLength&shared.BinarySequenceFrameFlag != 0
		if paddingFrame && sequenceFrame {
			return nil, fmt.Errorf("binary frame has conflicting flags")
		}
		n := int(wireLength & shared.BinaryFrameLengthMask)
		if n == 0 {
			if paddingFrame {
				return nil, fmt.Errorf("empty record padding frame")
			}
			continue
		}
		if paddingFrame && n > shared.MaxRecordPadding {
			return nil, fmt.Errorf("record padding frame too large: %d", n)
		}
		if n < 0 || n > maxBinaryFrameSize {
			return nil, fmt.Errorf("invalid frame size %d", n)
		}
		if off+n > len(raw) {
			return nil, fmt.Errorf("truncated frame: need %d have %d", n, len(raw)-off)
		}
		payload := raw[off : off+n]
		off += n
		if paddingFrame {
			continue
		}
		if sequenceFrame {
			if len(payload) <= 8 {
				return nil, fmt.Errorf("sequenced downlink frame too small: %d", len(payload))
			}
			result = append(result, decodedBinaryFrame{
				sequence: binary.BigEndian.Uint64(payload[:8]),
				payload:  payload[8:],
			})
			continue
		}
		result = append(result, decodedBinaryFrame{payload: payload})
	}
	if off != len(raw) {
		return nil, fmt.Errorf("trailing %d bytes in binary batch", len(raw)-off)
	}
	return result, nil
}

func encodeDownlinkAckFrame(sequence uint64) []byte {
	if sequence == 0 {
		return nil
	}
	frame := make([]byte, 12)
	binary.BigEndian.PutUint32(frame[:4], shared.BinarySequenceFrameFlag|8)
	binary.BigEndian.PutUint64(frame[4:], sequence)
	return frame
}

func (t *Transport) queueDownlinkAck(sequence uint64) {
	for {
		current := t.downlinkAck.Load()
		if sequence <= current {
			return
		}
		if t.downlinkAck.CompareAndSwap(current, sequence) {
			t.downlinkAckQueued.Add(sequence - current)
			break
		}
	}
	select {
	case t.downlinkAckNotify <- struct{}{}:
	default:
	}
}

// AckBatchStats describes how cumulative downlink ACKs are coalesced on the
// outer HTTPS carrier. Counters are monotonic for the lifetime of a transport.
type AckBatchStats struct {
	SequencesQueued    uint64
	SequencesConfirmed uint64
	PiggybackWrites    uint64
	TimerWrites        uint64
	ThresholdWrites    uint64
	ForcedWrites       uint64
}

func (t *Transport) AckBatchStats() AckBatchStats {
	if t == nil {
		return AckBatchStats{}
	}
	return AckBatchStats{
		SequencesQueued:    t.downlinkAckQueued.Load(),
		SequencesConfirmed: t.downlinkAckConfirmed.Load(),
		PiggybackWrites:    t.downlinkAckPiggyback.Load(),
		TimerWrites:        t.downlinkAckTimer.Load(),
		ThresholdWrites:    t.downlinkAckThreshold.Load(),
		ForcedWrites:       t.downlinkAckForced.Load(),
	}
}

func (t *Transport) registerSequencedDownlink(sequence uint64, payload []byte) ([][]byte, bool) {
	if sequence == 0 || len(payload) == 0 {
		return nil, false
	}
	t.downlinkReorderMu.Lock()
	if t.downlinkReorder == nil {
		t.downlinkReorder = make(map[uint64][]byte)
	}
	current := t.downlinkSequence.Load()
	if sequence <= current {
		t.downlinkReorderMu.Unlock()
		t.queueDownlinkAck(current)
		return nil, true
	}
	// Bound authenticated but out-of-order state so a broken peer cannot grow
	// memory indefinitely. The server's pending window is substantially smaller.
	if sequence-current > 65536 {
		t.downlinkReorderMu.Unlock()
		return nil, false
	}
	if _, exists := t.downlinkReorder[sequence]; !exists {
		t.downlinkReorder[sequence] = append([]byte(nil), payload...)
	}
	ready := make([][]byte, 0, 16)
	for {
		next := current + 1
		item, exists := t.downlinkReorder[next]
		if !exists {
			break
		}
		delete(t.downlinkReorder, next)
		ready = append(ready, item)
		current = next
	}
	if len(ready) > 0 {
		t.downlinkSequence.Store(current)
	}
	t.downlinkReorderMu.Unlock()
	if len(ready) > 0 {
		t.queueDownlinkAck(current)
	}
	return ready, true
}

func (t *Transport) emitBinaryPayload(payload []byte) {
	if len(payload) == 0 {
		return
	}
	atomic.AddInt64(&t.bytesRecv, int64(len(payload)))
	t.recordEpochPayload(int64(len(payload)))
	select {
	case t.streamRx <- payload:
	default:
		t.pushPendingRx([][]byte{payload})
	}
}

// UsesDownlinkStream reports whether persistent stream mode is active.
func (t *Transport) UsesDownlinkStream() bool {
	return t.streamEnabled
}

// UsesUplinkStream reports whether persistent upload stream mode is active.
func (t *Transport) UsesUplinkStream() bool {
	return t.uplinkEnabled
}

func (t *Transport) parseBinaryStream(body io.Reader) error {
	reader := bufio.NewReaderSize(body, 1024*1024)
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(reader, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		wireLength := binary.BigEndian.Uint32(hdr[:])
		paddingFrame := wireLength&shared.BinaryPaddingFrameFlag != 0
		sequenceFrame := wireLength&shared.BinarySequenceFrameFlag != 0
		if paddingFrame && sequenceFrame {
			return fmt.Errorf("stream frame has conflicting flags")
		}
		n := int(wireLength & shared.BinaryFrameLengthMask)
		if n == 0 {
			if paddingFrame {
				return fmt.Errorf("stream has empty padding frame")
			}
			continue
		}
		if paddingFrame {
			if n > shared.MaxRecordPadding {
				return fmt.Errorf("stream padding frame too large: %d", n)
			}
			if _, err := io.CopyN(io.Discard, reader, int64(n)); err != nil {
				return err
			}
			continue
		}
		if n < 0 || n > maxBinaryFrameSize {
			return fmt.Errorf("stream frame size invalid: %d", n)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}
		if sequenceFrame {
			if len(payload) <= 8 {
				return fmt.Errorf("stream sequence frame too small: %d", len(payload))
			}
			ready, valid := t.registerSequencedDownlink(binary.BigEndian.Uint64(payload[:8]), payload[8:])
			if !valid {
				return fmt.Errorf("stream downlink sequence out of order")
			}
			for _, item := range ready {
				t.emitBinaryPayload(item)
			}
			continue
		}
		t.emitBinaryPayload(payload)
	}
}

func (t *Transport) streamLoop() {
	reconnectDelay := 120 * time.Millisecond

	for {
		if t.ctx.Err() != nil {
			return
		}
		client, epochCtx, _ := t.currentStreamEpoch()
		if client == nil || epochCtx == nil {
			time.Sleep(reconnectDelay)
			continue
		}
		reqCtx, cancel := context.WithCancel(epochCtx)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, t.routeStream, nil)
		if err != nil {
			cancel()
			time.Sleep(reconnectDelay)
			if reconnectDelay < 2*time.Second {
				reconnectDelay *= 2
			}
			continue
		}
		t.addHeaders(req)
		req.Header.Set("Accept", "application/octet-stream")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			atomic.StoreInt32(&t.streamLive, 0)
			time.Sleep(reconnectDelay)
			if reconnectDelay < 2*time.Second {
				reconnectDelay *= 2
			}
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			t.noteSessionRejected()
			cancel()
			atomic.StoreInt32(&t.streamLive, 0)
			_ = resp.Body.Close()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode >= 400 {
			if sessionRejectedStatus(resp.StatusCode) {
				t.noteSessionRejected()
			}
			cancel()
			atomic.StoreInt32(&t.streamLive, 0)
			io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			time.Sleep(reconnectDelay)
			if reconnectDelay < 2*time.Second {
				reconnectDelay *= 2
			}
			continue
		}

		reconnectDelay = 120 * time.Millisecond
		t.noteSessionAccepted()
		atomic.StoreInt32(&t.streamLive, 1)
		t.onRequest()
		_ = t.parseBinaryStream(resp.Body)

		atomic.StoreInt32(&t.streamLive, 0)
		_ = resp.Body.Close()
		cancel()
		time.Sleep(reconnectDelay)
	}
}

func (t *Transport) uploadLoop() {
	reconnectDelay := 120 * time.Millisecond

	for {
		if t.ctx.Err() != nil {
			return
		}
		select {
		case drain := <-t.uploadDrain:
			drain.result <- nil
			select {
			case <-drain.release:
			case <-t.ctx.Done():
				return
			}
			continue
		default:
		}

		client, epochCtx, _ := t.currentStreamEpoch()
		if client == nil || epochCtx == nil {
			time.Sleep(reconnectDelay)
			continue
		}
		reqCtx, cancel := context.WithCancel(epochCtx)
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, t.routeUpload, pr)
		if err != nil {
			cancel()
			_ = pr.Close()
			_ = pw.Close()
			time.Sleep(reconnectDelay)
			if reconnectDelay < 2*time.Second {
				reconnectDelay *= 2
			}
			continue
		}
		t.addHeaders(req)
		req.Header.Set("Content-Type", "application/octet-stream")

		respCh := make(chan error, 1)
		go func() {
			resp, err := client.Do(req)
			if err != nil {
				respCh <- err
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode == http.StatusUnauthorized {
				t.noteSessionRejected()
				respCh <- fmt.Errorf("upload stream: authentication failed")
				return
			}
			if resp.StatusCode >= 400 {
				if sessionRejectedStatus(resp.StatusCode) {
					t.noteSessionRejected()
				}
				respCh <- fmt.Errorf("upload stream: server error %d", resp.StatusCode)
				return
			}
			t.noteSessionAccepted()
			respCh <- nil
		}()

		reconnectDelay = 120 * time.Millisecond
		atomic.StoreInt32(&t.uplinkLive, 1)
		var writeErr error
		ackBatcher := newDownlinkAckBatcher(t, pw)
		if err := ackBatcher.flush(downlinkAckWriteForced); err != nil {
			writeErr = err
		}

	loop:
		for writeErr == nil {
			select {
			case <-reqCtx.Done():
				writeErr = reqCtx.Err()
				break loop
			case drain := <-t.uploadDrain:
				drainErr := ackBatcher.flush(downlinkAckWriteForced)
				if drainErr == nil {
					drainErr = t.flushQueuedUplink(pw)
				}
				if drainErr == nil {
					drainErr = pw.Close()
				}
				if drainErr == nil {
					select {
					case drainErr = <-respCh:
					case <-drain.ctx.Done():
						drainErr = drain.ctx.Err()
					case <-reqCtx.Done():
						drainErr = reqCtx.Err()
					}
				}
				drain.result <- drainErr
				select {
				case <-drain.release:
				case <-t.ctx.Done():
					writeErr = t.ctx.Err()
				}
				if writeErr == nil {
					writeErr = drainErr
				}
				break loop
			case err := <-respCh:
				writeErr = err
				break loop
			case <-t.downlinkAckNotify:
				if err := ackBatcher.notify(); err != nil {
					writeErr = err
					break loop
				}
			case <-ackBatcher.timerChannel():
				if err := ackBatcher.flush(downlinkAckWriteTimer); err != nil {
					writeErr = err
					break loop
				}
			case framedBatch := <-t.uplinkFrames:
				if len(framedBatch) == 0 {
					continue
				}
				// BehaviorEngine already batches uplink packets. A second adaptive
				// wait here delayed TCP ACKs and made the outer HTTP/2 carrier
				// application-limited during uploads.
				if err := ackBatcher.writeBatch(framedBatch, downlinkAckWritePiggyback); err != nil {
					writeErr = err
					break loop
				}
			}
		}

		ackBatcher.close()
		atomic.StoreInt32(&t.uplinkLive, 0)
		_ = pw.CloseWithError(writeErr)
		_ = pr.Close()
		cancel()
		select {
		case <-respCh:
		default:
		}

		if t.ctx.Err() != nil {
			return
		}
		time.Sleep(reconnectDelay)
		if reconnectDelay < 2*time.Second {
			reconnectDelay *= 2
		}
	}
}

func payloadBytesOfBatch(batch [][]byte) int64 {
	var n int64
	for _, item := range batch {
		if len(item) == 0 {
			continue
		}
		n += int64(len(item))
	}
	return n
}

func (t *Transport) writeUplinkBatch(writer io.Writer, batch [][]byte) error {
	body, _ := encodeBinaryBatch(batch)
	if len(body) == 0 {
		return nil
	}
	if t.recordShapeEnabled.Load() {
		body = shared.ShapeBinaryRecord(body)
	}
	_, err := writer.Write(body)
	return err
}

// flushQueuedUplink runs while uplinkGate is exclusively held by rotation, so
// the channel has a stable end and every pre-drain frame is written in order.
func (t *Transport) flushQueuedUplink(writer io.Writer) error {
	for {
		select {
		case batch := <-t.uplinkFrames:
			if err := t.writeUplinkBatch(writer, batch); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// Push sends encrypted data to the server.
func (t *Transport) Push(data []byte) error {
	return t.PushBatch([][]byte{data})
}

// PushBatch sends multiple encrypted payloads in one HTTP request using binary frames.
func (t *Transport) PushBatch(batch [][]byte) error {
	if len(batch) == 0 {
		return nil
	}
	payloadBytes := payloadBytesOfBatch(batch)
	if payloadBytes == 0 {
		return nil
	}

	if t.uplinkEnabled {
		t.uplinkGate.RLock()
		if t.ctx.Err() != nil {
			t.uplinkGate.RUnlock()
			return fmt.Errorf("push batch: transport closed")
		}
		queued := false
		select {
		case t.uplinkFrames <- batch:
			queued = true
		default:
			timer := time.NewTimer(4 * time.Millisecond)
			select {
			case t.uplinkFrames <- batch:
				queued = true
			case <-timer.C:
			case <-t.ctx.Done():
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if queued {
			t.uplinkGate.RUnlock()
			t.onRequest()
			atomic.AddInt64(&t.bytesSent, payloadBytes)
			t.recordEpochPayload(payloadBytes)
			return nil
		}
		t.uplinkGate.RUnlock()
	}

	body, _ := encodeBinaryBatch(batch)
	if len(body) == 0 {
		return nil
	}
	if t.recordShapeEnabled.Load() {
		body = shared.ShapeBinaryRecord(body)
	}

	client, requestCtx, _ := t.currentRequestEpoch()
	if client == nil || requestCtx == nil {
		return fmt.Errorf("push batch: transport epoch unavailable")
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, t.routePush, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("push batch: create request failed: %w", err)
	}
	t.addHeaders(req)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push batch: request failed: %w", err)
	}
	defer resp.Body.Close()

	t.onRequest()
	atomic.AddInt64(&t.bytesSent, payloadBytes)
	t.recordEpochPayload(payloadBytes)

	if resp.StatusCode == http.StatusUnauthorized {
		t.noteSessionRejected()
		return fmt.Errorf("push batch: authentication failed")
	}
	if resp.StatusCode >= 400 {
		if sessionRejectedStatus(resp.StatusCode) {
			t.noteSessionRejected()
		}
		return fmt.Errorf("push batch: server error %d", resp.StatusCode)
	}
	t.noteSessionAccepted()
	return nil
}

func (t *Transport) pollHTTPS() ([]byte, error) {
	client, requestCtx, _ := t.currentRequestEpoch()
	if client == nil || requestCtx == nil {
		return nil, fmt.Errorf("poll: transport epoch unavailable")
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, t.routePoll, nil)
	if err != nil {
		return nil, fmt.Errorf("poll: create request failed: %w", err)
	}
	t.addHeaders(req)
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll: request failed: %w", err)
	}
	defer resp.Body.Close()

	t.onRequest()

	if resp.StatusCode == http.StatusUnauthorized {
		t.noteSessionRejected()
		return nil, errPollAuth
	}
	if resp.StatusCode >= 400 {
		if sessionRejectedStatus(resp.StatusCode) {
			t.noteSessionRejected()
		}
		return nil, fmt.Errorf("poll: server error %d", resp.StatusCode)
	}
	t.noteSessionAccepted()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("poll: read body failed: %w", err)
	}
	if len(rawBody) == 0 {
		return nil, nil
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "application/octet-stream") {
		return nil, fmt.Errorf("poll: unexpected content-type %q", ct)
	}

	decodedFrames, err := decodeBinaryFrames(rawBody)
	if err != nil {
		return nil, fmt.Errorf("poll: parse binary response failed: %w", err)
	}
	decodedBatch := make([][]byte, 0, len(decodedFrames))
	for _, frame := range decodedFrames {
		if frame.sequence == 0 {
			decodedBatch = append(decodedBatch, frame.payload)
			continue
		}
		ready, valid := t.registerSequencedDownlink(frame.sequence, frame.payload)
		if !valid {
			return nil, fmt.Errorf("poll: out-of-order downlink sequence %d", frame.sequence)
		}
		decodedBatch = append(decodedBatch, ready...)
	}
	if len(decodedBatch) == 0 {
		return nil, nil
	}

	var recvBytes int64
	for _, payload := range decodedBatch {
		recvBytes += int64(len(payload))
	}
	atomic.AddInt64(&t.bytesRecv, recvBytes)
	t.recordEpochPayload(recvBytes)
	if len(decodedBatch) > 1 {
		t.pushPendingRx(decodedBatch[1:])
	}
	return decodedBatch[0], nil
}

// Poll retrieves data from the server via persistent stream, long-polling, or DoH fallback.
func (t *Transport) Poll() ([]byte, error) {
	if pending := t.popPendingRx(); pending != nil {
		return pending, nil
	}

	if t.streamEnabled {
		// A negotiated CONNECT carrier owns the downlink. Keep draining its
		// queue across reconnects instead of blocking on a separate long poll.
		if t.connectCarrierEnabled.Load() || atomic.LoadInt32(&t.streamLive) == 1 {
			select {
			case data := <-t.streamRx:
				var drained [][]byte
			drainLoop:
				for i := 0; i < 63; i++ {
					select {
					case more := <-t.streamRx:
						if len(more) == 0 {
							continue
						}
						drained = append(drained, more)
					default:
						break drainLoop
					}
				}
				if len(drained) > 0 {
					t.pushPendingRx(drained)
				}
				return data, nil
			case <-time.After(180 * time.Millisecond):
				return nil, nil
			case <-t.ctx.Done():
				return nil, t.ctx.Err()
			}
		}
		// Stream is not live yet; fallback to classic long-poll.
	}

	data, err := t.pollHTTPS()
	if err == nil {
		return data, nil
	}
	if errors.Is(err, errPollAuth) {
		return nil, fmt.Errorf("poll: authentication failed")
	}

	if t.dohClient == nil {
		return nil, err
	}

	LogOperationalFailure("transport", "HTTPS poll failed; trying DoH fallback", err)
	dohData, dohErr := t.dohClient.Poll()
	if dohErr != nil {
		return nil, fmt.Errorf("poll: https failed (%v); doh fallback failed (%w)", err, dohErr)
	}
	if dohData == nil {
		return nil, fmt.Errorf("poll: https failed (%v); doh fallback returned no data", err)
	}
	atomic.AddInt64(&t.bytesRecv, int64(len(dohData)))
	t.recordEpochPayload(int64(len(dohData)))
	return dohData, nil
}

// PollBatch returns the next payload and any payloads that are already queued.
// The persistent carrier delivers many small encrypted IP packets. Returning
// them together lets the behavior engine authenticate a bounded window in
// parallel without changing their order at the TUN boundary.
func (t *Transport) PollBatch(maxPackets int) ([][]byte, error) {
	if maxPackets < 1 {
		maxPackets = 1
	}
	if maxPackets > maxPollBatchPackets {
		maxPackets = maxPollBatchPackets
	}

	first, err := t.Poll()
	if err != nil || len(first) == 0 {
		return nil, err
	}
	batch := make([][]byte, 0, maxPackets)
	batch = append(batch, first)

	for len(batch) < maxPackets {
		if pending := t.popPendingRx(); pending != nil {
			batch = append(batch, pending)
			continue
		}
		if !t.streamEnabled {
			break
		}
		select {
		case payload := <-t.streamRx:
			if len(payload) > 0 {
				batch = append(batch, payload)
			}
		default:
			return batch, nil
		}
	}
	return batch, nil
}

// Sync sends a heartbeat to the server.
// GET /<prefix>/sync
func (t *Transport) Sync() error {
	t.mu.RLock()
	client := t.client
	t.mu.RUnlock()
	previousEpochAck := t.epochAckEnabled.Load()
	if err := t.syncWithClient(client); err != nil {
		return err
	}
	if !previousEpochAck && t.epochAckEnabled.Load() {
		t.restartEpochRequests()
	}
	t.startHTTP2Workers()
	return nil
}

func (t *Transport) syncWithClient(client *http.Client) error {
	if client == nil {
		return fmt.Errorf("sync: transport client is unavailable")
	}
	ctx := t.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	syncCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if t.InnerCipher() == nil {
		if err := t.establishSession(syncCtx, client); err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(syncCtx, http.MethodGet, withCacheBuster(t.routeSync), nil)
	if err != nil {
		return fmt.Errorf("sync: create request failed: %w", err)
	}

	t.addHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sync: request failed: %w", err)
	}
	defer resp.Body.Close()

	t.onRequest()

	if resp.StatusCode == http.StatusUnauthorized {
		t.noteSessionRejected()
		return fmt.Errorf("sync: authentication failed")
	}
	if resp.StatusCode >= 400 {
		if sessionRejectedStatus(resp.StatusCode) {
			t.noteSessionRejected()
		}
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("sync: server error %d", resp.StatusCode)
	}
	var status struct {
		InnerAEAD string `json:"inner_aead"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&status); err != nil {
		return fmt.Errorf("sync: invalid server response: %w", err)
	}
	if status.InnerAEAD != shared.InnerProtocolID {
		return fmt.Errorf("sync: incompatible server inner protocol %q", status.InnerAEAD)
	}
	t.noteSessionAccepted()
	recordShapeSupported := resp.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion
	previousRecordShape := t.recordShapeEnabled.Swap(recordShapeSupported)
	if recordShapeSupported && !previousRecordShape {
		LogState("transport", "record shaping negotiated")
	} else if !recordShapeSupported && previousRecordShape {
		LogState("transport", "record shaping disabled by server capability")
	}
	epochAckSupported := resp.Header.Get(shared.EpochAckHeader) == shared.EpochAckVersion
	previousEpochAck := t.epochAckEnabled.Swap(epochAckSupported)
	if epochAckSupported && !previousEpochAck {
		LogState("transport", "epoch acknowledgement negotiated")
	} else if !epochAckSupported && previousEpochAck {
		LogState("transport", "epoch acknowledgement disabled by server capability")
	}
	tcpStreams := resp.Header.Get(shared.TCPStreamHeader) == shared.TCPStreamVersion
	t.tcpStreamShaped.Store(tcpStreams && resp.Header.Get(shared.TCPStreamShapeHeader) == shared.TCPStreamShapeVersion)
	if previous := t.tcpStreamEnabled.Swap(tcpStreams); tcpStreams && !previous {
		LogState("transport", "TCP streams negotiated")
	}
	connectSupported := epochAckSupported && resp.Header.Get(shared.ConnectCarrierHeader) == shared.ConnectCarrierVersion
	previousConnect := t.connectCarrierEnabled.Swap(connectSupported)
	if connectSupported && !previousConnect {
		LogState("transport", "CONNECT carrier negotiated")
	} else if !connectSupported && previousConnect {
		LogState("transport", "CONNECT carrier disabled by server capability")
	}
	return nil
}

func (t *Transport) establishSession(ctx context.Context, client *http.Client) error {
	challengeRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, withCacheBuster(t.routeSync), nil)
	if err != nil {
		return fmt.Errorf("session: create challenge request: %w", err)
	}
	t.addBrowserHeaders(challengeRequest)
	challengeResponse, err := client.Do(challengeRequest)
	if err != nil {
		return fmt.Errorf("session: challenge request failed: %w", err)
	}
	defer challengeResponse.Body.Close()
	t.onRequest()
	if challengeResponse.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, challengeResponse.Body)
		return fmt.Errorf("session: challenge failed with status %d", challengeResponse.StatusCode)
	}
	var challenge struct {
		Protocol    string `json:"protocol"`
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	if err := json.NewDecoder(io.LimitReader(challengeResponse.Body, 8*1024)).Decode(&challenge); err != nil {
		return fmt.Errorf("session: invalid challenge response: %w", err)
	}
	challengeIDBytes, challengeIDErr := hex.DecodeString(challenge.ChallengeID)
	challengeBytes, challengeErr := hex.DecodeString(challenge.Challenge)
	if challenge.Protocol != shared.SessionProtocolID || challengeIDErr != nil || len(challengeIDBytes) != 16 ||
		challengeErr != nil || len(challengeBytes) != 32 {
		return fmt.Errorf("session: incompatible or malformed challenge")
	}

	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return fmt.Errorf("session: generate client nonce: %w", err)
	}
	clientNonceHex := hex.EncodeToString(clientNonce)
	establishPayload := struct {
		Protocol       string `json:"protocol"`
		ChallengeID    string `json:"challenge_id"`
		ClientID       string `json:"client_id"`
		ClientInstance string `json:"client_instance"`
		ClientNonce    string `json:"client_nonce"`
	}{
		Protocol:       shared.SessionProtocolID,
		ChallengeID:    challenge.ChallengeID,
		ClientID:       t.clientID,
		ClientInstance: t.clientInstance,
		ClientNonce:    clientNonceHex,
	}
	body, err := json.Marshal(establishPayload)
	if err != nil {
		return fmt.Errorf("session: encode establishment request: %w", err)
	}
	establishRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, withCacheBuster(t.routeSync), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("session: create establishment request: %w", err)
	}
	t.addBrowserHeaders(establishRequest)
	establishRequest.Header.Set("Content-Type", "application/json")
	bootstrapMAC := shared.ComputeBootstrapMAC(
		t.psk,
		challenge.ChallengeID,
		challenge.Challenge,
		t.clientID,
		t.clientInstance,
		clientNonceHex,
	)
	establishRequest.Header.Set("Authorization", "Bootstrap "+hex.EncodeToString(bootstrapMAC))
	establishResponse, err := client.Do(establishRequest)
	if err != nil {
		return fmt.Errorf("session: establishment request failed: %w", err)
	}
	defer establishResponse.Body.Close()
	t.onRequest()
	if establishResponse.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("session: establishment rejected")
	}
	if establishResponse.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, establishResponse.Body)
		return fmt.Errorf("session: establishment failed with status %d", establishResponse.StatusCode)
	}
	var established struct {
		Protocol    string `json:"protocol"`
		InnerAEAD   string `json:"inner_aead"`
		SessionID   string `json:"session_id"`
		ServerNonce string `json:"server_nonce"`
		ServerProof string `json:"server_proof"`
	}
	if err := json.NewDecoder(io.LimitReader(establishResponse.Body, 8*1024)).Decode(&established); err != nil {
		return fmt.Errorf("session: invalid establishment response: %w", err)
	}
	sessionIDBytes, sessionIDErr := hex.DecodeString(established.SessionID)
	serverNonce, serverNonceErr := hex.DecodeString(established.ServerNonce)
	serverProof, proofErr := hex.DecodeString(established.ServerProof)
	if established.Protocol != shared.SessionProtocolID || established.InnerAEAD != shared.InnerProtocolID ||
		sessionIDErr != nil || len(sessionIDBytes) != 32 || serverNonceErr != nil || len(serverNonce) != 32 ||
		proofErr != nil || len(serverProof) != 32 {
		return fmt.Errorf("session: incompatible or malformed establishment response")
	}
	keys, err := shared.DeriveSessionKeys(
		t.psk,
		clientNonce,
		serverNonce,
		established.SessionID,
		t.clientID,
		t.clientInstance,
	)
	if err != nil {
		return fmt.Errorf("session: derive keys: %w", err)
	}
	expectedProof := shared.ComputeServerProof(
		keys.AuthKey,
		established.SessionID,
		clientNonceHex,
		established.ServerNonce,
		t.clientID,
		t.clientInstance,
	)
	if !hmac.Equal(serverProof, expectedProof) {
		return fmt.Errorf("session: server proof verification failed")
	}
	cipher, err := NewCipher(keys, established.SessionID)
	if err != nil {
		return fmt.Errorf("session: initialize inner cipher: %w", err)
	}
	t.mu.Lock()
	t.sessionID = established.SessionID
	t.sessionAuthKey = append([]byte(nil), keys.AuthKey...)
	t.streamKey = append([]byte(nil), keys.StreamKey...)
	t.innerCipher = cipher
	t.mu.Unlock()
	return nil
}

func (t *Transport) restartEpochRequests() {
	newEpochCtx, newEpochCancel := context.WithCancel(t.ctx)
	t.mu.Lock()
	oldEpochCancel := t.epochCancel
	t.epochCtx = newEpochCtx
	t.epochCancel = newEpochCancel
	t.mu.Unlock()
	if oldEpochCancel != nil {
		oldEpochCancel()
	}
}

// Stats returns current transport statistics.
func (t *Transport) Stats() (requests, sent, recv int64) {
	return atomic.LoadInt64(&t.requestCount),
		atomic.LoadInt64(&t.bytesSent),
		atomic.LoadInt64(&t.bytesRecv)
}

// CurrentShieldDomain returns currently active REALITY shield domain.
func (t *Transport) CurrentShieldDomain() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.shieldDomain
}

// IsOperational reports the state of the actual carrier rather than merely
// whether the client process was started. Persistent workers clear their live
// flags as soon as a network path dies and set them again after reconnection.
func (t *Transport) IsOperational() bool {
	if t == nil || t.ctx == nil || t.ctx.Err() != nil {
		return false
	}
	if t.protocol != "http2" {
		return false
	}
	downlinkReady := !t.streamEnabled || atomic.LoadInt32(&t.streamLive) == 1
	uplinkReady := !t.uplinkEnabled || atomic.LoadInt32(&t.uplinkLive) == 1
	return downlinkReady && uplinkReady
}

// Close terminates background loops and force-closes the active generation.
func (t *Transport) Close() {
	t.closeOnce.Do(func() {
		if t.cancelCtx != nil {
			t.cancelCtx()
		}

		t.mu.Lock()
		clients := transportClients{client: t.client, streamClient: t.streamClient}
		epochCancel := t.epochCancel
		t.mu.Unlock()

		if epochCancel != nil {
			epochCancel()
		}
		closeTransportClients(clients)
	})
}
