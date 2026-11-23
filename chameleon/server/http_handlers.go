package main

import (
	"bufio"
	"bytes"
	"chameleon/shared"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxBinaryFrameSize = 4 * 1024 * 1024

type incomingBinaryFrame struct {
	payload        []byte
	ackSequence    uint64
	acknowledgment bool
}

func processIncomingPayload(body []byte, session *clientSession, demasker *Demasker, cipher *Cipher) error {
	// Incoming authenticated payload proves that the currently bound network is
	// still live. A roaming handover is allowed only after this activity stops.
	session.touch()
	plaintext, err := cipher.Decrypt(body)
	if err != nil {
		return fmt.Errorf("reject unauthenticated inner payload: %w", err)
	}
	body = plaintext

	// Strip fast-path binary padding (padPacketBinary) if present. Only accept the
	// unpadded result when it looks like a raw IPv4 packet — this leaves legacy
	// Pack-framed payloads (e.g. cover traffic) untouched so they still reach the
	// demasker fallback below.
	if unp, ok := serverUnpadPacketBinary(body); ok && isLikelyRawIPv4Packet(unp) {
		body = unp
	}

	// Fast path for current mobile clients: raw IPv4 packet directly in binary frame.
	// Keeps backward compatibility by falling back to legacy demasking if payload
	// is not a valid raw IPv4 packet.
	if isLikelyRawIPv4Packet(body) {
		normalized, normErr := trimIPv4Packet(body)
		if normErr != nil {
			return normErr
		}
		if err := forwardClientPacketToVPN(session, normalized); err != nil {
			if errors.Is(err, errNotIPv4) {
				return nil
			}
			return fmt.Errorf("relay packet: %w", err)
		}
		return nil
	}

	session.cryptoMu.RLock()
	if session.packetDemasker != nil {
		demasker = session.packetDemasker
	}
	session.cryptoMu.RUnlock()
	result, dmErr := demasker.DemaskPlaintext(body)
	if dmErr != nil {
		return fmt.Errorf("demask payload: %w", dmErr)
	}
	if result == nil {
		return nil
	}
	if err := forwardClientPacketToVPN(session, result); err != nil {
		if errors.Is(err, errNotIPv4) {
			return nil
		}
		return fmt.Errorf("relay demasked packet: %w", err)
	}
	return nil
}

func readBinaryFrame(reader *bufio.Reader) (incomingBinaryFrame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(reader, hdr[:]); err != nil {
		return incomingBinaryFrame{}, err
	}
	wireLength := binary.BigEndian.Uint32(hdr[:])
	paddingFrame := wireLength&shared.BinaryPaddingFrameFlag != 0
	sequenceFrame := wireLength&shared.BinarySequenceFrameFlag != 0
	if paddingFrame && sequenceFrame {
		return incomingBinaryFrame{}, fmt.Errorf("binary frame has conflicting flags")
	}
	n := int(wireLength & shared.BinaryFrameLengthMask)
	if n == 0 {
		if paddingFrame {
			return incomingBinaryFrame{}, fmt.Errorf("empty record padding frame")
		}
		return incomingBinaryFrame{}, nil // keepalive frame
	}
	if paddingFrame {
		if n > shared.MaxRecordPadding {
			return incomingBinaryFrame{}, fmt.Errorf("record padding frame too large: %d", n)
		}
		if _, err := io.CopyN(io.Discard, reader, int64(n)); err != nil {
			return incomingBinaryFrame{}, err
		}
		return incomingBinaryFrame{}, nil
	}
	if sequenceFrame {
		if n != 8 {
			return incomingBinaryFrame{}, fmt.Errorf("invalid acknowledgement frame size %d", n)
		}
		var sequence [8]byte
		if _, err := io.ReadFull(reader, sequence[:]); err != nil {
			return incomingBinaryFrame{}, err
		}
		return incomingBinaryFrame{
			ackSequence:    binary.BigEndian.Uint64(sequence[:]),
			acknowledgment: true,
		}, nil
	}
	if n < 0 || n > maxBinaryFrameSize {
		return incomingBinaryFrame{}, fmt.Errorf("invalid frame size %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return incomingBinaryFrame{}, err
	}
	return incomingBinaryFrame{payload: payload}, nil
}

func writeBinaryBatch(w io.Writer, batch [][]byte, cipher *Cipher, shapeRecord bool) error {
	var encoded bytes.Buffer
	stepUp := serverBatchStepUp(batch)
	for _, payload := range batch {
		if len(payload) == 0 {
			continue
		}
		// Pad each downlink packet so the frame length is quantized to a bucket
		// instead of leaking the exact IP packet size. The client strips this in
		// handleInboundPacket (unpadPacketBinary).
		padded := serverPadPacketInBatch(payload, stepUp)
		encrypted, err := cipher.Encrypt(padded)
		if err != nil {
			return fmt.Errorf("encrypt downlink packet: %w", err)
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(encrypted)))
		encoded.Write(hdr[:])
		encoded.Write(encrypted)
	}
	if encoded.Len() == 0 {
		return nil
	}
	body := encoded.Bytes()
	if shapeRecord {
		body = shared.ShapeBinaryRecord(body)
	}
	_, err := w.Write(body)
	return err
}

func writeSequencedBinaryBatch(w io.Writer, batch []pendingDownlinkFrame, cipher *Cipher, shapeRecord bool) error {
	var encoded bytes.Buffer
	stepUp := sequencedBatchStepUp(batch)
	for _, frame := range batch {
		if frame.sequence == 0 || len(frame.payload) == 0 {
			continue
		}
		encrypted := frame.encrypted
		if len(encrypted) == 0 {
			padded := serverPadPacketInBatch(frame.payload, stepUp)
			var err error
			encrypted, err = cipher.Encrypt(padded)
			if err != nil {
				return fmt.Errorf("encrypt sequenced downlink packet: %w", err)
			}
		}
		wireSize := 8 + len(encrypted)
		if wireSize > int(shared.BinaryFrameLengthMask) {
			return fmt.Errorf("sequenced downlink frame too large: %d", wireSize)
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], shared.BinarySequenceFrameFlag|uint32(wireSize))
		encoded.Write(hdr[:])
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], frame.sequence)
		encoded.Write(sequence[:])
		encoded.Write(encrypted)
	}
	if encoded.Len() == 0 {
		return nil
	}
	body := encoded.Bytes()
	if shapeRecord {
		body = shared.ShapeBinaryRecord(body)
	}
	_, err := w.Write(body)
	return err
}

func sequencedBatchStepUp(batch []pendingDownlinkFrame) bool {
	total := 0
	for _, frame := range batch {
		total += len(frame.payload)
	}
	return shared.PacketPaddingStepUp(total)
}

func epochAckRequested(r *http.Request) bool {
	return r.Header.Get(shared.EpochAckHeader) == shared.EpochAckVersion
}

func collectOutboxBatch(session *clientSession, first []byte, maxPackets int, maxBytes int) [][]byte {
	batch := make([][]byte, 0, maxPackets)
	batch = append(batch, first)
	total := len(first)

	delay := serverAdaptiveCoalesceDelay(total)
	if delay <= 0 {
		for len(batch) < maxPackets && total < maxBytes {
			select {
			case next := <-session.outbox:
				batch = append(batch, next)
				total += len(next)
			default:
				return batch
			}
		}
		return batch
	}
	var timer *time.Timer
	var deadline <-chan time.Time
	timer = time.NewTimer(delay)
	deadline = timer.C
	defer timer.Stop()

	for len(batch) < maxPackets && total < maxBytes {
		select {
		case next := <-session.outbox:
			batch = append(batch, next)
			total += len(next)
			if total >= maxBytes {
				return batch
			}
		case <-deadline:
			return batch
		}
	}
	return batch
}

func serverAdaptiveCoalesceDelay(totalBytes int) time.Duration {
	// Large batches are ready immediately. Small control packets get only a
	// short randomized window so TCP ACKs are not held for up to 10 ms.
	if totalBytes >= 4*1024 {
		return 0
	}
	var entropy [1]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		entropy[0] = 0
	}
	return time.Duration(1+entropy[0]%3) * time.Millisecond
}

// admitSession resolves the authenticated request's runtime session without
// taking a request slot. TCP streams use it directly: they are bounded by
// their own per-session limit, not by the small tunnel request limit.
func admitSession(w http.ResponseWriter, r *http.Request, clientID string) (*clientSession, bool) {
	cryptoSession := CryptoSessionFromContext(r.Context())
	if cryptoSession == nil || cryptoSession.clientID != clientID || cryptoSession.cipher == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	session := getSession(cryptoSession.runtimeID(), remoteHost(r.RemoteAddr))
	if session == nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "Service temporarily at capacity", http.StatusServiceUnavailable)
		return nil, false
	}
	if session.bindCrypto(cryptoSession) {
		session.revokeCarrier()
		session.resetClientEpoch()
	}
	return session, true
}

func admitSessionRequest(w http.ResponseWriter, r *http.Request, clientID string) (*clientSession, func(), bool) {
	session, ok := admitSession(w, r, clientID)
	if !ok {
		return nil, nil, false
	}
	finishRequest, ok := session.tryBeginRequest()
	if !ok {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too many concurrent requests", http.StatusTooManyRequests)
		return nil, nil, false
	}
	return session, finishRequest, true
}

// handlePush receives encrypted tunnel data from client.
// Binary format: repeated [4-byte length][payload] frames.
func handlePush(demasker *Demasker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		cipher := CipherFromContext(r.Context())
		if cipher == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(ct, "application/octet-stream") {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		clientID := ClientIDFromContext(r.Context())
		session, finishRequest, ok := admitSessionRequest(w, r, clientID)
		if !ok {
			return
		}
		defer finishRequest()
		reader := bufio.NewReaderSize(r.Body, 1024*1024)

		for {
			if r.Context().Err() != nil {
				return
			}
			frame, err := readBinaryFrame(reader)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			if frame.acknowledgment {
				if !epochAckRequested(r) {
					http.Error(w, "Bad request", http.StatusBadRequest)
					return
				}
				if !session.acknowledgeDownlink(frame.ackSequence) {
					http.Error(w, "Bad request", http.StatusBadRequest)
					return
				}
				continue
			}
			if len(frame.payload) == 0 {
				continue
			}
			if err := processIncomingPayload(frame.payload, session, demasker, cipher); err != nil {
				if errors.Is(err, errPacketSourceNotAssigned) {
					logRateLimitedEvent("push", "dropped packet from unassigned source")
					continue
				}
				logOperationalFailure("push", "tunnel payload rejected", err)
				http.Error(w, "Tunnel forwarding failed", http.StatusBadGateway)
				return
			}
		}

		apiHeaders(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleUpload receives tunnel data via a persistent request body stream.
// Semantics match /push, but the client may keep this request open over HTTP/2.
func handleUpload(demasker *Demasker) http.HandlerFunc {
	return handlePush(demasker)
}

// handleConnect carries both tunnel directions over one authenticated HTTP/2
// CONNECT stream. The request body is uplink and the response body is downlink;
// inner encryption and sequence acknowledgements remain unchanged.
func handleConnect(demasker *Demasker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
			return
		}
		if !epochAckRequested(r) {
			http.Error(w, "Epoch acknowledgement required", http.StatusBadRequest)
			return
		}
		cipher := CipherFromContext(r.Context())
		if cipher == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			http.Error(w, "Streaming read unsupported", http.StatusInternalServerError)
			return
		}
		if err := controller.SetWriteDeadline(time.Time{}); err != nil {
			http.Error(w, "Streaming write unsupported", http.StatusInternalServerError)
			return
		}

		clientID := ClientIDFromContext(r.Context())
		instance := strings.TrimSpace(r.Header.Get(shared.ClientInstanceHeader))
		instanceBytes, instanceErr := hex.DecodeString(instance)
		if instanceErr != nil || len(instanceBytes) != 16 {
			http.Error(w, "Client instance required", http.StatusBadRequest)
			return
		}
		session, finishRequest, ok := admitSessionRequest(w, r, clientID)
		if !ok {
			return
		}
		defer finishRequest()
		carrierCtx, releaseCarrier, newClientEpoch := session.replaceCarrier(r.Context(), instance)
		defer releaseCarrier()
		if carrierCtx.Err() != nil {
			return
		}
		if newClientEpoch {
			session.resetClientEpoch()
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(shared.ConnectCarrierHeader, shared.ConnectCarrierVersion)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		readResult := make(chan error, 1)
		go func() {
			defer releaseCarrier()
			reader := bufio.NewReaderSize(r.Body, 1024*1024)
			for {
				if carrierCtx.Err() != nil {
					readResult <- carrierCtx.Err()
					return
				}
				frame, err := readBinaryFrame(reader)
				if err != nil {
					if errors.Is(err, io.EOF) {
						readResult <- nil
					} else {
						readResult <- err
					}
					return
				}
				if frame.acknowledgment {
					if !session.acknowledgeDownlink(frame.ackSequence) {
						readResult <- fmt.Errorf("invalid downlink acknowledgement %d", frame.ackSequence)
						return
					}
					continue
				}
				if len(frame.payload) == 0 {
					continue
				}
				if err := processIncomingPayload(frame.payload, session, demasker, cipher); err != nil {
					if errors.Is(err, errPacketSourceNotAssigned) {
						logRateLimitedEvent("connect", "dropped packet from unassigned source")
						continue
					}
					readResult <- err
					return
				}
			}
		}()

		// A single empty frame confirms that response streaming is established.
		var zero [4]byte
		if _, err := w.Write(zero[:]); err != nil {
			return
		}
		flusher.Flush()

		pending := session.pendingDownlinkSnapshot(maxPendingDownlinkPackets, maxPendingDownlinkBytes)
		for len(pending) > 0 {
			count := min(3072, len(pending))
			if err := writeSequencedBinaryBatch(
				w,
				pending[:count],
				cipher,
				r.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion,
			); err != nil {
				return
			}
			flusher.Flush()
			pending = pending[count:]
		}

		for {
			if !session.waitDownlinkCapacity(carrierCtx) {
				return
			}
			select {
			case err := <-readResult:
				if err != nil {
					logOperationalFailure("connect", "carrier read failed", err)
				}
				return
			case data := <-session.outbox:
				batch := collectOutboxBatch(session, data, 3072, 3*1024*1024)
				reserved, err := session.reserveDownlinkBatch(batch, cipher)
				if err != nil {
					return
				}
				if err := writeSequencedBinaryBatch(w, reserved, cipher,
					r.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion); err != nil {
					return
				}
				flusher.Flush()
			case <-carrierCtx.Done():
				return
			}
		}
	}
}

// handlePoll provides data to the client via long-polling.
// Binary format: repeated [4-byte length][payload] frames.
func handlePoll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cipher := CipherFromContext(r.Context())
		if cipher == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientID := ClientIDFromContext(r.Context())
		session, finishRequest, ok := admitSessionRequest(w, r, clientID)
		if !ok {
			return
		}
		defer finishRequest()
		sequenced := epochAckRequested(r)
		if sequenced {
			// The persistent stream owns sequenced downlink delivery. A fallback
			// poll must never queue behind it: doing so can outlive the client's
			// request timeout and repeatedly starve stream reconnection.
			if !session.downlinkOwnerMu.TryLock() {
				apiHeaders(w)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			defer session.downlinkOwnerMu.Unlock()
			if pending := session.pendingDownlinkSnapshot(1536, 1536*1024); len(pending) > 0 {
				apiHeaders(w)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)
				_ = writeSequencedBinaryBatch(
					w,
					pending,
					cipher,
					r.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion,
				)
				return
			}
			if !session.waitDownlinkCapacity(r.Context()) {
				return
			}
		}

		// A sequenced poll owns the downlink while it waits; give it up at once
		// when the persistent stream asks for it.
		var takeover <-chan struct{}
		if sequenced {
			takeover = session.downlinkTakeover
		}
		timeout := time.After(30 * time.Second)
		select {
		case <-takeover:
			apiHeaders(w)
			w.WriteHeader(http.StatusNoContent)
		case data := <-session.outbox:
			batch := collectOutboxBatch(session, data, 1536, 1536*1024)
			apiHeaders(w)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			shapeRecord := r.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion
			var err error
			if sequenced {
				var reserved []pendingDownlinkFrame
				reserved, err = session.reserveDownlinkBatch(batch, cipher)
				if err == nil {
					err = writeSequencedBinaryBatch(w, reserved, cipher, shapeRecord)
				}
			} else {
				err = writeBinaryBatch(w, batch, cipher, shapeRecord)
			}
			if err != nil {
				return
			}
		case <-timeout:
			// No payload available.
			apiHeaders(w)
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
			return
		}
	}
}

// handleStream provides a persistent downlink stream (best over HTTP/2).
// Binary format: repeated [4-byte length][payload] frames.
func handleStream() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cipher := CipherFromContext(r.Context())
		if cipher == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientID := ClientIDFromContext(r.Context())
		session, finishRequest, ok := admitSessionRequest(w, r, clientID)
		if !ok {
			return
		}
		defer finishRequest()
		sequenced := epochAckRequested(r)
		if sequenced {
			if !session.acquireDownlinkForStream(r.Context()) {
				return
			}
			defer session.downlinkOwnerMu.Unlock()
		}

		apiHeaders(w)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Initial keepalive frame so client can confirm stream is live.
		var zero [4]byte
		if _, err := w.Write(zero[:]); err != nil {
			return
		}
		flusher.Flush()
		if sequenced {
			pending := session.pendingDownlinkSnapshot(maxPendingDownlinkPackets, maxPendingDownlinkBytes)
			for len(pending) > 0 {
				count := min(3072, len(pending))
				if err := writeSequencedBinaryBatch(
					w,
					pending[:count],
					cipher,
					r.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion,
				); err != nil {
					return
				}
				flusher.Flush()
				pending = pending[count:]
			}
		}

		for {
			shapeRecord := r.Header.Get(shared.RecordShapeHeader) == shared.RecordShapeVersion
			if sequenced && !session.waitDownlinkCapacity(r.Context()) {
				return
			}
			select {
			case data := <-session.outbox:
				batch := collectOutboxBatch(session, data, 3072, 3*1024*1024)
				var err error
				if sequenced {
					var reserved []pendingDownlinkFrame
					reserved, err = session.reserveDownlinkBatch(batch, cipher)
					if err == nil {
						err = writeSequencedBinaryBatch(w, reserved, cipher, shapeRecord)
					}
				} else {
					err = writeBinaryBatch(w, batch, cipher, shapeRecord)
				}
				if err != nil {
					return
				}
				flusher.Flush()

			case <-r.Context().Done():
				return
			}
		}
	}
}

// randomVersion returns a plausible-looking semver string for response padding.
func randomVersion() string {
	major, _ := rand.Int(rand.Reader, big.NewInt(3))
	minor, _ := rand.Int(rand.Reader, big.NewInt(20))
	patch, _ := rand.Int(rand.Reader, big.NewInt(50))
	return fmt.Sprintf("%d.%d.%d", major.Int64()+1, minor.Int64(), patch.Int64())
}

// handleSync is a simple heartbeat endpoint.
// GET /<prefix>/sync
func handleSync() http.HandlerFunc {
	return handleSyncWithCapabilities(true)
}

func handleSyncWithCapabilities(advertiseConnect bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(shared.RecordShapeHeader, shared.RecordShapeVersion)
		w.Header().Set(shared.EpochAckHeader, shared.EpochAckVersion)
		w.Header().Set(shared.TCPStreamHeader, shared.TCPStreamVersion)
		w.Header().Set(shared.TCPStreamShapeHeader, shared.TCPStreamShapeVersion)
		if advertiseConnect {
			w.Header().Set(shared.ConnectCarrierHeader, shared.ConnectCarrierVersion)
		}
		sessionThinkTime(r.Context())
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","ts":%d,"v":"%s","rid":"%s","inner_aead":"%s","pad":"%s"}`,
			time.Now().UnixMilli(), randomVersion(), randomHex(8), shared.InnerProtocolID, sessionPadding())
	}
}

// handleSessionSync performs a challenge/response bootstrap for a new crypto
// session and serves authenticated heartbeats after establishment.
func handleSessionSync(sessions *cryptoSessionManager, advertiseConnect bool) http.HandlerFunc {
	heartbeat := SessionAuthMiddleware(sessions, handleSyncWithCapabilities(advertiseConnect))
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
				heartbeat(w, r)
				return
			}
			challenge, err := sessions.challenge(time.Now())
			if err != nil {
				http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			challenge.Padding = sessionPadding()
			sessionThinkTime(r.Context())
			apiHeaders(w)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(challenge)
		case http.MethodPost:
			defer r.Body.Close()
			var request sessionEstablishRequest
			decoder := json.NewDecoder(io.LimitReader(r.Body, 8*1024))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			auth := strings.TrimSpace(r.Header.Get("Authorization"))
			encodedMAC := strings.TrimPrefix(auth, "Bootstrap ")
			if encodedMAC == auth {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			bootstrapMAC, err := hex.DecodeString(encodedMAC)
			if err != nil || len(bootstrapMAC) != 32 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			response, _, err := sessions.establish(request, bootstrapMAC, time.Now())
			if err != nil {
				logRateLimitedEvent("auth", "rejected session establishment")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			response.Padding = sessionPadding()
			sessionThinkTime(r.Context())
			apiHeaders(w)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleBootstrap publishes minimal runtime profile for first-run clients.
// WARNING: this endpoint discloses PSK intentionally for one-tap family onboarding.
func handleBootstrap(cfg *ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if cfg.PSKKey == "" {
			http.Error(w, "Bootstrap unavailable", http.StatusServiceUnavailable)
			return
		}

		certMode := "auto"
		if strings.TrimSpace(cfg.RealityPublicKey) != "" {
			certMode = "reality"
		}

		// Always return tunnel endpoint (listen_port), not bootstrap listener port.
		host := strings.TrimSpace(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			host = strings.TrimSpace(cfg.Domain)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		if host == "" {
			host = "127.0.0.1"
		}
		serverAddress := net.JoinHostPort(host, strconv.Itoa(cfg.ListenPort))

		shieldPreset := strings.TrimSpace(cfg.ShieldPreset)
		if shieldPreset == "" {
			shieldPreset = strings.TrimSpace(cfg.ShieldDomain)
		}

		realityShieldDomain := ""
		if strings.EqualFold(shieldPreset, "custom") {
			realityShieldDomain = strings.TrimSpace(cfg.ShieldDomain)
		}

		tunnelMode := "udp-relay"
		if kernelTun != nil {
			tunnelMode = "full-device"
		}

		resp := map[string]any{
			"service":                   "chameleon",
			"server_tunnel_mode":        tunnelMode,
			"udp_enabled":               true,
			"ipv6_enabled":              false,
			"server_address":            serverAddress,
			"psk_key":                   strings.ToLower(cfg.PSKKey),
			"protocol":                  "http2",
			"buffer_size":               1000,
			"reconnect_interval":        5,
			"doh_domain":                strings.TrimSpace(cfg.DoHDomain),
			"cert_mode":                 certMode,
			"reality_shield_preset":     shieldPreset,
			"reality_server_public_key": strings.ToLower(strings.TrimSpace(cfg.RealityPublicKey)),
			"reality_shield_domain":     realityShieldDomain,
			"ts":                        time.Now().UnixMilli(),
		}

		apiHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
