package clientcore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"chameleon/shared"
)

const tcpStreamSetupTimeout = 15 * time.Second

var (
	ErrTCPStreamUnsupported = errors.New("server does not offer TCP streams")
	ErrTCPStreamRefused     = errors.New("server refused the TCP stream")
)

// TCPStream is one device TCP connection carried as an HTTP/2 request.
// Writes are the device's bytes to the site; reads are the site's bytes.
type TCPStream struct {
	body   *io.PipeWriter
	resp   *http.Response
	framer *shared.TCPStreamFramer
	cancel context.CancelFunc
	// release ends the stream's hold on its transport epoch; payload counts
	// the stream's bytes as epoch traffic.
	release func()
	payload func(int64)

	readMu  sync.Mutex
	pending []byte

	writeMu sync.Mutex
	closed  sync.Once
}

// OpenTCPStream asks the server to connect to target and returns the stream
// once the server has reached it. early is the device's first data, if it
// already sent some: it leaves together with the request, so the site gets it
// right after the server's dial instead of one round trip later, and the
// carrier shows one request instead of an opening exchange followed by the
// device's first message. The stream keeps its transport epoch's connection
// open after a rotation until it ends (see retireEpoch).
func (t *Transport) OpenTCPStream(ctx context.Context, target netip.AddrPort, early []byte) (stream *TCPStream, err error) {
	if !t.tcpStreamEnabled.Load() {
		return nil, ErrTCPStreamUnsupported
	}
	encodedTarget, err := shared.EncodeTCPStreamTarget(target)
	if err != nil {
		return nil, err
	}
	t.mu.RLock()
	streamKey, sessionID := t.streamKey, t.sessionID
	t.mu.RUnlock()
	client, generation, group := t.acquireStreamEpoch()
	defer func() {
		if stream == nil {
			t.releaseStreamEpoch(generation)
		}
	}()
	if client == nil || len(streamKey) != 32 || sessionID == "" {
		return nil, fmt.Errorf("tcp stream: transport not ready")
	}
	nonce := make([]byte, shared.TCPStreamNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cipher, err := shared.NewTCPStreamCipher(streamKey, sessionID, nonce, true)
	if err != nil {
		return nil, err
	}
	shaped := t.tcpStreamShaped.Load()
	framer := shared.NewTCPStreamFramer(cipher, shaped, true)
	// Nonce, destination and early data leave in one write: one DATA frame
	// whose size varies, instead of fixed-size records at every stream start.
	preamble := append(make([]byte, 0, len(nonce)+64+len(early)), nonce...)
	if preamble, err = framer.AppendFrame(preamble, encodedTarget); err != nil {
		return nil, err
	}
	for rest := early; len(rest) > 0; {
		chunk := rest[:min(len(rest), framer.MaxData())]
		if preamble, err = framer.AppendFrame(preamble, chunk); err != nil {
			return nil, err
		}
		rest = rest[len(chunk):]
	}

	streamCtx, cancel := context.WithCancel(t.ctx)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, t.routeTCP, pr)
	if err != nil {
		cancel()
		return nil, err
	}
	t.addHeaders(req)
	req.Header.Set("Content-Type", "application/octet-stream")
	if shaped {
		req.Header.Set(shared.TCPStreamShapeHeader, shared.TCPStreamShapeVersion)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	answered := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		answered <- result{resp, err}
	}()
	go func() {
		// Do reads the body concurrently; the write returns once the transport
		// has taken it, or fails when the request is abandoned. Later writes
		// on the pipe are gated behind it, so their order is kept.
		_, _ = pw.Write(preamble)
	}()

	timer := time.NewTimer(tcpStreamSetupTimeout)
	defer timer.Stop()
	var res result
	select {
	case res = <-answered:
	case <-timer.C:
		cancel()
		_ = pw.CloseWithError(context.DeadlineExceeded)
		return nil, fmt.Errorf("tcp stream: no answer from server")
	case <-ctx.Done():
		cancel()
		_ = pw.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
	if res.err != nil {
		cancel()
		_ = pw.CloseWithError(res.err)
		return nil, fmt.Errorf("tcp stream: %w", res.err)
	}
	t.onRequest()
	if res.resp.StatusCode != http.StatusOK {
		if sessionRejectedStatus(res.resp.StatusCode) {
			t.noteSessionRejected()
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.resp.Body, 4096))
		_ = res.resp.Body.Close()
		cancel()
		_ = pw.Close()
		return nil, fmt.Errorf("%w (status %d)", ErrTCPStreamRefused, res.resp.StatusCode)
	}
	t.noteSessionAccepted()
	return &TCPStream{
		body: pw, resp: res.resp, framer: framer, cancel: cancel,
		release: func() { t.releaseStreamEpoch(generation) },
		payload: func(bytes int64) {
			group.touch()
			t.recordEpochStreamBytes(bytes)
		},
	}, nil
}

// Read returns site bytes; io.EOF once the site has finished sending.
func (s *TCPStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.pending) == 0 {
		payload, err := s.framer.ReadFrame(s.resp.Body)
		if err != nil {
			return 0, err
		}
		s.pending = payload
		if s.payload != nil {
			s.payload(int64(len(payload)))
		}
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

// Write sends device bytes in frames of at most one HTTP/2 DATA frame. It
// blocks while the server's flow-control window is exhausted (backpressure).
func (s *TCPStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), s.framer.MaxData())]
		if err := s.framer.WriteFrame(s.body, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	if s.payload != nil {
		s.payload(int64(written))
	}
	return written, nil
}

// CloseWrite tells the site the device has finished sending (half-close).
func (s *TCPStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.body.Close()
}

// Close abandons the stream in both directions.
func (s *TCPStream) Close() error {
	s.closed.Do(func() {
		_ = s.body.CloseWithError(io.ErrClosedPipe)
		_ = s.resp.Body.Close()
		s.cancel()
		if s.release != nil {
			s.release()
		}
	})
	return nil
}

// TCPStreamsAvailable reports whether the server offered TCP streams when
// this transport synchronised.
func (t *Transport) TCPStreamsAvailable() bool {
	return t.tcpStreamEnabled.Load()
}

// TCPStreamsAvailable reports whether the active transport can carry TCP
// streams.
func (c *Connection) TCPStreamsAvailable() bool {
	c.transportMu.RLock()
	transport := c.transport
	c.transportMu.RUnlock()
	return transport != nil && transport.TCPStreamsAvailable()
}

// TCPStreamsAvailable reports whether the client's current connection can
// carry TCP streams. A renegotiated connection reports its own server's offer.
func (m *MobileClient) TCPStreamsAvailable() bool {
	m.mu.Lock()
	conn, started := m.conn, m.started
	m.mu.Unlock()
	return started && conn != nil && conn.TCPStreamsAvailable()
}

// OpenTCPStream opens a TCP stream on the active transport.
func (c *Connection) OpenTCPStream(ctx context.Context, target netip.AddrPort, early []byte) (*TCPStream, error) {
	c.transportMu.RLock()
	transport := c.transport
	c.transportMu.RUnlock()
	if transport == nil {
		return nil, fmt.Errorf("tcp stream: not connected")
	}
	return transport.OpenTCPStream(ctx, target, early)
}

// OpenTCPStream opens a TCP stream on the client's current connection. A
// renegotiated connection serves streams opened after the swap.
func (m *MobileClient) OpenTCPStream(ctx context.Context, target netip.AddrPort, early []byte) (*TCPStream, error) {
	m.mu.Lock()
	conn, started := m.conn, m.started
	m.mu.Unlock()
	if !started || conn == nil {
		return nil, fmt.Errorf("tcp stream: client not started")
	}
	return conn.OpenTCPStream(ctx, target, early)
}
