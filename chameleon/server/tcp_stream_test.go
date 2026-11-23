package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"chameleon/shared"
)

type tcpStreamHarness struct {
	server  *httptest.Server
	session *cryptoSession
}

func newTCPStreamHarness(t *testing.T) *tcpStreamHarness {
	t.Helper()
	resetSecurityTestSessions()
	t.Cleanup(resetSecurityTestSessions)
	_, session, _ := newTestCryptoPair(t, []byte("tcp-stream-test-secret"))
	handler := handleTCPStream()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contextKeyClientID, session.clientID)
		ctx = context.WithValue(ctx, contextKeyCryptoSession, session)
		handler(w, r.WithContext(ctx))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return &tcpStreamHarness{server: server, session: session}
}

type tcpStreamClient struct {
	body   *io.PipeWriter
	resp   *http.Response
	cipher *shared.InnerCipher
}

// open sends the stream preamble for target and waits for the answer.
func (h *tcpStreamHarness) open(t *testing.T, target netip.AddrPort) (*tcpStreamClient, int) {
	t.Helper()
	nonce := make([]byte, shared.TCPStreamNonceSize)
	_, _ = rand.Read(nonce)
	cipher, err := shared.NewTCPStreamCipher(h.session.streamKey, h.session.id, nonce, true)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/tcp", pr)
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := h.server.Client().Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	encoded, _ := shared.EncodeTCPStreamTarget(target)
	_, _ = pw.Write(nonce)
	if err := shared.WriteTCPStreamFrame(pw, cipher, encoded); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-respCh:
		return &tcpStreamClient{body: pw, resp: resp, cipher: cipher}, resp.StatusCode
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("no response to the stream preamble")
	}
	return nil, 0
}

func allowLoopbackTargets(t *testing.T) {
	t.Helper()
	previous := tcpStreamTargetAllowed
	tcpStreamTargetAllowed = func(netip.Addr) bool { return true }
	t.Cleanup(func() { tcpStreamTargetAllowed = previous })
}

func TestTCPStreamCarriesBothDirectionsAndHalfClose(t *testing.T) {
	allowLoopbackTargets(t)
	h := newTCPStreamHarness(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("hello from site"))
		data, _ := io.ReadAll(conn) // until the client's half-close
		received <- data
		_, _ = conn.Write([]byte(" bye"))
	}()

	stream, status := h.open(t, netip.MustParseAddrPort(listener.Addr().String()))
	if status != http.StatusOK {
		t.Fatalf("stream answered %d", status)
	}
	greeting, err := shared.ReadTCPStreamFrame(stream.resp.Body, stream.cipher)
	if err != nil || string(greeting) != "hello from site" {
		t.Fatalf("downstream %q, %v", greeting, err)
	}
	upload := bytes.Repeat([]byte("u"), 3*shared.TCPStreamMaxPlaintext+5)
	for off := 0; off < len(upload); off += shared.TCPStreamMaxPlaintext {
		end := min(off+shared.TCPStreamMaxPlaintext, len(upload))
		if err := shared.WriteTCPStreamFrame(stream.body, stream.cipher, upload[off:end]); err != nil {
			t.Fatal(err)
		}
	}
	stream.body.Close() // half-close: the site must still be able to answer
	select {
	case data := <-received:
		if !bytes.Equal(data, upload) {
			t.Fatalf("site received %d bytes, want %d", len(data), len(upload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("site did not see the client's half-close")
	}
	tail, err := shared.ReadTCPStreamFrame(stream.resp.Body, stream.cipher)
	if err != nil || string(tail) != " bye" {
		t.Fatalf("data after half-close %q, %v", tail, err)
	}
	if _, err := shared.ReadTCPStreamFrame(stream.resp.Body, stream.cipher); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream returned %v, want EOF", err)
	}
}

func TestTCPStreamRefusesForbiddenAndUnreachableTargets(t *testing.T) {
	h := newTCPStreamHarness(t)
	stream, status := h.open(t, netip.MustParseAddrPort("127.0.0.1:22"))
	if status != http.StatusForbidden {
		t.Fatalf("loopback target answered %d, want 403", status)
	}
	stream.body.Close()

	allowLoopbackTargets(t)
	listener, _ := net.Listen("tcp4", "127.0.0.1:0")
	closed := listener.Addr().String()
	listener.Close()
	stream, status = h.open(t, netip.MustParseAddrPort(closed))
	if status != http.StatusBadGateway {
		t.Fatalf("unreachable target answered %d, want 502", status)
	}
	stream.body.Close()
}

func TestDefaultTCPStreamPolicyBlocksInternalDestinations(t *testing.T) {
	for _, denied := range []string{"127.0.0.1", "10.10.0.1", "10.66.66.2", "172.17.0.2", "10.23.1.25",
		"169.254.169.254", "100.64.1.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"} {
		if defaultTCPStreamTargetAllowed(netip.MustParseAddr(denied)) {
			t.Fatalf("%s was allowed", denied)
		}
	}
	if defaultTCPStreamTargetAllowed(netip.MustParseAddr("2606:4700::1111")) {
		t.Fatal("IPv6 destination was allowed")
	}
	for _, allowed := range []string{"1.1.1.1", "93.184.215.14"} {
		if !defaultTCPStreamTargetAllowed(netip.MustParseAddr(allowed)) {
			t.Fatalf("%s was refused", allowed)
		}
	}
}

func TestTCPStreamsArePerSessionLimited(t *testing.T) {
	session := newClientSession()
	for i := 0; i < maxTCPStreamsPerSession; i++ {
		if !session.beginTCPStream() {
			t.Fatalf("stream %d refused below the limit", i+1)
		}
	}
	if session.beginTCPStream() {
		t.Fatal("stream above the limit was admitted")
	}
	session.endTCPStream()
	if !session.beginTCPStream() {
		t.Fatal("a freed slot was not reusable")
	}
}

// A browser keeps far more connections open than the tunnel's request limit;
// streams must not occupy those request slots, and a session with open
// streams is busy, never discarded as idle.
func TestTCPStreamsDoNotUseTunnelRequestSlots(t *testing.T) {
	allowLoopbackTargets(t)
	h := newTCPStreamHarness(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	target := netip.MustParseAddrPort(listener.Addr().String())
	want := int(sessionRequestLimit) * 3
	var streams []*tcpStreamClient
	for i := 0; i < want; i++ {
		stream, status := h.open(t, target)
		if status != http.StatusOK {
			t.Fatalf("stream %d answered %d with %d streams open", i+1, status, len(streams))
		}
		streams = append(streams, stream)
	}
	session := getSession(h.session.runtimeID(), "127.0.0.1")
	if session == nil || session.activeHTTP.Load() != 0 {
		t.Fatal("open streams hold tunnel request slots")
	}
	if !session.busy() {
		t.Fatal("a session with open streams is not busy")
	}
	finish, ok := session.tryBeginRequest()
	if !ok {
		t.Fatal("tunnel request refused while streams are open")
	}
	finish()
	for _, s := range streams {
		_ = s.body.Close()
		_ = s.resp.Body.Close()
	}
}

type shapedStreamClient struct {
	body   *io.PipeWriter
	resp   *http.Response
	framer *shared.TCPStreamFramer
}

// openShaped opens a stream the way the current client does: shaped frames
// requested by header, nonce, destination and early data in one write.
func (h *tcpStreamHarness) openShaped(t *testing.T, target netip.AddrPort, early []byte) (*shapedStreamClient, int) {
	t.Helper()
	nonce := make([]byte, shared.TCPStreamNonceSize)
	_, _ = rand.Read(nonce)
	cipher, err := shared.NewTCPStreamCipher(h.session.streamKey, h.session.id, nonce, true)
	if err != nil {
		t.Fatal(err)
	}
	framer := shared.NewTCPStreamFramer(cipher, true, true)
	encoded, _ := shared.EncodeTCPStreamTarget(target)
	preamble, err := framer.AppendFrame(append([]byte(nil), nonce...), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(early) > 0 {
		if preamble, err = framer.AppendFrame(preamble, early); err != nil {
			t.Fatal(err)
		}
	}
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/tcp", pr)
	req.Header.Set(shared.TCPStreamShapeHeader, shared.TCPStreamShapeVersion)
	respCh := make(chan *http.Response, 1)
	go func() {
		resp, err := h.server.Client().Do(req)
		if err == nil {
			respCh <- resp
		}
	}()
	go func() { _, _ = pw.Write(preamble) }()
	select {
	case resp := <-respCh:
		return &shapedStreamClient{body: pw, resp: resp, framer: framer}, resp.StatusCode
	case <-time.After(5 * time.Second):
		t.Fatal("no response to the shaped stream preamble")
	}
	return nil, 0
}

// A shaped stream with early data: the site receives the early bytes first,
// then the rest, and the site's answer comes back intact through shaped
// frames; the half-close still reaches the site.
func TestShapedStreamWithEarlyDataKeepsEveryByteInOrder(t *testing.T) {
	allowLoopbackTargets(t)
	h := newTCPStreamHarness(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	answer := bytes.Repeat([]byte("site answer "), 5000)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn) // until the client's half-close
		received <- data
		_, _ = conn.Write(answer)
	}()
	early := bytes.Repeat([]byte{0x16, 0x03, 0x01}, 650) // a ClientHello-sized first message
	stream, status := h.openShaped(t, netip.MustParseAddrPort(listener.Addr().String()), early)
	if status != http.StatusOK {
		t.Fatalf("shaped stream answered %d", status)
	}
	rest := bytes.Repeat([]byte("upload "), 6000)
	for chunk := rest; len(chunk) > 0; {
		n := min(len(chunk), stream.framer.MaxData())
		if err := stream.framer.WriteFrame(stream.body, chunk[:n]); err != nil {
			t.Fatal(err)
		}
		chunk = chunk[n:]
	}
	_ = stream.body.Close()
	select {
	case got := <-received:
		if want := append(append([]byte(nil), early...), rest...); !bytes.Equal(got, want) {
			t.Fatalf("site received %d bytes, want %d in order", len(got), len(want))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("site did not see the half-close")
	}
	var got []byte
	for {
		payload, err := stream.framer.ReadFrame(stream.resp.Body)
		if err != nil {
			break
		}
		got = append(got, payload...)
	}
	if !bytes.Equal(got, answer) {
		t.Fatalf("client received %d bytes of the answer, want %d", len(got), len(answer))
	}
}

// The destination policy applies to shaped streams exactly as to plain ones.
func TestShapedStreamStillRefusesInternalDestinations(t *testing.T) {
	h := newTCPStreamHarness(t)
	_, status := h.openShaped(t, netip.MustParseAddrPort("10.66.66.2:22"), []byte("SSH-2.0-probe\r\n"))
	if status != http.StatusForbidden {
		t.Fatalf("shaped stream to an internal address answered %d", status)
	}
}
