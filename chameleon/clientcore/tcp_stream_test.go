package clientcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"chameleon/shared"
)

const testStreamSessionID = "stream-session"

var testStreamKey = bytes.Repeat([]byte{5}, 32)

// fakeTCPStreamServer mimics the server side: it reads the preamble, checks
// the destination and echoes the device's bytes back until the half-close.
func fakeTCPStreamServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := make([]byte, shared.TCPStreamNonceSize)
		if _, err := io.ReadFull(r.Body, nonce); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cipher, _ := shared.NewTCPStreamCipher(testStreamKey, testStreamSessionID, nonce, false)
		framer := shared.NewTCPStreamFramer(cipher, r.Header.Get(shared.TCPStreamShapeHeader) == shared.TCPStreamShapeVersion, false)
		first, err := framer.ReadFrame(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if target, err := shared.DecodeTCPStreamTarget(first); err != nil || target.String() != "93.184.215.14:443" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			payload, err := framer.ReadFrame(r.Body)
			if err != nil {
				return // half-close ends the echo and the response
			}
			if err := framer.WriteFrame(w, payload); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func streamTestTransport(t *testing.T, server *httptest.Server) *Transport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport := &Transport{
		protocol:     "http2",
		fingerprint:  NewFingerprinter(),
		ctx:          ctx,
		epochCtx:     ctx,
		streamClient: server.Client(),
		routeTCP:     server.URL + "/tcp",
		streamKey:    testStreamKey,
		sessionID:    testStreamSessionID,
	}
	transport.tcpStreamEnabled.Store(true)
	return transport
}

var testTarget = netip.MustParseAddrPort("93.184.215.14:443")

func TestTCPStreamEchoesLargeDataAndEndsOnHalfClose(t *testing.T) {
	transport := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusOK))
	stream, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	payload := bytes.Repeat([]byte("0123456789"), 20000) // 200 KB, many frames
	readDone := make(chan []byte, 1)
	go func() {
		got, _ := io.ReadAll(stream)
		readDone <- got
	}()
	if n, err := stream.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("wrote %d, %v", n, err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-readDone:
		if !bytes.Equal(got, payload) {
			t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo did not finish after the half-close")
	}
}

func TestTCPStreamReportsRefusalAndSessionRejection(t *testing.T) {
	transport := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusForbidden))
	if _, err := transport.OpenTCPStream(context.Background(), testTarget, nil); !errors.Is(err, ErrTCPStreamRefused) {
		t.Fatalf("403 returned %v", err)
	}
	if transport.sessionRejectedSince.Load() != 0 {
		t.Fatal("a refused destination was treated as a session rejection")
	}

	rejected := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusNotFound))
	if _, err := rejected.OpenTCPStream(context.Background(), testTarget, nil); err == nil {
		t.Fatal("404 opened a stream")
	}
	if rejected.sessionRejectedSince.Load() == 0 {
		t.Fatal("404 on the stream route was not treated as a session rejection")
	}
}

func TestTCPStreamNeedsServerSupportAndIPv4(t *testing.T) {
	transport := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusOK))
	transport.tcpStreamEnabled.Store(false)
	if _, err := transport.OpenTCPStream(context.Background(), testTarget, nil); !errors.Is(err, ErrTCPStreamUnsupported) {
		t.Fatalf("unsupported server returned %v", err)
	}
	transport.tcpStreamEnabled.Store(true)
	_, err := transport.OpenTCPStream(context.Background(), netip.MustParseAddrPort("[2001:db8::1]:443"), nil)
	if err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("IPv6 target returned %v", err)
	}
}

// The device's first data travels with the open and reaches the site before
// anything written later, in order, plain or shaped.
func TestEarlyDataLeavesWithTheOpenAndKeepsOrder(t *testing.T) {
	for _, shaped := range []bool{false, true} {
		transport := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusOK))
		transport.tcpStreamShaped.Store(shaped)
		early := bytes.Repeat([]byte{0x16, 0x03, 0x01}, 650)
		stream, err := transport.OpenTCPStream(context.Background(), testTarget, early)
		if err != nil {
			t.Fatal(err)
		}
		rest := bytes.Repeat([]byte("rest of the connection "), 3000)
		readDone := make(chan []byte, 1)
		go func() {
			got, _ := io.ReadAll(stream)
			readDone <- got
		}()
		if _, err := stream.Write(rest); err != nil {
			t.Fatal(err)
		}
		_ = stream.CloseWrite()
		select {
		case got := <-readDone:
			if want := append(append([]byte(nil), early...), rest...); !bytes.Equal(got, want) {
				t.Fatalf("shaped=%v: echoed %d bytes, want %d in order", shaped, len(got), len(want))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("shaped=%v: echo did not finish", shaped)
		}
		stream.Close()
	}
}

// Shaped framing is requested only when the server advertised it, so a
// server that predates it keeps receiving the original frames.
func TestShapedFramingFollowsTheServersOffer(t *testing.T) {
	headers := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get(shared.TCPStreamShapeHeader)
		w.WriteHeader(http.StatusForbidden)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	for _, offered := range []bool{false, true} {
		transport := streamTestTransport(t, server)
		transport.tcpStreamShaped.Store(offered)
		_, _ = transport.OpenTCPStream(context.Background(), testTarget, nil)
		got := <-headers
		if offered != (got == shared.TCPStreamShapeVersion) {
			t.Fatalf("offered=%v, request header %q", offered, got)
		}
	}
}

func benchmarkStreamEcho(b *testing.B, shaped bool) {
	t := &testing.T{}
	server := fakeTCPStreamServer(t, http.StatusOK)
	defer server.Close()
	transport := streamTestTransport(t, server)
	transport.tcpStreamShaped.Store(shaped)
	payload := bytes.Repeat([]byte("x"), 64<<10)
	b.SetBytes(int64(len(payload)))
	stream, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()
	buf := make([]byte, len(payload))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := stream.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(stream, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamEchoPlain(b *testing.B)  { benchmarkStreamEcho(b, false) }
func BenchmarkStreamEchoShaped(b *testing.B) { benchmarkStreamEcho(b, true) }
