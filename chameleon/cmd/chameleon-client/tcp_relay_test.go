//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// echoStream echoes everything written to it after a half-close.
type echoStream struct {
	r  *io.PipeReader
	w  *io.PipeWriter
	in bytes.Buffer
}

func newEchoStream() *echoStream {
	r, w := io.Pipe()
	return &echoStream{r: r, w: w}
}
func (s *echoStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *echoStream) Write(p []byte) (int, error) { return s.in.Write(p) }
func (s *echoStream) CloseWrite() error {
	go func() { _, _ = s.w.Write(s.in.Bytes()); _ = s.w.Close() }()
	return nil
}
func (s *echoStream) Close() error { _ = s.r.Close(); return nil }

func startRelay(t *testing.T, opener tcpStreamOpener) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serveTCPStreams(ctx, listener, opener)
	return listener.Addr()
}

func TestRelayCarriesDeviceBytesToTheStreamAndBack(t *testing.T) {
	targets := make(chan netip.AddrPort, 1)
	addr := startRelay(t, func(_ context.Context, target netip.AddrPort, early []byte) (tcpStream, error) {
		targets <- target
		stream := newEchoStream()
		_, _ = stream.Write(early) // the server delivers early data first
		return stream, nil
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("relay"), 50000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes (%v), want %d", len(got), err, len(payload))
	}
	if target := <-targets; target.String() != addr.String() {
		t.Fatalf("stream opened for %s, want the accepted local address %s", target, addr)
	}
}

func TestRelayResetsTheDeviceWhenTheStreamCannotOpen(t *testing.T) {
	addr := startRelay(t, func(context.Context, netip.AddrPort, []byte) (tcpStream, error) {
		return nil, errors.New("refused")
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("device saw %v, want a connection reset", err)
	}
}

// A client-first protocol's opening message (a TLS ClientHello) leaves with
// the stream request; nothing is lost or reordered.
func TestRelaySendsTheDevicesFirstDataWithTheOpen(t *testing.T) {
	earlies := make(chan []byte, 1)
	addr := startRelay(t, func(_ context.Context, _ netip.AddrPort, early []byte) (tcpStream, error) {
		earlies <- append([]byte(nil), early...)
		stream := newEchoStream()
		_, _ = stream.Write(early)
		return stream, nil
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hello := bytes.Repeat([]byte{0x16, 0x03, 0x01}, 600)
	rest := bytes.Repeat([]byte("after the hello "), 4000)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if early := <-earlies; !bytes.Equal(early, hello) {
		t.Fatalf("early data %d bytes, want the %d-byte opening message", len(early), len(hello))
	}
	if _, err := conn.Write(rest); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if want := append(append([]byte(nil), hello...), rest...); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("relayed %d bytes (%v), want %d in order", len(got), err, len(want))
	}
}

const smtpGreeting = "220 mail.example ESMTP\r\n"

// A server-first protocol sends nothing at first; its stream opens after the
// short wait, without early data, and the server's greeting reaches it.
func TestRelayOpensServerFirstProtocolsAfterTheWait(t *testing.T) {
	opened := make(chan time.Duration, 1)
	start := time.Now()
	addr := startRelay(t, func(_ context.Context, _ netip.AddrPort, early []byte) (tcpStream, error) {
		if len(early) != 0 {
			t.Errorf("unexpected early data %q", early)
		}
		opened <- time.Since(start)
		stream := newEchoStream()
		_, _ = stream.Write([]byte(smtpGreeting))
		_ = stream.CloseWrite()
		return stream, nil
	})
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if waited := <-opened; waited > relayEarlyDataWait+500*time.Millisecond {
		t.Fatalf("stream opened after %v", waited)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, len(smtpGreeting))
	if _, err := io.ReadFull(conn, greeting); err != nil || !strings.HasPrefix(string(greeting), "220 ") {
		t.Fatalf("greeting %q (%v)", greeting, err)
	}
}

// recordRoutes replaces ip(8) and records each command as one string.
func recordRoutes(t *testing.T) chan string {
	t.Helper()
	calls := make(chan string, 64)
	previous := routeCommand
	routeCommand = func(args ...string) error {
		calls <- strings.Join(args, " ")
		return nil
	}
	t.Cleanup(func() { routeCommand = previous })
	return calls
}

func nextRoute(t *testing.T, calls chan string) string {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(3 * streamRouteCheckInterval):
		t.Fatal("no route change")
	}
	return ""
}

var testStreamRoute = tcpStreamRoute{Table: 51824, Via: "169.254.77.2", Dev: "chtcp0"}

// Device TCP may use streams only while the server offers them; otherwise
// (and after the client stops) it must fall back to the packet tunnel.
func TestStreamRouteFollowsServerSupport(t *testing.T) {
	calls := recordRoutes(t)
	var available atomic.Bool
	available.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manageStreamRoute(ctx, testStreamRoute, available.Load)
		close(done)
	}()
	if call := nextRoute(t, calls); call != "route del default table 51824" {
		t.Fatalf("first command %q, want removal of a stale route", call)
	}
	if call := nextRoute(t, calls); call != "route replace default via 169.254.77.2 dev chtcp0 table 51824" {
		t.Fatalf("streams available: %q", call)
	}
	available.Store(false)
	if call := nextRoute(t, calls); call != "route del default table 51824" {
		t.Fatalf("streams withdrawn: %q", call)
	}
	available.Store(true)
	if call := nextRoute(t, calls); !strings.HasPrefix(call, "route replace") {
		t.Fatalf("streams back: %q", call)
	}
	cancel()
	<-done
	if call := nextRoute(t, calls); call != "route del default table 51824" {
		t.Fatalf("client stop: %q", call)
	}
}

func TestStreamRouteNeverInstalledWithoutServerSupport(t *testing.T) {
	calls := recordRoutes(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manageStreamRoute(ctx, testStreamRoute, func() bool { return false })
		close(done)
	}()
	nextRoute(t, calls) // stale-route removal
	time.Sleep(2*streamRouteCheckInterval + 100*time.Millisecond)
	cancel()
	<-done
	select {
	case call := <-calls:
		t.Fatalf("unexpected route command %q", call)
	default:
	}
}

func TestStreamRouteConfigIsValidated(t *testing.T) {
	for _, route := range []tcpStreamRoute{
		{Table: 0, Via: "169.254.77.2", Dev: "chtcp0"},
		{Table: 51824, Via: "not-an-ip", Dev: "chtcp0"},
		{Table: 51824, Via: "fe80::1", Dev: "chtcp0"},
		{Table: 51824, Via: "169.254.77.2", Dev: "chtcp0; reboot"},
		{Table: 51824, Via: "169.254.77.2", Dev: "a-very-long-interface-name"},
	} {
		if route.valid() {
			t.Fatalf("accepted %+v", route)
		}
	}
	if !testStreamRoute.valid() {
		t.Fatal("rejected the EasyPi route")
	}
}
