//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"chameleon/clientcore"
)

// maxRelayedTCP bounds concurrently relayed device connections; beyond it new
// connections are refused instead of growing goroutines and buffers.
const maxRelayedTCP = 1024

// activatedTCPListener returns the transparent listener systemd passed with
// socket activation, or nil when none was passed. EasyPi creates it inside the
// TCP-stream network namespace, where TPROXY delivers device connections that
// already passed every EasyPi forwarding policy; this process keeps its own
// limited privileges and never enters that namespace.
func activatedTCPListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, nil
	}
	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || count < 1 {
		return nil, nil
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(name)
	}
	file := os.NewFile(3, "tcp-streams")
	defer file.Close()
	return net.FileListener(file)
}

// tcpStream is the part of clientcore.TCPStream the relay uses.
type tcpStream interface {
	io.ReadWriter
	CloseWrite() error
	Close() error
}

type tcpStreamOpener func(ctx context.Context, target netip.AddrPort, early []byte) (tcpStream, error)

// clientStreamOpener adapts the client core, keeping a nil stream a nil interface.
func clientStreamOpener(client *clientcore.MobileClient) tcpStreamOpener {
	return func(ctx context.Context, target netip.AddrPort, early []byte) (tcpStream, error) {
		stream, err := client.OpenTCPStream(ctx, target, early)
		if err != nil {
			return nil, err
		}
		return stream, nil
	}
}

// serveTCPStreams accepts device connections and carries each one as a TCP
// stream until ctx ends.
func serveTCPStreams(ctx context.Context, listener net.Listener, opener tcpStreamOpener) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	slots := make(chan struct{}, maxRelayedTCP)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			clientcore.LogOperationalFailure("tcp", "accept failed", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			clientcore.LogRateLimitedEvent("tcp", "device connection refused: relay limit reached")
			resetConn(conn)
			continue
		}
		go func() {
			defer func() { <-slots }()
			relayTCP(ctx, conn, opener)
		}()
	}
}

// relayTCP carries one device connection. With TPROXY the accepted socket's
// local address is the destination the device dialled.
func relayTCP(ctx context.Context, device net.Conn, opener tcpStreamOpener) {
	defer device.Close()
	target, err := netip.ParseAddrPort(device.LocalAddr().String())
	if err != nil {
		resetConn(device)
		return
	}
	early, err := readEarlyData(device)
	if err != nil {
		resetConn(device)
		return
	}
	stream, err := opener(ctx, target, early)
	if err != nil {
		clientcore.LogOperationalFailure("tcp", "stream open failed", err)
		resetConn(device)
		return
	}
	defer stream.Close()

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32<<10)
		_, _ = io.CopyBuffer(stream, onlyReader{device}, buf)
		_ = stream.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32<<10)
		_, _ = io.CopyBuffer(onlyWriter{device}, stream, buf)
		if tcp, ok := device.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// tcpStreamRoute is the route EasyPi reserves for device TCP: a default route
// in a dedicated table towards the namespace with the transparent listener.
// While it is absent, the same TCP falls through to the packet tunnel's table.
type tcpStreamRoute struct {
	Table int    `json:"table"`
	Via   string `json:"via"`
	Dev   string `json:"dev"`
}

var routeDevPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func (r tcpStreamRoute) valid() bool {
	via, err := netip.ParseAddr(r.Via)
	return r.Table > 0 && r.Table < 1<<31 && err == nil && via.Is4() && routeDevPattern.MatchString(r.Dev)
}

// routeCommand runs ip(8); tests replace it.
var routeCommand = func(args ...string) error {
	return exec.Command("ip", args...).Run()
}

const streamRouteCheckInterval = 2 * time.Second

// manageStreamRoute keeps device TCP on streams only while the server offers
// them: the route is installed when streams become available and removed when
// they are not (an older server, a renegotiated connection without them) and
// when the client stops. Without the route device TCP takes the packet tunnel,
// so a missing stream feature never cuts the network.
func manageStreamRoute(ctx context.Context, route tcpStreamRoute, available func() bool) {
	table := strconv.Itoa(route.Table)
	installed := false
	apply := func(want bool) {
		var err error
		if want {
			err = routeCommand("route", "replace", "default", "via", route.Via, "dev", route.Dev, "table", table)
		} else {
			err = routeCommand("route", "del", "default", "table", table)
		}
		if err != nil && want {
			clientcore.LogOperationalFailure("tcp", "stream route not installed; TCP stays on the packet tunnel", err)
			return
		}
		installed = want
		if want {
			clientcore.LogState("tcp", "device TCP carried as streams")
		} else {
			clientcore.LogState("tcp", "device TCP on the packet tunnel")
		}
	}
	// A route left by a previous run must not outlive a server without streams.
	apply(false)
	ticker := time.NewTicker(streamRouteCheckInterval)
	defer ticker.Stop()
	for {
		if want := available(); want != installed {
			apply(want)
		}
		select {
		case <-ctx.Done():
			if installed {
				apply(false)
			}
			return
		case <-ticker.C:
		}
	}
}

// relayEarlyDataWait bounds how long the relay waits for a device's first
// data before opening the stream. Client-first protocols (TLS above all) send
// it at once; server-first ones (SMTP, SSH banners from the server) send
// nothing and their stream opens after this wait.
const relayEarlyDataWait = 20 * time.Millisecond

// readEarlyData returns what the device sent right after connecting, so it
// can leave with the stream request: the site gets it one round trip sooner
// and the carrier shows a single request instead of an opening exchange
// followed by the device's first message.
func readEarlyData(device net.Conn) ([]byte, error) {
	buf := make([]byte, 16<<10)
	_ = device.SetReadDeadline(time.Now().Add(relayEarlyDataWait))
	n, err := device.Read(buf)
	_ = device.SetReadDeadline(time.Time{})
	if n > 0 {
		return buf[:n], nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil, nil
	}
	if err == nil {
		return nil, nil
	}
	return nil, err
}

// resetConn closes with RST so the device sees an immediate failure rather
// than a clean end of an empty connection.
func resetConn(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}

// onlyReader/onlyWriter hide ReadFrom/WriteTo so CopyBuffer uses the bounded
// buffer instead of splice paths that do not apply to a TCPStream.
type onlyReader struct{ io.Reader }
type onlyWriter struct{ io.Writer }
