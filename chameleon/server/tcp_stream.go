package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"chameleon/shared"
)

const (
	tcpStreamSetupTimeout   = 15 * time.Second
	tcpStreamDialTimeout    = 10 * time.Second
	maxTCPStreamsPerSession = 256
)

// Special-purpose and private IPv4 ranges a TCP stream may never reach. The
// server dials on the client's behalf, so these keep a client from reaching
// the VPS itself, its private networks or other tunnels' clients.
var deniedTCPStreamPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// tcpStreamTargetAllowed decides whether the server may dial a destination.
// Tests replace it to reach a loopback listener.
var tcpStreamTargetAllowed = defaultTCPStreamTargetAllowed

func defaultTCPStreamTargetAllowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	for _, prefix := range deniedTCPStreamPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	// The VPS's own public addresses: a stream must not reach its services.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				if local, ok := netip.AddrFromSlice(ipNet.IP); ok && local.Unmap() == addr {
					return false
				}
			}
		}
	}
	return true
}

var tcpStreamDialer = &net.Dialer{Timeout: tcpStreamDialTimeout, KeepAlive: 30 * time.Second}

// handleTCPStream carries one device TCP connection: the request body is the
// client-to-site byte stream, the response body the site-to-client stream.
// HTTP/2 flow control and blocking reads/writes give backpressure both ways;
// buffers are bounded by one frame.
func handleTCPStream() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cryptoSession := CryptoSessionFromContext(r.Context())
		if cryptoSession == nil || len(cryptoSession.streamKey) != 32 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// A browser keeps dozens of connections open, so streams must not
		// occupy the tunnel's request slots (max_requests_per_session); they
		// have their own per-session limit instead.
		session, ok := admitSession(w, r, ClientIDFromContext(r.Context()))
		if !ok {
			return
		}
		if !session.beginTCPStream() {
			logRateLimitedEvent("tcp", "stream refused: per-session stream limit reached")
			http.Error(w, "Too many concurrent requests", http.StatusTooManyRequests)
			return
		}
		defer session.endTCPStream()

		controller := http.NewResponseController(w)
		// Behind nginx the backend speaks HTTP/1.1, where answering while the
		// request body is still open must be enabled explicitly.
		_ = controller.EnableFullDuplex()
		_ = controller.SetReadDeadline(time.Now().Add(tcpStreamSetupTimeout))

		nonce := make([]byte, shared.TCPStreamNonceSize)
		if _, err := io.ReadFull(r.Body, nonce); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		cipher, err := shared.NewTCPStreamCipher(cryptoSession.streamKey, cryptoSession.id, nonce, false)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		framer := shared.NewTCPStreamFramer(cipher, r.Header.Get(shared.TCPStreamShapeHeader) == shared.TCPStreamShapeVersion, false)
		first, err := framer.ReadFrame(r.Body)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		target, err := shared.DecodeTCPStreamTarget(first)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if !tcpStreamTargetAllowed(target.Addr()) {
			logRateLimitedEvent("tcp", "stream refused: destination not allowed")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		upstream, err := tcpStreamDialer.DialContext(r.Context(), "tcp4", target.String())
		if err != nil {
			logOperationalFailure("tcp", "stream destination unreachable", err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		_ = controller.SetReadDeadline(time.Time{})
		// A cancelled request (client gone, session revoked) must also stop a
		// read blocked on the destination.
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-r.Context().Done():
				upstream.Close()
			case <-stop:
			}
		}()

		apiHeaders(w)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if err := controller.Flush(); err != nil {
			return
		}

		go func() {
			for {
				payload, err := framer.ReadFrame(r.Body)
				if err != nil {
					// A clean end of the body is the client's half-close.
					if errors.Is(err, io.EOF) {
						if tcp, ok := upstream.(*net.TCPConn); ok {
							_ = tcp.CloseWrite()
							return
						}
					}
					upstream.Close()
					return
				}
				if len(payload) == 0 {
					continue
				}
				if _, err := upstream.Write(payload); err != nil {
					return
				}
			}
		}()

		buf := make([]byte, framer.MaxData())
		for {
			n, readErr := upstream.Read(buf)
			if n > 0 {
				if err := framer.WriteFrame(w, buf[:n]); err != nil {
					return
				}
				if err := controller.Flush(); err != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}
}
