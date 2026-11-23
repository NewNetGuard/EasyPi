package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"chameleon/shared"

	"golang.org/x/net/http2"
)

const recordShapingTLSHandshakeTimeout = 10 * time.Second

// recordShapingHTTP2Server terminates TLS only after RealityListener has
// authenticated a Chameleon ClientHello. Record shaping is consequently never
// exposed on the cover/probe path.
type recordShapingHTTP2Server struct {
	listener  net.Listener
	tlsConfig *tls.Config
	http1     *http.Server
	http2     *http2.Server

	mu      sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func newRecordShapingHTTP2Server(
	listener net.Listener,
	tlsConfig *tls.Config,
	http1 *http.Server,
	http2Server *http2.Server,
) *recordShapingHTTP2Server {
	return &recordShapingHTTP2Server{
		listener:  listener,
		tlsConfig: tlsConfig,
		http1:     http1,
		http2:     http2Server,
		conns:     make(map[net.Conn]struct{}),
	}
}

func (s *recordShapingHTTP2Server) Serve() error {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing || errors.Is(err, net.ErrClosed) {
				return http.ErrServerClosed
			}
			return err
		}

		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			_ = raw.Close()
			return http.ErrServerClosed
		}
		s.conns[raw] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveConn(raw)
	}
}

func (s *recordShapingHTTP2Server) serveConn(raw net.Conn) {
	defer func() {
		_ = raw.Close()
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
		s.wg.Done()
	}()

	_ = raw.SetDeadline(time.Now().Add(recordShapingTLSHandshakeTimeout))
	tlsConn := tls.Server(raw, s.tlsConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		return
	}
	_ = raw.SetDeadline(time.Time{})

	shaped := shared.NewRecordShapingConn(tlsConn, shared.RecordShapingOptions{
		SenderPacingMode:           shared.SenderPacingRecordOnly,
		CoalesceHTTP2WindowUpdates: true,
	})
	s.http2.ServeConn(shaped, &http2.ServeConnOpts{
		BaseConfig: s.http1,
		Handler:    s.http1.Handler,
	})
	_ = shaped.Close()
}

func (s *recordShapingHTTP2Server) Close() error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	err := s.listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
	s.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
