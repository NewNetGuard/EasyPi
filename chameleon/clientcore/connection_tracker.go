package clientcore

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// connectionTracker gives a transport generation deterministic ownership of
// every TCP connection it opens. CloseIdleConnections alone cannot terminate
// active HTTP/2 streams, which is why the previous rotation kept one TCP flow.
type connectionTracker struct {
	mu             sync.Mutex
	conns          map[*trackedNetConn]struct{}
	retiring       bool
	gracefulFailed bool
}

type trackedNetConn struct {
	net.Conn
	owner       *connectionTracker
	mu          sync.Mutex
	closed      bool
	graceful    bool
	writeClosed bool
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{conns: make(map[*trackedNetConn]struct{})}
}

func (t *connectionTracker) track(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	tracked := &trackedNetConn{Conn: conn, owner: t}
	t.mu.Lock()
	t.conns[tracked] = struct{}{}
	retiring := t.retiring
	t.mu.Unlock()
	if retiring && !tracked.enableGracefulClose() {
		t.markGracefulFailure()
	}
	return tracked
}

func (t *connectionTracker) closeAll() {
	t.mu.Lock()
	conns := make([]*trackedNetConn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.mu.Unlock()
	for _, conn := range conns {
		_ = conn.forceClose()
	}
}

func (t *connectionTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

func (t *connectionTracker) beginGracefulClose() bool {
	t.mu.Lock()
	t.retiring = true
	t.gracefulFailed = false
	conns := make([]*trackedNetConn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.mu.Unlock()

	eligible := true
	for _, conn := range conns {
		if !conn.enableGracefulClose() {
			eligible = false
		}
	}
	if !eligible {
		t.markGracefulFailure()
	}
	return eligible
}

func (t *connectionTracker) markGracefulFailure() {
	t.mu.Lock()
	t.gracefulFailed = true
	t.mu.Unlock()
}

func (t *connectionTracker) gracefulResult() (remaining int, failed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns), t.gracefulFailed
}

func (c *trackedNetConn) enableGracefulClose() bool {
	if _, ok := c.Conn.(interface{ CloseWrite() error }); !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return true
	}
	c.graceful = true
	return true
}

func (c *trackedNetConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	if !c.graceful {
		c.mu.Unlock()
		return c.forceClose()
	}
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.mu.Unlock()

	if err := c.Conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		c.owner.markGracefulFailure()
		_ = c.forceClose()
		return err
	}
	return nil
}

func (c *trackedNetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		_ = c.forceClose()
	}
	return n, err
}

func (c *trackedNetConn) forceClose() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.owner.mu.Lock()
	delete(c.owner.conns, c)
	c.owner.mu.Unlock()
	return c.Conn.Close()
}

type trackedRoundTripper struct {
	base    http.RoundTripper
	tracker *connectionTracker
}

func (t *trackedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(req)
}

func (t *trackedRoundTripper) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *trackedRoundTripper) CloseConnections() {
	t.tracker.closeAll()
	t.CloseIdleConnections()
}

// CloseGracefully repeatedly asks the HTTP transport to retire idle
// connections. Epoch request contexts are cancelled before this method runs,
// allowing HTTP/2 streams to unwind without immediately resetting the socket.
func (t *trackedRoundTripper) CloseGracefully(timeout time.Duration) bool {
	if !t.tracker.beginGracefulClose() {
		return false
	}
	deadline := time.Now().Add(timeout)
	for {
		t.CloseIdleConnections()
		remaining, failed := t.tracker.gracefulResult()
		if remaining == 0 {
			return !failed
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}
