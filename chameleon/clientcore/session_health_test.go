package clientcore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only an authentication failure (401, or the 404 nginx turns it into) starts
// a session-rejection run; other failures do not, and an accepted
// authenticated response ends it.
func TestSessionRejectionIsTrackedOnlyForAuthenticationFailures(t *testing.T) {
	var status atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &Transport{
		protocol:    "http2",
		fingerprint: NewFingerprinter(),
		client:      server.Client(),
		epochCtx:    ctx,
		routePoll:   server.URL + "/poll",
	}

	status.Store(http.StatusServiceUnavailable)
	if _, err := transport.pollHTTPS(); err == nil {
		t.Fatal("503 poll succeeded")
	}
	if transport.SessionRejectedFor() != 0 {
		t.Fatal("a non-authentication failure was counted as a session rejection")
	}

	status.Store(http.StatusUnauthorized)
	if _, err := transport.pollHTTPS(); !errors.Is(err, errPollAuth) {
		t.Fatalf("401 poll returned %v", err)
	}
	first := transport.sessionRejectedSince.Load()
	if first == 0 {
		t.Fatal("401 did not start a session-rejection run")
	}
	time.Sleep(5 * time.Millisecond)
	_, _ = transport.pollHTTPS()
	if transport.sessionRejectedSince.Load() != first {
		t.Fatal("a repeated 401 restarted the rejection run instead of extending it")
	}
	if transport.SessionRejectedFor() <= 0 {
		t.Fatal("rejection duration not reported")
	}

	status.Store(http.StatusNoContent)
	if _, err := transport.pollHTTPS(); err != nil {
		t.Fatalf("204 poll failed: %v", err)
	}
	if transport.SessionRejectedFor() != 0 {
		t.Fatal("an accepted request did not end the rejection run")
	}

	// Through the production nginx front end the 401 arrives as 404.
	status.Store(http.StatusNotFound)
	if _, err := transport.pollHTTPS(); err == nil {
		t.Fatal("404 poll succeeded")
	}
	if transport.sessionRejectedSince.Load() == 0 {
		t.Fatal("a 404 on the tunnel route was not treated as a session rejection")
	}
	status.Store(http.StatusNoContent)
	_, _ = transport.pollHTTPS()

	// Other client errors are not session rejections.
	status.Store(http.StatusTooManyRequests)
	_, _ = transport.pollHTTPS()
	if transport.SessionRejectedFor() != 0 {
		t.Fatal("429 was treated as a session rejection")
	}
}

type supervisorSeams struct {
	mu      sync.Mutex
	built   []*Connection
	stopped []*Connection
	connect func(*Connection) error
}

func (s *supervisorSeams) install(t *testing.T) {
	t.Helper()
	oldTick, oldBuild, oldConnect := sessionSupervisorTick, buildSessionConnection, connectSessionWithRetry
	oldStart, oldStop := startSessionConnection, stopSessionConnection
	t.Cleanup(func() {
		sessionSupervisorTick, buildSessionConnection, connectSessionWithRetry = oldTick, oldBuild, oldConnect
		startSessionConnection, stopSessionConnection = oldStart, oldStop
	})
	sessionSupervisorTick = 10 * time.Millisecond
	buildSessionConnection = func(Config, *ProfileManager, *packetQueueInjector) (*Connection, string) {
		conn := &Connection{transport: &Transport{}}
		s.mu.Lock()
		s.built = append(s.built, conn)
		s.mu.Unlock()
		return conn, ""
	}
	connectSessionWithRetry = func(conn *Connection, _ time.Duration) error { return s.connect(conn) }
	startSessionConnection = func(*Connection) {}
	stopSessionConnection = func(conn *Connection) {
		s.mu.Lock()
		s.stopped = append(s.stopped, conn)
		s.mu.Unlock()
	}
}

func (s *supervisorSeams) snapshot() (built, stopped []*Connection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Connection(nil), s.built...), append([]*Connection(nil), s.stopped...)
}

func rejectedConnection(since time.Duration) *Connection {
	transport := &Transport{}
	transport.sessionRejectedSince.Store(time.Now().Add(-since).UnixNano())
	return &Connection{transport: transport}
}

func runSupervisor(t *testing.T, client *MobileClient) (stop func()) {
	t.Helper()
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		client.superviseSession(stopCh, Config{})
		close(done)
	}()
	return func() {
		close(stopCh)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("supervisor did not exit after stop")
		}
	}
}

func TestSupervisorReplacesARejectedSessionAndStopsTheOldConnection(t *testing.T) {
	seams := &supervisorSeams{connect: func(*Connection) error { return nil }}
	seams.install(t)
	old := rejectedConnection(5 * time.Second)
	client := &MobileClient{conn: old, started: true}
	stop := runSupervisor(t, client)
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		current := client.conn
		client.mu.Unlock()
		if current != old {
			built, stopped := seams.snapshot()
			if len(built) != 1 || current != built[0] {
				t.Fatalf("swapped in an unexpected connection (built %d)", len(built))
			}
			if len(stopped) != 1 || stopped[0] != old {
				t.Fatalf("old connection was not stopped exactly once after the swap: %d stops", len(stopped))
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("rejected session was not renegotiated")
}

func TestSupervisorIgnoresHealthyAndBrieflyRejectedSessions(t *testing.T) {
	seams := &supervisorSeams{connect: func(*Connection) error { return nil }}
	seams.install(t)
	for _, conn := range []*Connection{
		{transport: &Transport{}},           // accepted session
		rejectedConnection(time.Second / 2), // shorter than the grace period
	} {
		client := &MobileClient{conn: conn, started: true}
		stop := runSupervisor(t, client)
		time.Sleep(150 * time.Millisecond)
		stop()
		if built, _ := seams.snapshot(); len(built) != 0 {
			t.Fatalf("renegotiated a session that was not rejected long enough (%d builds)", len(built))
		}
	}
}

func TestSupervisorKeepsTheOldConnectionAndSpacesRetriesWhenHandshakeFails(t *testing.T) {
	seams := &supervisorSeams{connect: func(*Connection) error { return errors.New("handshake refused") }}
	seams.install(t)
	old := rejectedConnection(5 * time.Second)
	client := &MobileClient{conn: old, started: true}
	stop := runSupervisor(t, client)
	time.Sleep(300 * time.Millisecond)
	stop()

	client.mu.Lock()
	current := client.conn
	client.mu.Unlock()
	if current != old {
		t.Fatal("a failed handshake replaced the connection")
	}
	built, stopped := seams.snapshot()
	if len(built) != 1 {
		t.Fatalf("handshake retried %d times within the rebuild interval, want 1", len(built))
	}
	for _, conn := range stopped {
		if conn == old {
			t.Fatal("the old connection was stopped although no replacement was ready")
		}
	}
	if len(stopped) != 1 || stopped[0] != built[0] {
		t.Fatal("the failed candidate connection was not cleaned up")
	}
}

func TestStopClientEndsTheSupervisor(t *testing.T) {
	seams := &supervisorSeams{connect: func(*Connection) error { return nil }}
	seams.install(t)
	stopCh := make(chan struct{})
	// No connection: StopClient's real Connection.Stop is not under test here.
	client := &MobileClient{started: true, sessionStop: stopCh}
	done := make(chan struct{})
	go func() {
		client.superviseSession(stopCh, Config{})
		close(done)
	}()
	client.StopClient()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StopClient did not end the supervisor")
	}
	client.StopClient() // a second stop must not close the channel again
}
