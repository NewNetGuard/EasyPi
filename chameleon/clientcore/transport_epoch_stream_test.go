package clientcore

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// epochTestClients builds one transport generation the way production does:
// HTTP/2 over connections owned by a tracker, so retirement really closes
// sockets.
func epochTestClients(t *testing.T, server *httptest.Server) (transportClients, *connectionTracker) {
	t.Helper()
	tracker := newConnectionTracker()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}
	h2 := &http2.Transport{DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return tracker.track(conn), nil
	}}
	roundTripper := &trackedRoundTripper{base: h2, tracker: tracker}
	t.Cleanup(roundTripper.CloseConnections)
	return transportClients{
		client:       &http.Client{Transport: roundTripper},
		streamClient: &http.Client{Transport: roundTripper},
	}, tracker
}

// echoOnce sends one message over the stream and reads it back.
func echoOnce(stream *TCPStream, message string) error {
	if _, err := stream.Write([]byte(message)); err != nil {
		return err
	}
	got := make([]byte, len(message))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stream, got)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil && string(got) != message {
			return io.ErrUnexpectedEOF
		}
		return err
	case <-time.After(3 * time.Second):
		return context.DeadlineExceeded
	}
}

// swapTestEpoch replaces the active generation the way activateTransportEpoch
// does and returns the previous one.
func swapTestEpoch(transport *Transport, next transportClients) (uint64, transportClients) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	old := transportClients{client: transport.client, streamClient: transport.streamClient}
	generation := transport.epochGeneration
	transport.client, transport.streamClient = next.client, next.streamClient
	transport.epochGeneration++
	return generation, old
}

func waitForConnections(t *testing.T, tracker *connectionTracker, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for tracker.count() != want {
		if time.Now().After(deadline) {
			t.Fatalf("previous generation has %d connections, want %d", tracker.count(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func epochStreamTestSetup(t *testing.T) (*Transport, *connectionTracker, *httptest.Server) {
	t.Helper()
	server := fakeTCPStreamServer(t, http.StatusOK)
	transport := streamTestTransport(t, server)
	old, tracker := epochTestClients(t, server)
	transport.client, transport.streamClient = old.client, old.streamClient
	return transport, tracker, server
}

// Before the fix, retiring a generation reset every TCP stream it carried
// within two seconds ("use of closed network connection"): a download or SSH
// session through streams broke at each epoch rotation.
func TestRetiredEpochKeepsOpenStreamsUntilTheyEnd(t *testing.T) {
	transport, oldTracker, server := epochStreamTestSetup(t)
	stream, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(stream, "before"); err != nil {
		t.Fatal(err)
	}
	next, _ := epochTestClients(t, server)
	generation, old := swapTestEpoch(transport, next)
	transport.retireEpoch(generation, old)

	time.Sleep(gracefulEpochCloseTimeout + 500*time.Millisecond)
	if err := echoOnce(stream, "after rotation"); err != nil {
		t.Fatalf("open stream cut by the epoch rotation: %v", err)
	}
	// New streams use the new generation meanwhile.
	fresh, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := echoOnce(fresh, "new epoch"); err != nil {
		t.Fatal(err)
	}
	// The last stream of the old generation ending releases its connection.
	stream.Close()
	waitForConnections(t, oldTracker, 0, gracefulEpochCloseTimeout+2*time.Second)
	if err := echoOnce(fresh, "still open"); err != nil {
		t.Fatalf("closing the old generation cut a new-generation stream: %v", err)
	}
}

func shortenRetention(t *testing.T, idle time.Duration, kept int) {
	t.Helper()
	idleLimit, cap, interval := retiredEpochIdleLimit, maxRetainedEpochs, retiredEpochCheckInterval
	retiredEpochIdleLimit, maxRetainedEpochs, retiredEpochCheckInterval = idle, kept, 20*time.Millisecond
	t.Cleanup(func() {
		retiredEpochIdleLimit, maxRetainedEpochs, retiredEpochCheckInterval = idleLimit, cap, interval
	})
}

// A healthy stream that keeps moving data is never cut, however long it runs
// past the rotation; only a silent one is.
func TestRetiredEpochStaysOpenWhileItsStreamsAreActive(t *testing.T) {
	shortenRetention(t, 400*time.Millisecond, 4)
	transport, oldTracker, server := epochStreamTestSetup(t)
	stream, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	next, _ := epochTestClients(t, server)
	generation, old := swapTestEpoch(transport, next)
	transport.retireEpoch(generation, old)

	for elapsed := time.Duration(0); elapsed < 5*retiredEpochIdleLimit; elapsed += 100 * time.Millisecond {
		if err := echoOnce(stream, "keepalive"); err != nil {
			t.Fatalf("active stream cut after %v: %v", elapsed, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Silence beyond the idle limit releases the generation.
	waitForConnections(t, oldTracker, 0, retiredEpochIdleLimit+gracefulEpochCloseTimeout+2*time.Second)
	if err := echoOnce(stream, "after silence"); err == nil {
		t.Fatal("a silent stream outlived the idle limit")
	}
	stream.Close() // releasing after the forced close must be harmless
	transport.epochStreamMu.Lock()
	left := len(transport.epochStreams)
	transport.epochStreamMu.Unlock()
	if left != 0 {
		t.Fatalf("%d generations still tracked after their streams closed", left)
	}
}

// Resources stay bounded: beyond maxRetainedEpochs kept generations the
// oldest is closed, newer ones and the active one are untouched.
func TestRetainedEpochsAreCapped(t *testing.T) {
	shortenRetention(t, time.Hour, 1)
	transport, firstTracker, server := epochStreamTestSetup(t)
	first, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	secondClients, secondTracker := epochTestClients(t, server)
	generation, old := swapTestEpoch(transport, secondClients)
	transport.retireEpoch(generation, old)
	second, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	thirdClients, _ := epochTestClients(t, server)
	generation, old = swapTestEpoch(transport, thirdClients)
	transport.retireEpoch(generation, old)

	waitForConnections(t, firstTracker, 0, gracefulEpochCloseTimeout+2*time.Second)
	if err := echoOnce(first, "evicted"); err == nil {
		t.Fatal("the oldest kept generation was not closed at the cap")
	}
	if err := echoOnce(second, "kept"); err != nil {
		t.Fatalf("the newer kept generation was closed: %v", err)
	}
	if secondTracker.count() == 0 {
		t.Fatal("the newer kept generation lost its connection")
	}
	third, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if err := echoOnce(third, "active"); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredEpochWithoutStreamsClosesAtOnce(t *testing.T) {
	transport, oldTracker, server := epochStreamTestSetup(t)
	// A tunnel request opens the old generation's connection.
	stream, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	next, _ := epochTestClients(t, server)
	generation, old := swapTestEpoch(transport, next)
	started := time.Now()
	transport.retireEpoch(generation, old)
	waitForConnections(t, oldTracker, 0, gracefulEpochCloseTimeout+time.Second)
	if waited := time.Since(started); waited > gracefulEpochCloseTimeout+time.Second {
		t.Fatalf("idle generation retired after %v", waited)
	}
}

// Stream traffic counts toward the epoch's byte budget but never delays a
// rotation: streams survive it on their own generation. Before, a busy home
// network reset the quiet timer constantly and the epoch did not rotate for
// hours.
func TestStreamBytesCountTowardTheBudgetButNotTheQuietTimer(t *testing.T) {
	transport, _, _ := epochStreamTestSetup(t)
	start := time.Now().Add(-time.Hour)
	transport.epochPolicy = transportEpochPolicy{
		startedAt:   start,
		lastPayload: start,
		minAge:      time.Minute,
		maxAge:      2 * time.Hour,
		quietPeriod: 10 * time.Second,
		byteBudget:  1 << 30,
	}
	stream, err := transport.OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := echoOnce(stream, "count me"); err != nil {
		t.Fatal(err)
	}
	transport.epochPolicyMu.Lock()
	bytes, last := transport.epochPolicy.payloadBytes, transport.epochPolicy.lastPayload
	transport.epochPolicyMu.Unlock()
	if bytes < int64(2*len("count me")) {
		t.Fatalf("stream traffic not counted toward the budget: %d bytes", bytes)
	}
	if !last.Equal(start) {
		t.Fatal("stream traffic reset the quiet timer")
	}
}

func TestBusyStreamsDoNotPreventARotation(t *testing.T) {
	now := time.Now()
	policy := transportEpochPolicy{
		startedAt:   now.Add(-3 * time.Hour),
		lastPayload: now.Add(-time.Minute), // the packet tunnel is quiet
		minAge:      30 * time.Minute,
		maxAge:      2 * time.Hour,
		quietPeriod: 10 * time.Second,
		byteBudget:  1 << 30,
	}
	// Device streams busy every second of the last minute.
	for i := 0; i < 60; i++ {
		policy.recordStreamBytes(64 << 10)
	}
	if !policy.shouldRotate(now) {
		t.Fatal("constant stream traffic kept an overdue epoch from rotating")
	}
	// Stream traffic alone can also exhaust the byte budget.
	young := transportEpochPolicy{
		startedAt: now.Add(-time.Hour), lastPayload: now.Add(-time.Minute),
		minAge: 30 * time.Minute, maxAge: 4 * time.Hour,
		quietPeriod: 10 * time.Second, byteBudget: 256 << 20,
	}
	young.recordStreamBytes(300 << 20)
	if !young.shouldRotate(now) {
		t.Fatal("stream traffic over the byte budget did not rotate the epoch")
	}
	// Packet-tunnel traffic still needs its quiet moment.
	young.recordPayload(now, 1500)
	if young.shouldRotate(now) {
		t.Fatal("rotated in the middle of packet-tunnel traffic")
	}
}

func TestRefusedStreamDoesNotHoldItsEpoch(t *testing.T) {
	transport := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusForbidden))
	if _, err := transport.OpenTCPStream(context.Background(), testTarget, nil); err == nil {
		t.Fatal("refused stream opened")
	}
	stream, err := streamTestTransport(t, fakeTCPStreamServer(t, http.StatusOK)).OpenTCPStream(context.Background(), testTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	stream.Close() // a second Close must not release twice
	transport.epochStreamMu.Lock()
	open := len(transport.epochStreams)
	transport.epochStreamMu.Unlock()
	if open != 0 {
		t.Fatalf("refused stream still registered on %d generations", open)
	}
}
