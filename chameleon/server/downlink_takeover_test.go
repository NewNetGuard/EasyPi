package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"chameleon/shared"
)

// flushSignal records the status and reports the first Flush, which is when a
// streaming client receives the response headers.
type flushSignal struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	flushed chan struct{}
	once    sync.Once
}

func newFlushSignal() *flushSignal {
	return &flushSignal{header: http.Header{}, flushed: make(chan struct{})}
}

func (f *flushSignal) Header() http.Header { return f.header }
func (f *flushSignal) Write(b []byte) (int, error) {
	f.mu.Lock()
	if f.status == 0 {
		f.status = http.StatusOK
	}
	f.mu.Unlock()
	return len(b), nil
}
func (f *flushSignal) WriteHeader(code int) {
	f.mu.Lock()
	if f.status == 0 {
		f.status = code
	}
	f.mu.Unlock()
}
func (f *flushSignal) Flush() { f.once.Do(func() { close(f.flushed) }) }

func sequencedRequest(ctx context.Context, cryptoSession *cryptoSession) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.invalid/route", nil)
	req.Header.Set(shared.EpochAckHeader, shared.EpochAckVersion)
	ctx = context.WithValue(ctx, contextKeyClientID, cryptoSession.clientID)
	ctx = context.WithValue(ctx, contextKeyCryptoSession, cryptoSession)
	return req.WithContext(ctx)
}

// A fallback poll that owns the downlink while waiting for data must hand it
// to an arriving persistent stream at once instead of holding the stream for
// up to its 30 s timeout.
func TestStreamTakesDownlinkFromAWaitingPoll(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	_, cryptoSession, _ := newTestCryptoPair(t, []byte("downlink-takeover-secret"))

	pollDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handlePoll()(recorder, sequencedRequest(context.Background(), cryptoSession))
		pollDone <- recorder.Code
	}()
	time.Sleep(150 * time.Millisecond) // let the poll take ownership and wait

	streamCtx, stopStream := context.WithCancel(context.Background())
	defer stopStream()
	stream := newFlushSignal()
	streamDone := make(chan struct{})
	go func() {
		handleStream()(stream, sequencedRequest(streamCtx, cryptoSession))
		close(streamDone)
	}()

	select {
	case <-stream.flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("stream was held behind the waiting poll")
	}
	select {
	case code := <-pollDone:
		if code != http.StatusNoContent {
			t.Fatalf("poll that gave way answered %d, want 204", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting poll did not give up the downlink")
	}

	stopStream()
	select {
	case <-streamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not exit after its request ended")
	}
}

// Without a stream, a waiting poll keeps its normal behaviour: a stale
// takeover request left from an earlier stream must not end it early.
func TestStreamClearsItsTakeoverRequestOnceItOwnsTheDownlink(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	_, cryptoSession, _ := newTestCryptoPair(t, []byte("downlink-takeover-clear-secret"))

	streamCtx, stopStream := context.WithCancel(context.Background())
	stream := newFlushSignal()
	streamDone := make(chan struct{})
	go func() {
		handleStream()(stream, sequencedRequest(streamCtx, cryptoSession))
		close(streamDone)
	}()
	select {
	case <-stream.flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("uncontended stream did not start")
	}
	stopStream()
	<-streamDone

	pollCtx, stopPoll := context.WithCancel(context.Background())
	pollDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handlePoll()(recorder, sequencedRequest(pollCtx, cryptoSession))
		pollDone <- recorder.Code
	}()
	select {
	case <-pollDone:
		t.Fatal("a poll without a competing stream ended early")
	case <-time.After(300 * time.Millisecond):
	}
	stopPoll()
	<-pollDone
}
