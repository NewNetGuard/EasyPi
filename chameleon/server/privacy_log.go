package main

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

const privacyLogInterval = 5 * time.Second

type privacyLogState struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var privacyLogs = privacyLogState{last: make(map[string]time.Time)}

type privacyErrorWriter struct {
	component string
}

func (w privacyErrorWriter) Write(payload []byte) (int, error) {
	// net/http error strings contain peer addresses and protocol fragments.
	// Preserve only the fact that a protocol error occurred.
	logRateLimitedEvent(w.component, "protocol error")
	return len(payload), nil
}

func privacyErrorLogger(component string) *log.Logger {
	return log.New(privacyErrorWriter{component: component}, "", 0)
}

func privacyStructuredLogger(component string) *slog.Logger {
	return slog.New(slog.NewTextHandler(privacyErrorWriter{component: component}, nil))
}

// operationalErrorClass deliberately returns a small fixed vocabulary. Network
// errors often embed peer addresses, destinations, hostnames, or request data in
// Error(), so production logs must never print an arbitrary error string.
func operationalErrorClass(err error) string {
	switch {
	case err == nil:
		return "operation_failed"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.Is(err, os.ErrNotExist):
		return "not_found"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "operation_failed"
}

func logState(component, event string) {
	log.Printf("[%s] %s\n", component, event)
}

func logRateLimitedEvent(component, event string) {
	key := component + "\x00" + event
	now := time.Now()
	privacyLogs.mu.Lock()
	last := privacyLogs.last[key]
	if !last.IsZero() && now.Sub(last) < privacyLogInterval {
		privacyLogs.mu.Unlock()
		return
	}
	privacyLogs.last[key] = now
	privacyLogs.mu.Unlock()
	logState(component, event)
}

func logOperationalFailure(component, event string, err error) {
	logRateLimitedEvent(component, event+" ("+operationalErrorClass(err)+")")
}

func fatalState(component, event string) {
	log.Fatalf("[%s] %s\n", component, event)
}

func fatalOperationalFailure(component, event string, err error) {
	log.Fatalf("[%s] %s (%s)\n", component, event, operationalErrorClass(err))
}

func resetPrivacyLogLimiterForTest() {
	privacyLogs.mu.Lock()
	privacyLogs.last = make(map[string]time.Time)
	privacyLogs.mu.Unlock()
}
