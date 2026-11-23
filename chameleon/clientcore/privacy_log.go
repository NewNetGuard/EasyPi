package clientcore

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const privacyLogInterval = 5 * time.Second

type privacyLogState struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var privacyLogs = privacyLogState{last: make(map[string]time.Time)}

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
	// Keep user-visible diagnostics useful without ever returning the original
	// error text: network errors frequently contain the private endpoint, route,
	// or request URL. Only stable, non-sensitive classes leave this function.
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "x509:"),
		strings.Contains(message, "certificate"),
		strings.Contains(message, "tls handshake"),
		strings.Contains(message, "tls:"):
		return "tls_failed"
	case strings.Contains(message, "establishment rejected"),
		strings.Contains(message, "authentication failed"),
		strings.Contains(message, "status 401"):
		return "authentication_failed"
	case strings.Contains(message, "challenge failed with status 404"),
		strings.Contains(message, "establishment failed with status 404"):
		return "route_not_found"
	case strings.Contains(message, "incompatible"),
		strings.Contains(message, "malformed challenge"),
		strings.Contains(message, "malformed establishment"):
		return "protocol_mismatch"
	case strings.Contains(message, "http2:"),
		strings.Contains(message, "http/2"):
		return "http2_failed"
	case strings.Contains(message, "connection refused"),
		strings.Contains(message, "no route to host"),
		strings.Contains(message, "network is unreachable"):
		return "server_unavailable"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "operation_failed"
}

func LogState(component, event string) {
	log.Printf("[%s] %s\n", component, event)
}

func LogRateLimitedEvent(component, event string) {
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
	LogState(component, event)
}

func LogOperationalFailure(component, event string, err error) {
	LogRateLimitedEvent(component, event+" ("+operationalErrorClass(err)+")")
}

func FatalOperationalFailure(component, event string, err error) {
	log.Fatalf("[%s] %s (%s)\n", component, event, operationalErrorClass(err))
}

func resetPrivacyLogLimiterForTest() {
	privacyLogs.mu.Lock()
	privacyLogs.last = make(map[string]time.Time)
	privacyLogs.mu.Unlock()
}
