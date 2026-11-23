package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"chameleon/shared"
)

const (
	testPrivateDomain = "private-history-canary.invalid"
	testPublicIP      = "198.51.100.241"
	testDestinationIP = "203.0.113.77"
	testClientID      = "private-client-identity-canary"
)

func capturePrivacyLogs(t *testing.T, fn func()) string {
	t.Helper()
	var output bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	resetPrivacyLogLimiterForTest()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
		resetPrivacyLogLimiterForTest()
	})
	fn()
	return output.String()
}

func assertLogDoesNotContainPrivateData(t *testing.T, output string, privateValues ...string) {
	t.Helper()
	for _, value := range privateValues {
		if value != "" && strings.Contains(output, value) {
			t.Fatalf("private value %q reached log output: %q", value, output)
		}
	}
}

func sessionAuthHeaderAt(session *cryptoSession, timestamp int64, nonce, clientID, method, path string) string {
	ts := strconv.FormatInt(timestamp, 10)
	mac := shared.ComputeSessionRequestMAC(session.authKey, ts, nonce, clientID, session.id, method, path)
	return "Bearer " + hex.EncodeToString(mac) + ":" + ts + ":" + nonce + ":" + clientID + ":" + session.id
}

func TestAuthenticationFailuresDoNotLogCallerData(t *testing.T) {
	psk := []byte("privacy-test-installation-secret")
	manager, session, _ := newTestCryptoPair(t, psk)
	expectedID := session.clientID
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	output := capturePrivacyLogs(t, func() {
		attempts := []string{
			sessionAuthHeaderAt(session, time.Now().Unix(), "00112233445566778899aabbccddeeff", testClientID, http.MethodGet, "/private"),
			sessionAuthHeaderAt(session, time.Now().Add(-10*time.Minute).Unix(), "10112233445566778899aabbccddeeff", expectedID, http.MethodGet, "/private"),
			"Bearer " + strings.Repeat("00", sha256.Size) + ":" + strconv.FormatInt(time.Now().Unix(), 10) + ":20112233445566778899aabbccddeeff:" + expectedID + ":" + session.id,
		}
		validReplay := sessionAuthHeaderAt(session, time.Now().Unix(), "30112233445566778899aabbccddeeff", expectedID, http.MethodGet, "/private")
		attempts = append(attempts, validReplay, validReplay)

		for _, header := range attempts {
			req := httptest.NewRequest(http.MethodGet, "https://"+testPrivateDomain+"/private", nil)
			req.RemoteAddr = testPublicIP + ":49211"
			req.Header.Set("Authorization", header)
			handler(httptest.NewRecorder(), req)
		}
	})

	assertLogDoesNotContainPrivateData(t, output, testPublicIP, testPrivateDomain, testClientID, expectedID, "49211")
	for _, expected := range []string{
		"rejected caller-selected client identity",
		"rejected stale timestamp",
		"rejected invalid session authenticator",
		"rejected replayed session authenticator",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing safe authentication event %q in %q", expected, output)
		}
	}
}

func TestArbitraryNetworkErrorsAreReducedToSafeClasses(t *testing.T) {
	secretError := fmt.Errorf("dial %s:443 for %s from %s: %w", testDestinationIP, testPrivateDomain, testClientID, context.DeadlineExceeded)
	output := capturePrivacyLogs(t, func() {
		logOperationalFailure("relay", "connection failed", secretError)
	})

	assertLogDoesNotContainPrivateData(t, output, testDestinationIP, testPrivateDomain, testClientID)
	if !strings.Contains(output, "[relay] connection failed (timeout)") {
		t.Fatalf("safe error class missing from log: %q", output)
	}
}

func TestEveryOperationalErrorClassDropsOriginalErrorText(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{name: "nil", err: nil, expected: "operation_failed"},
		{name: "canceled", err: fmt.Errorf("%s: %w", testPrivateDomain, context.Canceled), expected: "canceled"},
		{name: "timeout", err: fmt.Errorf("%s: %w", testPublicIP, context.DeadlineExceeded), expected: "timeout"},
		{name: "eof", err: fmt.Errorf("%s: %w", testClientID, io.EOF), expected: "eof"},
		{name: "truncated", err: fmt.Errorf("%s: %w", testDestinationIP, io.ErrUnexpectedEOF), expected: "truncated"},
		{name: "closed", err: fmt.Errorf("%s: %w", testPrivateDomain, net.ErrClosed), expected: "closed"},
		{name: "permission", err: fmt.Errorf("%s: %w", testPublicIP, os.ErrPermission), expected: "permission_denied"},
		{name: "not-found", err: fmt.Errorf("%s: %w", testClientID, os.ErrNotExist), expected: "not_found"},
		{name: "unknown", err: fmt.Errorf("%s|%s|%s", testPrivateDomain, testPublicIP, testClientID), expected: "operation_failed"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := capturePrivacyLogs(t, func() {
				logOperationalFailure("privacy-test", "controlled failure", test.err)
			})
			assertLogDoesNotContainPrivateData(t, output, testPrivateDomain, testPublicIP, testDestinationIP, testClientID)
			if !strings.Contains(output, "[privacy-test] controlled failure ("+test.expected+")") {
				t.Fatalf("unexpected safe error class: %q", output)
			}
		})
	}
}

func TestHTTPServerErrorLoggerDoesNotExposeProtocolInputOrPeer(t *testing.T) {
	privateLine := "http: TLS handshake error from " + testPublicIP + ":49213: client sent " + testPrivateDomain
	output := capturePrivacyLogs(t, func() {
		privacyErrorLogger("http2").Print(privateLine)
	})

	assertLogDoesNotContainPrivateData(t, output, testPublicIP, testPrivateDomain, "49213")
	if !strings.Contains(output, "[http2] protocol error") {
		t.Fatalf("safe HTTP protocol event missing: %q", output)
	}
}

func TestHTTP3ErrorLoggerDoesNotExposeStructuredValues(t *testing.T) {
	output := capturePrivacyLogs(t, func() {
		privacyStructuredLogger("http3").Error(
			"handshake failed",
			"peer", testPublicIP+":49214",
			"server_name", testPrivateDomain,
		)
	})

	assertLogDoesNotContainPrivateData(t, output, testPublicIP, testPrivateDomain, "49214", "handshake failed")
	if !strings.Contains(output, "[http3] protocol error") {
		t.Fatalf("safe HTTP/3 protocol event missing: %q", output)
	}
}

func TestBadTunnelPayloadDoesNotLogPayloadOrIdentity(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	psk := []byte("privacy-test-payload-secret")
	_, cryptoSession, _ := newTestCryptoPair(t, psk)
	demasker := NewDemasker(psk)
	defer demasker.Stop()

	payload := []byte(testPrivateDomain + "|" + testDestinationIP + "|" + testClientID)
	var framed bytes.Buffer
	var length [4]byte
	length[0] = byte(len(payload) >> 24)
	length[1] = byte(len(payload) >> 16)
	length[2] = byte(len(payload) >> 8)
	length[3] = byte(len(payload))
	framed.Write(length[:])
	framed.Write(payload)

	output := capturePrivacyLogs(t, func() {
		req := httptest.NewRequest(http.MethodPost, "https://example.invalid/private", &framed)
		req.RemoteAddr = testPublicIP + ":49212"
		req.Header.Set("Content-Type", "application/octet-stream")
		ctx := context.WithValue(req.Context(), contextKeyClientID, cryptoSession.clientID)
		ctx = context.WithValue(ctx, contextKeyCryptoSession, cryptoSession)
		resp := httptest.NewRecorder()
		handlePush(demasker)(resp, req.WithContext(ctx))
		if resp.Code != http.StatusBadGateway {
			t.Fatalf("bad tunnel payload returned %d, want %d", resp.Code, http.StatusBadGateway)
		}
	})

	assertLogDoesNotContainPrivateData(t, output, testPrivateDomain, testDestinationIP, testClientID, testPublicIP, "49212")
	if !strings.Contains(output, "[push] tunnel payload rejected (operation_failed)") {
		t.Fatalf("safe payload failure event missing: %q", output)
	}
}

func TestDNSFailureDoesNotLogQueryOrUpstream(t *testing.T) {
	psk := []byte("privacy-test-dns-secret")
	_, cryptoSession, clientCipher := newTestCryptoPair(t, psk)
	rawQuery := append([]byte{0x12, 0x34, 0x01, 0x00}, []byte(testPrivateDomain)...)
	encrypted, err := clientCipher.Encrypt(rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(dnsRequest{D: base64.StdEncoding.EncodeToString(encrypted)})
	if err != nil {
		t.Fatal(err)
	}
	const invalidUpstream = "[203.0.113.77"

	output := capturePrivacyLogs(t, func() {
		req := httptest.NewRequest(http.MethodPost, "https://example.invalid/dns", bytes.NewReader(body))
		ctx := context.WithValue(req.Context(), contextKeyCryptoSession, cryptoSession)
		resp := httptest.NewRecorder()
		ctx = context.WithValue(ctx, contextKeyClientID, cryptoSession.clientID)
		handleDNS(invalidUpstream)(resp, req.WithContext(ctx))
		if resp.Code != http.StatusBadGateway {
			t.Fatalf("DNS failure returned %d, want %d", resp.Code, http.StatusBadGateway)
		}
	})

	assertLogDoesNotContainPrivateData(t, output, testPrivateDomain, testDestinationIP, invalidUpstream)
	if !strings.Contains(output, "[dns] upstream request failed") {
		t.Fatalf("safe DNS failure event missing: %q", output)
	}
}

func TestStaleSessionCleanupDoesNotLogIdentityOrSource(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	now := time.Now()
	session := newClientSession()
	session.source = testPublicIP
	session.lastSeen.Store(now.Add(-11 * time.Minute).UnixNano())
	sessionsMu.Lock()
	sessions[testClientID] = session
	sessionsMu.Unlock()

	output := capturePrivacyLogs(t, func() {
		cleanupSessionsAt(now)
	})
	assertLogDoesNotContainPrivateData(t, output, testClientID, testPublicIP)
	if !strings.Contains(output, "discarded stale inactive session") {
		t.Fatalf("safe cleanup event missing: %q", output)
	}
}

type privacyRoundTripper func(*http.Request) (*http.Response, error)

func (fn privacyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestCloudflareErrorsDoNotExposeResponseBody(t *testing.T) {
	privateBody := `{"success":false,"errors":[{"code":9109,"message":"` + testPrivateDomain + ` ` + testClientID + `"}]}`
	client := NewCloudflareClient("private-api-token", "private-zone", testPrivateDomain)
	client.client = &http.Client{Transport: privacyRoundTripper(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(privateBody)),
			Header:     make(http.Header),
		}, nil
	})}

	_, err := client.getRecordID()
	if err == nil {
		t.Fatal("Cloudflare failure was unexpectedly accepted")
	}
	assertLogDoesNotContainPrivateData(t, err.Error(), testPrivateDomain, testClientID, "private-api-token", privateBody)
	if !strings.Contains(err.Error(), "status=403") {
		t.Fatalf("safe HTTP status missing from error: %q", err)
	}
}

func TestRepeatedFailuresAreRateLimited(t *testing.T) {
	output := capturePrivacyLogs(t, func() {
		for i := 0; i < 1000; i++ {
			logRateLimitedEvent("auth", "rejected invalid authenticator")
		}
	})
	if count := strings.Count(output, "rejected invalid authenticator"); count != 1 {
		t.Fatalf("1000 repeated failures produced %d log entries, want 1", count)
	}
}

func TestProductionLoggingIsCentralizedAndUsesConstantLabels(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "privacy_log.go" {
			continue
		}
		path := filepath.Join(".", name)
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), `"log"`) || strings.Contains(string(source), "log.") ||
			strings.Contains(string(source), "fmt.Print") || strings.Contains(string(source), "os.Stdout") ||
			strings.Contains(string(source), "os.Stderr") {
			t.Fatalf("%s bypasses centralized privacy logging", name)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch ident.Name {
			case "logState", "logRateLimitedEvent", "logOperationalFailure", "fatalState", "fatalOperationalFailure":
				if len(call.Args) < 2 {
					t.Errorf("%s calls %s without fixed component and event", name, ident.Name)
					return true
				}
				for index := 0; index < 2; index++ {
					literal, ok := call.Args[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						t.Errorf("%s calls %s with a non-constant logging label", name, ident.Name)
					}
				}
			}
			return true
		})
	}
}
