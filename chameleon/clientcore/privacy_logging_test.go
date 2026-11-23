package clientcore

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	clientPrivateDomain = "private-client-history-canary.invalid"
	clientPublicIP      = "198.51.100.242"
	clientRoute         = "/private-route-derived-from-credential"
)

func captureClientPrivacyLogs(t *testing.T, fn func()) string {
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

func assertClientPrivateDataAbsent(t *testing.T, output string) {
	t.Helper()
	for _, value := range []string{clientPrivateDomain, clientPublicIP, clientRoute, "49152"} {
		if strings.Contains(output, value) {
			t.Fatalf("private value %q reached client output: %q", value, output)
		}
	}
}

func TestClientNetworkErrorIsReducedToSafeClass(t *testing.T) {
	err := &privateClientError{
		message: "Get https://" + clientPrivateDomain + clientRoute + ": dial tcp " + clientPublicIP + ":49152",
	}
	output := captureClientPrivacyLogs(t, func() {
		LogOperationalFailure("connection", "reconnect attempt failed", err)
	})
	assertClientPrivateDataAbsent(t, output)
	if !strings.Contains(output, "[connection] reconnect attempt failed (timeout)") {
		t.Fatalf("safe error class missing: %q", output)
	}
}

func TestEveryClientOperationalErrorClassDropsOriginalErrorText(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{name: "nil", err: nil, expected: "operation_failed"},
		{name: "canceled", err: fmt.Errorf("%s: %w", clientPrivateDomain, context.Canceled), expected: "canceled"},
		{name: "timeout", err: fmt.Errorf("%s: %w", clientPublicIP, context.DeadlineExceeded), expected: "timeout"},
		{name: "eof", err: fmt.Errorf("%s: %w", clientRoute, io.EOF), expected: "eof"},
		{name: "truncated", err: fmt.Errorf("%s: %w", clientPrivateDomain, io.ErrUnexpectedEOF), expected: "truncated"},
		{name: "closed", err: fmt.Errorf("%s: %w", clientPublicIP, net.ErrClosed), expected: "closed"},
		{name: "permission", err: fmt.Errorf("%s: %w", clientRoute, os.ErrPermission), expected: "permission_denied"},
		{name: "not-found", err: fmt.Errorf("%s: %w", clientPrivateDomain, os.ErrNotExist), expected: "not_found"},
		{name: "tls", err: fmt.Errorf("%s: tls: certificate verification failed", clientPrivateDomain), expected: "tls_failed"},
		{name: "authentication", err: fmt.Errorf("%s: session establishment rejected", clientRoute), expected: "authentication_failed"},
		{name: "route", err: fmt.Errorf("%s: session challenge failed with status 404", clientRoute), expected: "route_not_found"},
		{name: "protocol", err: fmt.Errorf("%s: incompatible or malformed challenge", clientPrivateDomain), expected: "protocol_mismatch"},
		{name: "http2", err: fmt.Errorf("%s: http2: frame too large", clientPublicIP), expected: "http2_failed"},
		{name: "unavailable", err: fmt.Errorf("%s: connection refused", clientPublicIP), expected: "server_unavailable"},
		{name: "unknown", err: fmt.Errorf("%s|%s|%s", clientPrivateDomain, clientPublicIP, clientRoute), expected: "operation_failed"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := captureClientPrivacyLogs(t, func() {
				LogOperationalFailure("privacy-test", "controlled failure", test.err)
			})
			assertClientPrivateDataAbsent(t, output)
			if !strings.Contains(output, "[privacy-test] controlled failure ("+test.expected+")") {
				t.Fatalf("unexpected safe error class: %q", output)
			}
		})
	}
}

type privateClientError struct {
	message string
}

func (e *privateClientError) Error() string   { return e.message }
func (e *privateClientError) Timeout() bool   { return true }
func (e *privateClientError) Temporary() bool { return true }

func TestClientRepeatedFailuresAreRateLimited(t *testing.T) {
	output := captureClientPrivacyLogs(t, func() {
		for range 1000 {
			LogOperationalFailure("behavior", "poll failed", context.DeadlineExceeded)
		}
	})
	if count := strings.Count(output, "poll failed"); count != 1 {
		t.Fatalf("1000 repeated failures produced %d log entries, want 1", count)
	}
}

func TestFailureStatusDoesNotPersistRawNetworkError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	detail := "Get https://" + clientPrivateDomain + clientRoute + ": dial tcp " + clientPublicIP + ":49152: connection refused"
	WriteFailureStatus(path, "configured-server.example:443", detail)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertClientPrivateDataAbsent(t, string(data))
	if !strings.Contains(string(data), `"failure_code":"server_unavailable"`) {
		t.Fatalf("safe failure classification missing: %s", data)
	}
}

func TestFailureStatusMapsSafeConnectionClasses(t *testing.T) {
	tests := []struct {
		detail string
		code   string
	}{
		{detail: "connect failed (server_unavailable)", code: "server_unavailable"},
		{detail: "connect failed (tls_failed)", code: "server_tls_failed"},
		{detail: "connect failed (authentication_failed)", code: "server_auth_failed"},
		{detail: "connect failed (route_not_found)", code: "server_route_failed"},
		{detail: "connect failed (protocol_mismatch)", code: "server_protocol_failed"},
		{detail: "connect failed (http2_failed)", code: "server_protocol_failed"},
	}

	for _, test := range tests {
		t.Run(test.code+"-"+test.detail, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "status.json")
			WriteFailureStatus(path, "configured-server.example:443", test.detail)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"failure_code":"`+test.code+`"`) {
				t.Fatalf("failure detail %q mapped incorrectly: %s", test.detail, data)
			}
		})
	}
}

func TestRuntimeProfileLearningDoesNotPersistTrafficHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity-profile.json")
	manager := NewProfileManager(path)

	manager.RecordActivity(1492, true)
	manager.RecordActivity(512, false)
	if err := manager.Save(); err != nil {
		t.Fatalf("disabled profile save returned an error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("traffic-derived profile was persisted while learning is disabled: %v", err)
	}

	stats := manager.GetStats()
	if stats.BytesSent != 0 || stats.BytesRecv != 0 {
		t.Fatalf("traffic byte totals were collected while learning is disabled: sent=%d recv=%d", stats.BytesSent, stats.BytesRecv)
	}
	for hour, activity := range stats.ActivityHeatmap {
		if activity != 0 {
			t.Fatalf("activity history was collected for hour %d while learning is disabled", hour)
		}
	}
}

func TestMobileProfileAPIIsMemoryOnlyAndCannotReadOrDeletePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unrelated-private-file")
	privateContents := clientPrivateDomain + "|" + clientPublicIP + "|" + clientRoute
	if err := os.WriteFile(path, []byte(privateContents), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewMobileClient()
	client.SetProfilePath(path)
	if got := client.GetProfileStats(); got != "{}" {
		t.Fatalf("mobile profile API read caller-selected file: %q", got)
	}
	if got := client.ResetProfile(); got != "" {
		t.Fatalf("mobile profile reset failed: %q", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mobile profile reset removed caller-selected file: %v", err)
	}
	if string(data) != privateContents {
		t.Fatal("mobile profile API changed caller-selected file")
	}
}

func TestMobileClientDoesNotReturnRawParserErrorText(t *testing.T) {
	client := NewMobileClient()
	privateConfig := `{"server_address":"` + clientPrivateDomain + `","psk_key":"` + clientRoute
	if got := client.SetConfigJSON(privateConfig); got != "config parse failed" {
		t.Fatalf("mobile config parser returned non-generic error: %q", got)
	}
}

func TestClientCoreLoggingIsCentralizedAndUsesConstantLabels(t *testing.T) {
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
			case "LogState", "LogRateLimitedEvent", "LogOperationalFailure", "FatalOperationalFailure":
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
