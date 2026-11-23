package clientcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type failureStatus struct {
	Connected   bool   `json:"connected"`
	ServerAddr  string `json:"server_addr"`
	FailureCode string `json:"failure_code"`
	HealthError string `json:"health_error"`
	FailedAt    string `json:"failed_at"`
}

// WriteFailureStatus preserves the initial connection error after the daemon
// exits so a supervising UI can distinguish failure from normal shutdown.
func WriteFailureStatus(path, serverAddr, detail string) {
	if path == "" {
		return
	}
	code := "server_connection_failed"
	lower := strings.ToLower(detail)
	if strings.Contains(lower, "connection refused") {
		code = "server_unavailable"
	} else if strings.Contains(lower, "server_unavailable") {
		code = "server_unavailable"
	} else if strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded") {
		code = "server_timeout"
	} else if strings.Contains(lower, "certificate") || strings.Contains(lower, "tls") {
		code = "server_tls_failed"
	} else if strings.Contains(lower, "authentication_failed") {
		code = "server_auth_failed"
	} else if strings.Contains(lower, "route_not_found") {
		code = "server_route_failed"
	} else if strings.Contains(lower, "protocol_mismatch") || strings.Contains(lower, "http2_failed") {
		code = "server_protocol_failed"
	}
	healthError := "The Stealth server connection failed."
	if code == "server_unavailable" {
		healthError = "The Stealth server refused the connection."
	} else if code == "server_timeout" {
		healthError = "The Stealth server connection timed out."
	} else if code == "server_tls_failed" {
		healthError = "The Stealth server identity or TLS certificate is invalid."
	} else if code == "server_auth_failed" {
		healthError = "The Stealth client and server credentials do not match."
	} else if code == "server_route_failed" {
		healthError = "The Stealth HTTPS route is not deployed on the server."
	} else if code == "server_protocol_failed" {
		healthError = "The Stealth client and server protocol versions do not match."
	}
	payload, err := json.Marshal(failureStatus{
		Connected: false, ServerAddr: serverAddr, FailureCode: code,
		HealthError: healthError, FailedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_ = tmp.Chmod(0o600)
	if _, err = tmp.Write(payload); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		_ = os.Rename(tmpName, path)
	}
}
