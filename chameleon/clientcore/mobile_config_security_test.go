package clientcore

import (
	"encoding/json"
	"strings"
	"testing"
)

func mobileConfigJSON(t *testing.T, mutate func(*Config)) string {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ServerAddress = "mobile.example.test:9446"
	cfg.PSKKey = strings.Repeat("11", 32)
	mutate(cfg)
	payload, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func TestNonStandardMobileTunnelPortRequiresCertificatePin(t *testing.T) {
	client := NewMobileClient()
	withoutPin := mobileConfigJSON(t, func(cfg *Config) {
		cfg.ServerDialAddress = "192.0.2.10:9446"
	})
	if got := client.SetConfigJSON(withoutPin); got != "non-standard tunnel ports require an exact certificate pin" {
		t.Fatalf("unexpected validation result: %q", got)
	}

	withPin := mobileConfigJSON(t, func(cfg *Config) {
		cfg.ServerDialAddress = "192.0.2.10:9446"
		cfg.BootstrapCertSHA256 = strings.Repeat("22", 32)
	})
	if got := client.SetConfigJSON(withPin); got != "" {
		t.Fatalf("expected pinned relay endpoint to be accepted: %q", got)
	}
}

func TestMobileTunnelDialAddressMustRemainAnIPv4Literal(t *testing.T) {
	client := NewMobileClient()
	config := mobileConfigJSON(t, func(cfg *Config) {
		cfg.ServerDialAddress = "relay.example.test:9446"
		cfg.BootstrapCertSHA256 = strings.Repeat("22", 32)
	})
	if got := client.SetConfigJSON(config); got != "server_dial_address must be an IPv4 address with a valid port" {
		t.Fatalf("unexpected validation result: %q", got)
	}
}
