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

func TestMobileIPv6EndpointIsTriedBeforeIPv4(t *testing.T) {
	client := NewMobileClient()
	config := mobileConfigJSON(t, func(cfg *Config) {
		cfg.ServerAddress = "vpn.example.test:443"
		cfg.ServerDialAddress = "198.51.100.7:443"
		cfg.ServerDialAddress6 = "[2a01:4f8:1:2::2]:443"
	})
	if got := client.SetConfigJSON(config); got != "" {
		t.Fatalf("expected the IPv6 endpoint to be accepted: %q", got)
	}
	if got := client.cfg.ServerDialAddress; got != "[2a01:4f8:1:2::2]:443,198.51.100.7:443" {
		t.Fatalf("dial order = %q", got)
	}
}

func TestMobileIPv6EndpointMustBePublicAndPairedWithIPv4(t *testing.T) {
	cases := map[string]func(*Config){
		"private address": func(cfg *Config) {
			cfg.ServerDialAddress = "198.51.100.7:443"
			cfg.ServerDialAddress6 = "[fd00::2]:443"
		},
		"IPv4 in the IPv6 field": func(cfg *Config) {
			cfg.ServerDialAddress = "198.51.100.7:443"
			cfg.ServerDialAddress6 = "198.51.100.8:443"
		},
		"host name": func(cfg *Config) {
			cfg.ServerDialAddress = "198.51.100.7:443"
			cfg.ServerDialAddress6 = "vpn.example.test:443"
		},
		"other port": func(cfg *Config) {
			cfg.ServerDialAddress = "198.51.100.7:443"
			cfg.ServerDialAddress6 = "[2a01:4f8:1:2::2]:8443"
		},
		"without IPv4": func(cfg *Config) {
			cfg.ServerDialAddress6 = "[2a01:4f8:1:2::2]:443"
		},
	}
	for name, mutate := range cases {
		client := NewMobileClient()
		config := mobileConfigJSON(t, func(cfg *Config) {
			cfg.ServerAddress = "vpn.example.test:443"
			mutate(cfg)
		})
		if got := client.SetConfigJSON(config); got != "server_dial_address6 must be a public IPv6 address with the IPv4 endpoint's port" {
			t.Fatalf("%s: unexpected validation result: %q", name, got)
		}
	}
}
