package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chameleon/shared"
)

func validServerConfig(t *testing.T) *ServerConfig {
	t.Helper()
	pub, err := shared.GenerateMarkerPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultServerConfig()
	cfg.PSKKey = strings.Repeat("11", 32)
	cfg.RealityPublicKey = hex.EncodeToString(pub)
	return cfg
}

func TestLoadServerConfigRejectsMalformedKeys(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ServerConfig)
	}{
		{name: "short PSK", mutate: func(cfg *ServerConfig) { cfg.PSKKey = "abcd" }},
		{name: "non-hex PSK", mutate: func(cfg *ServerConfig) { cfg.PSKKey = strings.Repeat("z", 64) }},
		{name: "shared marker and authentication key", mutate: func(cfg *ServerConfig) {
			cfg.PSKKey = strings.Repeat("ab", 32)
			cfg.ClientAuthKey = strings.Repeat("AB", 32)
		}},
		{name: "short marker public key", mutate: func(cfg *ServerConfig) { cfg.RealityPublicKey = "abcd" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.json")
			cfg := validServerConfig(t)
			tc.mutate(cfg)
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadServerConfig(path); err == nil {
				t.Fatal("expected malformed key to be rejected")
			}
		})
	}
}

func TestGeneratedConfigDoesNotPersistUnusedPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PSKKey) != 64 || len(cfg.RealityPublicKey) != 64 {
		t.Fatalf("unexpected generated key lengths: PSK=%d marker=%d", len(cfg.PSKKey), len(cfg.RealityPublicKey))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("reality_private_key")) {
		t.Fatal("generated configuration persisted an unused private key")
	}
}

func TestLegacyPrivateKeyIsIgnoredAndRemovedOnSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	cfg := validServerConfig(t)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["reality_private_key"] = strings.Repeat("22", 32)
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveServerConfig(path, loaded); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("reality_private_key")) {
		t.Fatal("legacy private key remained after configuration rewrite")
	}
}

func TestNginxFrontendRequiresLoopbackBackend(t *testing.T) {
	writeAndLoad := func(t *testing.T, mode string, backend string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "server.json")
		cfg := validServerConfig(t)
		cfg.FrontendMode = mode
		cfg.BackendAddress = backend
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = LoadServerConfig(path)
		return err
	}

	if err := writeAndLoad(t, "nginx", "0.0.0.0:9080"); err == nil {
		t.Fatal("expected public nginx backend to be rejected")
	}
	if err := writeAndLoad(t, "nginx", "127.0.0.1:9080"); err != nil {
		t.Fatalf("expected loopback nginx backend to be accepted: %v", err)
	}
	if err := writeAndLoad(t, "unknown", "127.0.0.1:9080"); err == nil {
		t.Fatal("expected unknown frontend mode to be rejected")
	}
}

func TestHomeTunnelNetworkSettingsAreValidated(t *testing.T) {
	writeAndLoad := func(t *testing.T, mutate func(*ServerConfig)) (*ServerConfig, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "server.json")
		cfg := validServerConfig(t)
		mutate(cfg)
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadServerConfig(path)
	}

	loaded, err := writeAndLoad(t, func(cfg *ServerConfig) {
		cfg.ListenAddress = "127.0.0.1"
		cfg.TunnelName = "easypi-mobile0"
		cfg.TunnelCIDR = "10.77.0.1/24"
	})
	if err != nil {
		t.Fatalf("expected isolated home tunnel settings to be accepted: %v", err)
	}
	if loaded.ListenAddress != "127.0.0.1" || loaded.TunnelName != "easypi-mobile0" || loaded.TunnelCIDR != "10.77.0.1/24" {
		t.Fatalf("unexpected normalized home tunnel settings: %#v", loaded)
	}

	invalid := []func(*ServerConfig){
		func(cfg *ServerConfig) { cfg.ListenAddress = "relay.example" },
		func(cfg *ServerConfig) { cfg.TunnelName = "name-that-is-far-too-long" },
		func(cfg *ServerConfig) { cfg.TunnelCIDR = "203.0.113.1/24" },
		func(cfg *ServerConfig) { cfg.TunnelCIDR = "10.77.0.2/24" },
		func(cfg *ServerConfig) { cfg.TunnelCIDR = "10.77.0.1/16" },
	}
	for index, mutate := range invalid {
		if _, err := writeAndLoad(t, mutate); err == nil {
			t.Fatalf("expected invalid network settings at index %d to be rejected", index)
		}
	}
}
