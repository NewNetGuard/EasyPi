package clientcore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config holds the client configuration.
type Config struct {
	ServerAddress           string `json:"server_address"`
	ServerDialAddress       string `json:"server_dial_address,omitempty"` // optional validated IP:port used only for the TCP dial
	PSKKey                  string `json:"psk_key"`                       // hex-encoded PSK
	TransportKey            string `json:"transport_key,omitempty"`       // routing/cover marker only, not session authentication
	Protocol                string `json:"protocol"`                      // fixed to "http2"
	DoHDomain               string `json:"doh_domain"`                    // Domain for DoH polling
	DNSListenAddr           string `json:"dns_listen_addr"`               // Local DNS proxy address, e.g. "127.0.0.1:53"
	BufferSize              int    `json:"buffer_size"`
	ReconnectInterval       int    `json:"reconnect_interval"`        // seconds
	FingerprintMode         string `json:"fingerprint_mode"`          // auto, mobile, or desktop
	BootstrapCertSHA256     string `json:"bootstrap_cert_sha256"`     // optional SHA-256 pin for tunnel TLS cert
	VerifyServerCertificate bool   `json:"verify_server_certificate"` // verify public CA + endpoint IP/DNS identity

	// REALITY settings
	RealityServerPublicKey string `json:"reality_server_public_key"` // hex-encoded
	RealityShieldPreset    string `json:"reality_shield_preset"`     // compatibility field; only "ip" is accepted
	RealityShieldDomain    string `json:"reality_shield_domain"`     // compatibility field; must be empty for IP Shield
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ServerAddress:       "127.0.0.1:443",
		PSKKey:              "",
		Protocol:            "http2",
		DNSListenAddr:       "127.0.0.1:53",
		BufferSize:          1000,
		ReconnectInterval:   5,
		FingerprintMode:     "auto",
		RealityShieldPreset: "ip",
	}
}

func normalizeProtocol(_ string) string {
	// Single stable transport mode.
	return "http2"
}

// LoadConfig loads configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			cfg.PSKKey = GeneratePSK()
			if saveErr := SaveConfig(path, cfg); saveErr != nil {
				return nil, fmt.Errorf("failed to save default config: %w", saveErr)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	cfg.Protocol = normalizeProtocol(strings.TrimSpace(cfg.Protocol))
	cfg.BootstrapCertSHA256 = normalizeSHA256Hex(cfg.BootstrapCertSHA256)
	cfg.FingerprintMode = normalizeFingerprintMode(cfg.FingerprintMode)

	return &cfg, nil
}

// SaveConfig saves configuration to a JSON file.
func SaveConfig(path string, cfg *Config) error {
	cfg.Protocol = "http2"
	cfg.BootstrapCertSHA256 = normalizeSHA256Hex(cfg.BootstrapCertSHA256)
	cfg.FingerprintMode = normalizeFingerprintMode(cfg.FingerprintMode)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	// WriteFile preserves permissions on an existing file, so explicitly tighten
	// legacy configurations that may have been created as world-readable.
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to secure config permissions: %w", err)
	}

	return nil
}

// GeneratePSK generates a new random 32-byte PSK key and returns it hex-encoded.
func GeneratePSK() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("failed to generate PSK: %v", err))
	}
	return hex.EncodeToString(key)
}

// GetPSKBytes returns the PSK key as raw bytes from hex encoding.
func (c *Config) GetPSKBytes() ([]byte, error) {
	return hex.DecodeString(c.PSKKey)
}
