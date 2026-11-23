package main

import (
	"chameleon/shared"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ServerConfig holds the server configuration.
type ServerConfig struct {
	ListenAddress         string `json:"listen_address"` // empty for all interfaces; use loopback behind Mobile Link
	ListenPort            int    `json:"listen_port"`
	BootstrapPort         int    `json:"bootstrap_port"`
	FrontendMode          string `json:"frontend_mode"`   // "direct" or "nginx"
	BackendAddress        string `json:"backend_address"` // loopback HTTP listener used by nginx
	PSKKey                string `json:"psk_key"`
	ClientAuthKey         string `json:"client_auth_key"`
	MobileClientsFile     string `json:"mobile_clients_file"`
	MaxConnections        int    `json:"max_connections"`
	MaxRequestsPerSession int    `json:"max_requests_per_session"`
	MaxSessionsPerSource  int    `json:"max_sessions_per_source"`
	MaxPreAuthConnections int    `json:"max_pre_auth_connections"`
	MaxPreAuthPerIP       int    `json:"max_pre_auth_per_ip"`
	LogLevel              string `json:"log_level"`
	TLSCert               string `json:"tls_cert"`
	TLSKey                string `json:"tls_key"`
	SiteDir               string `json:"site_dir"`
	Domain                string `json:"domain"`

	// Cloudflare DoH settings
	CFApiToken string `json:"cf_api_token"`
	CFZoneID   string `json:"cf_zone_id"`
	DoHDomain  string `json:"doh_domain"`

	// DNS tunnel settings
	UpstreamDNS string `json:"upstream_dns"` // e.g. "1.1.1.1:53"

	// REALITY settings
	RealityPublicKey string `json:"reality_public_key"` // public marker input; encoded as an X25519 public value
	ShieldDomain     string `json:"shield_domain"`      // compatibility field; must be empty for IP Shield
	ShieldPreset     string `json:"shield_preset"`      // compatibility field; only "ip" is accepted
	ProbeMode        string `json:"probe_mode"`         // fixed to "local" for the deployment cover endpoint
	ProbeTarget      string `json:"probe_target"`       // loopback TLS cover endpoint in local mode
	BlockQUICUDP443  bool   `json:"block_quic_udp443"`  // optional: block UDP/443 egress from tunnel for compatibility
	QUICDatagramPort int    `json:"quic_datagram_port"` // experimental build-tagged listener; disabled when zero
	TunnelName       string `json:"tunnel_name"`
	TunnelCIDR       string `json:"tunnel_cidr"`
	TunnelMTU        int    `json:"tunnel_mtu"`
	PrismLinkListen  string `json:"prism_link_listen"`
}

// DefaultServerConfig returns sensible defaults.
func DefaultServerConfig() *ServerConfig {
	authKey, err := secureHex(32)
	if err != nil {
		panic("secure random source unavailable")
	}
	return &ServerConfig{
		ClientAuthKey:         authKey,
		ListenAddress:         "",
		MobileClientsFile:     "mobile_clients.json",
		ListenPort:            443,
		BootstrapPort:         8443,
		FrontendMode:          "direct",
		BackendAddress:        "127.0.0.1:9080",
		PSKKey:                "",
		MaxConnections:        100,
		MaxRequestsPerSession: 8,
		MaxSessionsPerSource:  8,
		MaxPreAuthConnections: 256,
		MaxPreAuthPerIP:       32,
		LogLevel:              "info",
		TLSCert:               "cert.pem",
		TLSKey:                "key.pem",
		SiteDir:               "site",
		Domain:                "",
		UpstreamDNS:           "1.1.1.1:53",
		ShieldDomain:          "",
		ShieldPreset:          "ip",
		ProbeMode:             "local",
		ProbeTarget:           "127.0.0.1:9443",
		BlockQUICUDP443:       false,
		TunnelName:            "chameleon0",
		TunnelCIDR:            "10.10.0.1/24",
		TunnelMTU:             1420,
		PrismLinkListen:       "",
	}
}

// LoadServerConfig loads server configuration from a JSON file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultServerConfig()
			cfg.MobileClientsFile = filepath.Join(filepath.Dir(path), "mobile_clients.json")
			registry, registryErr := os.OpenFile(cfg.MobileClientsFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if registryErr == nil {
				_, registryErr = registry.WriteString("{\"version\":1,\"devices\":[]}")
				closeErr := registry.Close()
				if registryErr == nil {
					registryErr = closeErr
				}
			}
			if registryErr != nil && !os.IsExist(registryErr) {
				return nil, fmt.Errorf("create mobile registry: %w", registryErr)
			}
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return nil, fmt.Errorf("failed to generate PSK: %w", err)
			}
			cfg.PSKKey = hex.EncodeToString(key)
			pub, err := shared.GenerateMarkerPublicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to generate marker public key: %w", err)
			}
			cfg.RealityPublicKey = hex.EncodeToString(pub)
			if saveErr := SaveServerConfig(path, cfg); saveErr != nil {
				return nil, fmt.Errorf("failed to save default config: %w", saveErr)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if cfg.BootstrapPort <= 0 {
		cfg.BootstrapPort = 8443
	}
	if cfg.ListenAddress != "" {
		listenIP := net.ParseIP(strings.TrimSpace(cfg.ListenAddress))
		if listenIP == nil {
			return nil, fmt.Errorf("listen_address must be an IP address")
		}
		cfg.ListenAddress = listenIP.String()
	}
	if cfg.TunnelName == "" {
		cfg.TunnelName = "chameleon0"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`).MatchString(cfg.TunnelName) {
		return nil, fmt.Errorf("tunnel_name must be a valid Linux interface name")
	}
	if cfg.TunnelCIDR == "" {
		cfg.TunnelCIDR = "10.10.0.1/24"
	}
	tunnelIP, tunnelNetwork, err := net.ParseCIDR(cfg.TunnelCIDR)
	if err != nil || tunnelIP.To4() == nil || tunnelNetwork == nil {
		return nil, fmt.Errorf("tunnel_cidr must be a private IPv4 network")
	}
	ones, bits := tunnelNetwork.Mask.Size()
	if bits != 32 || ones != 24 || !tunnelIP.IsPrivate() || tunnelIP.IsLoopback() || tunnelIP.IsUnspecified() {
		return nil, fmt.Errorf("tunnel_cidr must be a private IPv4 /24")
	}
	firstUsable := append(net.IP(nil), tunnelNetwork.IP.To4()...)
	firstUsable[3]++
	if !tunnelIP.To4().Equal(firstUsable) {
		return nil, fmt.Errorf("tunnel_cidr must use the first usable address")
	}
	cfg.TunnelCIDR = fmt.Sprintf("%s/24", tunnelIP.To4().String())
	if cfg.TunnelMTU == 0 {
		cfg.TunnelMTU = 1420
	}
	if cfg.TunnelMTU < 1200 || cfg.TunnelMTU > 1500 {
		return nil, fmt.Errorf("tunnel_mtu must be between 1200 and 1500")
	}
	if strings.TrimSpace(cfg.PrismLinkListen) != "" {
		host, portText, err := net.SplitHostPort(strings.TrimSpace(cfg.PrismLinkListen))
		if err != nil || net.ParseIP(host) == nil {
			return nil, fmt.Errorf("prism_link_listen must be an IP:PORT endpoint")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("prism_link_listen must use a valid UDP port")
		}
		cfg.PrismLinkListen = net.JoinHostPort(net.ParseIP(host).String(), strconv.Itoa(port))
	}
	cfg.FrontendMode = strings.ToLower(strings.TrimSpace(cfg.FrontendMode))
	if cfg.FrontendMode == "" {
		cfg.FrontendMode = "direct"
	}
	if cfg.BackendAddress == "" {
		cfg.BackendAddress = "127.0.0.1:9080"
	}
	switch cfg.FrontendMode {
	case "direct":
	case "nginx":
		if !isLoopbackTarget(cfg.BackendAddress) {
			return nil, fmt.Errorf("nginx backend_address must be a loopback TCP endpoint")
		}
	default:
		return nil, fmt.Errorf("frontend_mode must be direct or nginx")
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 100
	}
	if cfg.MaxRequestsPerSession <= 0 {
		cfg.MaxRequestsPerSession = 8
	}
	if cfg.MaxSessionsPerSource <= 0 {
		cfg.MaxSessionsPerSource = 8
	}
	if cfg.MaxPreAuthConnections <= 0 {
		cfg.MaxPreAuthConnections = 256
	}
	if cfg.MaxPreAuthPerIP <= 0 {
		cfg.MaxPreAuthPerIP = 32
	}

	if !strings.EqualFold(strings.TrimSpace(cfg.ShieldPreset), "ip") {
		return nil, fmt.Errorf("only IP Shield is supported; redeploy the server configuration")
	}
	if strings.TrimSpace(cfg.ShieldDomain) != "" {
		return nil, fmt.Errorf("IP Shield must not configure an unrelated shield domain")
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.ProbeMode), "local") {
		return nil, fmt.Errorf("only the local IP Shield probe endpoint is supported")
	}
	cfg.ShieldPreset = "ip"
	cfg.ProbeMode = "local"
	if strings.TrimSpace(cfg.ProbeTarget) == "" {
		cfg.ProbeTarget = "127.0.0.1:9443"
	}

	if cfg.PSKKey != "" {
		psk, err := hex.DecodeString(cfg.PSKKey)
		if err != nil || len(psk) != 32 {
			return nil, fmt.Errorf("psk_key must contain exactly 32 bytes encoded as hex")
		}
	}
	auth, err := hex.DecodeString(cfg.ClientAuthKey)
	if err != nil || len(auth) != 32 || strings.EqualFold(cfg.ClientAuthKey, cfg.PSKKey) {
		return nil, fmt.Errorf("independent client_auth_key required; migrate server and home client together")
	}
	if cfg.MobileClientsFile == "" {
		cfg.MobileClientsFile = "mobile_clients.json"
	}

	// The marker uses only a public deployment value. Older configurations may
	// contain reality_private_key; encoding/json safely ignores that retired field.
	if cfg.RealityPublicKey == "" {
		pub, err := shared.GenerateMarkerPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate marker public key: %w", err)
		}
		cfg.RealityPublicKey = hex.EncodeToString(pub)
		if err := SaveServerConfig(path, &cfg); err != nil {
			return nil, fmt.Errorf("failed to save generated marker public key: %w", err)
		}
	} else {
		pub, err := hex.DecodeString(cfg.RealityPublicKey)
		if err != nil || len(pub) != 32 {
			return nil, fmt.Errorf("reality_public_key must contain exactly 32 bytes encoded as hex")
		}
		if err := shared.VerifyPubKey(pub); err != nil {
			return nil, fmt.Errorf("reality_public_key is invalid: %w", err)
		}
	}

	return &cfg, nil
}

// SaveServerConfig saves the server configuration to a JSON file.
func SaveServerConfig(path string, cfg *ServerConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to secure config permissions: %w", err)
	}

	return nil
}
