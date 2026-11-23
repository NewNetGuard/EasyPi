package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"chameleon/mobilelink"
)

type config struct {
	AgentListen         string            `json:"agent_listen"`
	MobileListen        string            `json:"mobile_listen"`
	BaseDomain          string            `json:"base_domain"`
	TLSCertFile         string            `json:"tls_cert_file"`
	TLSKeyFile          string            `json:"tls_key_file"`
	Installations       map[string]string `json:"installations"`
	HostRoutes          map[string]string `json:"host_routes"`
	TunnelAgentListen   string            `json:"tunnel_agent_listen,omitempty"`
	TunnelMobileListen  string            `json:"tunnel_mobile_listen,omitempty"`
	TunnelInstallations map[string]string `json:"tunnel_installations,omitempty"`
	TunnelHostRoutes    map[string]string `json:"tunnel_host_routes,omitempty"`
	PrismAgentListen    string            `json:"prism_agent_listen,omitempty"`
	PrismMobileListen   string            `json:"prism_mobile_listen,omitempty"`
	PrismInstallations  map[string]string `json:"prism_installations,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "path to the Mobile Link relay JSON configuration")
	flag.Parse()
	if *configPath == "" {
		fatal("-config is required")
	}
	var cfg config
	loadJSON(*configPath, &cfg)
	relay, err := configuredRelay(cfg.BaseDomain, cfg.Installations, cfg.HostRoutes)
	if err != nil {
		fatal(err.Error())
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		fatal("load relay TLS certificate: " + err.Error())
	}
	errors := make(chan error, 8)
	serveRelay(relay, cfg.AgentListen, cfg.MobileListen, certificate, errors)

	tunnelConfigured := cfg.TunnelAgentListen != "" || cfg.TunnelMobileListen != "" || len(cfg.TunnelInstallations) > 0
	if tunnelConfigured {
		if cfg.TunnelAgentListen == "" || cfg.TunnelMobileListen == "" || len(cfg.TunnelInstallations) == 0 {
			fatal("tunnel relay requires agent, mobile, and installation configuration")
		}
		tunnelRelay, tunnelErr := configuredRelay(cfg.BaseDomain, cfg.TunnelInstallations, cfg.TunnelHostRoutes)
		if tunnelErr != nil {
			fatal("invalid tunnel relay: " + tunnelErr.Error())
		}
		serveRelay(tunnelRelay, cfg.TunnelAgentListen, cfg.TunnelMobileListen, certificate, errors)
	}
	prismConfigured := cfg.PrismAgentListen != "" || cfg.PrismMobileListen != "" || len(cfg.PrismInstallations) > 0
	if prismConfigured {
		if cfg.PrismAgentListen == "" || cfg.PrismMobileListen == "" || len(cfg.PrismInstallations) == 0 {
			fatal("PrismLink relay requires agent, mobile, and installation configuration")
		}
		prismRelay, prismErr := configuredPrismRelay(cfg.PrismInstallations)
		if prismErr != nil {
			fatal("invalid PrismLink relay: " + prismErr.Error())
		}
		servePrismRelay(prismRelay, cfg.PrismAgentListen, cfg.PrismMobileListen, errors)
	}
	if err := <-errors; err != nil {
		fatal(err.Error())
	}
}

func configuredPrismRelay(encodedSecrets map[string]string) (*mobilelink.PrismRelay, error) {
	secrets := make(map[[16]byte][32]byte, len(encodedSecrets))
	for encodedID, encodedSecret := range encodedSecrets {
		id, err := mobilelink.PrismInstallationID(encodedID)
		secretBytes, secretErr := hex.DecodeString(strings.TrimSpace(encodedSecret))
		if err != nil || secretErr != nil || len(secretBytes) != 32 || mobilelink.InstallationID(secretBytes) != encodedID {
			return nil, fmt.Errorf("PrismLink installation map contains an invalid id or secret")
		}
		var secret [32]byte
		copy(secret[:], secretBytes)
		secrets[id] = secret
	}
	return mobilelink.NewPrismRelay(func(id [16]byte) ([32]byte, bool) {
		secret, ok := secrets[id]
		return secret, ok
	})
}

func servePrismRelay(relay *mobilelink.PrismRelay, agentAddress, mobileAddress string, errors chan<- error) {
	agentUDPAddress, err := net.ResolveUDPAddr("udp", agentAddress)
	if err != nil {
		fatal(err.Error())
	}
	agentUDP, err := net.ListenUDP("udp", agentUDPAddress)
	if err != nil {
		fatal(err.Error())
	}
	mobileUDPAddress, err := net.ResolveUDPAddr("udp", mobileAddress)
	if err != nil {
		_ = agentUDP.Close()
		fatal(err.Error())
	}
	mobileUDP, err := net.ListenUDP("udp", mobileUDPAddress)
	if err != nil {
		_ = agentUDP.Close()
		fatal(err.Error())
	}
	_ = agentUDP.SetReadBuffer(4 * 1024 * 1024)
	_ = agentUDP.SetWriteBuffer(4 * 1024 * 1024)
	_ = mobileUDP.SetReadBuffer(4 * 1024 * 1024)
	_ = mobileUDP.SetWriteBuffer(4 * 1024 * 1024)
	go func() { errors <- relay.Serve(agentUDP, mobileUDP) }()
}

func configuredRelay(baseDomain string, encodedSecrets, hostRoutes map[string]string) (*mobilelink.Relay, error) {
	secrets := make(map[string][]byte, len(encodedSecrets))
	for id, encoded := range encodedSecrets {
		secret, err := hex.DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(secret) != 32 || mobilelink.InstallationID(secret) != id {
			return nil, fmt.Errorf("installation map contains an invalid id or secret")
		}
		secrets[id] = secret
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("at least one installation is required")
	}
	relay, err := mobilelink.NewRelay(baseDomain, func(id string) ([]byte, bool) {
		secret, ok := secrets[id]
		return secret, ok
	})
	if err != nil {
		return nil, err
	}
	for hostname, installationID := range hostRoutes {
		if err := relay.AddStaticHostname(hostname, installationID); err != nil {
			return nil, fmt.Errorf("invalid host route: %w", err)
		}
	}
	return relay, nil
}

func serveRelay(relay *mobilelink.Relay, agentAddress, mobileAddress string, certificate tls.Certificate, errors chan<- error) {
	agentTCP, err := net.Listen("tcp", agentAddress)
	if err != nil {
		fatal(err.Error())
	}
	agentListener := tls.NewListener(agentTCP, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	mobileListener, err := net.Listen("tcp", mobileAddress)
	if err != nil {
		_ = agentTCP.Close()
		fatal(err.Error())
	}
	go func() { errors <- relay.ServeAgents(agentListener) }()
	go func() { errors <- relay.ServeMobile(mobileListener) }()
}

func loadJSON(path string, target any) {
	info, err := os.Lstat(path)
	if err != nil {
		fatal(err.Error())
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		fatal("relay configuration must be a regular non-symlink file")
	}
	// Allow read-only access by the dedicated service group, but never group
	// writes or any access for unrelated users.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o037 != 0 {
		fatal("relay configuration permissions are too broad")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err.Error())
	}
	if err := json.Unmarshal(raw, target); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "chameleon-mobile-link-relay:", message)
	os.Exit(1)
}
