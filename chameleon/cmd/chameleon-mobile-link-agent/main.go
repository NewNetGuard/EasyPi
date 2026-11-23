package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"chameleon/mobilelink"
)

type config struct {
	RelayAddress      string `json:"relay_address"`
	ServerName        string `json:"server_name"`
	LocalAddress      string `json:"local_address"`
	SecretFile        string `json:"secret_file"`
	PrismRelayAddress string `json:"prism_relay_address,omitempty"`
	PrismLocalAddress string `json:"prism_local_address,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "path to the Mobile Link agent JSON configuration")
	flag.Parse()
	if *configPath == "" {
		fatal("-config is required")
	}
	var cfg config
	loadJSON(*configPath, &cfg)
	secret := loadSecret(cfg.SecretFile)
	if cfg.RelayAddress == "" || cfg.ServerName == "" || cfg.LocalAddress == "" {
		fatal("relay_address, server_name and local_address are required")
	}
	agent := &mobilelink.Agent{
		RelayAddress:   cfg.RelayAddress,
		LocalAddress:   cfg.LocalAddress,
		InstallationID: mobilelink.InstallationID(secret),
		Secret:         secret,
		TLSConfig:      &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errors := make(chan error, 2)
	go func() { errors <- agent.Run(ctx) }()
	if cfg.PrismRelayAddress != "" || cfg.PrismLocalAddress != "" {
		if cfg.PrismRelayAddress == "" || cfg.PrismLocalAddress == "" {
			fatal("PrismLink requires relay and local UDP addresses")
		}
		installationID, err := mobilelink.PrismInstallationID(mobilelink.InstallationID(secret))
		if err != nil {
			fatal(err.Error())
		}
		var prismSecret [32]byte
		copy(prismSecret[:], secret)
		prismAgent := &mobilelink.PrismAgent{
			RelayAddress: cfg.PrismRelayAddress, LocalAddress: cfg.PrismLocalAddress,
			InstallationID: installationID, Secret: prismSecret,
		}
		go func() { errors <- prismAgent.Run(ctx) }()
	}
	if err := <-errors; err != nil && ctx.Err() == nil {
		fatal(err.Error())
	}
}

func loadSecret(path string) []byte {
	info, err := os.Lstat(path)
	if err != nil {
		fatal("read secret metadata: " + err.Error())
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		fatal("secret file must be a regular non-symlink file")
	}
	// A root-owned 0440 file shared with the dedicated service group prevents
	// the unprivileged agent from rewriting its own transport identity.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o037 != 0 {
		fatal("secret file permissions are too broad")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("read secret: " + err.Error())
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(secret) != 32 {
		fatal("secret file must contain exactly 64 hexadecimal characters")
	}
	return secret
}

func loadJSON(path string, target any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err.Error())
	}
	if err := json.Unmarshal(raw, target); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "chameleon-mobile-link-agent:", message)
	os.Exit(1)
}
