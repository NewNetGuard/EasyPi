package main

import (
	"encoding/hex"
	"testing"

	"chameleon/mobilelink"
)

func TestConfiguredRelaySeparatesAPIAndTunnelIdentities(t *testing.T) {
	apiSecret := make([]byte, 32)
	tunnelSecret := make([]byte, 32)
	for index := range apiSecret {
		apiSecret[index] = 0x11
		tunnelSecret[index] = 0x22
	}
	apiID := mobilelink.InstallationID(apiSecret)
	tunnelID := mobilelink.InstallationID(tunnelSecret)
	if _, err := configuredRelay(
		"example.test",
		map[string]string{apiID: hex.EncodeToString(apiSecret)},
		map[string]string{"api.example.test": apiID},
	); err != nil {
		t.Fatalf("API relay configuration rejected: %v", err)
	}
	if _, err := configuredRelay(
		"example.test",
		map[string]string{tunnelID: hex.EncodeToString(tunnelSecret)},
		map[string]string{"tunnel.example.test": tunnelID},
	); err != nil {
		t.Fatalf("tunnel relay configuration rejected: %v", err)
	}
	if _, err := configuredRelay(
		"example.test",
		map[string]string{apiID: hex.EncodeToString(tunnelSecret)},
		nil,
	); err == nil {
		t.Fatal("mismatched relay identity and secret were accepted")
	}
}
