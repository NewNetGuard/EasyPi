package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"time"

	"chameleon/prismlink"
	"chameleon/shared"
)

type clientCredential struct {
	psk     []byte
	address net.IP
}

func (m *cryptoSessionManager) prismLinkCredential(clientID [16]byte) (prismlink.Credential, bool) {
	m.mu.Lock()
	credential, ok := m.credentials[hex.EncodeToString(clientID[:])]
	m.mu.Unlock()
	if !ok || len(credential.psk) != 32 || credential.address.To4() == nil {
		return prismlink.Credential{}, false
	}
	result := prismlink.Credential{ClientID: clientID}
	copy(result.PSK[:], credential.psk)
	copy(result.Address[:], credential.address.To4())
	return result, true
}

var mobileDeviceID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// The root-owned registry contains identities/addresses, never the master key.
// A missing, malformed or unreadable registry fails closed for mobile clients.
func (m *cryptoSessionManager) refreshCredentials() error {
	m.credentialMu.Lock()
	defer m.credentialMu.Unlock()
	if m.credentialsFile == "" {
		return nil
	}
	f, err := os.Open(m.credentialsFile)
	var data []byte
	if err == nil {
		data, err = io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
		if len(data) > 65536 {
			err = fmt.Errorf("mobile registry too large")
		}
	}
	digest := sha256.Sum256(data)
	m.mu.Lock()
	if err == nil && m.credentials != nil && digest == m.credentialDigest {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	legacyAddress := append(net.IP(nil), m.legacyAddress...)
	if legacyAddress == nil {
		legacyAddress = net.ParseIP("10.10.0.2").To4()
	}
	next := map[string]clientCredential{m.clientID: {psk: m.psk, address: legacyAddress}}
	if err == nil {
		var registry struct {
			Version int `json:"version"`
			Devices []struct {
				ID      string `json:"id"`
				Address string `json:"address"`
			} `json:"devices"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&registry)
		if err == nil && (registry.Version != 1 || len(registry.Devices) > 200) {
			err = fmt.Errorf("invalid mobile registry")
		}
		addresses := map[string]bool{}
		if err == nil {
			for _, d := range registry.Devices {
				ip := net.ParseIP(d.Address).To4()
				if !mobileDeviceID.MatchString(d.ID) || ip == nil || m.credentialNet == nil || !m.credentialNet.Contains(ip) || ip.Equal(m.credentialNet.IP) || ip.Equal(m.legacyAddress) || ip[3] == 255 || addresses[ip.String()] {
					err = fmt.Errorf("invalid mobile identity/address")
					break
				}
				psk := shared.MobilePSK(m.psk, d.ID)
				id := shared.ClientIDForPSK(psk)
				if _, exists := next[id]; exists {
					err = fmt.Errorf("duplicate mobile identity")
					break
				}
				addresses[ip.String()] = true
				next[id] = clientCredential{psk: psk, address: ip}
			}
		}
	}
	if err != nil {
		next = map[string]clientCredential{m.clientID: {psk: m.psk, address: legacyAddress}}
	}
	var revoked []string
	m.mu.Lock()
	m.credentials = next
	if err == nil {
		m.credentialDigest = digest
	} else {
		m.credentialDigest = [32]byte{}
	}
	for id, s := range m.sessions {
		credential, exists := next[s.clientID]
		if !exists || !credential.address.Equal(s.allowedIP) {
			s.cancel()
			delete(m.sessions, id)
			delete(m.activeByClient, s.runtimeID())
			revoked = append(revoked, s.runtimeID())
		}
	}
	m.mu.Unlock()
	for _, runtime := range revoked {
		revokeClientRuntime(runtime)
	}
	return err
}

func (m *cryptoSessionManager) knownClient(id string) bool {
	_ = m.refreshCredentials()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.credentialsFile == "" {
		return id == m.clientID
	}
	_, ok := m.credentials[id]
	return ok
}

func (m *cryptoSessionManager) watchCredentials(stop <-chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			_ = m.refreshCredentials()
		}
	}
}
