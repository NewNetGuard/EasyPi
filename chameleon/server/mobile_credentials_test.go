package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chameleon/shared"
)

type revocationBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *revocationBody) Read([]byte) (int, error) { <-b.closed; return 0, io.EOF }
func (b *revocationBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

func TestSessionRevocationInterruptsAStreamingRequestBody(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	manager, session, _ := newTestCryptoPair(t, psk)
	body := &revocationBody{closed: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPost, "https://example.test/private", body)
	req.Header.Set("Authorization", GenerateSessionAuthHeader(session.authKey, session.id, strings.Repeat("aa", 16), session.clientID, req.Method, requestPath(req)))
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		SessionAuthMiddleware(manager, func(w http.ResponseWriter, r *http.Request) { close(started); _, _ = io.Copy(io.Discard, r.Body) })(httptest.NewRecorder(), req)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not enter handler")
	}
	session.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked stream body remains readable/blocking")
	}
}

func TestDeviceCredentialRevocationRejectsFreshAndExistingSessions(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	manager := newCryptoSessionManager(master)
	manager.credentialsFile = filepath.Join(t.TempDir(), "clients.json")
	const id = "00000000-0000-4000-8000-000000000001"
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(manager.credentialsFile, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf(`{"version":1,"devices":[{"id":%q,"address":"10.10.0.3"}]}`, id))
	if err := manager.refreshCredentials(); err != nil {
		t.Fatal(err)
	}
	devicePSK := shared.MobilePSK(master, id)
	establish := func(psk []byte) (*cryptoSession, error) {
		challenge, err := manager.challenge(time.Now())
		if err != nil {
			return nil, err
		}
		instance := make([]byte, 16)
		nonce := make([]byte, 32)
		rand.Read(instance)
		rand.Read(nonce)
		req := sessionEstablishRequest{Protocol: shared.SessionProtocolID, ChallengeID: challenge.ChallengeID, ClientID: shared.ClientIDForPSK(psk), ClientInstance: hex.EncodeToString(instance), ClientNonce: hex.EncodeToString(nonce)}
		mac := shared.ComputeBootstrapMAC(psk, req.ChallengeID, challenge.Challenge, req.ClientID, req.ClientInstance, req.ClientNonce)
		_, session, err := manager.establish(req, mac, time.Now())
		return session, err
	}
	session, err := establish(devicePSK)
	if err != nil || !session.allowedIP.Equal(net.ParseIP("10.10.0.3")) {
		t.Fatalf("device enrollment failed: %v", err)
	}
	write(`{"version":1,"devices":[]}`)
	if manager.get(session.id, session.clientID) != nil {
		t.Fatal("revoked session remains accepted")
	}
	select {
	case <-session.ctx.Done():
	default:
		t.Fatal("active stream not canceled on revocation")
	}
	if _, err := establish(devicePSK); err == nil {
		t.Fatal("revoked credential started a new session")
	}
	if _, err := establish(master); err != nil {
		t.Fatalf("mobile revocation interrupted home identity: %v", err)
	}
	write("invalid registry")
	if manager.knownClient(shared.ClientIDForPSK(devicePSK)) {
		t.Fatal("corrupt registry authorized mobile")
	}
}

func TestTunnelAddressCannotBeClaimedByAnotherPrincipal(t *testing.T) {
	ipToSessMu.Lock()
	ipToSess = make(map[string]*clientSession)
	ipToSessMu.Unlock()
	t.Cleanup(func() { ipToSessMu.Lock(); ipToSess = make(map[string]*clientSession); ipToSessMu.Unlock() })
	first := &clientSession{credentialID: "device-a", allowedIP: net.ParseIP("10.10.0.3")}
	second := &clientSession{credentialID: "device-b", allowedIP: net.ParseIP("10.10.0.4")}
	if !setSessionClientIP(first, first.allowedIP, 0) {
		t.Fatal("first owner rejected")
	}
	if setSessionClientIP(second, first.allowedIP, 0) {
		t.Fatal("foreign address overwritten")
	}
	if sessionForClientIP(first.allowedIP) != first {
		t.Fatal("original downlink owner changed")
	}
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 20
	copy(packet[12:16], first.allowedIP.To4())
	copy(packet[16:20], []byte{192, 0, 2, 1})
	if err := forwardClientPacketToVPN(second, packet); err == nil {
		t.Fatal("spoofed packet accepted before TUN")
	}
}

func TestCredentialRegistryUsesConfiguredTunnelNetwork(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	manager := newCryptoSessionManager(master)
	if err := manager.setCredentialNetwork("10.77.0.1/24"); err != nil {
		t.Fatal(err)
	}
	manager.credentialsFile = filepath.Join(t.TempDir(), "clients.json")
	const id = "00000000-0000-4000-8000-000000000001"
	if err := os.WriteFile(
		manager.credentialsFile,
		[]byte(fmt.Sprintf(`{"version":1,"devices":[{"id":%q,"address":"10.77.0.3"}]}`, id)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := manager.refreshCredentials(); err != nil {
		t.Fatalf("configured home tunnel address rejected: %v", err)
	}
	credential := manager.credentials[shared.ClientIDForPSK(shared.MobilePSK(master, id))]
	if !credential.address.Equal(net.ParseIP("10.77.0.3")) {
		t.Fatalf("unexpected credential address: %v", credential.address)
	}

	if err := os.WriteFile(
		manager.credentialsFile,
		[]byte(fmt.Sprintf(`{"version":1,"devices":[{"id":%q,"address":"10.10.0.3"}]}`, id)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := manager.refreshCredentials(); err == nil {
		t.Fatal("address outside the configured tunnel network was accepted")
	}
}
