package main

import (
	"crypto/hmac"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chameleon/shared"
)

func makeEstablishRequest(t *testing.T, manager *cryptoSessionManager) (sessionEstablishRequest, []byte) {
	return makeEstablishRequestForInstance(t, manager, strings.Repeat("11", 16))
}

func makeEstablishRequestForInstance(t *testing.T, manager *cryptoSessionManager, instance string) (sessionEstablishRequest, []byte) {
	t.Helper()
	challenge, err := manager.challenge(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := sessionEstablishRequest{
		Protocol:       shared.SessionProtocolID,
		ChallengeID:    challenge.ChallengeID,
		ClientID:       manager.clientID,
		ClientInstance: instance,
		ClientNonce:    strings.Repeat("22", 32),
	}
	mac := shared.ComputeBootstrapMAC(
		manager.psk,
		challenge.ChallengeID,
		challenge.Challenge,
		request.ClientID,
		request.ClientInstance,
		request.ClientNonce,
	)
	return request, mac
}

func TestNewInstanceRevokesPreviousInstanceOfTheSameDevice(t *testing.T) {
	manager := newCryptoSessionManager([]byte("0123456789abcdef0123456789abcdef"))
	firstRequest, firstMAC := makeEstablishRequestForInstance(t, manager, strings.Repeat("11", 16))
	_, first, err := manager.establish(firstRequest, firstMAC, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, secondMAC := makeEstablishRequestForInstance(t, manager, strings.Repeat("33", 16))
	_, second, err := manager.establish(secondRequest, secondMAC, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if manager.get(first.id, first.clientID) != nil || manager.get(second.id, second.clientID) != second {
		t.Fatal("same credential can evade device quotas with extra instances")
	}
	select {
	case <-first.ctx.Done():
	default:
		t.Fatal("previous process stream remains active")
	}
}

func TestBootstrapChallengeCanBeConsumedOnlyOnce(t *testing.T) {
	manager := newCryptoSessionManager([]byte("0123456789abcdef0123456789abcdef"))
	request, mac := makeEstablishRequest(t, manager)
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, _, err := manager.establish(request, mac, time.Now()); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("same bootstrap challenge established %d sessions", got)
	}
}

func TestBootstrapReplayFailsAfterServerRestart(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	first := newCryptoSessionManager(psk)
	request, mac := makeEstablishRequest(t, first)
	if _, _, err := first.establish(request, mac, time.Now()); err != nil {
		t.Fatalf("initial establishment failed: %v", err)
	}
	restarted := newCryptoSessionManager(psk)
	if _, _, err := restarted.establish(request, mac, time.Now()); err == nil {
		t.Fatal("bootstrap request was replayed after server restart")
	}
}

func TestSessionAuthenticatorFailsAfterServerRestart(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	manager, session, _ := newTestCryptoPair(t, psk)
	request := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	request.Header.Set("Authorization", GenerateSessionAuthHeader(
		session.authKey, session.id, strings.Repeat("33", 16), session.clientID,
		request.Method, requestPath(request),
	))

	accepted := false
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, _ *http.Request) {
		accepted = true
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusNoContent || !accepted {
		t.Fatalf("active session rejected: status=%d", response.Code)
	}

	restarted := newCryptoSessionManager(psk)
	replayed := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	replayed.Header.Set("Authorization", request.Header.Get("Authorization"))
	response = httptest.NewRecorder()
	SessionAuthMiddleware(restarted, func(http.ResponseWriter, *http.Request) {
		t.Fatal("restarted server accepted an old session")
	})(response, replayed)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old session after restart returned %d", response.Code)
	}
}

func TestReplayNonceSurvivesFullTimestampValidityWindow(t *testing.T) {
	store := newReplayNonceStore()
	const (
		firstSeen       = int64(1000)
		clientClockLead = int64(60)
	)
	nonce := strings.Repeat("66", 16)
	expiresAt := firstSeen + clientClockLead + authTimestampTolerance
	if !store.register(nonce, expiresAt, firstSeen) {
		t.Fatal("first nonce registration was rejected")
	}
	if store.register(nonce, expiresAt, firstSeen+121) {
		t.Fatal("nonce was accepted again while its signed timestamp was still valid")
	}
}

func TestSessionAuthenticatorIsBoundToRequestPath(t *testing.T) {
	manager, session, _ := newTestCryptoPair(t, []byte("0123456789abcdef0123456789abcdef"))
	header := GenerateSessionAuthHeader(
		session.authKey, session.id, strings.Repeat("44", 16), session.clientID,
		http.MethodGet, "/poll",
	)
	request := httptest.NewRequest(http.MethodGet, "https://example.test/stream", nil)
	request.Header.Set("Authorization", header)
	response := httptest.NewRecorder()
	SessionAuthMiddleware(manager, func(http.ResponseWriter, *http.Request) {
		t.Fatal("authenticator was reusable on another path")
	})(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("path-swapped request returned %d", response.Code)
	}
}

func TestOldPSKAuthenticatorHasNoFallback(t *testing.T) {
	manager, _, _ := newTestCryptoPair(t, []byte("0123456789abcdef0123456789abcdef"))
	request := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("00", 32)+":"+
		"1700000000:"+strings.Repeat("11", 16)+":"+manager.clientID)
	response := httptest.NewRecorder()
	SessionAuthMiddleware(manager, func(http.ResponseWriter, *http.Request) {
		t.Fatal("legacy PSK authenticator was accepted")
	})(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("legacy authenticator returned %d", response.Code)
	}
}

func TestServerProofMatchesNegotiatedSession(t *testing.T) {
	manager := newCryptoSessionManager([]byte("0123456789abcdef0123456789abcdef"))
	request, mac := makeEstablishRequest(t, manager)
	response, session, err := manager.establish(request, mac, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := hex.DecodeString(response.ServerProof)
	if err != nil {
		t.Fatal(err)
	}
	expected := shared.ComputeServerProof(
		session.authKey,
		response.SessionID,
		request.ClientNonce,
		response.ServerNonce,
		request.ClientID,
		request.ClientInstance,
	)
	if !hmac.Equal(proof, expected) {
		t.Fatal("server proof does not match negotiated session")
	}
}

func TestReplacingSessionCancelsActiveRequests(t *testing.T) {
	manager := newCryptoSessionManager([]byte("0123456789abcdef0123456789abcdef"))
	firstRequest, firstMAC := makeEstablishRequest(t, manager)
	_, firstSession, err := manager.establish(firstRequest, firstMAC, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	finished := make(chan struct{})
	handler := SessionAuthMiddleware(manager, func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(finished)
	})
	request := httptest.NewRequest(http.MethodGet, "https://example.test/stream", nil)
	request.Header.Set("Authorization", GenerateSessionAuthHeader(
		firstSession.authKey,
		firstSession.id,
		strings.Repeat("55", 16),
		firstSession.clientID,
		request.Method,
		requestPath(request),
	))
	go handler(httptest.NewRecorder(), request)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first session request did not start")
	}

	secondRequest, secondMAC := makeEstablishRequest(t, manager)
	if _, _, err := manager.establish(secondRequest, secondMAC, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("replaced session request was not canceled")
	}
}
