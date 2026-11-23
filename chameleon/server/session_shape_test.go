package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"chameleon/shared"
)

// The session setup answers every carrier connection opens with: each one
// still works with a cache-busting query, carries padding of varying length
// and is delayed by at most sessionThinkTimeMax.
func TestSessionSetupAnswersVaryInSizeAndTiming(t *testing.T) {
	previous := sessionThinkTimeMax
	sessionThinkTimeMax = 30 * time.Millisecond
	t.Cleanup(func() { sessionThinkTimeMax = previous })

	psk := []byte("0123456789abcdef0123456789abcdef")
	manager := newCryptoSessionManager(psk)
	handler := handleSessionSync(manager, false)
	const route = "https://carrier.example/abcdef/sync"

	bodySizes := map[int]bool{}
	var slowest, fastest time.Duration = 0, time.Hour
	for i := 0; i < 60; i++ {
		started := time.Now()
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, route+"?_=x"+strings.Repeat("y", i%7), nil))
		elapsed := time.Since(started)
		slowest, fastest = max(slowest, elapsed), min(fastest, elapsed)
		var challenge sessionChallengeResponse
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &challenge) != nil || challenge.ChallengeID == "" {
			t.Fatalf("challenge failed: %d %s", response.Code, response.Body.String())
		}
		bodySizes[response.Body.Len()] = true
	}
	if len(bodySizes) < 30 {
		t.Fatalf("challenge bodies took only %d sizes in 60 answers", len(bodySizes))
	}
	if fastest < sessionThinkTimeMin || slowest > sessionThinkTimeMax+20*time.Millisecond ||
		slowest-fastest < 5*time.Millisecond {
		t.Fatalf("think time out of range: fastest %v, slowest %v", fastest, slowest)
	}

	// Establishment and the authenticated heartbeat, both with a query.
	request, mac := makeEstablishRequest(t, manager)
	body, _ := json.Marshal(request)
	establish := httptest.NewRequest(http.MethodPost, route+"?_=0a1b2c", strings.NewReader(string(body)))
	establish.Header.Set("Authorization", "Bootstrap "+hex.EncodeToString(mac))
	response := httptest.NewRecorder()
	handler(response, establish)
	var established sessionEstablishResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &established) != nil ||
		established.InnerAEAD != shared.InnerProtocolID {
		t.Fatalf("establishment failed: %d %s", response.Code, response.Body.String())
	}

	session := manager.get(established.SessionID, request.ClientID)
	if session == nil {
		t.Fatal("established session not found")
	}
	heartbeat := httptest.NewRequest(http.MethodGet, route+"?_=q9", nil)
	heartbeat.Header.Set("Authorization", GenerateSessionAuthHeader(
		session.authKey, session.id, strings.Repeat("44", 16), session.clientID,
		heartbeat.Method, requestPath(heartbeat),
	))
	response = httptest.NewRecorder()
	handler(response, heartbeat)
	var status struct {
		InnerAEAD string `json:"inner_aead"`
		Padding   string `json:"pad"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil ||
		status.InnerAEAD != shared.InnerProtocolID {
		t.Fatalf("heartbeat failed: %d %s", response.Code, response.Body.String())
	}
	if len(status.Padding) > sessionPaddingMax {
		t.Fatalf("padding longer than %d", sessionPaddingMax)
	}
}
