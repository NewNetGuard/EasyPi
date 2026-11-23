package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthRejectsCallerSelectedClientIdentity(t *testing.T) {
	manager, session, _ := newTestCryptoPair(t, []byte("test-installation-secret"))
	nextCalled := false
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "https://example.test/poll", nil)
	request.Header.Set("Authorization", GenerateSessionAuthHeader(
		session.authKey,
		session.id,
		"00112233445566778899aabbccddeeff",
		"attacker-chosen-id",
		request.Method,
		requestPath(request),
	))
	response := httptest.NewRecorder()
	handler(response, request)

	if response.Code != http.StatusUnauthorized || nextCalled {
		t.Fatalf("caller-selected identity was accepted: status=%d called=%v", response.Code, nextCalled)
	}
}

func TestAuthAcceptsActiveSessionIdentity(t *testing.T) {
	manager, session, _ := newTestCryptoPair(t, []byte("test-installation-secret"))
	nextCalled := false
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "https://example.test/poll", nil)
	request.Header.Set("Authorization", GenerateSessionAuthHeader(
		session.authKey,
		session.id,
		"ffeeddccbbaa99887766554433221100",
		session.clientID,
		request.Method,
		requestPath(request),
	))
	response := httptest.NewRecorder()
	handler(response, request)

	if response.Code != http.StatusNoContent || !nextCalled {
		t.Fatalf("active session identity was rejected: status=%d called=%v", response.Code, nextCalled)
	}
}
