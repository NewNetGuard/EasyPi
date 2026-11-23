package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func resetSecurityTestSessions() {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for _, session := range sessions {
		closeSession(session)
	}
	sessions = make(map[string]*clientSession)
}

func TestSessionQuotaAllowsAuthenticatedRoamingAfterOldPathStops(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 2)

	if getSession("client-a", "198.51.100.1") == nil || getSession("client-b", "198.51.100.1") == nil {
		t.Fatal("sessions inside per-source quota were rejected")
	}
	if getSession("client-c", "198.51.100.1") != nil {
		t.Fatal("one credential source occupied more than its session quota")
	}
	if getSession("client-c", "203.0.113.2") == nil {
		t.Fatal("one exhausted source starved an independent source")
	}
	clientA := getSession("client-a", "198.51.100.1")
	if clientA == nil {
		t.Fatal("existing session disappeared")
	}
	if getSession("client-a", "203.0.113.2") != nil {
		t.Fatal("a currently active client ID moved to another source")
	}
	clientA.lastSeen.Store(time.Now().Add(-sessionSourceHandoverDelay - time.Second).UnixNano())
	if got := getSession("client-a", "203.0.113.2"); got != clientA {
		t.Fatal("authenticated client could not resume after changing networks")
	}
	if clientA.source != "203.0.113.0/24" {
		t.Fatalf("session source was not migrated: %q", clientA.source)
	}
}

func TestSessionRoamingResetsOnlyNetworkBoundState(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 8)

	session := getSession("roaming-client", "198.51.100.10")
	if session == nil {
		t.Fatal("initial session was rejected")
	}
	setSessionClientIP(session, net.ParseIP("10.10.0.2"), 1234)
	session.downlinkPending = []pendingDownlinkFrame{{sequence: 1, payload: []byte("pending")}}
	session.downlinkBytes = len("pending")
	session.lastSeen.Store(time.Now().Add(-sessionSourceHandoverDelay - time.Second).UnixNano())

	if got := getSession("roaming-client", "203.0.113.20"); got != session {
		t.Fatal("roaming client did not retain its authenticated session")
	}
	if session.clientIP != nil || session.clientPort != 0 {
		t.Fatal("old client network path survived roaming")
	}
	if sessionForClientIP(net.ParseIP("10.10.0.2")) != nil {
		t.Fatal("old tunnel address mapping survived roaming")
	}
	if len(session.downlinkPending) != 1 || session.downlinkBytes != len("pending") {
		t.Fatal("unacknowledged downlink was discarded during roaming")
	}
}

func TestSessionRoamingHonorsDestinationSourceQuota(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 2)

	roaming := getSession("roaming", "198.51.100.1")
	if roaming == nil || getSession("destination-a", "203.0.113.1") == nil ||
		getSession("destination-b", "203.0.113.2") == nil {
		t.Fatal("test sessions were rejected before quota was filled")
	}
	roaming.lastSeen.Store(time.Now().Add(-sessionSourceHandoverDelay - time.Second).UnixNano())
	if getSession("roaming", "203.0.113.3") != nil {
		t.Fatal("roaming bypassed the destination source quota")
	}
}

func TestAuthenticatedHTTPClientResumesFromNewNetwork(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 8)
	psk := []byte("0123456789abcdef0123456789abcdef")
	manager, cryptoSession, _ := newTestCryptoPair(t, psk)
	clientID := cryptoSession.clientID
	handler := SessionAuthMiddleware(manager, func(w http.ResponseWriter, r *http.Request) {
		_, finish, ok := admitSessionRequest(w, r, ClientIDFromContext(r.Context()))
		if !ok {
			return
		}
		finish()
		w.WriteHeader(http.StatusNoContent)
	})

	call := func(source, nonce string) int {
		req := httptest.NewRequest(http.MethodGet, "https://chameleon.invalid/test", nil)
		req.RemoteAddr = net.JoinHostPort(source, "44321")
		req.Header.Set("Authorization", GenerateSessionAuthHeader(
			cryptoSession.authKey, cryptoSession.id, nonce, clientID, req.Method, requestPath(req),
		))
		response := httptest.NewRecorder()
		handler(response, req)
		return response.Code
	}

	if got := call("198.51.100.10", "00000000000000000000000000000001"); got != http.StatusNoContent {
		t.Fatalf("initial authenticated request returned %d", got)
	}
	if got := call("203.0.113.20", "00000000000000000000000000000002"); got != http.StatusServiceUnavailable {
		t.Fatalf("simultaneous source handover returned %d", got)
	}
	session := sessions[cryptoSession.runtimeID()]
	session.lastSeen.Store(time.Now().Add(-sessionSourceHandoverDelay - time.Second).UnixNano())
	if got := call("203.0.113.20", "00000000000000000000000000000003"); got != http.StatusNoContent {
		t.Fatalf("authenticated roaming request returned %d", got)
	}
	if session.source != "203.0.113.0/24" {
		t.Fatalf("authenticated request did not migrate the source: %q", session.source)
	}
}

func TestSessionQuotaGroupsRotatingIPv6Addresses(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 2)

	if getSession("client-a", "2001:db8:1234:1::1") == nil ||
		getSession("client-b", "2001:db8:1234:2::1") == nil {
		t.Fatal("sessions inside IPv6 prefix quota were rejected")
	}
	if getSession("client-c", "2001:db8:1234:ffff::99") != nil {
		t.Fatal("rotating IPv6 addresses bypassed the shared /48 quota")
	}
	if getSession("client-c", "2001:db8:5678::1") == nil {
		t.Fatal("independent IPv6 /48 was incorrectly starved")
	}
}

func TestSourceQuotaKeyNormalizesIPFamilies(t *testing.T) {
	tests := map[string]string{
		"198.51.100.42":        "198.51.100.0/24",
		"::ffff:198.51.100.42": "198.51.100.0/24",
		"2001:db8:abcd:1::1":   "2001:db8:abcd::/48",
		"127.0.0.1":            "127.0.0.0/24",
		"::1":                  "::1/128",
	}
	for input, want := range tests {
		if got := sourceQuotaKey(input); got != want {
			t.Fatalf("sourceQuotaKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPreAuthAdmissionHasGlobalAndPerIPBounds(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	dial := func() net.Conn {
		client, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		t.Cleanup(func() { _ = client.Close() })
		server, acceptErr := listener.Accept()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		t.Cleanup(func() { _ = server.Close() })
		return server
	}

	rl := &RealityListener{
		admission: make(chan struct{}, 2),
		perIP:     make(map[string]int),
		maxPerIP:  1,
	}
	first := dial()
	second := dial()
	ip, ok := rl.tryAdmit(first)
	if !ok {
		t.Fatal("first pre-auth connection was rejected")
	}
	if _, ok := rl.tryAdmit(second); ok {
		t.Fatal("per-IP pre-auth quota was not enforced")
	}
	rl.release(ip)
	if secondIP, ok := rl.tryAdmit(second); !ok {
		t.Fatal("quota was not released")
	} else {
		rl.release(secondIP)
	}
}
