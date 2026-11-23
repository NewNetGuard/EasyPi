package main

import (
	"fmt"
	"testing"
	"time"
)

func sessionExists(key string) bool {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	return sessions[key] != nil
}

// Behind nginx (and the Mobile Link relay) every client reaches the backend
// from loopback. Restarting one client many times within the idle timeout must
// still leave one session: each new instance frees the idle sessions of the
// same credential's earlier instances.
func TestClientRestartsDoNotExhaustTheSharedSourceQuota(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 2) // stricter than production's 8

	for i := 0; i < 12; i++ {
		key := "pi-credential:" + string(rune('a'+i))
		if getSession(key, "127.0.0.1") == nil {
			t.Fatalf("restart %d of one client was refused by the shared quota", i+1)
		}
	}
	sessionsMu.Lock()
	remaining := len(sessions)
	sessionsMu.Unlock()
	if remaining != 1 {
		t.Fatalf("%d sessions left after 12 restarts of one client, want 1", remaining)
	}
}

// The deployed configuration (max_sessions_per_source 8) refused the ninth
// device behind nginx, because the loopback frontend counted as one subscriber
// network. Distinct devices behind the local frontend are bounded only by the
// server-wide session limit.
func TestDevicesBehindLocalFrontendAreNotOneSourceQuota(t *testing.T) {
	for _, frontend := range []string{"127.0.0.1", "::1"} {
		resetSecurityTestSessions()
		configureSessionLimits(100, 8, 8) // deployed values
		for i := 0; i < 50; i++ {
			if getSession(fmt.Sprintf("device-%d:instance", i), frontend) == nil {
				t.Fatalf("device %d behind %s refused", i+1, frontend)
			}
		}

		resetSecurityTestSessions()
		configureSessionLimits(10, 8, 8)
		for i := 0; i < 10; i++ {
			if getSession(fmt.Sprintf("device-%d:instance", i), frontend) == nil {
				t.Fatalf("device %d behind %s refused below the server-wide limit", i+1, frontend)
			}
		}
		if getSession("device-10:instance", frontend) != nil {
			t.Fatalf("server-wide session limit not enforced behind %s", frontend)
		}
	}
	resetSecurityTestSessions()
}

// A real subscriber network keeps its quota in the same configuration.
func TestSubscriberNetworkKeepsSourceQuota(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 8)
	for i := 0; i < 8; i++ {
		if getSession(fmt.Sprintf("device-%d:instance", i), "198.51.100.7") == nil {
			t.Fatalf("device %d inside the source quota refused", i+1)
		}
	}
	if getSession("device-8:instance", "198.51.100.8") != nil {
		t.Fatal("a ninth session from one subscriber /24 was admitted")
	}
	for _, key := range []string{"127.0.0.0/24", "::1/48"} {
		if perSourceQuotaApplies(key) {
			t.Fatalf("loopback key %s treated as a subscriber network", key)
		}
	}
	for _, key := range []string{"198.51.100.0/24", "2001:db8::/48", "10.0.0.0/24", ""} {
		if !perSourceQuotaApplies(key) {
			t.Fatalf("key %q exempted from the source quota", key)
		}
	}
}

func TestNewInstanceKeepsBusyAndForeignSessions(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 8) // production per-source limit

	busy := getSession("pi:old-busy", "127.0.0.1")
	busy.activeHTTP.Store(1) // a request of the old instance is still in flight
	getSession("phone:one", "127.0.0.1")
	getSession("pi:old-idle", "127.0.0.1")

	if getSession("pi:new", "127.0.0.1") == nil {
		t.Fatal("new instance refused")
	}
	if !sessionExists("pi:old-busy") {
		t.Fatal("a session with a request in flight was retired")
	}
	if !sessionExists("phone:one") {
		t.Fatal("another credential's session was retired")
	}
	if sessionExists("pi:old-idle") {
		t.Fatal("an idle session of an earlier instance was kept")
	}
}

// An earlier instance that was busy when its successor arrived is retired by
// the periodic cleanup once it has been idle for the grace period, well before
// the 10-minute timeout; the newest instance is kept.
func TestCleanupRetiresEarlierInstancesAfterTheGracePeriod(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 2)

	now := time.Now()
	old := getSession("pi:old", "127.0.0.1")
	old.activeHTTP.Store(1)
	newest := getSession("pi:new", "127.0.0.1")
	old.activeHTTP.Store(0)
	old.lastSeen.Store(now.Add(-time.Minute).UnixNano())
	newest.lastSeen.Store(now.Add(-time.Minute).UnixNano() + 1)

	cleanupSessionsAt(now)
	if sessionExists("pi:old") {
		t.Fatal("idle earlier instance survived the cleanup")
	}
	if !sessionExists("pi:new") {
		t.Fatal("the newest instance was retired")
	}

	recent := getSession("pi:recent-old", "127.0.0.1")
	_ = recent
	newer := getSession("pi:recent-new", "127.0.0.1")
	newer.lastSeen.Store(time.Now().Add(time.Second).UnixNano())
	sessionsMu.Lock()
	if s := sessions["pi:recent-old"]; s != nil {
		s.activeHTTP.Store(0)
	}
	sessionsMu.Unlock()
	cleanupSessionsAt(time.Now())
	// pi:recent-old was already retired on creation of pi:recent-new (idle at
	// that moment); the grace period only applies to sessions busy at that time.
	if sessionExists("pi:recent-old") {
		t.Fatal("idle earlier instance was not retired when its successor arrived")
	}
}

// Keys without an instance part (legacy and test identities) are never
// treated as instances of one credential.
func TestKeysWithoutInstanceAreNotRetired(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	configureSessionLimits(100, 8, 2)

	getSession("client-a", "198.51.100.1")
	getSession("client-b", "198.51.100.1")
	if !sessionExists("client-a") || !sessionExists("client-b") {
		t.Fatal("sessions without an instance part were retired")
	}
}
