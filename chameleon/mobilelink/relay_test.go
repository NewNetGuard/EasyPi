package mobilelink

import (
	"bytes"
	"testing"
	"time"
)

func TestRelayAcceptsOnlyExactInstallationHostname(t *testing.T) {
	secret := bytes.Repeat([]byte{0x61}, 32)
	id := InstallationID(secret)
	relay, err := NewRelay("mobile.example.com", func(candidate string) ([]byte, bool) {
		return secret, candidate == id
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := relay.installationFromServerName(id + ".mobile.example.com")
	if err != nil || got != id {
		t.Fatalf("valid installation hostname was rejected: %v", err)
	}
	for _, invalid := range []string{
		id + ".attacker.mobile.example.com",
		id + ".mobile.example.com.attacker.test",
		"ffffffffffffffffffffffffffffffff.mobile.example.com",
	} {
		if _, err := relay.installationFromServerName(invalid); err == nil {
			t.Fatalf("invalid installation hostname %q was accepted", invalid)
		}
	}
}

func TestReplayCacheRejectsDuplicateNonce(t *testing.T) {
	var cache replayCache
	now := time.Unix(1_800_000_000, 0)
	if !cache.accept("installation", "nonce", now) {
		t.Fatal("first nonce was rejected")
	}
	if cache.accept("installation", "nonce", now.Add(time.Second)) {
		t.Fatal("replayed nonce was accepted")
	}
	if !cache.accept("installation", "nonce", now.Add(2*AuthWindow+time.Second)) {
		t.Fatal("expired nonce entry was not released")
	}
}

func TestRelaySupportsExactDuckDNSHostname(t *testing.T) {
	secret := bytes.Repeat([]byte{0x37}, 32)
	id := InstallationID(secret)
	relay, err := NewRelay("myrelay.duckdns.org", func(candidate string) ([]byte, bool) {
		return secret, candidate == id
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.AddStaticHostname("myrelay.duckdns.org", id); err != nil {
		t.Fatal(err)
	}
	got, err := relay.installationFromServerName("myrelay.duckdns.org")
	if err != nil || got != id {
		t.Fatalf("DuckDNS hostname was not routed to the installation: %v", err)
	}
	if _, err := relay.installationFromServerName("attacker.myrelay.duckdns.org"); err == nil {
		t.Fatal("unregistered DuckDNS subdomain was accepted")
	}
}
