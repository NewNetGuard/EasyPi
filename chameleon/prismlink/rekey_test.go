package prismlink

import (
	"testing"
	"time"
)

func TestSessionPairAcceptsThePreviousSessionOnlyDuringGrace(t *testing.T) {
	credential := Credential{ClientID: [16]byte{1}, PSK: [32]byte{2}, Address: [4]byte{10, 77, 0, 3}}
	lookup := func([16]byte) (Credential, bool) { return credential, true }
	now := time.Unix(1_800_000_000, 0)
	establish := func() (client, server *Session) {
		pending, hello, err := NewClientHandshake(credential, now)
		if err != nil {
			t.Fatal(err)
		}
		server, response, err := AcceptClientHello(hello, lookup, now)
		if err != nil {
			t.Fatal(err)
		}
		if !IsServerHello(response) || IsServerHello(hello) {
			t.Fatal("server hello classification failed")
		}
		client, err = pending.Complete(response, now)
		if err != nil {
			t.Fatal(err)
		}
		return client, server
	}
	oldClient, oldServer := establish()
	newClient, newServer := establish()
	pair := NewSessionPair(oldClient)
	pair.Promote(newClient, now, 10*time.Second)
	if pair.Current() != newClient {
		t.Fatal("promoted session is not current")
	}
	late, _ := oldServer.Seal(PacketData, []byte{0x45})
	if _, _, err := pair.Open(late, now.Add(5*time.Second)); err != nil {
		t.Fatalf("in-flight packet of the previous session rejected: %v", err)
	}
	fresh, _ := newServer.Seal(PacketData, []byte{0x45})
	if _, _, err := pair.Open(fresh, now.Add(5*time.Second)); err != nil {
		t.Fatalf("current session packet rejected: %v", err)
	}
	expired, _ := oldServer.Seal(PacketData, []byte{0x45})
	if _, _, err := pair.Open(expired, now.Add(11*time.Second)); err == nil {
		t.Fatal("previous session accepted after the grace period")
	}
}
