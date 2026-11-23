package prismlink

import (
	"bytes"
	"testing"
	"time"
)

func testCredential() Credential {
	return Credential{
		ClientID: [16]byte{1, 2, 3, 4},
		PSK:      [32]byte{5, 6, 7, 8},
		Address:  [4]byte{10, 77, 0, 3},
	}
}

func establishTestSession(t *testing.T) (*Session, *Session) {
	t.Helper()
	credential := testCredential()
	now := time.Unix(1_800_000_000, 0)
	handshake, hello, err := NewClientHandshake(credential, now)
	if err != nil {
		t.Fatal(err)
	}
	server, response, err := AcceptClientHello(hello, func(id [16]byte) (Credential, bool) {
		return credential, id == credential.ClientID
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	client, err := handshake.Complete(response, now)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestHandshakeAndBidirectionalPackets(t *testing.T) {
	client, server := establishTestSession(t)
	payload := []byte{0x45, 0, 0, 20}
	packet, err := client.Seal(PacketData, payload)
	if err != nil {
		t.Fatal(err)
	}
	typ, opened, err := server.Open(packet)
	if err != nil || typ != PacketData || !bytes.Equal(payload, opened) {
		t.Fatalf("server open failed: type=%d payload=%x error=%v", typ, opened, err)
	}
	reply, err := server.Seal(PacketPong, []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	typ, opened, err = client.Open(reply)
	if err != nil || typ != PacketPong || string(opened) != "ok" {
		t.Fatalf("client open failed: type=%d payload=%q error=%v", typ, opened, err)
	}
}

func TestReplayAndTamperingAreRejected(t *testing.T) {
	client, server := establishTestSession(t)
	packet, err := client.Seal(PacketData, []byte{0x45})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.Open(packet); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.Open(packet); err == nil {
		t.Fatal("replayed packet was accepted")
	}
	tampered, _ := client.Seal(PacketData, []byte{0x45})
	tampered[len(tampered)-1] ^= 1
	if _, _, err := server.Open(tampered); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}

func TestWrongCredentialCannotCompleteHandshake(t *testing.T) {
	credential := testCredential()
	now := time.Unix(1_800_000_000, 0)
	_, hello, err := NewClientHandshake(credential, now)
	if err != nil {
		t.Fatal(err)
	}
	credential.PSK[0] ^= 1
	if _, _, err := AcceptClientHello(hello, func([16]byte) (Credential, bool) {
		return credential, true
	}, now); err == nil {
		t.Fatal("client hello with another credential was accepted")
	}
}

func TestReplayWindowAllowsWideUDPReordering(t *testing.T) {
	client, server := establishTestSession(t)
	packets := make([][]byte, 400)
	for index := range packets {
		packet, err := client.Seal(PacketData, []byte{0x45, byte(index)})
		if err != nil {
			t.Fatal(err)
		}
		packets[index] = packet
	}
	for index := len(packets) - 1; index >= 0; index-- {
		if _, _, err := server.Open(packets[index]); err != nil {
			t.Fatalf("reordered packet %d rejected: %v", index, err)
		}
	}
}
