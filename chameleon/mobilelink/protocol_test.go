package mobilelink

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestSignedControlMessageRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	message := Message{Type: "register", InstallationID: InstallationID(secret)}
	now := time.Unix(1_800_000_000, 0)
	if err := Sign(secret, &message, now); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := WriteMessage(&wire, message); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(secret, decoded, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	decoded.ConnectionID = "00000000000000000000000000000000"
	if err := Verify(secret, decoded, now); err == nil {
		t.Fatal("modified authenticated message was accepted")
	}
}

func TestAuthenticationTimestampExpires(t *testing.T) {
	secret := bytes.Repeat([]byte{0x21}, 32)
	message := Message{Type: "ping", InstallationID: InstallationID(secret)}
	now := time.Unix(1_800_000_000, 0)
	if err := Sign(secret, &message, now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(secret, message, now.Add(AuthWindow+time.Second)); err == nil {
		t.Fatal("expired mobile link authenticator was accepted")
	}
}

func TestReadClientHelloPreservesTLSAndExtractsSNI(t *testing.T) {
	clientSide, relaySide := net.Pipe()
	defer clientSide.Close()
	defer relaySide.Close()
	client := tls.Client(clientSide, &tls.Config{ServerName: "0123456789abcdef0123456789abcdef.mobile.example", MinVersion: tls.VersionTLS13})
	done := make(chan struct{})
	go func() {
		_ = client.Handshake()
		close(done)
	}()
	name, preface, err := ReadClientHelloSNI(relaySide, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if name != "0123456789abcdef0123456789abcdef.mobile.example" {
		t.Fatalf("unexpected SNI %q", name)
	}
	if len(preface) < 6 || preface[0] != 22 {
		t.Fatal("TLS ClientHello bytes were not preserved")
	}
}

func TestAgentLocalTargetMustBeLoopback(t *testing.T) {
	for _, allowed := range []string{"127.0.0.1:9445", "[::1]:9445"} {
		if !isLoopbackTarget(allowed) {
			t.Fatalf("loopback target %q was rejected", allowed)
		}
	}
	for _, denied := range []string{"0.0.0.0:443", "192.168.1.10:443", "localhost:443", "bad"} {
		if isLoopbackTarget(denied) {
			t.Fatalf("non-literal or non-loopback target %q was accepted", denied)
		}
	}
}
