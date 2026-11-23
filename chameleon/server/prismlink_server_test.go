package main

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"chameleon/prismlink"
)

func TestPrismLinkRekeyKeepsTheOldSessionUntilTheNewOneIsProven(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	credential := prismlink.Credential{ClientID: [16]byte{1}, PSK: [32]byte{2}, Address: [4]byte{10, 77, 0, 3}}
	server := &prismLinkServer{
		conn: conn,
		credentials: &cryptoSessionManager{credentials: map[string]clientCredential{
			hex.EncodeToString(credential.ClientID[:]): {psk: credential.PSK[:], address: net.IP(credential.Address[:])},
		}},
		peers:     make(map[uint64]*prismLinkPeer),
		byIP:      make(map[[4]byte]*prismLinkPeer),
		handshake: make(map[[32]byte]prismLinkHelloResult),
		closed:    make(chan struct{}),
	}
	defer server.Close()
	go server.readLoop()

	client, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	buffer := make([]byte, prismlink.MaxDatagram)
	handshake := func() *prismlink.Session {
		t.Helper()
		pending, hello, err := prismlink.NewClientHandshake(credential, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(hello); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		session, err := pending.Complete(buffer[:n], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	ping := func(session *prismlink.Session) bool {
		t.Helper()
		packet, _ := session.Seal(prismlink.PacketPing, []byte("12345678"))
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		n, err := client.Read(buffer)
		if err != nil {
			return false
		}
		typ, _, err := session.Open(buffer[:n])
		return err == nil && typ == prismlink.PacketPong
	}
	downlinkSession := func() uint64 {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.byIP[credential.Address].session.ID()
	}

	first := handshake()
	if !ping(first) || downlinkSession() != first.ID() {
		t.Fatal("first session is not established")
	}
	second := handshake()
	if downlinkSession() != first.ID() {
		t.Fatal("downlink moved to a session the phone has not confirmed")
	}
	if !ping(second) || downlinkSession() != second.ID() {
		t.Fatal("confirmed session was not promoted")
	}
	// Packets still in flight on the replaced session remain valid briefly
	// and never move the downlink back.
	if !ping(first) || downlinkSession() != second.ID() {
		t.Fatal("replaced session broke during the grace period or demoted the new one")
	}
	server.mu.RLock()
	retiring := server.peers[first.ID()]
	server.mu.RUnlock()
	if retiring == nil || retiring.retireAt.IsZero() {
		t.Fatal("replaced session is not scheduled for removal")
	}
}
