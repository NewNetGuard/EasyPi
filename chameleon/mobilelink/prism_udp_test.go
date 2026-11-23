package mobilelink

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"chameleon/prismlink"
)

func TestPrismRelayForwardsOnlyRegisteredInstallation(t *testing.T) {
	secretBytes := make([]byte, 32)
	secretBytes[0] = 7
	encodedID := InstallationID(secretBytes)
	id, err := PrismInstallationID(encodedID)
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	copy(secret[:], secretBytes)
	relay, err := NewPrismRelay(func(candidate [16]byte) ([32]byte, bool) {
		return secret, candidate == id
	})
	if err != nil {
		t.Fatal(err)
	}
	agentListener := testUDPListener(t)
	mobileListener := testUDPListener(t)
	defer agentListener.Close()
	defer mobileListener.Close()
	go func() { _ = relay.Serve(agentListener, mobileListener) }()

	agent := testUDPListener(t)
	mobile := testUDPListener(t)
	defer agent.Close()
	defer mobile.Close()
	registration, err := prismlink.EncodeRelayRegistration(id, secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.WriteToUDP(registration, agentListener.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	credential := prismlink.Credential{ClientID: [16]byte{1}, PSK: [32]byte{2}, Address: [4]byte{10, 77, 0, 3}}
	_, hello, err := prismlink.NewClientHandshake(credential, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	route := [8]byte{9}
	uplink, err := prismlink.EncodeRelayData(prismlink.RelayMobileData, id, route, hello)
	if err != nil {
		t.Fatal(err)
	}
	relayMobile := mobileListener.LocalAddr().(*net.UDPAddr)
	buffer := make([]byte, prismlink.RelayHeaderSize+prismlink.MaxDatagram)
	// Without an authenticated binding the relay forwards nothing.
	if _, err := mobile.WriteToUDP(uplink, relayMobile); err != nil {
		t.Fatal(err)
	}
	_ = agent.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := agent.ReadFromUDP(buffer); err == nil {
		t.Fatal("relay forwarded data for an unbound route")
	}
	bind, err := prismlink.EncodeRelayMobileBind(id, route, credential.ClientID, prismlink.MobileRouteKey(secret, credential.ClientID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mobile.WriteToUDP(bind, relayMobile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := mobile.WriteToUDP(uplink, relayMobile); err != nil {
		t.Fatal(err)
	}
	_ = agent.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := agent.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := prismlink.ParseRelayDatagram(buffer[:n])
	if err != nil || forwarded.Type != prismlink.RelayToAgent || forwarded.Route != route {
		t.Fatalf("invalid agent forwarding: %+v %v", forwarded, err)
	}

	downlink, err := prismlink.EncodeRelayData(prismlink.RelayFromAgent, id, route, hello)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.WriteToUDP(downlink, agentListener.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = mobile.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = mobile.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(hello) {
		t.Fatal("relay changed the opaque PrismLink payload")
	}

	// An observer that knows the clear route identifiers cannot redirect the
	// phone's traffic: neither with data nor by replaying the binding.
	attacker := testUDPListener(t)
	defer attacker.Close()
	for _, packet := range [][]byte{uplink, bind} {
		if _, err := attacker.WriteToUDP(packet, relayMobile); err != nil {
			t.Fatal(err)
		}
	}
	otherPhone := [16]byte{3}
	stolen, _ := prismlink.EncodeRelayMobileBind(id, route, otherPhone, prismlink.MobileRouteKey(secret, otherPhone), time.Now())
	if _, err := attacker.WriteToUDP(stolen, relayMobile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := agent.WriteToUDP(downlink, agentListener.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = attacker.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := attacker.ReadFromUDP(buffer); err == nil {
		t.Fatal("relay delivered a phone's traffic to another address")
	}
	_ = mobile.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := mobile.ReadFromUDP(buffer); err != nil {
		t.Fatal("phone lost its route after a hijack attempt")
	}

	// A fresh binding from the phone's new NAT address moves the route.
	moved := testUDPListener(t)
	defer moved.Close()
	rebind, _ := prismlink.EncodeRelayMobileBind(id, route, credential.ClientID, prismlink.MobileRouteKey(secret, credential.ClientID), time.Now())
	if _, err := moved.WriteToUDP(rebind, relayMobile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := agent.WriteToUDP(downlink, agentListener.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = moved.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := moved.ReadFromUDP(buffer); err != nil {
		t.Fatal("authenticated rebinding was not applied")
	}
}

func TestPrismAgentFollowsChangedRelayAddress(t *testing.T) {
	first := testUDPListener(t)
	second := testUDPListener(t)
	local := testUDPListener(t)
	defer first.Close()
	defer second.Close()
	defer local.Close()
	var current atomic.Pointer[net.UDPAddr]
	current.Store(first.LocalAddr().(*net.UDPAddr))
	previous := resolvePrismRelay
	resolvePrismRelay = func(string, string) (*net.UDPAddr, error) { return current.Load(), nil }
	defer func() { resolvePrismRelay = previous }()

	agent := &PrismAgent{
		RelayAddress: "relay.invalid:9446", LocalAddress: local.LocalAddr().String(),
		InstallationID: [16]byte{1}, Secret: [32]byte{2}, registerInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = agent.Run(ctx) }()
	buffer := make([]byte, 512)
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := first.ReadFromUDP(buffer); err != nil {
		t.Fatal("agent did not register with the first relay address")
	}
	current.Store(second.LocalAddr().(*net.UDPAddr))
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := second.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal("agent kept registering with a stale relay address")
	}
	if message, err := prismlink.ParseRelayDatagram(buffer[:n]); err != nil || message.Type != prismlink.RelayRegister {
		t.Fatalf("unexpected agent datagram: %v", err)
	}
}

func testUDPListener(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}
