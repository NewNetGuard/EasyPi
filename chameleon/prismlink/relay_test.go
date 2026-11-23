package prismlink

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"chameleon/shared"
)

func TestRelayRegistrationAuthentication(t *testing.T) {
	id := [16]byte{1, 2, 3}
	secret := [32]byte{4, 5, 6}
	now := time.Unix(1_800_000_000, 0)
	packet, err := EncodeRelayRegistration(id, secret, now)
	if err != nil || VerifyRelayRegistration(packet, secret, now) != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	packet[len(packet)-1] ^= 1
	if VerifyRelayRegistration(packet, secret, now) == nil {
		t.Fatal("tampered registration accepted")
	}
}

func TestRelayDataRoundTrip(t *testing.T) {
	id := [16]byte{1}
	route := [8]byte{2}
	payload := make([]byte, HeaderSize+clientHelloBodySize)
	_ = encodeHeader(payload, header{typ: PacketClientHello})
	packet, err := EncodeRelayData(RelayMobileData, id, route, payload)
	if err != nil {
		t.Fatal(err)
	}
	message, err := ParseRelayDatagram(packet)
	if err != nil || message.InstallationID != id || message.Route != route || len(message.Payload) != len(payload) {
		t.Fatalf("relay packet failed: %+v %v", message, err)
	}
}

func TestMobileRouteBindingIsBoundToThePhoneKey(t *testing.T) {
	id := [16]byte{1}
	secret := [32]byte{4, 5, 6}
	route := [8]byte{7}
	phone := [16]byte{9}
	other := [16]byte{10}
	now := time.Unix(1_800_000_000, 0)
	packet, err := EncodeRelayMobileBind(id, route, phone, MobileRouteKey(secret, phone), now)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := VerifyRelayMobileBind(packet, secret, now)
	if err != nil || owner != phone {
		t.Fatalf("valid binding rejected: %v", err)
	}
	// A phone cannot bind a route in another phone's name with its own key.
	forged, _ := EncodeRelayMobileBind(id, route, other, MobileRouteKey(secret, phone), now)
	if _, err := VerifyRelayMobileBind(forged, secret, now); err == nil {
		t.Fatal("binding with another phone's identity accepted")
	}
	if _, err := VerifyRelayMobileBind(packet, secret, now.Add(2*RelayAuthWindow)); err == nil {
		t.Fatal("stale binding accepted")
	}
	tampered := append([]byte(nil), packet...)
	tampered[24] ^= 1
	if _, err := VerifyRelayMobileBind(tampered, secret, now); err == nil {
		t.Fatal("binding for a changed route accepted")
	}
	if MobileRouteKey(secret, phone) == secret {
		t.Fatal("route key must not expose the installation secret")
	}
}

// The home EasyPi derives the same key in scripts/settings/mobile_link_agent.sh
// (home-profile); tests/security pins that side to this vector.
func TestMobileRouteKeyCrossLanguageVector(t *testing.T) {
	var secret [32]byte
	for index := range secret {
		secret[index] = 0x11
	}
	psk, _ := hex.DecodeString(strings.Repeat("22", 32))
	encodedID := shared.ClientIDForPSK(psk)
	if encodedID != "3ae1e9e7325021023b5eb4990a32c2f3" {
		t.Fatalf("client identity changed: %s", encodedID)
	}
	var clientID [16]byte
	decoded, _ := hex.DecodeString(encodedID)
	copy(clientID[:], decoded)
	key := MobileRouteKey(secret, clientID)
	if hex.EncodeToString(key[:]) != "91000311317042bf77b84dd6f37f3ebc93a7f1d1880b8045422be92562990ed1" {
		t.Fatalf("route key derivation changed: %x", key)
	}
}
