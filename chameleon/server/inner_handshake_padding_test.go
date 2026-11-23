package main

import (
	"bytes"
	"testing"

	"chameleon/shared"
)

func TestInnerHandshakePaddingRoundTrips(t *testing.T) {
	packet := make([]byte, 40+300)
	packet[0], packet[9], packet[32] = 0x45, 6, 5<<4
	packet[2], packet[3] = byte(len(packet)>>8), byte(len(packet))
	copy(packet[40:], []byte{0x16, 0x03, 0x01, 0x01, 0x2b})
	padded := serverPadPacketBinary(packet)
	if len(padded) < shared.InnerHandshakePadMin {
		t.Fatalf("inner handshake packet padded to only %d bytes", len(padded))
	}
	restored, ok := serverUnpadPacketBinary(padded)
	if !ok || !bytes.Equal(restored, packet) || !isLikelyRawIPv4Packet(restored) {
		t.Fatal("padded inner handshake packet did not round-trip")
	}
}
