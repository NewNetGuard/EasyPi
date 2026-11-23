package shared

import "testing"

func tcpPacket(payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	packet[9] = 6
	packet[32] = 5 << 4
	copy(packet[40:], payload)
	return packet
}

func TestInnerTLSHandshakeDetection(t *testing.T) {
	hello := tcpPacket([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01})
	if !IsInnerTLSHandshake(hello) {
		t.Fatal("inner ClientHello not detected")
	}
	for name, packet := range map[string][]byte{
		"application data": tcpPacket([]byte{0x17, 0x03, 0x03, 0x00, 0x10}),
		"plain http":       tcpPacket([]byte("GET / HTTP/1.1")),
		"udp":              func() []byte { p := tcpPacket([]byte{0x16, 0x03, 0x01}); p[9] = 17; return p }(),
		"truncated":        hello[:41],
	} {
		if IsInnerTLSHandshake(packet) {
			t.Fatalf("%s misdetected as an inner handshake", name)
		}
	}
}

func TestInnerHandshakePaddingSpreadsSizes(t *testing.T) {
	hello := tcpPacket(append([]byte{0x16, 0x03, 0x01, 0x02, 0x00}, make([]byte, 512)...))
	need := 2 + len(hello)
	seen := map[int]bool{}
	for range 64 {
		target := InnerHandshakePaddingTarget(hello, need)
		if target < InnerHandshakePadMin || target > InnerHandshakePadMax || target < need {
			t.Fatalf("target %d outside [%d, %d]", target, InnerHandshakePadMin, InnerHandshakePadMax)
		}
		seen[target] = true
	}
	if len(seen) < 32 {
		t.Fatalf("handshake padding is not random enough: %d distinct sizes", len(seen))
	}
	if InnerHandshakePaddingTarget(tcpPacket([]byte{0x17, 0x03, 0x03}), 100) != 0 {
		t.Fatal("non-handshake packet was padded")
	}
}
