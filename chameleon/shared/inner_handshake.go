package shared

import (
	"crypto/rand"
	"encoding/binary"
)

// Inner TLS handshakes (a tunnelled browser's ClientHello, a site's
// ServerHello) have characteristic sizes that remain visible through the outer
// TLS records and are the basis of TLS-in-TLS detection. Packets that carry
// them are padded to a random size spanning ordinary bulk packets, so the
// first records of a tunnelled connection no longer reveal the inner handshake.
const (
	InnerHandshakePadMin = 1200
	InnerHandshakePadMax = 3000
)

// IsInnerTLSHandshake reports whether a raw IPv4 packet is a TCP segment whose
// payload starts with a TLS handshake record.
func IsInnerTLSHandshake(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}
	ipHeader := int(packet[0]&0x0f) * 4
	if ipHeader < 20 || len(packet) < ipHeader+20 {
		return false
	}
	tcpHeader := int(packet[ipHeader+12]>>4) * 4
	payload := ipHeader + tcpHeader
	if tcpHeader < 20 || len(packet) < payload+3 {
		return false
	}
	return packet[payload] == 0x16 && packet[payload+1] == 0x03 &&
		packet[payload+2] >= 0x01 && packet[payload+2] <= 0x04
}

// InnerHandshakePaddingTarget returns the padded size for a framed packet of
// need bytes, or 0 when the packet carries no inner TLS handshake.
func InnerHandshakePaddingTarget(packet []byte, need int) int {
	if !IsInnerTLSHandshake(packet) {
		return 0
	}
	low := max(need, InnerHandshakePadMin)
	if low >= InnerHandshakePadMax {
		return need
	}
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return low
	}
	return low + int(binary.BigEndian.Uint64(entropy[:])%uint64(InnerHandshakePadMax-low+1))
}
