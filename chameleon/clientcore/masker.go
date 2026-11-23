package clientcore

import (
	"fmt"
	"sync/atomic"

	"chameleon/shared"
)

// packetIDCounter is used by cover-traffic packets to keep packet IDs unique.
var packetIDCounter uint32

// Masker handles packet preparation for HTTP transport.
type Masker struct {
	analyzer *Analyzer
	cipher   *Cipher
	profile  *ProfileManager
	psk      []byte
}

// NewMasker creates a new Masker instance.
func NewMasker(analyzer *Analyzer, cipher *Cipher, pm *ProfileManager, psk []byte) *Masker {
	return &Masker{
		analyzer: analyzer,
		cipher:   cipher,
		profile:  pm,
		psk:      psk,
	}
}

// PadBatch copies VPN packets into their padded plaintext form (see
// padPacketBinary) and records them in the traffic profile. The copies are
// safe to keep after the caller reuses its buffers; SealBatch encrypts them
// once the write they travel in is known.
//
// Fast path rationale:
// - Transport channel is already protected by TLS.
// - Per-packet HMAC/chunk framing costs significant CPU on mobile devices.
// - We keep payloads as raw IP packets and batch at transport layer.
func (m *Masker) PadBatch(vpnPackets [][]byte) [][]byte {
	padded := make([][]byte, 0, len(vpnPackets))
	for _, vpnPacket := range vpnPackets {
		if len(vpnPacket) == 0 {
			continue
		}
		if m.profile != nil {
			m.profile.RecordActivity(len(vpnPacket), true)
		}
		padded = append(padded, padPacketBinary(vpnPacket))
	}
	return padded
}

// SealBatch encrypts the padded packets of one uplink write, in order. Padding
// is applied before encryption so the authenticated ciphertext hides both the
// packet contents and its exact original length from transport relays; the
// packets of a small write also get the random bucket raise
// (shared.PacketPaddingStepUp).
func (m *Masker) SealBatch(padded [][]byte) ([][]byte, error) {
	total := 0
	for _, packet := range padded {
		total += paddedPacketLength(packet)
	}
	stepUp := shared.PacketPaddingStepUp(total)

	sealed := make([][]byte, 0, len(padded))
	for _, packet := range padded {
		if len(packet) == 0 {
			continue
		}
		if stepUp {
			packet = raisePaddedPacket(packet)
		}
		encrypted, err := m.cipher.Encrypt(packet)
		if err != nil {
			return nil, fmt.Errorf("encrypt tunnel packet: %w", err)
		}
		sealed = append(sealed, encrypted)
	}
	return sealed, nil
}

// ChunkForHttp keeps compatibility with existing call sites.
// In fast path we do not split packets.
func ChunkForHttp(data []byte, minSize, maxSize int) [][]byte {
	_ = minSize
	_ = maxSize
	if len(data) == 0 {
		return nil
	}
	return [][]byte{data}
}

// _ is a compile-time check that atomic is imported.
var _ = atomic.AddUint32
