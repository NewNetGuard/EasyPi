package clientcore

import (
	"crypto/rand"
	"encoding/base64"

	"chameleon/shared"
)

// paddingBuckets defines standard payload sizes (bytes) to normalize traffic to.
// Payloads are padded to the next bucket size to defeat size-based ML classifiers.
// Sizes chosen to match common HTTPS response sizes.
var paddingBuckets = []int{128, 192, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 10240, 12288, 14336, 16384, 24576, 32768, 49152, 65536}

// padToStandardSize pads or truncates data so the resulting base64 encoding
// lands in a predefined bucket. Padding bytes are random (indistinguishable
// from ciphertext). The real length is encoded as the first 4 bytes of data.
//
// Wire format of the padded blob:
//
//	[4 bytes big-endian] real payload length
//	[N bytes]            real payload
//	[P bytes]            random padding
//
// Total (before base64) is rounded up to the next paddingBuckets value.
func padToStandardSize(data []byte) []byte {
	// Calculate the minimum total size needed.
	needed := 4 + len(data)

	// Find the next bucket that fits.
	target := needed
	for _, b := range paddingBuckets {
		if b >= needed {
			target = b
			break
		}
	}

	// Build padded buffer.
	buf := make([]byte, target)
	// Write real length as big-endian uint32.
	realLen := len(data)
	buf[0] = byte(realLen >> 24)
	buf[1] = byte(realLen >> 16)
	buf[2] = byte(realLen >> 8)
	buf[3] = byte(realLen)
	copy(buf[4:], data)

	// Fill remaining bytes with random data.
	padding := buf[4+len(data):]
	if len(padding) > 0 {
		rand.Read(padding)
	}

	return buf
}

// unpadFromStandardSize removes padding added by padToStandardSize.
// Returns the original payload.
func unpadFromStandardSize(padded []byte) ([]byte, bool) {
	if len(padded) < 4 {
		return nil, false
	}
	realLen := int(padded[0])<<24 | int(padded[1])<<16 | int(padded[2])<<8 | int(padded[3])
	if realLen < 0 || 4+realLen > len(padded) {
		return nil, false
	}
	return padded[4 : 4+realLen], true
}

// padBase64 returns a base64-encoded padded payload.
func padBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(padToStandardSize(data))
}

// unpadBase64 decodes and removes padding from a padBase64 result.
func unpadBase64(s string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return unpadFromStandardSize(raw)
}

// binPaddingBuckets is the size ladder (bytes, including the 2-byte length prefix)
// used to normalize INDIVIDUAL tunnel packets in the fast binary path. Kept tight
// around the tunnel MTU so overhead stays low: small control packets collapse onto
// a handful of sizes and full-MTU packets land on one bucket. Must stay identical
// to the server's serverBinPaddingBuckets.
var binPaddingBuckets = []int{128, 256, 512, 768, 1024, 1280, 1456, 1600}

// adaptivePaddingTarget keeps the compact bucket format while avoiding a
// deterministic packet-size -> wire-size mapping. Small packets may advance by
// two buckets; larger packets by one. entropy is passed in so the policy can be
// tested without weakening runtime randomness.
func adaptivePaddingTarget(need int, buckets []int, entropy byte) int {
	base := -1
	for i, bucket := range buckets {
		if bucket >= need {
			base = i
			break
		}
	}
	if base < 0 {
		return need
	}

	steps := 0
	switch r := entropy & 0x0f; {
	case r >= 14:
		steps = 2
	case r >= 8:
		steps = 1
	}
	maxSteps := 1
	if need <= 256 {
		maxSteps = 2
	}
	if steps > maxSteps {
		steps = maxSteps
	}
	if base+steps >= len(buckets) {
		steps = len(buckets) - base - 1
	}
	return buckets[base+steps]
}

// padPacketBinary wraps one raw tunnel packet as
//
//	[2-byte big-endian real length][packet][random padding]
//
// padded up to its binPaddingBuckets size, so the length that surfaces in the
// transport's binary frame header is quantized to a small set of values instead of
// leaking the exact IP packet size to size-based classifiers. Oversized packets
// (larger than the top bucket) are sent length-prefixed but unpadded. Returns a
// fresh buffer (safe to retain / send).
//
// The random bucket raise is left to raisePaddedPacket: whether it is needed
// depends on the write the packet ends up in (shared.PacketPaddingStepUp).
func padPacketBinary(pkt []byte) []byte {
	need := 2 + len(pkt)
	target := adaptivePaddingTarget(need, binPaddingBuckets, 0)
	target = max(target, shared.InnerHandshakePaddingTarget(pkt, need))
	buf := make([]byte, target)
	buf[0] = byte(len(pkt) >> 8)
	buf[1] = byte(len(pkt))
	copy(buf[2:], pkt)
	if target > need {
		rand.Read(buf[need:]) // random tail, indistinguishable from ciphertext
	}
	return buf
}

// paddedPacketLength returns the real packet length of a padPacketBinary buffer.
func paddedPacketLength(padded []byte) int {
	if len(padded) < 2 {
		return 0
	}
	return int(padded[0])<<8 | int(padded[1])
}

// raisePaddedPacket gives a padPacketBinary buffer the random bucket raise of
// adaptivePaddingTarget. The result has exactly the size distribution a packet
// padded with the raise in one step would have.
func raisePaddedPacket(padded []byte) []byte {
	var entropy [1]byte
	_, _ = rand.Read(entropy[:])
	target := adaptivePaddingTarget(2+paddedPacketLength(padded), binPaddingBuckets, entropy[0])
	if target <= len(padded) {
		return padded
	}
	raised := make([]byte, target)
	copy(raised, padded)
	rand.Read(raised[len(padded):])
	return raised
}

// unpadPacketBinary reverses padPacketBinary. ok is false when the blob is not a
// valid padded packet (e.g. an un-padded payload from a legacy peer), letting the
// caller fall back to treating the bytes as-is.
func unpadPacketBinary(blob []byte) (pkt []byte, ok bool) {
	if len(blob) < 2 {
		return nil, false
	}
	n := int(blob[0])<<8 | int(blob[1])
	if n <= 0 || 2+n > len(blob) {
		return nil, false
	}
	return blob[2 : 2+n], true
}
