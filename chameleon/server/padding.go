package main

import (
	"crypto/rand"
	"encoding/base64"

	"chameleon/shared"
)

// serverPaddingBuckets mirrors the client-side buckets to ensure that
// poll responses are padded to the same standard sizes.
var serverPaddingBuckets = []int{128, 192, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 10240, 12288, 14336, 16384, 24576, 32768, 49152, 65536}

// serverPadBase64 pads data and returns a base64 string for use in JSON responses.
func serverPadBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(serverPadToStandardSize(data))
}

// serverPadToStandardSize pads data to the next bucket boundary with random bytes.
func serverPadToStandardSize(data []byte) []byte {
	needed := 4 + len(data)
	target := needed
	for _, b := range serverPaddingBuckets {
		if b >= needed {
			target = b
			break
		}
	}

	buf := make([]byte, target)
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

// serverUnpadBase64 decodes and strips padding from a padBase64-encoded string.
func serverUnpadBase64(s string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if len(raw) < 4 {
		return nil, false
	}
	realLen := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if realLen < 0 || 4+realLen > len(raw) {
		return nil, false
	}
	return raw[4 : 4+realLen], true
}

// serverBinPaddingBuckets mirrors the client's binPaddingBuckets. Kept identical
// so downlink packets are normalized to the same small set of on-wire sizes.
var serverBinPaddingBuckets = []int{128, 256, 512, 768, 1024, 1280, 1456, 1600}

func serverAdaptivePaddingTarget(need int, entropy byte) int {
	base := -1
	for i, bucket := range serverBinPaddingBuckets {
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
	if base+steps >= len(serverBinPaddingBuckets) {
		steps = len(serverBinPaddingBuckets) - base - 1
	}
	return serverBinPaddingBuckets[base+steps]
}

// serverBatchStepUp applies shared.PacketPaddingStepUp to the raw packets of
// one downlink write.
func serverBatchStepUp(batch [][]byte) bool {
	total := 0
	for _, packet := range batch {
		total += len(packet)
	}
	return shared.PacketPaddingStepUp(total)
}

func serverRandomPaddingTarget(need int) int {
	var entropy [1]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return serverAdaptivePaddingTarget(need, 0)
	}
	return serverAdaptivePaddingTarget(need, entropy[0])
}

// serverPadPacketBinary wraps one raw tunnel packet as
//
//	[2-byte big-endian real length][packet][random padding]
//
// padded up to the next serverBinPaddingBuckets size. Mirror of the client's
// padPacketBinary; used on the downlink so transport frame lengths do not leak
// exact IP packet sizes. Oversized packets are length-prefixed but unpadded.
// The packet is sent on its own, so its bucket gets the random raise.
func serverPadPacketBinary(pkt []byte) []byte {
	return serverPadPacketInBatch(pkt, true)
}

// serverPadPacketInBatch pads one packet of a write; stepUp comes from
// shared.PacketPaddingStepUp for the whole write (see serverBatchStepUp).
func serverPadPacketInBatch(pkt []byte, stepUp bool) []byte {
	need := 2 + len(pkt)
	target := serverAdaptivePaddingTarget(need, 0)
	if stepUp {
		target = serverRandomPaddingTarget(need)
	}
	target = max(target, shared.InnerHandshakePaddingTarget(pkt, need))
	buf := make([]byte, target)
	buf[0] = byte(len(pkt) >> 8)
	buf[1] = byte(len(pkt))
	copy(buf[2:], pkt)
	if target > need {
		rand.Read(buf[need:])
	}
	return buf
}

// serverUnpadPacketBinary reverses serverPadPacketBinary (and the client's
// padPacketBinary). ok is false when the blob is not a valid padded packet, so the
// caller can fall back to treating the bytes as-is.
func serverUnpadPacketBinary(blob []byte) (pkt []byte, ok bool) {
	if len(blob) < 2 {
		return nil, false
	}
	n := int(blob[0])<<8 | int(blob[1])
	if n <= 0 || 2+n > len(blob) {
		return nil, false
	}
	return blob[2 : 2+n], true
}
