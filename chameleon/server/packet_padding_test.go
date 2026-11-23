package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"chameleon/shared"
)

// Downlink packets of a bulk write are padded to their bucket only; a packet
// written on its own keeps the random bucket raise. The client still gets
// every packet back unchanged.
func TestDownlinkPaddingDependsOnTheWrite(t *testing.T) {
	_, session, clientCipher := newTestCryptoPair(t, []byte("0123456789abcdef0123456789abcdef"))
	cipher := session.cipher

	sizesOf := func(batch [][]byte) []int {
		t.Helper()
		var out bytes.Buffer
		if err := writeBinaryBatch(&out, batch, cipher, false); err != nil {
			t.Fatal(err)
		}
		var sizes []int
		body := out.Bytes()
		for index := 0; len(body) > 0; index++ {
			n := int(binary.BigEndian.Uint32(body[:4]))
			plain, err := clientCipher.Decrypt(body[4 : 4+n])
			if err != nil {
				t.Fatalf("packet %d does not decrypt: %v", index, err)
			}
			restored, ok := serverUnpadPacketBinary(plain)
			if !ok || !bytes.Equal(restored, batch[index]) {
				t.Fatalf("packet %d does not round-trip", index)
			}
			sizes = append(sizes, len(plain))
			body = body[4+n:]
		}
		return sizes
	}

	for round := 0; round < 50; round++ {
		batch := [][]byte{
			bytes.Repeat([]byte{1}, 1420), bytes.Repeat([]byte{2}, 1420),
			bytes.Repeat([]byte{3}, 1420), bytes.Repeat([]byte{4}, 52),
		}
		if sizes := sizesOf(batch); sizes[0] != 1456 || sizes[1] != 1456 || sizes[2] != 1456 || sizes[3] != 128 {
			t.Fatalf("bulk write padded to %v, want buckets without the raise", sizes)
		}
	}

	seen := map[int]bool{}
	for round := 0; round < 200; round++ {
		seen[sizesOf([][]byte{bytes.Repeat([]byte{5}, 1420)})[0]] = true
	}
	if len(seen) != 2 || !seen[1456] || !seen[1600] {
		t.Fatalf("single full-size packet padded to %v, want 1456 and 1600", seen)
	}
}

// Sequenced downlink frames take their padding from the batch they are
// reserved in, and a retransmission resends exactly those frames.
func TestReservedDownlinkBatchUsesTheBatchPadding(t *testing.T) {
	_, cryptoSession, clientCipher := newTestCryptoPair(t, []byte("0123456789abcdef0123456789abcdef"))
	session := &clientSession{}
	batch := make([][]byte, 8)
	for i := range batch {
		batch[i] = bytes.Repeat([]byte{byte(i)}, 1420)
	}
	reserved, err := session.reserveDownlinkBatch(batch, cryptoSession.cipher)
	if err != nil {
		t.Fatal(err)
	}
	for i, frame := range reserved {
		plain, err := clientCipher.Decrypt(frame.encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if len(plain) != 1456 {
			t.Fatalf("frame %d padded to %d, want 1456", i, len(plain))
		}
	}
	snapshot := session.pendingDownlinkSnapshot(16, 1<<20)
	if len(snapshot) != len(reserved) || !bytes.Equal(snapshot[0].encrypted, reserved[0].encrypted) {
		t.Fatal("retransmission does not resend the reserved frames")
	}
}

func TestPacketPaddingStepUpThreshold(t *testing.T) {
	if !shared.PacketPaddingStepUp(1420) || !shared.PacketPaddingStepUp(shared.PacketPaddingStepUpBatchBytes-1) {
		t.Fatal("a small write lost the random bucket raise")
	}
	if shared.PacketPaddingStepUp(shared.PacketPaddingStepUpBatchBytes) || shared.PacketPaddingStepUp(3*1420) {
		t.Fatal("a bulk write still gets the random bucket raise")
	}
}
