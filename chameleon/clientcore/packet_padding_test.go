package clientcore

import (
	"bytes"
	"testing"

	"chameleon/shared"
)

func newUplinkTestCiphers(t *testing.T) (*Cipher, *shared.InnerCipher) {
	t.Helper()
	keys, err := shared.DeriveSessionKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 32), bytes.Repeat([]byte{1}, 32),
		"padding-session", "padding-client", "padding-instance",
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := NewCipher(keys, "padding-session")
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := shared.NewInnerCipher(
		keys.ServerToClientKey, keys.ClientToServerKey,
		keys.ServerToClientNonceBase, keys.ClientToServerNonceBase,
		"padding-session", "server-to-client", "client-to-server",
	)
	if err != nil {
		t.Fatal(err)
	}
	return clientCipher, serverCipher
}

func testPacket(size int, fill byte) []byte {
	return bytes.Repeat([]byte{fill}, size)
}

// Packets of a bulk write are padded to their bucket only; a packet sent on
// its own keeps the random bucket raise. Every packet still decrypts and
// unpads to exactly what was sent.
func TestUplinkPaddingDependsOnTheWrite(t *testing.T) {
	clientCipher, serverCipher := newUplinkTestCiphers(t)
	masker := NewMasker(nil, clientCipher, nil, nil)

	openAll := func(sealed [][]byte, want [][]byte) []int {
		t.Helper()
		if len(sealed) != len(want) {
			t.Fatalf("sealed %d packets, want %d", len(sealed), len(want))
		}
		sizes := make([]int, len(sealed))
		for i, packet := range sealed {
			plain, err := serverCipher.Decrypt(packet)
			if err != nil {
				t.Fatalf("packet %d does not decrypt: %v", i, err)
			}
			restored, ok := unpadPacketBinary(plain)
			if !ok || !bytes.Equal(restored, want[i]) {
				t.Fatalf("packet %d does not round-trip", i)
			}
			sizes[i] = len(plain)
		}
		return sizes
	}

	// Bulk: full-size packets and a TCP acknowledgement in one write.
	for round := 0; round < 50; round++ {
		packets := [][]byte{testPacket(1420, 1), testPacket(1420, 2), testPacket(1420, 3), testPacket(52, 4)}
		sealed, err := masker.SealBatch(masker.PadBatch(packets))
		if err != nil {
			t.Fatal(err)
		}
		sizes := openAll(sealed, packets)
		if sizes[0] != 1456 || sizes[1] != 1456 || sizes[2] != 1456 || sizes[3] != 128 {
			t.Fatalf("bulk write padded to %v, want buckets without the raise", sizes)
		}
	}

	// Alone: the raise still varies the size of a full-size packet.
	seen := map[int]bool{}
	for round := 0; round < 200; round++ {
		packet := [][]byte{testPacket(1420, 5)}
		sealed, err := masker.SealBatch(masker.PadBatch(packet))
		if err != nil {
			t.Fatal(err)
		}
		seen[openAll(sealed, packet)[0]] = true
	}
	if len(seen) != 2 || !seen[1456] || !seen[1600] {
		t.Fatalf("single full-size packet padded to %v, want 1456 and 1600", seen)
	}
}

// PadBatch copies: a caller may reuse its packet buffers at once, while the
// packets wait for their write.
func TestPadBatchDoesNotKeepCallerBuffers(t *testing.T) {
	clientCipher, serverCipher := newUplinkTestCiphers(t)
	masker := NewMasker(nil, clientCipher, nil, nil)
	buffer := testPacket(300, 7)
	padded := masker.PadBatch([][]byte{buffer})
	copy(buffer, testPacket(300, 9))

	sealed, err := masker.SealBatch(padded)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := serverCipher.Decrypt(sealed[0])
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := unpadPacketBinary(plain)
	if !ok || !bytes.Equal(restored, testPacket(300, 7)) {
		t.Fatal("queued packet changed with the caller's buffer")
	}
}

// Raising a bucket-padded packet gives the same sizes as the one-step policy.
func TestRaisePaddedPacketMatchesAdaptivePadding(t *testing.T) {
	for _, size := range []int{40, 200, 700, 1300, 1420} {
		want := map[int]bool{}
		for entropy := 0; entropy < 256; entropy++ {
			want[adaptivePaddingTarget(2+size, binPaddingBuckets, byte(entropy))] = true
		}
		got := map[int]bool{}
		for round := 0; round < 400; round++ {
			got[len(raisePaddedPacket(padPacketBinary(testPacket(size, 1))))] = true
		}
		if len(got) != len(want) {
			t.Fatalf("size %d: raised to %v, adaptive padding gives %v", size, got, want)
		}
		for target := range got {
			if !want[target] {
				t.Fatalf("size %d: raised to %d, adaptive padding gives %v", size, target, want)
			}
		}
	}
}
