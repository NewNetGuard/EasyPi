package shared

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func testStreamKeys(t *testing.T) *SessionKeys {
	t.Helper()
	keys, err := DeriveSessionKeys(bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{1}, 32),
		bytes.Repeat([]byte{2}, 32), "session-1", "client-1", "instance-1")
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// Adding the stream key must not change any key an older peer derives.
func TestStreamKeyLeavesExistingSessionKeysUnchanged(t *testing.T) {
	keys := testStreamKeys(t)
	salt := sha256.Sum256(append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...))
	reader := hkdf.New(sha256.New, bytes.Repeat([]byte{7}, 32), salt[:],
		sessionFields(SessionProtocolID, "session-1", "client-1", "instance-1"))
	legacy := make([]byte, 128)
	if _, err := io.ReadFull(reader, legacy); err != nil {
		t.Fatal(err)
	}
	got := bytes.Join([][]byte{keys.AuthKey, keys.ClientToServerKey, keys.ServerToClientKey,
		keys.ClientToServerNonceBase, keys.ServerToClientNonceBase}, nil)
	if !bytes.Equal(got, legacy) {
		t.Fatal("existing session keys changed")
	}
	if len(keys.StreamKey) != 32 || bytes.Equal(keys.StreamKey, keys.AuthKey) {
		t.Fatal("stream key missing or reused")
	}
}

func TestTCPStreamFramesRoundTripBetweenClientAndServer(t *testing.T) {
	keys := testStreamKeys(t)
	nonce := bytes.Repeat([]byte{9}, TCPStreamNonceSize)
	client, err := NewTCPStreamCipher(keys.StreamKey, "session-1", nonce, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTCPStreamCipher(keys.StreamKey, "session-1", nonce, false)
	if err != nil {
		t.Fatal(err)
	}

	var up, down bytes.Buffer
	for _, msg := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{'x'}, TCPStreamMaxPlaintext)} {
		if err := WriteTCPStreamFrame(&up, client, msg); err != nil {
			t.Fatal(err)
		}
		if err := WriteTCPStreamFrame(&down, server, msg); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range []struct {
		r io.Reader
		c *InnerCipher
	}{{&up, server}, {&down, client}} {
		first, err := ReadTCPStreamFrame(pair.r, pair.c)
		if err != nil || string(first) != "hello" {
			t.Fatalf("first frame %q, %v", first, err)
		}
		second, err := ReadTCPStreamFrame(pair.r, pair.c)
		if err != nil || len(second) != TCPStreamMaxPlaintext {
			t.Fatalf("second frame %d bytes, %v", len(second), err)
		}
		if _, err := ReadTCPStreamFrame(pair.r, pair.c); !errors.Is(err, io.EOF) {
			t.Fatalf("end of stream returned %v, want EOF", err)
		}
	}
}

func TestTCPStreamsDoNotShareKeys(t *testing.T) {
	keys := testStreamKeys(t)
	a, _ := NewTCPStreamCipher(keys.StreamKey, "session-1", bytes.Repeat([]byte{1}, TCPStreamNonceSize), true)
	b, _ := NewTCPStreamCipher(keys.StreamKey, "session-1", bytes.Repeat([]byte{2}, TCPStreamNonceSize), false)
	var buf bytes.Buffer
	if err := WriteTCPStreamFrame(&buf, a, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTCPStreamFrame(&buf, b); err == nil {
		t.Fatal("a stream decrypted another stream's frame")
	}
}

func TestTCPStreamRejectsOversizedFrames(t *testing.T) {
	keys := testStreamKeys(t)
	c, _ := NewTCPStreamCipher(keys.StreamKey, "session-1", bytes.Repeat([]byte{3}, TCPStreamNonceSize), true)
	if err := WriteTCPStreamFrame(io.Discard, c, make([]byte, TCPStreamMaxPlaintext+1)); !errors.Is(err, ErrTCPStreamFrameTooLarge) {
		t.Fatalf("oversized write returned %v", err)
	}
	huge := []byte{0xff, 0xff, 0xff, 0xff}
	if _, err := ReadTCPStreamFrame(bytes.NewReader(huge), c); !errors.Is(err, ErrTCPStreamFrameTooLarge) {
		t.Fatalf("oversized read returned %v", err)
	}
}

func TestTCPStreamTargetEncoding(t *testing.T) {
	target := netip.MustParseAddrPort("93.184.215.14:443")
	encoded, err := EncodeTCPStreamTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTCPStreamTarget(encoded)
	if err != nil || decoded != target {
		t.Fatalf("decoded %v, %v", decoded, err)
	}
	for _, bad := range []string{"[2001:db8::1]:443", "93.184.215.14:0"} {
		if _, err := EncodeTCPStreamTarget(netip.MustParseAddrPort(bad)); err == nil {
			t.Fatalf("encoded unsupported target %s", bad)
		}
	}
	if _, err := DecodeTCPStreamTarget([]byte{2, 1, 2, 3, 4, 0, 80}); err == nil {
		t.Fatal("decoded an unknown target version")
	}
}

func shapedPair(t *testing.T, shaped bool) (client, server *TCPStreamFramer) {
	t.Helper()
	key := bytes.Repeat([]byte{7}, 32)
	nonce := bytes.Repeat([]byte{9}, TCPStreamNonceSize)
	c, err := NewTCPStreamCipher(key, "shape-session", nonce, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewTCPStreamCipher(key, "shape-session", nonce, false)
	if err != nil {
		t.Fatal(err)
	}
	return NewTCPStreamFramer(c, shaped, true), NewTCPStreamFramer(s, shaped, false)
}

// Shaped frames carry every byte intact, at every size, in order.
func TestShapedFramesRoundTrip(t *testing.T) {
	client, server := shapedPair(t, true)
	var wire bytes.Buffer
	sizes := []int{0, 1, 7, 64, 512, 513, 1984, 4096, 9000, client.MaxData()}
	var sent [][]byte
	for i, n := range sizes {
		data := bytes.Repeat([]byte{byte(i + 1)}, n)
		sent = append(sent, data)
		if err := client.WriteFrame(&wire, data); err != nil {
			t.Fatal(err)
		}
	}
	for i := range sizes {
		got, err := server.ReadFrame(&wire)
		if err != nil || !bytes.Equal(got, sent[i]) {
			t.Fatalf("frame %d: %d bytes (%v), want %d", i, len(got), err, len(sent[i]))
		}
	}
	if err := client.WriteFrame(&wire, make([]byte, client.MaxData()+1)); !errors.Is(err, ErrTCPStreamFrameTooLarge) {
		t.Fatalf("oversized shaped frame: %v", err)
	}
}

// A shaped frame whose declared length exceeds its plaintext is rejected,
// never read past or truncated silently.
func TestMalformedShapedFrameIsRejected(t *testing.T) {
	client, server := shapedPair(t, true)
	for _, plaintext := range [][]byte{{}, {0}, {0, 9, 1, 2}} {
		var wire bytes.Buffer
		if err := WriteTCPStreamFrame(&wire, client.cipher, plaintext); err != nil {
			t.Fatal(err)
		}
		if _, err := server.ReadFrame(&wire); err == nil {
			t.Fatalf("accepted malformed shaped plaintext %x", plaintext)
		}
	}
}

// Unshaped framing is exactly the original format, so peers that predate
// shaping interoperate.
func TestUnshapedFramerKeepsTheOriginalFormat(t *testing.T) {
	client, server := shapedPair(t, false)
	var wire bytes.Buffer
	if err := client.WriteFrame(&wire, []byte("plain")); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != 4+innerCounterSize+len("plain")+16 {
		t.Fatalf("unshaped frame is %d bytes", wire.Len())
	}
	got, err := ReadTCPStreamFrame(&wire, server.cipher)
	if err != nil || string(got) != "plain" {
		t.Fatalf("original reader got %q (%v)", got, err)
	}
}

func frameSize(t *testing.T, f *TCPStreamFramer, n int) int {
	t.Helper()
	frame, err := f.AppendFrame(nil, make([]byte, n))
	if err != nil {
		t.Fatal(err)
	}
	return len(frame) - 4 - innerCounterSize - 16 - tcpStreamShapePrefix // data + padding
}

// Padding is confined to a stream's opening frames: small ones up to the
// small cap, the first larger one up to its direction's cap, nothing after.
func TestShapingOnlyTouchesTheOpeningFrames(t *testing.T) {
	for run := 0; run < 200; run++ {
		client, server := shapedPair(t, true)
		if size := frameSize(t, client, 7); size < 7 || size > tcpStreamShapeSmallCap {
			t.Fatalf("small frame shaped to %d", size)
		}
		if size := frameSize(t, client, 1984); size < 1984 || size > tcpStreamShapeUpstream {
			t.Fatalf("upstream hello shaped to %d", size)
		}
		if size := frameSize(t, client, 1984); size != 1984 {
			t.Fatalf("second larger frame padded to %d", size)
		}
		frameSize(t, client, 64)
		if size := frameSize(t, client, 64); size != 64 {
			t.Fatalf("frame after the opening ones padded to %d", size)
		}
		if size := frameSize(t, server, 3321); size < 3321 || size > tcpStreamShapeDownstream {
			t.Fatalf("downstream flight shaped to %d", size)
		}
		if size := frameSize(t, server, 12000); size != 12000 {
			t.Fatalf("bulk frame padded to %d", size)
		}
	}
}

// One observed size must not pin the inner size, and the shaping must not
// create a size of its own that recurs: no value may cover more than a few
// percent of streams.
func TestShapedSizesSpreadWithoutARecurringValue(t *testing.T) {
	for _, n := range []int{7, 64, 1984} {
		counts := map[int]int{}
		const runs = 2000
		for run := 0; run < runs; run++ {
			client, _ := shapedPair(t, true)
			if n == 1984 {
				frameSize(t, client, 7) // the destination frame comes first
			}
			counts[frameSize(t, client, n)]++
		}
		top := 0
		for _, c := range counts {
			top = max(top, c)
		}
		if len(counts) < 200 || top > runs/50 {
			t.Fatalf("inner %d: %d distinct outer sizes, most common %d of %d", n, len(counts), top, runs)
		}
	}
}
