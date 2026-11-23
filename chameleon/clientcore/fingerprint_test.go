package clientcore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sort"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && value>>8 == value&0xff
}

type parsedHello struct {
	extensions []uint16
	bodies     map[uint16][]byte
}

// buildChrome157Hello marshals one ClientHello exactly as dialUTLS would.
func buildChrome157Hello(t *testing.T) parsedHello {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := utls.UClient(client, &utls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}}, utls.HelloCustom)
	spec, err := chrome157ClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	raw := conn.HandshakeState.Hello.Raw

	// handshake header (4) + version (2) + random (32)
	i := 38
	i += 1 + int(raw[i])
	i += 2 + int(binary.BigEndian.Uint16(raw[i:]))
	i += 1 + int(raw[i])
	end := i + 2 + int(binary.BigEndian.Uint16(raw[i:]))
	i += 2
	hello := parsedHello{bodies: map[uint16][]byte{}}
	for i < end {
		id := binary.BigEndian.Uint16(raw[i:])
		length := int(binary.BigEndian.Uint16(raw[i+2:]))
		hello.extensions = append(hello.extensions, id)
		hello.bodies[id] = raw[i+4 : i+4+length]
		i += 4 + length
	}
	return hello
}

// The extension set, trust anchors and signature algorithms below are those of
// fresh Chrome 157 desktop ClientHellos captured on the wire.
func TestChrome157HelloMatchesCapturedChrome(t *testing.T) {
	want := []uint16{0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 51764, 65037, 65281}
	wantSignatures := []uint16{0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	anchors, _ := hex.DecodeString(chromeTrustAnchorIDs)

	orders := map[string]bool{}
	signatureGREASE := map[uint16]bool{}
	for run := 0; run < 64; run++ {
		hello := buildChrome157Hello(t)
		first, last := hello.extensions[0], hello.extensions[len(hello.extensions)-1]
		if !isGREASE(first) || !isGREASE(last) || first == last {
			t.Fatalf("GREASE extensions must open and close the list with distinct values: %x %x", first, last)
		}
		var got []uint16
		for _, id := range hello.extensions {
			if !isGREASE(id) {
				got = append(got, id)
			}
		}
		orders[string(fmtOrder(got))] = true
		sorted := append([]uint16{}, got...)
		sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
		if len(sorted) != len(want) {
			t.Fatalf("extensions %v, want %v", sorted, want)
		}
		for index := range want {
			if sorted[index] != want[index] {
				t.Fatalf("extensions %v, want %v", sorted, want)
			}
		}
		if !bytes.Equal(hello.bodies[extensionTrustAnchors], anchors) {
			t.Fatalf("trust_anchors body differs from Chrome 157")
		}

		body := hello.bodies[13]
		var signatures []uint16
		for j := 2; j < len(body); j += 2 {
			signatures = append(signatures, binary.BigEndian.Uint16(body[j:]))
		}
		if !isGREASE(signatures[0]) {
			t.Fatalf("signature algorithms must start with GREASE, got %x", signatures[0])
		}
		signatureGREASE[signatures[0]] = true
		for index, scheme := range wantSignatures {
			if signatures[index+1] != scheme {
				t.Fatalf("signature algorithms %x, want GREASE then %x", signatures, wantSignatures)
			}
		}
	}
	// Chrome draws a fresh order and signature GREASE on every connection.
	if len(orders) < 32 {
		t.Fatalf("extension order repeated too often: %d distinct in 64 hellos", len(orders))
	}
	if len(signatureGREASE) < 8 {
		t.Fatalf("signature GREASE barely varies: %d distinct values in 64 hellos", len(signatureGREASE))
	}
}

func fmtOrder(ids []uint16) []byte {
	out := make([]byte, 0, 2*len(ids))
	for _, id := range ids {
		out = binary.BigEndian.AppendUint16(out, id)
	}
	return out
}

// Every browser profile dials the carrier with that browser's TCP keepalive
// (Chrome: 45 s idle and interval), never Go's 15 s default.
func TestCarrierKeepAliveFollowsTheBrowserProfile(t *testing.T) {
	for _, profile := range append(append([]FingerprintProfile{}, desktopFingerprintProfiles...), mobileFingerprintProfiles...) {
		config := profileDialer(profile).KeepAliveConfig
		if !config.Enable || config.Idle != 45*time.Second || config.Interval != 45*time.Second {
			t.Fatalf("%s keepalive %+v, want Chrome's 45 s", profile.Name, config)
		}
	}
}
