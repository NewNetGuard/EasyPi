package clientcore

import (
	"bytes"
	"testing"
)

func TestNewTransportPreservesDedicatedTransportKey(t *testing.T) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	transportKey := bytes.Repeat([]byte{0x22}, 32)

	transport := NewTransport(
		"example.com:443",
		"203.0.113.10:443",
		psk,
		NewFingerprinter("mobile"),
		"http2",
		"test",
		"",
		nil,
		bytes.Repeat([]byte{0x33}, 32),
		false,
		transportKey,
	)
	t.Cleanup(transport.Close)

	if !bytes.Equal(transport.transportKey, transportKey) {
		t.Fatalf("transport key = %x, want %x", transport.transportKey, transportKey)
	}
	if bytes.Equal(transport.transportKey, psk) {
		t.Fatal("dedicated transport key was replaced by PSK")
	}

	transportKey[0] ^= 0xff
	if transport.transportKey[0] != 0x22 {
		t.Fatal("transport key aliases caller-owned memory")
	}
}
