package shared

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// GenerateMarkerPublicKey returns a valid X25519 public value for use as the
// public deployment-specific input to the visibility marker. The corresponding
// private value is intentionally discarded: this protocol does not perform an
// X25519 key exchange and must not persist a misleading unused secret.
func GenerateMarkerPublicKey() (pub []byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

// ComputeVisibilityMarker derives a 16-byte REALITY marker from the server's
// public key, the pre-shared key (PSK), and a per-connection nonce. Because the
// nonce changes every connection, the marker (and therefore the TLS SessionID it
// is embedded in) is different every time — there is no static prefix a DPI box
// can fingerprint — yet the server can re-derive and verify it with the PSK.
func ComputeVisibilityMarker(serverPubKey, psk, nonce []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(serverPubKey)
	mac.Write(nonce)
	full := mac.Sum(nil)
	// We only need 16 bytes for a SessionID-sized marker.
	return full[:16]
}

// EmbedMarkerInSessionID fills a 32-byte SessionID with a per-connection REALITY
// identifier. We use the SessionID because it's a 32-byte field that many
// browsers still populate with random data even in TLS 1.3, making it a perfect
// covert channel.
//
// Layout written into sessionId:
//
//	[0:16]  marker = HMAC(psk, serverPubKey || nonce)[:16]
//	[16:32] nonce  = 16 fresh cryptographically-random bytes
//
// The whole 32-byte value looks random on the wire and is unique per connection,
// so there is no fixed pattern for a censor to key on (unlike a static marker).
func EmbedMarkerInSessionID(sessionId, serverPubKey, psk []byte) {
	if len(sessionId) < 32 || len(serverPubKey) == 0 || len(psk) == 0 {
		return
	}
	// Fresh per-connection nonce in the second half (crypto-random).
	if _, err := rand.Read(sessionId[16:32]); err != nil {
		return
	}
	marker := ComputeVisibilityMarker(serverPubKey, psk, sessionId[16:32])
	copy(sessionId[0:16], marker)
}

// DetectMarker checks whether a 32-byte window [marker(16) || nonce(16)] — usually
// a candidate SessionID location inside a peeked ClientHello — authenticates under
// the per-connection scheme. It needs the server public key + PSK (not a
// precomputed key) because the marker depends on the embedded nonce.
func DetectMarker(window, serverPubKey, psk []byte) bool {
	if len(window) < 32 || len(serverPubKey) == 0 || len(psk) == 0 {
		return false
	}
	expected := ComputeVisibilityMarker(serverPubKey, psk, window[16:32])
	return hmac.Equal(window[0:16], expected)
}

// VerifyPubKey checks if the provided bytes represent a valid X25519 public key.
func VerifyPubKey(pub []byte) error {
	_, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("invalid x25519 public key: %w", err)
	}
	return nil
}
