package clientcore

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

func normalizeSHA256Hex(value string) string {
	return strings.ToLower(
		strings.ReplaceAll(
			strings.ReplaceAll(
				strings.TrimPrefix(
					strings.TrimPrefix(strings.TrimSpace(value), "SHA256:"),
					"sha256:",
				),
				":",
				"",
			),
			" ",
			"",
		),
	)
}

func decodeSHA256Pin(value string) ([]byte, error) {
	normalized := normalizeSHA256Hex(value)
	if normalized == "" {
		return nil, nil
	}
	if len(normalized) != 64 {
		return nil, fmt.Errorf("sha256 pin must be 64 hex chars")
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("sha256 pin must be valid hex: %w", err)
	}
	return decoded, nil
}

func certificateFingerprintSHA256(rawCert []byte) []byte {
	sum := sha256.Sum256(rawCert)
	return sum[:]
}

func verifyTLSConnectionPin(state tls.ConnectionState, expected []byte) error {
	return verifyPeerCertificatePin(state.PeerCertificates, expected)
}

func verifyPeerCertificatePin(peerCertificates []*x509.Certificate, expected []byte) error {
	if len(expected) == 0 {
		return nil
	}
	if len(peerCertificates) == 0 || peerCertificates[0] == nil {
		return fmt.Errorf("tls peer certificate missing")
	}

	actual := certificateFingerprintSHA256(peerCertificates[0].Raw)
	if len(actual) != len(expected) {
		return fmt.Errorf("tls peer certificate fingerprint length mismatch")
	}
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return fmt.Errorf("tls certificate pin mismatch")
	}
	return nil
}
