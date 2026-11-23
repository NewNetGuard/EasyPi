package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const SessionProtocolID = "chameleon-session-v1"

// SessionKeys contains independent request-authentication, traffic and nonce
// material for one negotiated Chameleon session.
type SessionKeys struct {
	AuthKey                 []byte
	ClientToServerKey       []byte
	ServerToClientKey       []byte
	ClientToServerNonceBase []byte
	ServerToClientNonceBase []byte
	// StreamKey seeds the per-stream keys of TCP streams. It is read after the
	// other keys from the same HKDF output, so those keys are unchanged.
	StreamKey []byte
}

func sessionFields(label string, fields ...string) []byte {
	return []byte(label + "\x00" + strings.Join(fields, "\x00"))
}

func computeHMAC(key []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

// DeriveSessionKeys binds all traffic keys to both fresh nonces, the active
// session identifier, the installation identity and this client process.
func DeriveSessionKeys(
	psk, clientNonce, serverNonce []byte,
	sessionID, clientID, clientInstance string,
) (*SessionKeys, error) {
	if len(psk) < 16 {
		return nil, fmt.Errorf("PSK must contain at least 16 bytes")
	}
	if len(clientNonce) != 32 || len(serverNonce) != 32 {
		return nil, fmt.Errorf("session nonces must contain 32 bytes")
	}
	if sessionID == "" || clientID == "" || clientInstance == "" {
		return nil, fmt.Errorf("session context is incomplete")
	}

	saltInput := make([]byte, 0, len(clientNonce)+len(serverNonce))
	saltInput = append(saltInput, clientNonce...)
	saltInput = append(saltInput, serverNonce...)
	salt := sha256.Sum256(saltInput)
	info := sessionFields(SessionProtocolID, sessionID, clientID, clientInstance)
	reader := hkdf.New(sha256.New, psk, salt[:], info)
	material := make([]byte, 32+32+32+16+16+32)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	return &SessionKeys{
		AuthKey:                 append([]byte(nil), material[0:32]...),
		ClientToServerKey:       append([]byte(nil), material[32:64]...),
		ServerToClientKey:       append([]byte(nil), material[64:96]...),
		ClientToServerNonceBase: append([]byte(nil), material[96:112]...),
		ServerToClientNonceBase: append([]byte(nil), material[112:128]...),
		StreamKey:               append([]byte(nil), material[128:160]...),
	}, nil
}

func ComputeBootstrapMAC(
	psk []byte,
	challengeID, challenge, clientID, clientInstance, clientNonce string,
) []byte {
	return computeHMAC(psk, sessionFields(
		SessionProtocolID+"/bootstrap",
		challengeID, challenge, clientID, clientInstance, clientNonce,
	))
}

func ComputeServerProof(
	authKey []byte,
	sessionID, clientNonce, serverNonce, clientID, clientInstance string,
) []byte {
	return computeHMAC(authKey, sessionFields(
		SessionProtocolID+"/server-proof",
		sessionID, clientNonce, serverNonce, clientID, clientInstance,
	))
}

func ComputeSessionRequestMAC(
	authKey []byte,
	timestamp, nonce, clientID, sessionID, method, requestPath string,
) []byte {
	return computeHMAC(authKey, sessionFields(
		SessionProtocolID+"/request",
		timestamp, nonce, clientID, sessionID, method, requestPath,
	))
}
