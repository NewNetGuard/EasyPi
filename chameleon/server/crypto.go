package main

import (
	"fmt"

	"chameleon/shared"
)

// Cipher provides end-to-end authenticated encryption inside the outer TLS
// transport. Its directions are the inverse of the client cipher.
type Cipher struct {
	inner *shared.InnerCipher
}

func NewCipher(keys *shared.SessionKeys, sessionID string) (*Cipher, error) {
	if keys == nil {
		return nil, fmt.Errorf("session keys are required")
	}
	inner, err := shared.NewInnerCipher(
		keys.ServerToClientKey,
		keys.ClientToServerKey,
		keys.ServerToClientNonceBase,
		keys.ClientToServerNonceBase,
		sessionID,
		"server-to-client",
		"client-to-server",
	)
	if err != nil {
		return nil, err
	}
	return &Cipher{inner: inner}, nil
}

func (c *Cipher) Encrypt(data []byte) ([]byte, error) {
	return c.inner.Encrypt(data)
}

func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	return c.inner.Decrypt(data)
}
