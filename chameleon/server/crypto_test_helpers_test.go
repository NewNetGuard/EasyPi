package main

import (
	"context"
	"strings"
	"testing"

	"chameleon/clientcore"
	"chameleon/shared"
)

func newTestCryptoPair(t *testing.T, psk []byte) (*cryptoSessionManager, *cryptoSession, *clientcore.Cipher) {
	t.Helper()
	clientID := shared.ClientIDForPSK(psk)
	sessionID := strings.Repeat("ab", 32)
	clientInstance := strings.Repeat("cd", 16)
	clientNonce := make([]byte, 32)
	serverNonce := make([]byte, 32)
	for i := range serverNonce {
		serverNonce[i] = 1
	}
	keys, err := shared.DeriveSessionKeys(psk, clientNonce, serverNonce, sessionID, clientID, clientInstance)
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := NewCipher(keys, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := clientcore.NewCipher(keys, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	sessionContext, cancelSession := context.WithCancel(context.Background())
	t.Cleanup(cancelSession)
	session := &cryptoSession{
		id:             sessionID,
		clientID:       clientID,
		clientInstance: clientInstance,
		authKey:        append([]byte(nil), keys.AuthKey...),
		streamKey:      append([]byte(nil), keys.StreamKey...),
		cipher:         serverCipher,
		nonces:         newReplayNonceStore(),
		ctx:            sessionContext,
		cancel:         cancelSession,
	}
	session.touch()
	manager := newCryptoSessionManager(psk)
	manager.sessions[sessionID] = session
	manager.activeByClient[session.runtimeID()] = sessionID
	return manager, session, clientCipher
}
