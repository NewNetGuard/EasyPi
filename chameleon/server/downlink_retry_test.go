package main

import (
	"bytes"
	"testing"
)

func TestReservedDownlinkCiphertextIsStableForEpochRetry(t *testing.T) {
	_, cryptoSession, _ := newTestCryptoPair(t, []byte("0123456789abcdef0123456789abcdef"))
	session := newClientSession()
	reserved, err := session.reserveDownlinkBatch([][]byte{[]byte("payload")}, cryptoSession.cipher)
	if err != nil {
		t.Fatal(err)
	}
	if len(reserved) != 1 || len(reserved[0].encrypted) == 0 {
		t.Fatalf("reserved frame did not cache ciphertext: %#v", reserved)
	}
	snapshot := session.pendingDownlinkSnapshot(1, 1024)
	if len(snapshot) != 1 || !bytes.Equal(snapshot[0].encrypted, reserved[0].encrypted) {
		t.Fatal("retry snapshot changed the authenticated ciphertext")
	}
}
