package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func framedPayload(payload []byte) []byte {
	var length [4]byte
	length[0] = byte(len(payload) >> 24)
	length[1] = byte(len(payload) >> 16)
	length[2] = byte(len(payload) >> 8)
	length[3] = byte(len(payload))
	return append(length[:], payload...)
}

func ipv4PacketFrom(source, destination [4]byte) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[3] = 20
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	return packet
}

// A decrypted packet whose source is not the device's tunnel address is a
// stray packet (for example from a flow the client's NAT forgot), not an
// integrity failure: it must be dropped without closing the upload stream.
func TestPushDropsUnassignedSourcePacketsAndKeepsTheStream(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	psk := []byte("push-source-drop-secret")
	_, cryptoSession, clientCipher := newTestCryptoPair(t, psk)
	demasker := NewDemasker(psk)
	defer demasker.Stop()

	var body bytes.Buffer
	for i := 0; i < 3; i++ {
		encrypted, err := clientCipher.Encrypt(ipv4PacketFrom([4]byte{10, 23, 1, 34}, [4]byte{192, 0, 2, 1}))
		if err != nil {
			t.Fatal(err)
		}
		body.Write(framedPayload(encrypted))
	}

	var status int
	output := capturePrivacyLogs(t, func() {
		req := httptest.NewRequest(http.MethodPost, "https://example.invalid/upload", &body)
		req.Header.Set("Content-Type", "application/octet-stream")
		ctx := context.WithValue(req.Context(), contextKeyClientID, cryptoSession.clientID)
		ctx = context.WithValue(ctx, contextKeyCryptoSession, cryptoSession)
		resp := httptest.NewRecorder()
		handlePush(demasker)(resp, req.WithContext(ctx))
		status = resp.Code
	})

	if status != http.StatusNoContent {
		t.Fatalf("stream with stray packets returned %d, want %d", status, http.StatusNoContent)
	}
	if !strings.Contains(output, "[push] dropped packet from unassigned source") {
		t.Fatalf("drop event missing: %q", output)
	}
	if strings.Contains(output, "tunnel payload rejected") || strings.Contains(output, "10.23.1.34") {
		t.Fatalf("stray packet closed the stream or leaked its address: %q", output)
	}
}

// Authentication failures still close the stream.
func TestPushStillClosesTheStreamOnUndecryptablePayload(t *testing.T) {
	resetSecurityTestSessions()
	defer resetSecurityTestSessions()
	psk := []byte("push-source-drop-auth-secret")
	_, cryptoSession, _ := newTestCryptoPair(t, psk)
	demasker := NewDemasker(psk)
	defer demasker.Stop()

	body := bytes.NewReader(framedPayload([]byte("not an authenticated payload")))
	req := httptest.NewRequest(http.MethodPost, "https://example.invalid/upload", body)
	req.Header.Set("Content-Type", "application/octet-stream")
	ctx := context.WithValue(req.Context(), contextKeyClientID, cryptoSession.clientID)
	ctx = context.WithValue(ctx, contextKeyCryptoSession, cryptoSession)
	resp := httptest.NewRecorder()
	handlePush(demasker)(resp, req.WithContext(ctx))
	if resp.Code != http.StatusBadGateway {
		t.Fatalf("undecryptable payload returned %d, want %d", resp.Code, http.StatusBadGateway)
	}
}
