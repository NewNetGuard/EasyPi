package shared

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func testInnerPair(t *testing.T) (*InnerCipher, *InnerCipher) {
	t.Helper()
	keys, err := DeriveSessionKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 32), bytesOf(1, 32),
		"session-test", "client-test", "instance-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewInnerCipher(
		keys.ClientToServerKey, keys.ServerToClientKey,
		keys.ClientToServerNonceBase, keys.ServerToClientNonceBase,
		"session-test", "client-to-server", "server-to-client",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewInnerCipher(
		keys.ServerToClientKey, keys.ClientToServerKey,
		keys.ServerToClientNonceBase, keys.ClientToServerNonceBase,
		"session-test", "server-to-client", "client-to-server",
	)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func TestInnerCipherRejectsConcurrentReplay(t *testing.T) {
	client, server := testInnerPair(t)
	packet, err := client.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := server.Decrypt(packet); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("concurrent replay accepted %d times", got)
	}
}

func TestInnerCipherSlidingWindow(t *testing.T) {
	client, server := testInnerPair(t)
	packets := make([][]byte, 130)
	for i := range packets {
		var err error
		packets[i], err = client.Encrypt([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.Decrypt(packets[129]); err != nil {
		t.Fatalf("newest packet rejected: %v", err)
	}
	if _, err := server.Decrypt(packets[2]); err != nil {
		t.Fatalf("packet inside sliding window rejected: %v", err)
	}
	if _, err := server.Decrypt(packets[2]); !errors.Is(err, ErrInnerReplay) {
		t.Fatalf("duplicate inside window returned %v", err)
	}
	if _, err := server.Decrypt(packets[1]); !errors.Is(err, ErrInnerReplay) {
		t.Fatalf("packet outside sliding window returned %v", err)
	}
}

func TestInnerCipherSessionBinding(t *testing.T) {
	client, _ := testInnerPair(t)
	packet, err := client.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveSessionKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 32), bytesOf(2, 32),
		"other-session", "client-test", "instance-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewInnerCipher(
		keys.ServerToClientKey, keys.ClientToServerKey,
		keys.ServerToClientNonceBase, keys.ClientToServerNonceBase,
		"other-session", "server-to-client", "client-to-server",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Decrypt(packet); err == nil {
		t.Fatal("packet from another session was accepted")
	}
}

func TestInnerCipherCounterExhaustionNeverWraps(t *testing.T) {
	client, _ := testInnerPair(t)
	client.sendNext.Store(^uint64(0))
	for i := 0; i < 2; i++ {
		if _, err := client.Encrypt([]byte("payload")); !errors.Is(err, ErrInnerCounterExhaust) {
			t.Fatalf("exhausted counter attempt %d returned %v", i+1, err)
		}
	}
}
