package clientcore

import (
	"bytes"
	"testing"
	"time"

	"chameleon/shared"
)

func TestShouldFlushUplinkBatchBoundsContinuousSmallPackets(t *testing.T) {
	started := time.Unix(100, 0)
	if shouldFlushUplinkBatch(512, started, started.Add(3*time.Millisecond)) {
		t.Fatal("small uplink batch flushed before its latency bound")
	}
	if !shouldFlushUplinkBatch(512, started, started.Add(uplinkForceFlushAfter)) {
		t.Fatal("continuous small packets postponed the uplink latency bound")
	}
}

func TestProcessInboundBatchPreservesOrderAtReplayWindowLimit(t *testing.T) {
	keys, err := shared.DeriveSessionKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 32), bytes.Repeat([]byte{1}, 32),
		"batch-session", "batch-client", "batch-instance",
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := NewCipher(keys, "batch-session")
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := shared.NewInnerCipher(
		keys.ServerToClientKey, keys.ClientToServerKey,
		keys.ServerToClientNonceBase, keys.ClientToServerNonceBase,
		"batch-session", "server-to-client", "client-to-server",
	)
	if err != nil {
		t.Fatal(err)
	}

	encrypted := make([][]byte, maxPollBatchPackets)
	for index := range encrypted {
		encrypted[index], err = serverCipher.Encrypt([]byte{byte(index)})
		if err != nil {
			t.Fatal(err)
		}
	}
	var received [][]byte
	engine := &BehaviorEngine{
		mode:   shared.BehaviorActive,
		cipher: clientCipher,
		inboundFn: func(packet []byte) {
			received = append(received, append([]byte(nil), packet...))
		},
	}
	engine.processInboundBatch(encrypted, 0)

	if len(received) != len(encrypted) {
		t.Fatalf("received %d packets, want %d", len(received), len(encrypted))
	}
	for index, packet := range received {
		if !bytes.Equal(packet, []byte{byte(index)}) {
			t.Fatalf("packet %d = %v", index, packet)
		}
	}
}

func TestShouldFlushUplinkBatchFlushesBySize(t *testing.T) {
	now := time.Unix(100, 0)
	if !shouldFlushUplinkBatch(uplinkMinBatchBytes, now, now) {
		t.Fatal("full uplink batch was not flushed immediately")
	}
}

func TestShouldFlushUplinkBatchNeedsStartTime(t *testing.T) {
	if shouldFlushUplinkBatch(512, time.Time{}, time.Unix(100, 0)) {
		t.Fatal("empty batch state triggered a latency flush")
	}
}
