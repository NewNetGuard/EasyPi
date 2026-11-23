package clientcore

import (
	"bytes"
	"context"
	"testing"
)

func TestPollBatchDrainsQueuedStreamPayloadsInOrder(t *testing.T) {
	transport := &Transport{
		streamEnabled: true,
		streamRx:      make(chan []byte, 8),
		pendingRx:     [][]byte{{1}, {2}},
	}
	transport.streamRx <- []byte{3}
	transport.streamRx <- []byte{4}

	batch, err := transport.PollBatch(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 4 {
		t.Fatalf("got %d payloads, want 4", len(batch))
	}
	for index, want := range [][]byte{{1}, {2}, {3}, {4}} {
		if !bytes.Equal(batch[index], want) {
			t.Fatalf("payload %d = %v, want %v", index, batch[index], want)
		}
	}
}

func TestPollBatchHonorsBound(t *testing.T) {
	transport := &Transport{
		streamEnabled: true,
		streamRx:      make(chan []byte, maxPollBatchPackets+2),
		ctx:           context.Background(),
	}
	transport.connectCarrierEnabled.Store(true)
	for index := 0; index < maxPollBatchPackets+2; index++ {
		transport.streamRx <- []byte{byte(index)}
	}

	batch, err := transport.PollBatch(maxPollBatchPackets + 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != maxPollBatchPackets {
		t.Fatalf("got %d payloads, want bounded %d", len(batch), maxPollBatchPackets)
	}
}
