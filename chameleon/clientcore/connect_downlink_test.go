package clientcore

import (
	"bytes"
	"context"
	"testing"
)

func TestPollDrainsConnectDownlinkDuringReconnect(t *testing.T) {
	transport := &Transport{
		ctx: context.Background(), streamEnabled: true, streamRx: make(chan []byte, 1),
	}
	transport.connectCarrierEnabled.Store(true)
	want := []byte("queued reply")
	transport.streamRx <- want

	got, err := transport.Poll()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Poll() = %q, %v; want %q", got, err, want)
	}
}
