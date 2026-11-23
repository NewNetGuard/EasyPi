package main

import (
	"context"
	"testing"
	"time"
)

func TestHTTP2DownlinkCoalescingKeepsControlPacketsResponsive(t *testing.T) {
	for i := 0; i < 128; i++ {
		delay := serverAdaptiveCoalesceDelay(64)
		if delay < time.Millisecond || delay > 3*time.Millisecond {
			t.Fatalf("small packet delay outside 1-3 ms: %s", delay)
		}
	}
	if delay := serverAdaptiveCoalesceDelay(4 * 1024); delay != 0 {
		t.Fatalf("ready data batch was delayed by %s", delay)
	}
}

func TestNewestCarrierCancelsStaleOwner(t *testing.T) {
	session := newClientSession()
	first, releaseFirst, newFirst := session.replaceCarrier(context.Background(), "first")
	second, releaseSecond, newSecond := session.replaceCarrier(context.Background(), "first")
	if newFirst || newSecond {
		t.Fatal("same client process was treated as a new epoch")
	}

	select {
	case <-first.Done():
	default:
		t.Fatal("replacement carrier did not cancel stale owner")
	}
	select {
	case <-second.Done():
		t.Fatal("new carrier was cancelled with stale owner")
	default:
	}

	releaseFirst()
	select {
	case <-second.Done():
		t.Fatal("stale release cancelled the current carrier")
	default:
	}

	releaseSecond()
	select {
	case <-second.Done():
	default:
		t.Fatal("current carrier release did not cancel its context")
	}
}

func TestNewClientInstanceStartsFreshDownlinkEpoch(t *testing.T) {
	session := newClientSession()
	_, releaseFirst, _ := session.replaceCarrier(context.Background(), "first")
	session.downlinkNext = 7
	session.downlinkPending = []pendingDownlinkFrame{{sequence: 7, payload: []byte("stale")}}
	session.downlinkBytes = 5
	session.outbox <- []byte("stale")

	_, releaseSecond, newEpoch := session.replaceCarrier(context.Background(), "second")
	if !newEpoch {
		t.Fatal("new client process did not start a new epoch")
	}
	session.resetClientEpoch()
	if session.downlinkNext != 0 || len(session.downlinkPending) != 0 || session.downlinkBytes != 0 {
		t.Fatal("stale downlink sequence state survived client restart")
	}
	if len(session.outbox) != 0 {
		t.Fatal("stale outbound packet survived client restart")
	}

	releaseFirst()
	releaseSecond()
}
