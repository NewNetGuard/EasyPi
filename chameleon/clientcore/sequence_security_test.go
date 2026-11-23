package clientcore

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSequencedDownlinkRegistrationIsAtomic(t *testing.T) {
	transport := &Transport{}
	var fresh atomic.Int32
	var valid atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ready, isValid := transport.registerSequencedDownlink(1, []byte("payload"))
			if len(ready) > 0 {
				fresh.Add(1)
			}
			if isValid {
				valid.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := fresh.Load(); got != 1 {
		t.Fatalf("same sequence registered as fresh %d times", got)
	}
	if got := valid.Load(); got != 64 {
		t.Fatalf("duplicate acknowledgements were not treated as valid: %d", got)
	}
}

func TestSequencedDownlinkReordersAcrossCarriers(t *testing.T) {
	transport := &Transport{}
	ready, valid := transport.registerSequencedDownlink(2, []byte("second"))
	if !valid || len(ready) != 0 {
		t.Fatalf("early second packet returned ready=%q valid=%v", ready, valid)
	}
	ready, valid = transport.registerSequencedDownlink(1, []byte("first"))
	if !valid || len(ready) != 2 {
		t.Fatalf("gap closure returned %d packets, valid=%v", len(ready), valid)
	}
	if !bytes.Equal(ready[0], []byte("first")) || !bytes.Equal(ready[1], []byte("second")) {
		t.Fatalf("reordered payloads = %q", ready)
	}
	if got := transport.downlinkAck.Load(); got != 2 {
		t.Fatalf("cumulative acknowledgement = %d, want 2", got)
	}
}
