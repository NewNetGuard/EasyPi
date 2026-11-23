package shared

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
)

const (
	h2FrameHeaderSize       = 9
	h2WindowUpdateFrameType = 0x8
	h2WindowUpdateSize      = 4
	h2MaxFramePayload       = (1 << 24) - 1
)

var h2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

var h2FlowCounters struct {
	frames                    atomic.Uint64
	initialConnectionUpdates  atomic.Uint64
	reactiveConnectionUpdates atomic.Uint64
	streamUpdates             atomic.Uint64
	creditBytes               atomic.Uint64
}

// H2FlowControlStats contains process-lifetime counters for plaintext HTTP/2
// frames emitted by the outer client carrier. Payload content is never kept.
type H2FlowControlStats struct {
	Frames                    uint64
	InitialConnectionUpdates  uint64
	ReactiveConnectionUpdates uint64
	StreamUpdates             uint64
	CreditBytes               uint64
}

// CurrentH2FlowControlStats returns a race-free snapshot for the status file.
func CurrentH2FlowControlStats() H2FlowControlStats {
	return H2FlowControlStats{
		Frames:                    h2FlowCounters.frames.Load(),
		InitialConnectionUpdates:  h2FlowCounters.initialConnectionUpdates.Load(),
		ReactiveConnectionUpdates: h2FlowCounters.reactiveConnectionUpdates.Load(),
		StreamUpdates:             h2FlowCounters.streamUpdates.Load(),
		CreditBytes:               h2FlowCounters.creditBytes.Load(),
	}
}

type h2FlowObserver struct {
	mu                    sync.Mutex
	buffer                []byte
	prefaceConsumed       bool
	initialConnectionSeen bool
}

func newH2FlowObserver() *h2FlowObserver {
	return &h2FlowObserver{buffer: make([]byte, 0, 256)}
}

func (o *h2FlowObserver) observe(payload []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.buffer = append(o.buffer, payload...)
	if !o.prefaceConsumed {
		if len(o.buffer) < len(h2ClientPreface) {
			if !bytes.Equal(o.buffer, h2ClientPreface[:len(o.buffer)]) {
				o.buffer = o.buffer[:0]
			}
			return
		}
		if !bytes.Equal(o.buffer[:len(h2ClientPreface)], h2ClientPreface) {
			o.buffer = o.buffer[:0]
			return
		}
		o.buffer = o.buffer[len(h2ClientPreface):]
		o.prefaceConsumed = true
	}

	for len(o.buffer) >= h2FrameHeaderSize {
		length := int(o.buffer[0])<<16 | int(o.buffer[1])<<8 | int(o.buffer[2])
		if length < 0 || length > h2MaxFramePayload {
			o.buffer = o.buffer[:0]
			return
		}
		frameSize := h2FrameHeaderSize + length
		if len(o.buffer) < frameSize {
			return
		}
		frame := o.buffer[:frameSize]
		h2FlowCounters.frames.Add(1)
		if frame[3] == h2WindowUpdateFrameType && length == h2WindowUpdateSize {
			streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
			credit := binary.BigEndian.Uint32(frame[9:13]) & 0x7fffffff
			h2FlowCounters.creditBytes.Add(uint64(credit))
			switch {
			case streamID != 0:
				h2FlowCounters.streamUpdates.Add(1)
			case !o.initialConnectionSeen:
				o.initialConnectionSeen = true
				h2FlowCounters.initialConnectionUpdates.Add(1)
			default:
				h2FlowCounters.reactiveConnectionUpdates.Add(1)
			}
		}
		o.buffer = o.buffer[frameSize:]
	}
}
