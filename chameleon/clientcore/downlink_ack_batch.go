package clientcore

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"chameleon/shared"
)

// A browser acknowledges a download with rare HTTP/2 WINDOW_UPDATE frames
// against a 15 MiB window, not with a small record every few packets. ACKs
// are therefore cumulative over up to ~1 MiB or about a second, which stays
// well inside the server's retained-downlink limit (2048 packets / 4 MiB).
const (
	downlinkAckMinDelay   = 400 * time.Millisecond
	downlinkAckMaxDelay   = 1200 * time.Millisecond
	downlinkAckMaxAdvance = uint64(768)
)

type downlinkAckWriteReason uint8

const (
	downlinkAckWriteForced downlinkAckWriteReason = iota
	downlinkAckWriteTimer
	downlinkAckWriteThreshold
	downlinkAckWritePiggyback
)

// downlinkAckBatcher turns per-packet notifications into cumulative ACKs. It
// prefers piggybacking the newest ACK on useful uplink data, but bounds server
// replay memory with both a short timer and a maximum sequence advance.
type downlinkAckBatcher struct {
	transport *Transport
	writer    io.Writer

	lastWritten uint64
	timer       *time.Timer
	timerC      <-chan time.Time
	minDelay    time.Duration
	maxDelay    time.Duration
	maxAdvance  uint64
}

func newDownlinkAckBatcher(transport *Transport, writer io.Writer) *downlinkAckBatcher {
	return &downlinkAckBatcher{
		transport:  transport,
		writer:     writer,
		minDelay:   downlinkAckMinDelay,
		maxDelay:   downlinkAckMaxDelay,
		maxAdvance: downlinkAckMaxAdvance,
	}
}

func (b *downlinkAckBatcher) nextDelay() time.Duration {
	if b.maxDelay <= b.minDelay {
		return b.minDelay
	}
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return b.minDelay + (b.maxDelay-b.minDelay)/2
	}
	// A single random byte spread only 0-255 ns over the window, so every
	// ACK left at the minimum delay with a machine-regular rhythm.
	span := uint64(b.maxDelay - b.minDelay)
	return b.minDelay + time.Duration(binary.BigEndian.Uint64(entropy[:])%(span+1))
}

func (b *downlinkAckBatcher) timerChannel() <-chan time.Time {
	return b.timerC
}

func (b *downlinkAckBatcher) stopTimer() {
	if b.timer != nil && !b.timer.Stop() {
		select {
		case <-b.timer.C:
		default:
		}
	}
	b.timer = nil
	b.timerC = nil
}

func (b *downlinkAckBatcher) close() {
	b.stopTimer()
}

// notify schedules a cumulative ACK. Large bursts are acknowledged
// immediately; small bursts get a bounded opportunity to merge with useful
// uplink data or with later ACK notifications.
func (b *downlinkAckBatcher) notify() error {
	sequence := b.transport.downlinkAck.Load()
	if sequence == 0 || sequence <= b.lastWritten {
		return nil
	}
	if b.maxAdvance > 0 && sequence-b.lastWritten >= b.maxAdvance {
		return b.flush(downlinkAckWriteThreshold)
	}
	if b.timerC == nil {
		b.timer = time.NewTimer(b.nextDelay())
		b.timerC = b.timer.C
	}
	return nil
}

func (b *downlinkAckBatcher) flush(reason downlinkAckWriteReason) error {
	return b.writeBatch(nil, reason)
}

// writeBatch prepends the newest cumulative ACK to a useful uplink batch and
// applies record shaping once to the combined write. This avoids producing a
// separate small TLS application record for the ACK.
func (b *downlinkAckBatcher) writeBatch(batch [][]byte, reason downlinkAckWriteReason) error {
	body, _ := encodeBinaryBatch(batch)
	sequence := b.transport.downlinkAck.Load()
	ackIncluded := sequence > b.lastWritten
	if ackIncluded {
		body = append(encodeDownlinkAckFrame(sequence), body...)
	}
	if len(body) == 0 {
		return nil
	}
	if b.transport.recordShapeEnabled.Load() {
		body = shared.ShapeBinaryRecord(body)
	}
	if _, err := b.writer.Write(body); err != nil {
		return err
	}
	if ackIncluded {
		b.transport.downlinkAckConfirmed.Add(sequence - b.lastWritten)
		switch reason {
		case downlinkAckWriteTimer:
			b.transport.downlinkAckTimer.Add(1)
		case downlinkAckWriteThreshold:
			b.transport.downlinkAckThreshold.Add(1)
		case downlinkAckWritePiggyback:
			b.transport.downlinkAckPiggyback.Add(1)
		default:
			b.transport.downlinkAckForced.Add(1)
		}
		b.lastWritten = sequence
		b.stopTimer()
	}
	return nil
}
