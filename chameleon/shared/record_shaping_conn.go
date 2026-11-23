package shared

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	ExternalRecordMinChunk     = 3 * 1024
	ExternalRecordMaxChunk     = 14 * 1024
	ExternalRecordMaxLatency   = 24 * time.Millisecond
	ExternalRecordMaxQueue     = 1024 * 1024
	externalRecordDefaultQueue = 512 * 1024
	externalRecordDrainTimeout = 500 * time.Millisecond
)

// RecordShapingOptions is intentionally internal-policy shaped rather than
// user-configurable. The exported fields make deterministic bounds testable by
// both endpoints without allowing runtime configuration to exceed hard limits.
type RecordShapingOptions struct {
	MinChunkBytes        int
	MaxChunkBytes        int
	MaxQueueBytes        int
	CoalesceMin          time.Duration
	CoalesceMax          time.Duration
	MaxPacing            time.Duration
	SenderPacingMode     SenderPacingMode
	InitialBurstMinBytes int
	InitialBurstMaxBytes int
	TailRateMinBytes     int
	TailRateMaxBytes     int
	KernelBacklogBytes   int
	ObserveHTTP2Flow     bool
	// CoalesceHTTP2WindowUpdates returns HTTP/2 flow-control credit at half
	// a window, as browsers do, instead of x/net's every 4 KiB.
	CoalesceHTTP2WindowUpdates bool
	// BrowserRecords writes each batch whole so TLS fills records to the
	// maximum, as Chrome (BoringSSL) does: a bulk transfer goes out in
	// full-size records, a short write in one record of its own size. A
	// capture of Chrome 158 uploading 25 MB showed 1485 of 1487 records at the
	// full 16401 bytes, where splitting into random 3-14 KiB writes stood out.
	BrowserRecords bool
}

type ExternalRecordPlan struct {
	Chunks        []int
	CoalesceDelay time.Duration
	PacingDelay   time.Duration
}

func normalizedRecordShapingOptions(options RecordShapingOptions) RecordShapingOptions {
	if options.MinChunkBytes <= 0 {
		options.MinChunkBytes = ExternalRecordMinChunk
	}
	if options.MinChunkBytes > ExternalRecordMaxChunk {
		options.MinChunkBytes = ExternalRecordMaxChunk
	}
	if options.MaxChunkBytes <= 0 || options.MaxChunkBytes > ExternalRecordMaxChunk {
		options.MaxChunkBytes = ExternalRecordMaxChunk
	}
	if options.MaxChunkBytes < options.MinChunkBytes {
		options.MaxChunkBytes = options.MinChunkBytes
	}
	if options.MaxQueueBytes <= 0 {
		options.MaxQueueBytes = externalRecordDefaultQueue
	}
	if options.MaxQueueBytes > ExternalRecordMaxQueue {
		options.MaxQueueBytes = ExternalRecordMaxQueue
	}
	if options.SenderPacingMode == SenderPacingDefault || options.SenderPacingMode > SenderPacingUserspace {
		options.SenderPacingMode = SenderPacingUserspace
	}
	if options.SenderPacingMode == SenderPacingRecordOnly {
		// Record-only mode varies TLS application-record lengths but deliberately
		// leaves timing to TCP. Re-applying the default coalescing and per-chunk
		// delays here throttled the single HTTP/2 carrier, especially on download.
		options.CoalesceMin = 0
		options.CoalesceMax = 0
		options.MaxPacing = 0
	} else {
		if options.CoalesceMin < 0 {
			options.CoalesceMin = 0
		}
		if options.CoalesceMax <= 0 {
			options.CoalesceMax = 8 * time.Millisecond
		}
		if options.CoalesceMax > 8*time.Millisecond {
			options.CoalesceMax = 8 * time.Millisecond
		}
		if options.CoalesceMin > options.CoalesceMax {
			options.CoalesceMin = options.CoalesceMax
		}
		remaining := ExternalRecordMaxLatency - options.CoalesceMax
		if remaining < 0 {
			remaining = 0
		}
		if options.MaxPacing <= 0 {
			options.MaxPacing = 16 * time.Millisecond
		}
		if options.MaxPacing > remaining {
			options.MaxPacing = remaining
		}
	}
	if options.InitialBurstMinBytes <= 0 {
		options.InitialBurstMinBytes = persistentPacingDefaultBurstMin
	}
	if options.InitialBurstMinBytes < 8*1024 {
		options.InitialBurstMinBytes = 8 * 1024
	}
	if options.InitialBurstMinBytes > 256*1024 {
		options.InitialBurstMinBytes = 256 * 1024
	}
	if options.InitialBurstMaxBytes <= 0 {
		options.InitialBurstMaxBytes = persistentPacingDefaultBurstMax
	}
	if options.InitialBurstMaxBytes < options.InitialBurstMinBytes {
		options.InitialBurstMaxBytes = options.InitialBurstMinBytes
	}
	if options.InitialBurstMaxBytes > 256*1024 {
		options.InitialBurstMaxBytes = 256 * 1024
	}
	if options.TailRateMinBytes <= 0 {
		options.TailRateMinBytes = persistentPacingDefaultRateMin
	}
	if options.TailRateMinBytes < 1024*1024 {
		options.TailRateMinBytes = 1024 * 1024
	}
	if options.TailRateMinBytes > 256*1024*1024 {
		options.TailRateMinBytes = 256 * 1024 * 1024
	}
	if options.TailRateMaxBytes <= 0 {
		options.TailRateMaxBytes = persistentPacingDefaultRateMax
	}
	if options.TailRateMaxBytes < options.TailRateMinBytes {
		options.TailRateMaxBytes = options.TailRateMinBytes
	}
	if options.TailRateMaxBytes > 256*1024*1024 {
		options.TailRateMaxBytes = 256 * 1024 * 1024
	}
	if options.KernelBacklogBytes <= 0 {
		options.KernelBacklogBytes = persistentPacingDefaultBacklog
	}
	if options.KernelBacklogBytes > 512*1024 {
		options.KernelBacklogBytes = 512 * 1024
	}
	return options
}

type shapePRNG struct{ state uint64 }

func newShapePRNG(seed uint64) *shapePRNG {
	if seed == 0 {
		seed = 0x9e3779b97f4a7c15
	}
	return &shapePRNG{state: seed}
}

func (r *shapePRNG) next() uint64 {
	x := r.state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.state = x
	return x
}

func (r *shapePRNG) between(minimum, maximum int) int {
	if maximum <= minimum {
		return minimum
	}
	return minimum + int(r.next()%uint64(maximum-minimum+1))
}

// PlanExternalRecordShape splits an existing plaintext write into varied
// sub-16KiB writes. It never adds bytes. TLS therefore emits varied application
// record lengths without cover traffic or protocol-visible padding.
func PlanExternalRecordShape(payloadSize int, entropy uint64, options RecordShapingOptions) ExternalRecordPlan {
	if payloadSize <= 0 {
		return ExternalRecordPlan{}
	}
	options = normalizedRecordShapingOptions(options)
	rng := newShapePRNG(entropy)
	plan := ExternalRecordPlan{}
	if options.CoalesceMax > 0 {
		coalesceMin := options.CoalesceMin
		// HTTP/2 WINDOW_UPDATE frames commonly arrive as a 26-byte pair. Give
		// only these short control bursts enough time to merge with their next
		// sibling; data writes keep the full 0..8ms distribution.
		if payloadSize <= 128 && coalesceMin < 5*time.Millisecond {
			coalesceMin = 5 * time.Millisecond
		}
		if coalesceMin > options.CoalesceMax {
			coalesceMin = options.CoalesceMax
		}
		span := options.CoalesceMax - coalesceMin
		plan.CoalesceDelay = coalesceMin
		if span > 0 {
			plan.CoalesceDelay += time.Duration(rng.next() % uint64(span+1))
		}
	}

	if options.BrowserRecords {
		plan.Chunks = []int{payloadSize}
		return plan
	}

	remaining := payloadSize
	for remaining > 0 {
		if remaining <= options.MaxChunkBytes {
			plan.Chunks = append(plan.Chunks, remaining)
			break
		}
		maximum := options.MaxChunkBytes
		minimum := options.MinChunkBytes
		// Avoid leaving a tiny deterministic tail where possible.
		if tail := remaining - maximum; tail > 0 && tail < minimum/2 {
			maximum = remaining - minimum/2
		}
		if maximum < minimum {
			maximum = minimum
		}
		size := rng.between(minimum, maximum)
		plan.Chunks = append(plan.Chunks, size)
		remaining -= size
	}

	if len(plan.Chunks) > 1 && options.MaxPacing > 0 && payloadSize >= 8*1024 {
		limit := options.MaxPacing
		switch {
		case payloadSize < 16*1024 && limit > 3*time.Millisecond:
			limit = 3 * time.Millisecond
		case payloadSize < 64*1024 && limit > 8*time.Millisecond:
			limit = 8 * time.Millisecond
		}
		if limit > 0 {
			plan.PacingDelay = limit/2 + time.Duration(rng.next()%uint64(limit/2+1))
		}
	}
	return plan
}

// RecordShapingConn is a bounded asynchronous plaintext write buffer placed
// directly above TLS. Short HTTP/2 control writes can coalesce briefly, while
// larger writes are split and paced. Read behavior is untouched.
type RecordShapingConn struct {
	net.Conn
	options RecordShapingOptions

	mu          sync.Mutex
	pending     []byte
	queuedBytes int
	writing     bool
	closing     bool
	forceClosed bool
	writeErr    error
	stateChange chan struct{}
	wake        chan struct{}
	stop        chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	closeErr    error
	pacer       *persistentSenderPacer
	telemetry   tcpPacingTelemetry
	nextTCPInfo time.Time
	h2Flow      *h2FlowObserver
	// h2WindowMu keeps frame rewriting and queueing in write order.
	h2WindowMu sync.Mutex
	h2Window   *h2WindowCoalescer
}

func NewRecordShapingConn(conn net.Conn, options RecordShapingOptions) *RecordShapingConn {
	options = normalizedRecordShapingOptions(options)
	shaped := &RecordShapingConn{
		Conn:        conn,
		options:     options,
		stateChange: make(chan struct{}),
		wake:        make(chan struct{}, 1),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	if options.ObserveHTTP2Flow {
		shaped.h2Flow = newH2FlowObserver()
	}
	if options.CoalesceHTTP2WindowUpdates {
		shaped.h2Window = newH2WindowCoalescer()
	}
	if options.SenderPacingMode == SenderPacingUserspace {
		shaped.pacer = newPersistentSenderPacer(options, randomShapeEntropy())
	}
	go shaped.writeLoop()
	return shaped
}

func (c *RecordShapingConn) notifyLocked() {
	close(c.stateChange)
	c.stateChange = make(chan struct{})
}

func (c *RecordShapingConn) signalWorker() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *RecordShapingConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if c.h2Window != nil {
		c.h2WindowMu.Lock()
		defer c.h2WindowMu.Unlock()
		// The caller's bytes are fully consumed even when held credit makes
		// the wire output shorter; counters describe what is actually sent.
		out := c.h2Window.process(payload)
		if len(out) == 0 {
			return len(payload), nil
		}
		if c.h2Flow != nil {
			c.h2Flow.observe(out)
		}
		if _, err := c.enqueue(out); err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	if c.h2Flow != nil {
		c.h2Flow.observe(payload)
	}
	return c.enqueue(payload)
}

func (c *RecordShapingConn) enqueue(payload []byte) (int, error) {
	written := 0
	for written < len(payload) {
		pieceSize := len(payload) - written
		if pieceSize > c.options.MaxQueueBytes {
			pieceSize = c.options.MaxQueueBytes
		}
		for {
			c.mu.Lock()
			if c.forceClosed {
				c.mu.Unlock()
				if written > 0 {
					return written, nil
				}
				return 0, net.ErrClosed
			}
			if c.writeErr != nil {
				err := c.writeErr
				c.mu.Unlock()
				return written, err
			}
			if c.closing {
				c.mu.Unlock()
				return written, net.ErrClosed
			}
			if c.queuedBytes+pieceSize <= c.options.MaxQueueBytes {
				c.pending = append(c.pending, payload[written:written+pieceSize]...)
				c.queuedBytes += pieceSize
				c.notifyLocked()
				c.mu.Unlock()
				c.signalWorker()
				written += pieceSize
				break
			}
			changed := c.stateChange
			c.mu.Unlock()
			<-changed
		}
	}
	return written, nil
}

func (c *RecordShapingConn) writeLoop() {
	defer close(c.done)
	for {
		select {
		case <-c.wake:
		case <-c.stop:
			return
		}

		for {
			c.mu.Lock()
			if c.forceClosed || c.writeErr != nil {
				c.mu.Unlock()
				return
			}
			if len(c.pending) == 0 {
				closing := c.closing
				c.mu.Unlock()
				if closing {
					return
				}
				break
			}
			entropy := randomShapeEntropy()
			coalesce := PlanExternalRecordShape(len(c.pending), entropy, c.options).CoalesceDelay
			c.mu.Unlock()

			if coalesce > 0 {
				timer := time.NewTimer(coalesce)
				select {
				case <-timer.C:
				case <-c.stop:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return
				}
			}

			c.mu.Lock()
			if c.forceClosed || c.writeErr != nil {
				c.mu.Unlock()
				return
			}
			batch := bytesClone(c.pending)
			c.pending = c.pending[:0]
			c.writing = true
			c.notifyLocked()
			c.mu.Unlock()

			err := c.writeBatch(batch, randomShapeEntropy())

			c.mu.Lock()
			c.queuedBytes -= len(batch)
			c.writing = false
			if err != nil && c.writeErr == nil {
				c.writeErr = err
				c.pending = nil
				c.queuedBytes = 0
			}
			more := len(c.pending) > 0
			closing := c.closing
			c.notifyLocked()
			c.mu.Unlock()
			if err != nil {
				return
			}
			if !more {
				if closing {
					return
				}
				break
			}
		}
	}
}

func bytesClone(payload []byte) []byte {
	copyOfPayload := make([]byte, len(payload))
	copy(copyOfPayload, payload)
	return copyOfPayload
}

func randomShapeEntropy() uint64 {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return binary.LittleEndian.Uint64(raw[:])
	}
	return uint64(time.Now().UnixNano())
}

func (c *RecordShapingConn) writeBatch(payload []byte, entropy uint64) error {
	plan := PlanExternalRecordShape(len(payload), entropy, c.options)
	offset := 0
	gaps := len(plan.Chunks) - 1
	for index, size := range plan.Chunks {
		if c.pacer != nil {
			now := time.Now()
			if c.nextTCPInfo.IsZero() || !now.Before(c.nextTCPInfo) {
				if telemetry, ok := readTCPPacingTelemetry(c.Conn); ok {
					c.telemetry = telemetry
				}
				c.nextTCPInfo = now.Add(50 * time.Millisecond)
			}
			if delay := c.pacer.delayBeforeChunk(now, size, c.telemetry); delay > 0 {
				if err := c.waitPacingDelay(delay); err != nil {
					return err
				}
			}
		}
		if err := writeFull(c.Conn, payload[offset:offset+size]); err != nil {
			return err
		}
		offset += size
		if c.pacer == nil && index < gaps && plan.PacingDelay > 0 {
			delay := plan.PacingDelay / time.Duration(gaps)
			if index < int(plan.PacingDelay%time.Duration(gaps)) {
				delay++
			}
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-c.stop:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return net.ErrClosed
				}
			}
		}
	}
	return nil
}

func (c *RecordShapingConn) waitPacingDelay(delay time.Duration) error {
	timer := time.NewTimer(delay)
	select {
	case <-timer.C:
		return nil
	case <-c.stop:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return net.ErrClosed
	}
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *RecordShapingConn) Flush(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.writeErr != nil {
			err := c.writeErr
			c.mu.Unlock()
			return err
		}
		if c.queuedBytes == 0 && !c.writing && len(c.pending) == 0 {
			c.mu.Unlock()
			return nil
		}
		changed := c.stateChange
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *RecordShapingConn) CloseWrite() error {
	c.mu.Lock()
	if c.forceClosed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closing = true
	c.notifyLocked()
	c.mu.Unlock()
	c.signalWorker()

	ctx, cancel := context.WithTimeout(context.Background(), externalRecordDrainTimeout)
	err := c.Flush(ctx)
	cancel()
	if err != nil {
		return err
	}
	select {
	case <-c.done:
	case <-time.After(externalRecordDrainTimeout):
		return context.DeadlineExceeded
	}
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.New("underlying connection does not support CloseWrite")
}

func (c *RecordShapingConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.notifyLocked()
		c.mu.Unlock()
		c.signalWorker()

		ctx, cancel := context.WithTimeout(context.Background(), externalRecordDrainTimeout)
		flushErr := c.Flush(ctx)
		cancel()

		c.mu.Lock()
		c.forceClosed = true
		c.pending = nil
		c.queuedBytes = 0
		c.notifyLocked()
		c.mu.Unlock()
		close(c.stop)
		c.signalWorker()
		connErr := c.Conn.Close()
		c.closeErr = errors.Join(flushErr, connErr)
	})
	select {
	case <-c.done:
	case <-time.After(externalRecordDrainTimeout):
	}
	return c.closeErr
}

// ConnectionState preserves TLS metadata discovery in x/net/http2 after the
// uTLS/tls connection is wrapped by the shaper.
func (c *RecordShapingConn) ConnectionState() tls.ConnectionState {
	if state, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return state.ConnectionState()
	}
	return tls.ConnectionState{}
}
