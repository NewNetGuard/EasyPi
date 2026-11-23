package clientcore

import (
	"math"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/shared"
)

// Standalone cover packets create a machine-like periodic baseline that normal
// browser sessions do not have. Keep the implementation for controlled lab
// experiments, but never enable it in the shipping runtime.
const runtimeCoverTrafficEnabled = false

const (
	uplinkMinBatchBytes   = 64 * 1024
	uplinkForceFlushAfter = 4 * time.Millisecond
)

func shouldFlushUplinkBatch(batchBytes int, batchStarted, now time.Time) bool {
	return batchBytes >= uplinkMinBatchBytes ||
		(!batchStarted.IsZero() && now.Sub(batchStarted) >= uplinkForceFlushAfter)
}

// BehaviorConfig defines timing parameters for each mode.
type BehaviorConfig struct {
	PushMinInterval time.Duration
	PushMaxInterval time.Duration
	PollTimeout     time.Duration
	MinPayloadSize  int
	MaxPayloadSize  int
	SyncMinInterval time.Duration
	SyncMaxInterval time.Duration
}

var behaviorConfigs = map[shared.BehaviorMode]BehaviorConfig{
	shared.BehaviorActive: {
		PushMinInterval: 50 * time.Millisecond,
		PushMaxInterval: 200 * time.Millisecond,
		PollTimeout:     0, // continuous
		MinPayloadSize:  200,
		MaxPayloadSize:  1400,
		SyncMinInterval: 2 * time.Minute,
		SyncMaxInterval: 7 * time.Minute,
	},
	shared.BehaviorBackground: {
		PushMinInterval: 5 * time.Second,
		PushMaxInterval: 30 * time.Second,
		PollTimeout:     60 * time.Second,
		MinPayloadSize:  50,
		MaxPayloadSize:  200,
		SyncMinInterval: 5 * time.Minute,
		SyncMaxInterval: 15 * time.Minute,
	},
	shared.BehaviorIdle: {
		PushMinInterval: 0, // no push
		PushMaxInterval: 0,
		PollTimeout:     0, // no poll
		MinPayloadSize:  0,
		MaxPayloadSize:  0,
		SyncMinInterval: 12 * time.Minute,
		SyncMaxInterval: 30 * time.Minute,
	},
}

// BehaviorEngine manages mode transitions and timing.
type BehaviorEngine struct {
	mu           sync.RWMutex
	mode         shared.BehaviorMode
	lastActivity time.Time
	transport    *Transport
	cipher       *Cipher
	masker       *Masker
	inboundFn    func([]byte)
	stopChan     chan struct{}
	pushQueue    chan []byte

	// Thresholds
	// Thresholds
	backgroundAfter time.Duration
	idleAfter       time.Duration

	profile *ProfileManager
	psk     []byte
}

type inboundDecryptResult struct {
	payload []byte
	err     error
}

// NewBehaviorEngine creates a new behavior engine.
func NewBehaviorEngine(transport *Transport, cipher *Cipher, masker *Masker, inboundFn func([]byte), pm *ProfileManager, psk []byte) *BehaviorEngine {
	return &BehaviorEngine{
		mode:            shared.BehaviorActive,
		lastActivity:    time.Now(),
		transport:       transport,
		cipher:          cipher,
		masker:          masker,
		inboundFn:       inboundFn,
		stopChan:        make(chan struct{}),
		pushQueue:       make(chan []byte, 65536),
		backgroundAfter: 30 * time.Minute,
		idleAfter:       4 * time.Hour,
		profile:         pm,
		psk:             psk,
	}
}

// Start begins the behavior engine loops.
func (b *BehaviorEngine) Start() {
	go b.modeWatcher()
	go b.pushLoop()

	pollWorkers := 8
	if b.transport != nil && b.transport.UsesDownlinkStream() {
		// In stream mode additional poll workers only add CPU/wakeups noise.
		pollWorkers = 1
	}

	for i := 0; i < pollWorkers; i++ {
		go b.pollLoop(i)
	}
	go b.syncLoop()
	if runtimeCoverTrafficEnabled && b.transport != nil && b.cipher != nil && b.profile != nil {
		go b.coverTrafficLoop()
	}
}

// Stop shuts down the behavior engine.
func (b *BehaviorEngine) Stop() {
	close(b.stopChan)
}

// RecordActivity resets the activity timer (called when real data needs to be sent).
func (b *BehaviorEngine) RecordActivity() {
	b.mu.Lock()
	b.lastActivity = time.Now()
	if b.mode != shared.BehaviorActive {
		b.mode = shared.BehaviorActive
	}
	b.mu.Unlock()
}

// RecordInboundActivity marks inbound traffic as real activity so the engine
// does not downgrade to background during long download-heavy sessions.
func (b *BehaviorEngine) RecordInboundActivity(size int) {
	if size > 0 && b.profile != nil {
		b.profile.RecordActivity(size, false)
	}
	b.RecordActivity()
}

// enqueueOne places one packet into push queue with a very short wait.
func (b *BehaviorEngine) enqueueOne(data []byte) bool {
	select {
	case b.pushQueue <- data:
		return true
	default:
	}

	timer := time.NewTimer(2 * time.Millisecond)
	defer timer.Stop()
	select {
	case b.pushQueue <- data:
		return true
	case <-timer.C:
		return false
	case <-b.stopChan:
		return false
	}
}

// EnqueueBatchData queues padded packets (Masker.PadBatch) for push with one
// activity update. pushLoop encrypts them per write.
func (b *BehaviorEngine) EnqueueBatchData(batch [][]byte) {
	if len(batch) == 0 {
		return
	}
	b.RecordActivity()

	dropped := 0
	for _, data := range batch {
		if len(data) == 0 {
			continue
		}
		if !b.enqueueOne(data) {
			dropped++
		}
	}
	if dropped > 0 {
		LogRateLimitedEvent("behavior", "packets dropped because push queue is full")
	}
}

// GetMode returns the current behavior mode.
func (b *BehaviorEngine) GetMode() shared.BehaviorMode {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.mode
}

// modeWatcher auto-transitions between modes based on activity.
func (b *BehaviorEngine) modeWatcher() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.mu.Lock()
			elapsed := time.Since(b.lastActivity)

			newMode := b.mode
			if elapsed > b.idleAfter {
				newMode = shared.BehaviorIdle
			} else if elapsed > b.backgroundAfter {
				newMode = shared.BehaviorBackground
			}

			if newMode != b.mode {
				b.mode = newMode
			}
			b.mu.Unlock()
		}
	}
}

// pushLoop batches packets by bytes (16-64KB target) for better throughput.
func (b *BehaviorEngine) pushLoop() {
	// Keep one short batching window here. The persistent HTTP/2 upload
	// carrier writes the resulting batch immediately, so small TCP ACKs do
	// not wait in two independent coalescing stages.
	const (
		maxBatchPackets      = 2048
		targetBatchBytes     = 512 * 1024
		flushInterval        = 2 * time.Millisecond
		maxPendingBatches    = 1024
		backpressureQueueLen = 6144
		workerQueueWait      = 4 * time.Millisecond
	)

	// Scale workers conservatively to avoid self-overload on one H2 connection.
	numWorkers := runtime.GOMAXPROCS(0) + 4
	if b.transport != nil && b.transport.UsesUplinkStream() {
		// One writer preserves the order in which inner-AEAD counters were
		// assigned. The persistent HTTP/2 request serializes writes anyway, so
		// additional workers cannot increase carrier throughput.
		numWorkers = 1
	} else {
		if b.transport != nil && b.transport.UsesDownlinkStream() {
			numWorkers += 2
		}
		if numWorkers < 6 {
			numWorkers = 6
		}
		if numWorkers > 16 {
			numWorkers = 16
		}
	}

	jobChan := make(chan [][]byte, maxPendingBatches)
	for range numWorkers {
		go func() {
			for batch := range jobChan {
				if err := b.transport.PushBatch(batch); err != nil {
					LogOperationalFailure("behavior", "push failed", err)
				}
			}
		}()
	}

	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	batch := make([][]byte, 0, 256)
	batchBytes := 0
	var batchStarted time.Time

	flush := func() {
		if len(batch) == 0 {
			return
		}
		padded := batch
		batch = make([][]byte, 0, 256)
		batchBytes = 0
		batchStarted = time.Time{}

		// Encrypting here, in queue order, keeps the inner-AEAD counters in
		// the order the packets are sent, and lets the padding depend on the
		// write the packets travel in.
		ready, err := b.masker.SealBatch(padded)
		if err != nil {
			LogOperationalFailure("behavior", "uplink batch encryption failed", err)
			return
		}

		select {
		case jobChan <- ready:
		default:
			timer := time.NewTimer(workerQueueWait)
			select {
			case jobChan <- ready:
			case <-timer.C:
				LogRateLimitedEvent("behavior", "batch dropped because worker queue is full")
			case <-b.stopChan:
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}

	for {
		select {
		case <-b.stopChan:
			flush()
			close(jobChan)
			return
		case data := <-b.pushQueue:
			b.mu.RLock()
			mode := b.mode
			b.mu.RUnlock()

			if mode == shared.BehaviorIdle || len(data) == 0 {
				continue
			}

			if len(batch) == 0 {
				batchStarted = time.Now()
			}
			batch = append(batch, data)
			batchBytes += len(data)

			if len(batch) >= maxBatchPackets || batchBytes >= targetBatchBytes || len(b.pushQueue) >= backpressureQueueLen {
				flush()
			}
		case <-flushTicker.C:
			if len(batch) == 0 {
				continue
			}
			if shouldFlushUplinkBatch(batchBytes, batchStarted, time.Now()) {
				flush()
			}
		}
	}
}

// pollLoop does long-polling with timing based on the current mode.
func (b *BehaviorEngine) pollLoop(workerID int) {
	for {
		select {
		case <-b.stopChan:
			return
		default:
		}

		b.mu.RLock()
		mode := b.mode
		b.mu.RUnlock()

		// The persistent carrier can receive replies even while the local
		// behavior profile is idle. Keep its primary consumer awake.
		if mode == shared.BehaviorIdle && !b.transport.UsesDownlinkStream() {
			time.Sleep(5 * time.Second)
			continue
		}

		if b.transport != nil && b.transport.UsesDownlinkStream() && workerID > 0 {
			// One consumer is enough in stream mode; keep additional workers mostly idle.
			time.Sleep(2500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)
			continue
		}

		// Keep one poller in background mode to reduce noise and CPU usage.
		if mode == shared.BehaviorBackground && workerID > 0 {
			time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1500))*time.Millisecond)
			continue
		}

		batch, err := b.transport.PollBatch(maxPollBatchPackets)
		if err != nil {
			if workerID == 0 {
				LogOperationalFailure("behavior", "poll failed", err)
			}
			// Short jittered sleep per-worker to avoid thundering herd on server errors.
			// Was 2s for all workers simultaneously — now 100-400ms with per-worker offset.
			sleepMs := 100 + rand.Intn(300) + workerID*10
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
			continue
		}

		if len(batch) > 0 {
			b.processInboundBatch(batch, workerID)
		}

		if mode == shared.BehaviorBackground && (b.transport == nil || !b.transport.UsesDownlinkStream()) {
			if workerID == 0 {
				cfg := behaviorConfigs[mode]
				time.Sleep(jitteredDuration(cfg.SyncMinInterval/4, cfg.SyncMaxInterval/4))
			} else {
				time.Sleep(1200 * time.Millisecond)
			}
		}
	}
}

func (b *BehaviorEngine) processInboundBatch(batch [][]byte, workerID int) {
	if len(batch) == 0 {
		return
	}
	results := make([]inboundDecryptResult, len(batch))
	if len(batch) < 4 {
		for index := range batch {
			results[index].payload, results[index].err = b.cipher.Decrypt(batch[index])
		}
		b.emitInboundResults(results, workerID)
		return
	}
	workers := min(runtime.GOMAXPROCS(0), len(batch))
	if workers > 8 {
		workers = 8
	}
	jobs := make(chan int, len(batch))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index].payload, results[index].err = b.cipher.Decrypt(batch[index])
			}
		}()
	}
	for index := range batch {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	b.emitInboundResults(results, workerID)
}

func (b *BehaviorEngine) emitInboundResults(results []inboundDecryptResult, workerID int) {
	for _, result := range results {
		if result.err != nil {
			if workerID == 0 {
				LogOperationalFailure("behavior", "downlink decryption failed", result.err)
			}
			continue
		}
		b.RecordInboundActivity(len(result.payload))
		if b.inboundFn != nil {
			b.inboundFn(result.payload)
		}
	}
}

// coverTrafficLoop sends fake encrypted packets during idle periods to mask traffic patterns.
func (b *BehaviorEngine) coverTrafficLoop() {
	if b.transport == nil || b.cipher == nil || b.profile == nil {
		return
	}

	for {
		select {
		case <-b.stopChan:
			return
		default:
		}

		b.mu.RLock()
		mode := b.mode
		b.mu.RUnlock()

		// Only send cover traffic in Active or Background modes to avoid complete silence.
		// In Idle mode, we might want to be silent or very sparse.
		// Send at random 5-30 second intervals.
		// Let's apply this when queue is empty.

		// Get probability of activity for this hour from profile
		hour := time.Now().Hour()
		prob := b.profile.GetActivityLevel(hour)

		// If very low activity (e.g. night), we might skip cover traffic entirely,
		// OR reduce frequency significantly.

		var delay time.Duration
		if mode == shared.BehaviorIdle {
			baseDelay := jitteredDuration(30*time.Second, 60*time.Second)
			// Apply profile modulation to Idle mode
			if prob < 0.1 {
				// Night time / Inactive time: sleep much longer (5-10m)
				delay = time.Duration(5+rand.Intn(5)) * time.Minute
			} else if prob < 0.5 {
				delay = baseDelay * 2
			} else {
				delay = baseDelay
			}
		} else {
			delay = jitteredDuration(5*time.Second, 30*time.Second)
		}

		select {
		case <-b.stopChan:
			return
		case <-time.After(delay):
			// Skip cover packets while there is real traffic waiting to send.
			if len(b.pushQueue) > 0 {
				continue
			}

			// Check if we have been idle (no real push) for a while?
			// Just send a cover packet.

			// Generate random cover packet using profile target size
			targetSize := b.profile.GetTargetPacketSize()
			// Cover packets should mimic real packets in size
			size := targetSize

			dummyData := make([]byte, size)
			rand.Read(dummyData)

			packetID := atomic.AddUint32(&packetIDCounter, 1)
			packed := shared.Pack(b.psk, packetID, 0, 1, shared.PacketTypeCover, dummyData)

			encrypted, err := b.cipher.Encrypt(packed)
			if err != nil {
				LogOperationalFailure("behavior", "cover encryption failed", err)
				continue
			}

			// Send directly to transport
			if err := b.transport.Push(encrypted); err != nil {
				LogOperationalFailure("behavior", "cover push failed", err)
			}
		}
	}
}

// syncLoop sends a sparse liveness request only after an equally long period
// without useful traffic. Active upload/download streams already prove that the
// connection is alive and should not acquire an artificial heartbeat cadence.
func (b *BehaviorEngine) syncLoop() {
	for {
		b.mu.RLock()
		mode := b.mode
		b.mu.RUnlock()

		cfg := behaviorConfigs[mode]
		delay := jitteredDuration(cfg.SyncMinInterval, cfg.SyncMaxInterval)

		select {
		case <-b.stopChan:
			return
		case <-time.After(delay):
			b.mu.RLock()
			usefulIdle := time.Since(b.lastActivity)
			b.mu.RUnlock()
			if usefulIdle < delay {
				continue
			}
			if err := b.transport.Sync(); err != nil {
				LogOperationalFailure("behavior", "synchronization failed", err)
			}
		}
	}
}

// jitteredDuration returns a duration with gaussian (normal) distribution
// centred between min and max, with σ = (max-min)/6.
// This matches real human network activity patterns far better than uniform
// random, making traffic timing indistinguishable from browser activity.
func jitteredDuration(min, max time.Duration) time.Duration {
	if max <= min || min == 0 {
		if min == 0 {
			return time.Second
		}
		return min
	}
	return gaussianDuration(min, max)
}

// gaussianDuration samples from a normal distribution centred at the midpoint
// of [min, max] and clipped to that range.
// Uses Box-Muller transform on Go's math/rand (seeded from crypto/rand at init).
func gaussianDuration(min, max time.Duration) time.Duration {
	mean := float64(min+max) / 2.0
	sigma := float64(max-min) / 6.0 // 99.7% of samples within [min, max]

	// Box-Muller transform: two uniform → one standard normal.
	u1 := rand.Float64()
	u2 := rand.Float64()
	if u1 == 0 {
		u1 = 1e-10
	}
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)

	d := time.Duration(mean + sigma*z)
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}
