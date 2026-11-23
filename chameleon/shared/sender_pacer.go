package shared

import "time"

const (
	PersistentPacingIdleReset = 250 * time.Millisecond
	PersistentPacingMaxDebt   = 24 * time.Millisecond

	persistentPacingDefaultBurstMin = 64 * 1024
	persistentPacingDefaultBurstMax = 96 * 1024
	persistentPacingDefaultTailRate = 12 * 1024 * 1024
	persistentPacingDefaultRateMin  = 4 * 1024 * 1024
	persistentPacingDefaultRateMax  = 96 * 1024 * 1024
	persistentPacingDefaultBacklog  = 64 * 1024
)

type SenderPacingMode uint8

const (
	// SenderPacingDefault selects the production userspace mode.
	SenderPacingDefault SenderPacingMode = iota
	// SenderPacingRecordOnly preserves Record Shaping v2 without persistent pacing.
	SenderPacingRecordOnly
	// SenderPacingUserspace enables the persistent pacer without changing kernel settings.
	SenderPacingUserspace
)

type tcpPacingTelemetry struct {
	DeliveryRateBytesPerSecond uint64
	NotSentBytes               uint32
}

type persistentSenderPacer struct {
	options                RecordShapingOptions
	rng                    *shapePRNG
	burstRemaining         int
	nextSend               time.Time
	lastActivity           time.Time
	tailRateBytesPerSecond float64
}

func newPersistentSenderPacer(options RecordShapingOptions, entropy uint64) *persistentSenderPacer {
	defaultRate := float64(persistentPacingDefaultTailRate)
	if defaultRate < float64(options.TailRateMinBytes) {
		defaultRate = float64(options.TailRateMinBytes)
	}
	if defaultRate > float64(options.TailRateMaxBytes) {
		defaultRate = float64(options.TailRateMaxBytes)
	}
	return &persistentSenderPacer{
		options:                options,
		rng:                    newShapePRNG(entropy),
		tailRateBytesPerSecond: defaultRate,
	}
}

func (p *persistentSenderPacer) resetBurst(now time.Time) {
	p.burstRemaining = p.rng.between(
		p.options.InitialBurstMinBytes,
		p.options.InitialBurstMaxBytes,
	)
	p.nextSend = now
}

func (p *persistentSenderPacer) updateTailRate(telemetry tcpPacingTelemetry) {
	if telemetry.DeliveryRateBytesPerSecond == 0 {
		return
	}
	candidate := float64(telemetry.DeliveryRateBytesPerSecond) * 0.85
	if candidate < float64(p.options.TailRateMinBytes) {
		candidate = float64(p.options.TailRateMinBytes)
	}
	if candidate > float64(p.options.TailRateMaxBytes) {
		candidate = float64(p.options.TailRateMaxBytes)
	}
	// Slow convergence avoids turning one TCP_INFO sample into a new stable
	// wire rhythm of its own.
	p.tailRateBytesPerSecond = (p.tailRateBytesPerSecond * 0.85) + (candidate * 0.15)
}

func (p *persistentSenderPacer) delayBeforeChunk(
	now time.Time,
	chunkBytes int,
	telemetry tcpPacingTelemetry,
) time.Duration {
	if chunkBytes <= 0 {
		return 0
	}
	if p.lastActivity.IsZero() || now.Sub(p.lastActivity) > PersistentPacingIdleReset || now.Before(p.lastActivity) {
		p.resetBurst(now)
	}
	p.lastActivity = now
	p.updateTailRate(telemetry)

	if p.burstRemaining > 0 {
		p.burstRemaining -= chunkBytes
		if p.burstRemaining < 0 {
			p.burstRemaining = 0
		}
		p.nextSend = now
		return 0
	}

	// If TCP already has a meaningful unsent backlog, congestion control is
	// pacing the flow. Reset our debt instead of stacking another delay.
	if p.options.KernelBacklogBytes > 0 &&
		telemetry.NotSentBytes >= uint32(p.options.KernelBacklogBytes) {
		p.nextSend = now
		return 0
	}

	if p.nextSend.Before(now) {
		p.nextSend = now
	}
	delay := p.nextSend.Sub(now)
	if delay > PersistentPacingMaxDebt {
		// Fail open relative to shaping: discard pacing debt, never the tunnel.
		p.nextSend = now
		return 0
	}

	jitter := 0.85 + (float64(p.rng.next()%3001) / 10000.0)
	intervalSeconds := (float64(chunkBytes) / p.tailRateBytesPerSecond) * jitter
	p.nextSend = p.nextSend.Add(time.Duration(intervalSeconds * float64(time.Second)))
	return delay
}
