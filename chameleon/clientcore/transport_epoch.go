package clientcore

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	gracefulEpochCloseTimeout = 2 * time.Second
	uploadEpochDrainTimeout   = 1500 * time.Millisecond

	// Browsers commonly keep a healthy HTTP/2 origin connection for a long
	// time. Minute-scale forced epochs made Chameleon visibly reconnect even
	// when neither endpoint nor the network required it.
	epochMinAgeFloor     = 20 * time.Minute
	epochMinAgeCeiling   = 40 * time.Minute
	epochMaxAgeFloor     = 90 * time.Minute
	epochMaxAgeCeiling   = 4 * time.Hour
	epochQuietFloor      = 3 * time.Second
	epochQuietCeiling    = 15 * time.Second
	epochByteBudgetFloor = 256 << 20
	epochByteBudgetCeil  = 1 << 30
)

type uploadDrainRequest struct {
	ctx     context.Context
	result  chan error
	release chan struct{}
}

// transportClients is one independently closeable HTTP transport generation.
// A candidate is authenticated before it replaces the active generation.
type transportClients struct {
	client       *http.Client
	streamClient *http.Client
}

// transportEpochPolicy bounds a transport by useful work rather than by a
// periodic reconnect timer. Both age and byte thresholds are evaluated only at
// a quiet boundary, so an active transfer is never cut merely because it aged.
type transportEpochPolicy struct {
	startedAt    time.Time
	lastPayload  time.Time
	retryAfter   time.Time
	minAge       time.Duration
	maxAge       time.Duration
	quietPeriod  time.Duration
	byteBudget   int64
	payloadBytes int64
}

func newTransportEpochPolicy(now time.Time) transportEpochPolicy {
	return transportEpochPolicy{
		startedAt:   now,
		lastPayload: now,
		minAge:      randomDuration(epochMinAgeFloor, epochMinAgeCeiling),
		maxAge:      randomDuration(epochMaxAgeFloor, epochMaxAgeCeiling),
		quietPeriod: randomDuration(epochQuietFloor, epochQuietCeiling),
		byteBudget:  randomInt64(epochByteBudgetFloor, epochByteBudgetCeil),
	}
}

func (p *transportEpochPolicy) recordPayload(now time.Time, bytes int64) {
	if bytes <= 0 {
		return
	}
	p.lastPayload = now
	p.payloadBytes += bytes
}

// recordStreamBytes counts device TCP stream traffic toward the byte budget
// only. Streams survive a rotation on their own generation, so they need no
// quiet moment; letting them reset the quiet timer kept a busy home network
// from ever rotating.
func (p *transportEpochPolicy) recordStreamBytes(bytes int64) {
	if bytes > 0 {
		p.payloadBytes += bytes
	}
}

func (p *transportEpochPolicy) shouldRotate(now time.Time) bool {
	if now.Before(p.retryAfter) || p.payloadBytes == 0 {
		return false
	}
	age := now.Sub(p.startedAt)
	if age < p.minAge || now.Sub(p.lastPayload) < p.quietPeriod {
		return false
	}
	return age >= p.maxAge || p.payloadBytes >= p.byteBudget
}

func randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(randomInt64(0, int64(max-min)))
}

func randomInt64(min, max int64) int64 {
	if max <= min {
		return min
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return min
	}
	span := uint64(max - min + 1)
	return min + int64(binary.BigEndian.Uint64(raw[:])%span)
}

func (t *Transport) recordEpochPayload(bytes int64) {
	if bytes <= 0 || t.protocol != "http2" {
		return
	}
	t.epochPolicyMu.Lock()
	t.epochPolicy.recordPayload(time.Now(), bytes)
	t.epochPolicyMu.Unlock()
}

func (t *Transport) recordEpochStreamBytes(bytes int64) {
	if bytes <= 0 || t.protocol != "http2" {
		return
	}
	t.epochPolicyMu.Lock()
	t.epochPolicy.recordStreamBytes(bytes)
	t.epochPolicyMu.Unlock()
}

func (t *Transport) epochLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case now := <-ticker.C:
			t.epochPolicyMu.Lock()
			rotate := t.epochPolicy.shouldRotate(now)
			t.epochPolicyMu.Unlock()
			if !rotate {
				continue
			}
			if err := t.RefreshTransport(); err != nil {
				LogOperationalFailure("transport", "epoch candidate rejected; active connection retained", err)
				t.epochPolicyMu.Lock()
				t.epochPolicy.retryAfter = now.Add(randomDuration(20*time.Second, 45*time.Second))
				t.epochPolicyMu.Unlock()
				continue
			}

			t.epochPolicyMu.Lock()
			t.epochPolicy = newTransportEpochPolicy(time.Now())
			t.epochPolicyMu.Unlock()
		}
	}
}

func (t *Transport) buildTransportClients() (transportClients, error) {
	if t.protocol != "http2" {
		return transportClients{}, fmt.Errorf("transport epochs require HTTP/2")
	}
	t.mu.RLock()
	profile := t.fingerprint.GetProfile()
	realityPub := append([]byte(nil), t.realityPub...)
	transportKey := append([]byte(nil), t.transportKey...)
	shieldDomain := t.shieldDomain
	serverDialAddr := t.serverDialAddr
	t.mu.RUnlock()

	roundTripper := CreateTLSTransport(
		profile,
		t.serverAddr,
		serverDialAddr,
		realityPub,
		transportKey,
		shieldDomain,
		t.tlsCertSHA256,
		t.verifyServerCertificate,
	)
	return transportClients{
		client: &http.Client{
			Transport: roundTripper,
			Timeout:   35 * time.Second,
		},
		streamClient: &http.Client{Transport: roundTripper},
	}, nil
}

// activateTransportEpoch probes the candidate before the atomic swap. A failed
// probe cannot cancel or replace the last-known-good transport.
func (t *Transport) activateTransportEpoch(candidate transportClients) error {
	if candidate.client == nil || candidate.streamClient == nil {
		closeTransportClients(candidate)
		return fmt.Errorf("incomplete transport epoch candidate")
	}
	if err := t.syncWithClient(candidate.client); err != nil {
		closeTransportClients(candidate)
		return fmt.Errorf("candidate health check failed: %w", err)
	}

	drainCtx, drainCancel := context.WithTimeout(t.ctx, uploadEpochDrainTimeout)
	releaseUpload, err := t.beginUploadDrain(drainCtx)
	drainCancel()
	if err != nil {
		closeTransportClients(candidate)
		return fmt.Errorf("active upload drain failed: %w", err)
	}
	released := false
	defer func() {
		if !released {
			releaseUpload()
		}
	}()

	newEpochCtx, newEpochCancel := context.WithCancel(t.ctx)

	t.mu.Lock()
	old := transportClients{client: t.client, streamClient: t.streamClient}
	oldGeneration := t.epochGeneration
	oldEpochCancel := t.epochCancel
	t.client = candidate.client
	t.streamClient = candidate.streamClient
	t.epochCtx = newEpochCtx
	t.epochCancel = newEpochCancel
	t.epochGeneration++
	t.mu.Unlock()

	if oldEpochCancel != nil {
		oldEpochCancel()
	}
	releaseUpload()
	released = true
	t.retireEpoch(oldGeneration, old)
	LogState("transport", "new connection epoch activated")
	return nil
}

// Limits for replaced generations kept open for device TCP streams. A
// generation closes as soon as its last stream ends; these only guard against
// stuck streams and unbounded retention. Tests shorten them.
var (
	// retiredEpochIdleLimit: no stream byte in either direction for this long.
	retiredEpochIdleLimit = 2 * time.Hour
	// maxRetainedEpochs: older generations beyond this are closed, oldest
	// first, even with open streams.
	maxRetainedEpochs = 4
	// retiredEpochCheckInterval: how often a kept generation checks its idle time.
	retiredEpochCheckInterval = time.Minute
)

// epochStreamGroup tracks the TCP streams opened on one generation.
type epochStreamGroup struct {
	open    int
	lastUse atomic.Int64 // unix nanoseconds of the last stream byte
	// Set when the generation is replaced: drained closes when the last
	// stream ends, evict when the retention cap needs the slot.
	drained chan struct{}
	evict   chan struct{}
}

func (g *epochStreamGroup) touch() { g.lastUse.Store(time.Now().UnixNano()) }

// acquireStreamEpoch returns the current stream client and registers one open
// TCP stream on its generation. The registration happens under the same lock
// as the epoch swap, so a stream never lands on a generation that was already
// checked for open streams.
func (t *Transport) acquireStreamEpoch() (*http.Client, uint64, *epochStreamGroup) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	t.epochStreamMu.Lock()
	defer t.epochStreamMu.Unlock()
	if t.epochStreams == nil {
		t.epochStreams = make(map[uint64]*epochStreamGroup)
	}
	group := t.epochStreams[t.epochGeneration]
	if group == nil {
		group = &epochStreamGroup{}
		t.epochStreams[t.epochGeneration] = group
	}
	group.open++
	group.touch()
	return t.streamClient, t.epochGeneration, group
}

// releaseStreamEpoch ends one TCP stream's registration; the last stream of a
// replaced generation lets that generation close.
func (t *Transport) releaseStreamEpoch(generation uint64) {
	t.epochStreamMu.Lock()
	defer t.epochStreamMu.Unlock()
	group := t.epochStreams[generation]
	if group == nil {
		return
	}
	if group.open > 1 {
		group.open--
		return
	}
	delete(t.epochStreams, generation)
	if group.drained != nil {
		close(group.drained)
	}
}

// keepEpochForStreams marks a replaced generation as kept for its open
// streams. It returns nil when there are none, and evicts the oldest kept
// generation when the cap would be exceeded.
func (t *Transport) keepEpochForStreams(generation uint64) *epochStreamGroup {
	t.epochStreamMu.Lock()
	defer t.epochStreamMu.Unlock()
	group := t.epochStreams[generation]
	if group == nil || group.open == 0 {
		return nil
	}
	group.drained = make(chan struct{})
	group.evict = make(chan struct{})
	var kept []uint64
	for g, other := range t.epochStreams {
		if other.drained != nil && other.evict != nil {
			kept = append(kept, g)
		}
	}
	sort.Slice(kept, func(a, b int) bool { return kept[a] < kept[b] })
	for len(kept) > maxRetainedEpochs {
		oldest := t.epochStreams[kept[0]]
		close(oldest.evict)
		oldest.evict = nil
		kept = kept[1:]
	}
	return group
}

// retireEpoch closes a replaced generation. Tunnel traffic has already moved
// to the new one; device TCP connections carried as streams keep the old
// connection until they end, as a browser lets requests on an old connection
// finish. It is closed earlier only when its streams have been silent for
// retiredEpochIdleLimit, when maxRetainedEpochs newer generations are kept,
// or when the transport stops. Then the connection and its resources go.
func (t *Transport) retireEpoch(generation uint64, old transportClients) {
	group := t.keepEpochForStreams(generation)
	if group == nil {
		_ = retireTransportClients(old, gracefulEpochCloseTimeout)
		return
	}
	LogState("transport", "previous connection kept for open TCP streams")
	evict := group.evict
	go func() {
		check := time.NewTicker(retiredEpochCheckInterval)
		defer check.Stop()
	wait:
		for {
			select {
			case <-group.drained:
				break wait
			case <-evict:
				LogState("transport", "previous connection closed: too many kept for TCP streams")
				break wait
			case <-t.ctx.Done():
				break wait
			case now := <-check.C:
				if now.Sub(time.Unix(0, group.lastUse.Load())) >= retiredEpochIdleLimit {
					LogState("transport", "previous connection closed: its TCP streams were silent")
					break wait
				}
			}
		}
		t.epochStreamMu.Lock()
		group.evict = nil
		t.epochStreamMu.Unlock()
		_ = retireTransportClients(old, gracefulEpochCloseTimeout)
	}()
}

func (t *Transport) beginUploadDrain(ctx context.Context) (func(), error) {
	if !t.uplinkEnabled || t.uploadDrain == nil {
		return func() {}, nil
	}
	t.uplinkGate.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			t.uplinkGate.Unlock()
		}
	}
	request := uploadDrainRequest{
		ctx:     ctx,
		result:  make(chan error, 1),
		release: make(chan struct{}),
	}
	select {
	case t.uploadDrain <- request:
	case <-ctx.Done():
		unlock()
		return nil, ctx.Err()
	case <-t.ctx.Done():
		unlock()
		return nil, t.ctx.Err()
	}

	select {
	case err := <-request.result:
		if err != nil {
			close(request.release)
			unlock()
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				close(request.release)
				unlock()
			})
		}, nil
	case <-ctx.Done():
		close(request.release)
		unlock()
		return nil, ctx.Err()
	case <-t.ctx.Done():
		close(request.release)
		unlock()
		return nil, t.ctx.Err()
	}
}

// RefreshTransport creates a fresh TLS/HTTP2 generation. Only one candidate may
// be evaluated at a time, preventing overlapping swaps under load.
func (t *Transport) RefreshTransport() error {
	t.epochRefreshMu.Lock()
	defer t.epochRefreshMu.Unlock()

	candidate, err := t.buildTransportClients()
	if err != nil {
		return err
	}
	return t.activateTransportEpoch(candidate)
}

func (t *Transport) currentStreamEpoch() (*http.Client, context.Context, uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.streamClient, t.epochCtx, t.epochGeneration
}

func (t *Transport) currentRequestEpoch() (*http.Client, context.Context, uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.client, t.epochCtx, t.epochGeneration
}

func closeTransportClients(clients transportClients) {
	for _, roundTripper := range uniqueRoundTrippers(clients) {
		if closer, ok := roundTripper.(interface{ CloseConnections() }); ok {
			closer.CloseConnections()
			continue
		}
		if closer, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func retireTransportClients(clients transportClients, timeout time.Duration) bool {
	graceful := true
	for _, roundTripper := range uniqueRoundTrippers(clients) {
		closer, ok := roundTripper.(interface {
			CloseGracefully(time.Duration) bool
		})
		if ok && closer.CloseGracefully(timeout) {
			continue
		}
		graceful = false
		if forceCloser, ok := roundTripper.(interface{ CloseConnections() }); ok {
			forceCloser.CloseConnections()
			continue
		}
		if idleCloser, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			idleCloser.CloseIdleConnections()
		}
	}
	return graceful
}

func uniqueRoundTrippers(clients transportClients) []http.RoundTripper {
	seen := make(map[http.RoundTripper]struct{}, 2)
	result := make([]http.RoundTripper, 0, 2)
	for _, client := range []*http.Client{clients.client, clients.streamClient} {
		if client == nil || client.Transport == nil {
			continue
		}
		if _, ok := seen[client.Transport]; ok {
			continue
		}
		seen[client.Transport] = struct{}{}
		result = append(result, client.Transport)
	}
	return result
}
