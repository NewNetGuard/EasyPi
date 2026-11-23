package clientcore

// Load bench for one Chameleon server behind nginx. Runs only when LOAD_MODE
// is set; tools/chameleon-load/run_load.sh builds the isolated stand.
//
// A device is one Chameleon client session (its own credential, carrier
// connection and keys), exactly like a phone or a home client. A device opens
// several TCP streams, which are not devices.
//
//   LOAD_MODE=origin: the "internet" site the streams reach. Per connection:
//     "D <down> <up>\n" -> reads <up> bytes, then sends <down> bytes and closes;
//     "E\n"             -> echoes everything back.
//   LOAD_MODE=idle|active: N devices connect and run the device profile.

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chameleon/shared"
)

func loadEnvInt(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return fallback
}

func TestChameleonLoad(t *testing.T) {
	switch os.Getenv("LOAD_MODE") {
	case "":
		t.Skip("set LOAD_MODE (see tools/chameleon-load/run_load.sh)")
	case "origin":
		runLoadOrigin(t, os.Getenv("LOAD_ORIGIN_LISTEN"))
	default:
		runLoadDevices(t)
	}
}

// ---- origin ------------------------------------------------------------

func runLoadOrigin(t *testing.T, listen string) {
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 64<<10)
	rand.Read(payload)
	for {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			r := bufio.NewReaderSize(c, 64<<10)
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			var down, up int
			if line == "E\n" {
				_, _ = io.Copy(c, r)
				return
			}
			if _, err := fmt.Sscanf(line, "D %d %d\n", &down, &up); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, r, int64(up)); err != nil {
				return
			}
			for down > 0 {
				n := min(down, len(payload))
				if _, err := c.Write(payload[:n]); err != nil {
					return
				}
				down -= n
			}
		}(conn)
	}
}

// ---- statistics --------------------------------------------------------

type loadStats struct {
	mu       sync.Mutex
	samples  map[string][]float64
	counts   map[string]int
	measured atomic.Bool
}

func newLoadStats() *loadStats {
	return &loadStats{samples: map[string][]float64{}, counts: map[string]int{}}
}

func (s *loadStats) add(name string, v float64) {
	if !s.measured.Load() {
		return
	}
	s.mu.Lock()
	s.samples[name] = append(s.samples[name], v)
	s.mu.Unlock()
}

func (s *loadStats) count(name string) {
	if !s.measured.Load() {
		return
	}
	s.mu.Lock()
	s.counts[name]++
	s.mu.Unlock()
}

func (s *loadStats) addCount(name string, n int) {
	if !s.measured.Load() {
		return
	}
	s.mu.Lock()
	s.counts[name] += n
	s.mu.Unlock()
}

// noteError keeps a count per distinct error text (first 80 characters).
func (s *loadStats) noteError(err error) {
	if err == nil {
		return
	}
	text := err.Error()
	if len(text) > 80 {
		text = text[:80]
	}
	s.countAlways("error: " + text)
}

func (s *loadStats) countAlways(name string) {
	s.mu.Lock()
	s.counts[name]++
	s.mu.Unlock()
}

func quantiles(v []float64) map[string]float64 {
	if len(v) == 0 {
		return nil
	}
	sort.Float64s(v)
	q := func(p float64) float64 {
		return math.Round(v[min(len(v)-1, int(float64(len(v))*p))]*100) / 100
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return map[string]float64{"n": float64(len(v)), "p50": q(0.5), "p95": q(0.95), "p99": q(0.99),
		"min": math.Round(v[0]*100) / 100, "max": math.Round(v[len(v)-1]*100) / 100,
		"mean": math.Round(sum/float64(len(v))*100) / 100}
}

// ---- devices -----------------------------------------------------------

type loadDevice struct {
	conn   *Connection
	origin netip.AddrPort
	stats  *loadStats
}

func classify(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrTCPStreamRefused):
		return "refused"
	case errors.Is(err, ErrTCPStreamUnsupported):
		return "unsupported"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "eof"
	default:
		return "other"
	}
}

// fetch opens a stream to the origin, sends up bytes, reads down bytes.
func (d *loadDevice) fetch(ctx context.Context, kind string, down, up int) (time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	stream, err := d.conn.OpenTCPStream(ctx, d.origin, []byte(fmt.Sprintf("D %d %d\n", down, up)))
	if err != nil {
		d.stats.count(kind + "_open_fail_" + classify(err))
		d.stats.noteError(err)
		return 0, err
	}
	defer stream.Close()
	go func() {
		<-ctx.Done()
		stream.Close()
	}()
	chunk := make([]byte, 32<<10)
	for left := up; left > 0; {
		n := min(left, len(chunk))
		if _, err := stream.Write(chunk[:n]); err != nil {
			d.stats.count(kind + "_fail_write")
			return 0, err
		}
		left -= n
	}
	_ = stream.CloseWrite()
	got, err := io.Copy(io.Discard, stream)
	if err != nil || got != int64(down) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		d.stats.count(kind + "_fail_" + classify(err))
		d.stats.noteError(err)
		return 0, err
	}
	d.stats.count(kind + "_stream_ok")
	d.stats.addCount("bytes_down", down)
	d.stats.addCount("bytes_up", up)
	return time.Since(start), nil
}

// echoLoop keeps one long-lived stream (a messenger/push connection) and
// measures the round trip of a small message every interval.
func (d *loadDevice) echoLoop(ctx context.Context, interval time.Duration) {
	for ctx.Err() == nil {
		stream, err := d.conn.OpenTCPStream(ctx, d.origin, []byte("E\n"))
		if err != nil {
			d.stats.count("echo_open_fail_" + classify(err))
			d.stats.noteError(err)
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		d.stats.countAlways("echo_streams_opened")
		go func() {
			<-ctx.Done()
			stream.Close()
		}()
		msg := make([]byte, 64)
		reply := make([]byte, 64)
		sleepCtx(ctx, time.Duration(rand.Int63n(int64(interval))))
		for ctx.Err() == nil {
			start := time.Now()
			if _, err := stream.Write(msg); err != nil {
				break
			}
			if _, err := io.ReadFull(stream, reply); err != nil {
				break
			}
			d.stats.add("echo_ms", float64(time.Since(start).Microseconds())/1000)
			d.stats.count("echo_ok")
			sleepCtx(ctx, interval)
		}
		stream.Close()
		if ctx.Err() == nil {
			d.stats.count("echo_dropped")
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func expWait(mean time.Duration) time.Duration {
	return time.Duration(rand.ExpFloat64() * float64(mean))
}

func (d *loadDevice) page(ctx context.Context) {
	start := time.Now()
	var wg sync.WaitGroup
	var failed atomic.Bool
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.fetch(ctx, "page", 20<<10+rand.Intn(280<<10), 600); err != nil {
				failed.Store(true)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	if failed.Load() {
		d.stats.count("page_failed")
		return
	}
	d.stats.count("page_ok")
	d.stats.add("page_ms", float64(time.Since(start).Milliseconds()))
}

func (d *loadDevice) run(ctx context.Context, active bool) {
	var wg sync.WaitGroup
	loop := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	echoEvery := 30 * time.Second
	if active {
		echoEvery = 5 * time.Second
	}
	loop(func() { d.echoLoop(ctx, echoEvery) })
	loop(func() { d.echoLoop(ctx, echoEvery) })
	if !active {
		// Background sync of an idle phone: a small fetch now and then.
		loop(func() {
			for sleepCtx(ctx, expWait(60*time.Second)); ctx.Err() == nil; sleepCtx(ctx, expWait(60*time.Second)) {
				if took, err := d.fetch(ctx, "bg", 20<<10, 1<<10); err == nil {
					d.stats.count("bg_ok")
					d.stats.add("bg_ms", float64(took.Milliseconds()))
				}
			}
		})
	} else {
		loop(func() {
			for sleepCtx(ctx, expWait(10*time.Second)); ctx.Err() == nil; sleepCtx(ctx, expWait(10*time.Second)) {
				d.page(ctx)
			}
		})
		loop(func() {
			for sleepCtx(ctx, time.Duration(rand.Int63n(int64(60*time.Second)))); ctx.Err() == nil; sleepCtx(ctx, expWait(60*time.Second)) {
				size := 5 << 20
				if took, err := d.fetch(ctx, "download", size, 200); err == nil {
					d.stats.count("download_ok")
					d.stats.add("download_mb_s", float64(size)/took.Seconds()/1e6)
				}
			}
		})
		loop(func() {
			for sleepCtx(ctx, time.Duration(rand.Int63n(int64(120*time.Second)))); ctx.Err() == nil; sleepCtx(ctx, expWait(120*time.Second)) {
				size := 2 << 20
				if took, err := d.fetch(ctx, "upload", 100, size); err == nil {
					d.stats.count("upload_ok")
					d.stats.add("upload_mb_s", float64(size)/took.Seconds()/1e6)
				}
			}
		})
	}
	wg.Wait()
}

type loadKeys struct {
	PSKKey           string   `json:"psk_key"`
	ClientAuthKey    string   `json:"client_auth_key"`
	RealityPublicKey string   `json:"reality_public_key"`
	DeviceIDs        []string `json:"device_ids"`
	CertSHA256       string   `json:"cert_sha256"`
}

func runLoadDevices(t *testing.T) {
	n := loadEnvInt("LOAD_DEVICES", 10)
	active := os.Getenv("LOAD_MODE") == "active"
	warm := time.Duration(loadEnvInt("LOAD_WARM_S", 20)) * time.Second
	measure := time.Duration(loadEnvInt("LOAD_MEASURE_S", 120)) * time.Second
	raw, err := os.ReadFile(os.Getenv("LOAD_KEYS"))
	if err != nil {
		t.Fatal(err)
	}
	var keys loadKeys
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	authKey, _ := hex.DecodeString(keys.ClientAuthKey)
	origin := netip.MustParseAddrPort(os.Getenv("LOAD_ORIGIN"))
	stats := newLoadStats()

	// Device 0 is the home client (client_auth_key); the rest are registered
	// mobile devices, each with its own derived credential.
	devices := make([]*loadDevice, n)
	connectMS := make([]float64, n)
	var connectFail atomic.Int64
	var wg sync.WaitGroup
	gate := make(chan struct{}, 8) // connect several devices at a time
	rampStart := time.Now()
	for i := 0; i < n; i++ {
		psk := authKey
		if i > 0 {
			psk = shared.MobilePSK(authKey, keys.DeviceIDs[i-1])
		}
		cfg := Config{
			ServerAddress:          os.Getenv("LOAD_SERVER"),
			PSKKey:                 hex.EncodeToString(psk),
			TransportKey:           keys.PSKKey,
			Protocol:               "http2",
			BufferSize:             1000,
			ReconnectInterval:      5,
			FingerprintMode:        "auto",
			BootstrapCertSHA256:    keys.CertSHA256,
			RealityServerPublicKey: keys.RealityPublicKey,
			RealityShieldPreset:    "ip",
		}
		wg.Add(1)
		gate <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-gate }()
			conn, problem := buildMobileConnection(cfg, NewProfileManager(""), newPacketQueueInjector(4096))
			if problem != "" {
				t.Errorf("device %d: %s", i, problem)
				connectFail.Add(1)
				return
			}
			start := time.Now()
			if err := connectWithRetries(conn, 30*time.Second); err != nil {
				connectFail.Add(1)
				return
			}
			conn.Start()
			connectMS[i] = float64(time.Since(start).Milliseconds())
			devices[i] = &loadDevice{conn: conn, origin: origin, stats: stats}
		}(i)
		time.Sleep(50 * time.Millisecond)
	}
	wg.Wait()
	rampSeconds := time.Since(rampStart).Seconds()
	var connected []float64
	for i, d := range devices {
		if d != nil {
			connected = append(connected, connectMS[i])
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	var run sync.WaitGroup
	for _, d := range devices {
		if d == nil {
			continue
		}
		run.Add(1)
		go func(d *loadDevice) {
			defer run.Done()
			d.run(ctx, active)
		}(d)
	}
	if mark := os.Getenv("LOAD_MARK"); mark != "" {
		_ = os.WriteFile(mark+".warm", []byte("1"), 0o644)
	}
	time.Sleep(warm)
	if mark := os.Getenv("LOAD_MARK"); mark != "" {
		_ = os.WriteFile(mark+".measure", []byte("1"), 0o644)
	}
	stats.measured.Store(true)
	time.Sleep(measure)
	stats.measured.Store(false)
	if mark := os.Getenv("LOAD_MARK"); mark != "" {
		_ = os.WriteFile(mark+".done", []byte("1"), 0o644)
	}
	stillStreams := 0
	for _, d := range devices {
		if d != nil && d.conn.TCPStreamsAvailable() {
			stillStreams++
		}
	}
	cancel()
	stopped := make(chan struct{})
	go func() { run.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(20 * time.Second):
	}
	for _, d := range devices {
		if d != nil {
			d.conn.Stop()
		}
	}

	stats.mu.Lock()
	out := map[string]any{
		"devices": n, "mode": os.Getenv("LOAD_MODE"),
		"connected": len(connected), "connect_failed": connectFail.Load(),
		"connect_ms": quantiles(connected), "ramp_s": math.Round(rampSeconds*10) / 10,
		"streams_available_at_end": stillStreams, "measure_s": measure.Seconds(),
		"counts": stats.counts,
	}
	for name, v := range stats.samples {
		out[name] = quantiles(v)
	}
	stats.mu.Unlock()
	data, _ := json.MarshalIndent(out, "", " ")
	t.Logf("%s", data)
	if path := os.Getenv("LOAD_OUT"); path != "" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
