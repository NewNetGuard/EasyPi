package clientcore

// Bench for the nginx WINDOW_UPDATE threshold patch over TLS, with the real
// carrier stack (uTLS Chrome profile, REALITY-path HTTP/2 transport). It runs
// only when NGINX_BENCH_ADDR is set; tools/nginx-h2-window/run_tls.sh sets it
// up locally (nginx + sink.py + wan.py). WINDOW_UPDATE frames are counted from
// outside TLS: alone in a TLS 1.3 record a 13-byte frame is a 30-byte record.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const benchMB25 = 25 << 20

// benchRecords yields records [4B len][8B unix ns at creation][payload], the
// format tools/nginx-h2-window/sink.py measures delays from.
type benchRecords struct {
	payload, left int
	pending      []byte
}

func (r *benchRecords) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.left > 0 {
		if len(r.pending) == 0 {
			rec := make([]byte, 12+r.payload)
			binary.BigEndian.PutUint32(rec, uint32(r.payload))
			binary.BigEndian.PutUint64(rec[4:], uint64(time.Now().UnixNano()))
			r.pending = rec
		}
		k := min(len(p)-n, len(r.pending), r.left)
		copy(p[n:], r.pending[:k])
		r.pending = r.pending[k:]
		n += k
		r.left -= k
	}
	return n, nil
}

func benchRecord(payload int) []byte {
	rec := make([]byte, 12+payload)
	binary.BigEndian.PutUint32(rec, uint32(payload))
	binary.BigEndian.PutUint64(rec[4:], uint64(time.Now().UnixNano()))
	return rec
}

type benchSink struct {
	Bytes    int            `json:"bytes"`
	Leftover int            `json:"leftover"`
	SmallMS  map[string]any `json:"small_ms"`
	BigMS    map[string]any `json:"big_ms"`
}

type benchEnv struct {
	t        *testing.T
	pin      []byte
	capped   string
	free     string
	profile  FingerprintProfile
	results  map[string]any
	deadline time.Duration
}

// client returns a fresh carrier-like HTTP/2 client and the TLS record tap
// of its (single) connection.
func (e *benchEnv) client(target string) (*http.Client, *recordProxy) {
	proxy := startRecordProxy(e.t, target)
	transport := CreateTLSTransport(e.profile, "bench.local", proxy.listener.Addr().String(),
		bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32), "bench.local", e.pin, false)
	return &http.Client{Transport: transport}, proxy
}

func (e *benchEnv) post(ctx context.Context, client *http.Client, body io.Reader, slow string) (benchSink, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://bench.local/up", body)
	if err != nil {
		return benchSink{}, err
	}
	req.ContentLength = -1 // streamed like a carrier stream
	if slow != "" {
		req.Header.Set("X-Slow-Rate", slow)
	}
	resp, err := client.Do(req)
	if err != nil {
		return benchSink{}, err
	}
	defer resp.Body.Close()
	var out benchSink
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("status %d", resp.StatusCode)
	}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// downRecords summarises server-to-client application records after mark:
// count, how many are a lone WINDOW_UPDATE (record length 30), top sizes.
func downRecords(records []tlsRecord, mark time.Duration) map[string]any {
	counts := map[int]int{}
	total := 0
	for _, r := range records {
		if !r.up && r.kind == 0x17 && r.at >= mark {
			counts[r.size-5]++
			total++
		}
	}
	type kv struct{ size, n int }
	var list []kv
	for s, n := range counts {
		list = append(list, kv{s, n})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].n > list[b].n })
	var top []string
	for i, x := range list {
		if i == 5 {
			break
		}
		top = append(top, fmt.Sprintf("%dx%d", x.size, x.n))
	}
	return map[string]any{"down_records": total, "wu_records_30": counts[30], "top": strings.Join(top, " ")}
}

func (e *benchEnv) warm(ctx context.Context, client *http.Client, proxy *recordProxy) time.Duration {
	if _, err := e.post(ctx, client, bytes.NewReader(benchRecord(10)), ""); err != nil {
		e.t.Fatalf("warm: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	return time.Since(proxy.down.start)
}

func (e *benchEnv) run(name string, fn func(ctx context.Context) (map[string]any, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), e.deadline)
	defer cancel()
	out, err := fn(ctx)
	if err != nil {
		out = map[string]any{"ok": false, "FAIL": err.Error()}
	}
	e.results[name] = out
	e.t.Logf("%s: %v", name, out)
}

func (e *benchEnv) bulk(target, slow string) func(ctx context.Context) (map[string]any, error) {
	return func(ctx context.Context) (map[string]any, error) {
		client, proxy := e.client(target)
		mark := e.warm(ctx, client, proxy)
		start := time.Now()
		sink, err := e.post(ctx, client, &benchRecords{payload: 16384 - 12, left: benchMB25}, slow)
		if err != nil {
			return nil, err
		}
		secs := time.Since(start).Seconds()
		time.Sleep(100 * time.Millisecond)
		out := downRecords(proxy.down.snapshot(), mark)
		out["mb_s"] = float64(benchMB25) / secs / 1e6
		out["big_ms"] = sink.BigMS
		out["ok"] = sink.Bytes == benchMB25 && sink.Leftover == 0
		return out, nil
	}
}

// piped runs one streamed POST whose body is written by write.
func (e *benchEnv) piped(ctx context.Context, client *http.Client, write func(w io.Writer) error) (benchSink, error) {
	r, w := io.Pipe()
	go func() { w.CloseWithError(write(w)) }()
	return e.post(ctx, client, r, "")
}

func TestNginxWindowBench(t *testing.T) {
	capped := os.Getenv("NGINX_BENCH_ADDR")
	if capped == "" {
		t.Skip("set NGINX_BENCH_ADDR (see tools/nginx-h2-window/run_tls.sh)")
	}
	certPEM, err := os.ReadFile(os.Getenv("NGINX_BENCH_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	pin := sha256.Sum256(block.Bytes)
	e := &benchEnv{t: t, pin: pin[:], capped: capped, free: os.Getenv("NGINX_BENCH_FREE_ADDR"),
		profile: desktopFingerprintProfiles[0], results: map[string]any{}, deadline: 180 * time.Second}

	for i := 1; i <= 3; i++ {
		e.run(fmt.Sprintf("bulk_capped_%d", i), e.bulk(e.capped, ""))
	}
	for i := 1; i <= 2; i++ {
		e.run(fmt.Sprintf("bulk_free_%d", i), e.bulk(e.free, ""))
	}
	e.run("slow_3mb", e.bulk(e.free, "3000000"))

	e.run("interactive", func(ctx context.Context) (map[string]any, error) {
		client, proxy := e.client(e.capped)
		mark := e.warm(ctx, client, proxy)
		done := make(chan struct{})
		var bulkSink benchSink
		var bulkErr error
		start := time.Now()
		go func() {
			defer close(done)
			bulkSink, bulkErr = e.post(ctx, client, &benchRecords{payload: 16384 - 12, left: benchMB25}, "")
		}()
		probe, err := e.piped(ctx, client, func(w io.Writer) error {
			for {
				select {
				case <-done:
					return nil
				case <-time.After(20 * time.Millisecond):
					if _, err := w.Write(benchRecord(64)); err != nil {
						return err
					}
				}
			}
		})
		<-done
		if bulkErr != nil {
			return nil, bulkErr
		}
		if err != nil {
			return nil, err
		}
		secs := time.Since(start).Seconds()
		time.Sleep(100 * time.Millisecond)
		out := downRecords(proxy.down.snapshot(), mark)
		out["bulk_mb_s"] = float64(benchMB25) / secs / 1e6
		out["probe_ms"] = probe.SmallMS
		out["ok"] = bulkSink.Bytes == benchMB25 && probe.Leftover == 0
		return out, nil
	})

	e.run("trickle", func(ctx context.Context) (map[string]any, error) {
		client, proxy := e.client(e.capped)
		mark := e.warm(ctx, client, proxy)
		sink, err := e.piped(ctx, client, func(w io.Writer) error {
			for i := 0; i < 400; i++ {
				if _, err := w.Write(benchRecord(100)); err != nil {
					return err
				}
				time.Sleep(5 * time.Millisecond)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		out := downRecords(proxy.down.snapshot(), mark)
		out["small_ms"] = sink.SmallMS
		out["ok"] = sink.Bytes == 400*112 && sink.Leftover == 0
		return out, nil
	})

	e.run("pauses", func(ctx context.Context) (map[string]any, error) {
		client, _ := e.client(e.capped)
		sink, err := e.piped(ctx, client, func(w io.Writer) error {
			if _, err := io.Copy(w, &benchRecords{payload: 16384 - 12, left: 200 * 16384}); err != nil {
				return err
			}
			for i := 0; i < 2; i++ {
				time.Sleep(2 * time.Second)
				if _, err := w.Write(benchRecord(100)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"small_ms": sink.SmallMS, "ok": sink.Bytes == 200*16384+224 && sink.Leftover == 0}, nil
	})

	for _, mode := range []string{"last_byte", "bare_end"} {
		e.run("last_"+mode, func(ctx context.Context) (map[string]any, error) {
			client, _ := e.client(e.capped)
			sink, err := e.piped(ctx, client, func(w io.Writer) error {
				size := benchMB25
				if mode == "last_byte" {
					size--
				}
				src := &benchRecords{payload: 16384 - 12, left: size}
				if _, err := io.Copy(w, src); err != nil {
					return err
				}
				time.Sleep(time.Second)
				if mode == "last_byte" {
					_, err := w.Write(src.pending[:1])
					return err
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"ok": sink.Bytes == benchMB25 && sink.Leftover == 0}, nil
		})
	}

	data, _ := json.MarshalIndent(e.results, "", " ")
	if out := os.Getenv("NGINX_BENCH_OUT"); out != "" {
		if err := os.WriteFile(out, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// procMemory reads VmPeak/VmSize (virtual) and VmHWM/VmRSS (resident), in KiB.
func procMemory(t *testing.T, pid string) map[string]int {
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		for _, key := range []string{"VmPeak", "VmSize", "VmHWM", "VmRSS"} {
			if strings.HasPrefix(line, key+":") {
				var kb int
				fmt.Sscanf(strings.TrimSpace(line[len(key)+1:]), "%d", &kb)
				out[key] = kb
			}
		}
	}
	return out
}

// TestNginxMemoryBench opens NGINX_MEM_STREAMS concurrent full-duplex streams
// (like the carrier's device TCP streams) on one carrier connection and
// records nginx's memory before and with them:
//   - idle: each stream sent one small record, then waits;
//   - active: every stream uploads continuously;
//   - stalled: every stream uploads, the upstream reads ~nothing (the buffers
//     fill up to their flow-control limit; worst case).
func TestNginxMemoryBench(t *testing.T) {
	addr, pid := os.Getenv("NGINX_MEM_ADDR"), os.Getenv("NGINX_MEM_PID")
	if addr == "" || pid == "" {
		t.Skip("set NGINX_MEM_ADDR and NGINX_MEM_PID (see tools/nginx-h2-window/run_mem.sh)")
	}
	n, _ := strconv.Atoi(os.Getenv("NGINX_MEM_STREAMS"))
	mode := os.Getenv("NGINX_MEM_MODE")
	certPEM, err := os.ReadFile(os.Getenv("NGINX_BENCH_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	pin := sha256.Sum256(block.Bytes)
	e := &benchEnv{t: t, pin: pin[:], profile: desktopFingerprintProfiles[0]}
	client, proxy := e.client(addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.warm(ctx, client, proxy)
	time.Sleep(300 * time.Millisecond)
	before := procMemory(t, pid)

	var opened sync.WaitGroup
	var openErrs atomic.Int64
	var pipes []*io.PipeWriter
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		r, w := io.Pipe()
		mu.Lock()
		pipes = append(pipes, w)
		mu.Unlock()
		opened.Add(1)
		go func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://bench.local/up", r)
			req.ContentLength = -1
			req.Header.Set("X-Early", "1")
			if mode == "stalled" {
				req.Header.Set("X-Slow-Rate", "1")
			}
			go func() {
				if mode == "idle" {
					_, _ = w.Write(benchRecord(1000))
					return
				}
				_, _ = io.Copy(w, &benchRecords{payload: 16384 - 12, left: 1 << 40})
			}()
			resp, err := client.Do(req)
			if err != nil {
				openErrs.Add(1)
			} else {
				go func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
			}
			opened.Done()
		}()
	}
	waited := make(chan struct{})
	go func() { opened.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(30 * time.Second):
		t.Fatalf("streams did not open within 30 s")
	}
	maxRSS := 0
	for i := 0; i < 24; i++ { // 6 s under load, sampled
		time.Sleep(250 * time.Millisecond)
		if rss := procMemory(t, pid)["VmRSS"]; rss > maxRSS {
			maxRSS = rss
		}
	}
	after := procMemory(t, pid)
	cancel()
	for _, w := range pipes {
		w.CloseWithError(context.Canceled)
	}
	line, _ := json.Marshal(map[string]any{
		"streams": n, "mode": mode, "open_errors": openErrs.Load(),
		"before": before, "after": after, "max_sampled_rss": maxRSS,
	})
	t.Logf("%s", line)
	if out := os.Getenv("NGINX_MEM_OUT"); out != "" {
		f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		_, _ = f.Write(append(line, '\n'))
	}
	if openErrs.Load() > 0 {
		t.Fatalf("%d streams failed to open", openErrs.Load())
	}
}
