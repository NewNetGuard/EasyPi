package clientcore

// TLS record sizes the real client stack (uTLS Chrome profile, record
// shaping, HTTP/2) puts on the wire during a bulk upload, read by a proxy
// between the client and a local HTTP/2 server.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// recordProxy forwards TCP connections to target and counts the TLS
// application-data records in each direction.
type recordProxy struct {
	listener net.Listener
	up, down *recordTap
}

func startRecordProxy(t *testing.T, target string) *recordProxy {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	p := &recordProxy{listener: listener, up: &recordTap{start: time.Now()}, down: &recordTap{start: time.Now()}}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp4", target)
			if err != nil {
				client.Close()
				return
			}
			go copyTapped(server, client, p.up, true)
			go copyTapped(client, server, p.down, false)
		}
	}()
	return p
}

func copyTapped(dst, src net.Conn, tap *recordTap, up bool) {
	buf := make([]byte, 64<<10)
	var pending []byte
	for {
		n, err := src.Read(buf)
		if n > 0 {
			tap.feed(&pending, buf[:n], up)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if tcp, ok := dst.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			return
		}
	}
}

func histogram(records []tlsRecord, up bool, after time.Duration) string {
	counts := map[int]int{}
	total := 0
	for _, r := range records {
		if r.up == up && r.kind == 0x17 && r.at >= after {
			counts[r.size-5]++ // the record length field, as tshark reports it
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
	for i, e := range list {
		if i == 6 {
			break
		}
		top = append(top, fmt.Sprintf("%d x%d", e.size, e.n))
	}
	full := counts[16401]
	return fmt.Sprintf("%d records, full-size (length 16401) %.0f%%, top: %s", total, 100*float64(full)/float64(max(total, 1)), strings.Join(top, ", "))
}

// Chrome 158 uploaded 25 MB in full-size records (1485 of 1487 at length
// 16401). The carrier used to split bulk writes into random 3-14 KiB records,
// none of them full-size; it must now send bulk like Chrome.
func TestBulkUploadUsesFullSizeRecordsLikeChrome(t *testing.T) {
	payload := bytes.Repeat([]byte("u"), 8<<20)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write(payload)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	pin := sha256.Sum256(server.Certificate().Raw)
	proxy := startRecordProxy(t, server.Listener.Addr().String())

	profile := desktopFingerprintProfiles[0]
	transport := CreateTLSTransport(profile, "example.com", proxy.listener.Addr().String(),
		bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32), "example.com", pin[:], false)
	client := &http.Client{Transport: transport}

	// Warm the connection (handshake, settings) before measuring.
	resp, err := client.Post("https://example.com/warm", "application/octet-stream", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)

	mark := time.Since(proxy.up.start)
	resp, err = client.Post("https://example.com/upload", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	records := proxy.up.snapshot()
	t.Logf("upload 8 MiB, client records: %s", histogram(records, true, mark))
	full, total := 0, 0
	for _, r := range records {
		if r.up && r.kind == 0x17 && r.at >= mark {
			total++
			if r.size-5 == 16401 {
				full++
			}
		}
	}
	if total == 0 || full*100 < total*90 {
		t.Fatalf("%d of %d upload records full-size, want at least 90%%", full, total)
	}
}
