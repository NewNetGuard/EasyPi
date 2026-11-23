package clientcore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// When the server ends an upload stream with an error while the client is
// still writing into it, the client must notice and open the next stream at
// once instead of staying blocked in the write.
func TestUploadStreamReopensPromptlyAfterServerError(t *testing.T) {
	var requests atomic.Int32
	var failedAt atomic.Int64
	secondAt := make(chan time.Time, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			buf := make([]byte, 64<<10)
			_, _ = io.ReadFull(r.Body, buf)
			failedAt.Store(time.Now().UnixNano())
			http.Error(w, "Tunnel forwarding failed", http.StatusBadGateway)
			return
		}
		select {
		case secondAt <- time.Now():
		default:
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &Transport{
		protocol:          "http2",
		fingerprint:       NewFingerprinter(),
		ctx:               ctx,
		epochCtx:          ctx,
		streamClient:      server.Client(),
		routeUpload:       server.URL + "/upload",
		uplinkFrames:      make(chan [][]byte, 64),
		downlinkAckNotify: make(chan struct{}, 1),
		uploadDrain:       make(chan uploadDrainRequest),
	}
	go transport.uploadLoop()
	go func() {
		packet := make([]byte, 1200)
		batch := [][]byte{packet, packet, packet, packet, packet, packet, packet, packet}
		for {
			select {
			case transport.uplinkFrames <- batch:
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case at := <-secondAt:
		gap := at.Sub(time.Unix(0, failedAt.Load()))
		t.Logf("next upload stream opened %s after the server error", gap.Round(time.Millisecond))
		if gap > 2*time.Second {
			t.Fatalf("next upload stream opened %s after the server error, want under 2s", gap)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("no new upload stream within 40s of the server error")
	}
}
