package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"chameleon/shared"
)

func TestSyncDoesNotAdvertiseConnectCarrierBehindNginx(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/sync", nil)

	nginxResponse := httptest.NewRecorder()
	handleSyncWithCapabilities(false)(nginxResponse, request)
	if got := nginxResponse.Header().Get(shared.ConnectCarrierHeader); got != "" {
		t.Fatalf("nginx frontend advertised unsupported CONNECT carrier %q", got)
	}

	directResponse := httptest.NewRecorder()
	handleSyncWithCapabilities(true)(directResponse, request)
	if got := directResponse.Header().Get(shared.ConnectCarrierHeader); got != shared.ConnectCarrierVersion {
		t.Fatalf("direct frontend CONNECT carrier = %q, want %q", got, shared.ConnectCarrierVersion)
	}
}

// Older clients enable streams only on the exact TCP stream version; shaped
// framing is advertised beside it, never instead of it.
func TestSyncAdvertisesShapedStreamsBesideTheStreamVersion(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/sync", nil)
	for _, direct := range []bool{false, true} {
		response := httptest.NewRecorder()
		handleSyncWithCapabilities(direct)(response, request)
		if got := response.Header().Get(shared.TCPStreamHeader); got != "1" {
			t.Fatalf("stream version %q, want \"1\"", got)
		}
		if got := response.Header().Get(shared.TCPStreamShapeHeader); got != shared.TCPStreamShapeVersion {
			t.Fatalf("shaped streams advertised as %q", got)
		}
	}
}
