package clientcore

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

// The carrier's HTTP/2 client announces the default frame size, which the
// record shaper then leaves out of the opening SETTINGS, as Chromium does.
func TestCarrierHTTP2ClientKeepsTheDefaultFrameSize(t *testing.T) {
	roundTripper := createRealityHTTP2Transport(FingerprintProfile{}, "127.0.0.1:1", nil, nil, "", nil, false)
	tracked, ok := roundTripper.(*trackedRoundTripper)
	if !ok {
		t.Fatalf("unexpected round tripper %T", roundTripper)
	}
	transport, ok := tracked.base.(*http2.Transport)
	if !ok {
		t.Fatalf("unexpected base transport %T", tracked.base)
	}
	if transport.MaxReadFrameSize != 16<<10 || transport.MaxHeaderListSize != 256<<10 ||
		transport.MaxDecoderHeaderTableSize != 64<<10 {
		t.Fatalf("HTTP/2 limits differ from Chromium's: frame=%d headers=%d table=%d",
			transport.MaxReadFrameSize, transport.MaxHeaderListSize, transport.MaxDecoderHeaderTableSize)
	}
}

func TestSessionRequestsVaryInSizeButKeepTheirPath(t *testing.T) {
	const route = "https://carrier.example/abcdef0123456789/sync"
	lengths := map[int]bool{}
	for i := 0; i < 400; i++ {
		target := withCacheBuster(route)
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		token := parsed.Query().Get("_")
		if !strings.HasPrefix(target, route+"?_=") || len(token) < sessionQueryMinLength || len(token) > sessionQueryMaxLength {
			t.Fatalf("unexpected cache-busting query: %q", target)
		}
		lengths[len(token)] = true

		// The authenticator is bound to the path, which the query leaves alone.
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		if requestPath(request) != "/abcdef0123456789/sync" {
			t.Fatalf("authenticated path changed: %q", requestPath(request))
		}
	}
	if len(lengths) < 20 {
		t.Fatalf("only %d different query lengths in 400 requests", len(lengths))
	}
}
