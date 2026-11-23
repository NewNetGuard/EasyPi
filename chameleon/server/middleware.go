package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// nginxMiddleware applies ordinary web security headers to the internal HTTP
// application. It deliberately does not forge a Server header: production TLS
// and HTTP/2 are terminated by the real nginx frontend.
func nginxMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Vary header is standard for CORS-enabled APIs.
		w.Header().Set("Vary", "Accept-Encoding, Origin")

		next.ServeHTTP(w, r)
	})
}

// apiHeaders adds realistic API-endpoint-specific headers.
// Called by each API handler after the nginx middleware has run.
func apiHeaders(w http.ResponseWriter) {
	// Realistic cache-control for API responses.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Request-ID", randomHex(16))

	// Add a realistic Date header (nginx always sets this).
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
}

// randomHex generates a random hex string of n bytes.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// notFoundHandler returns a generic cover-site 404 page.
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(coverErrorPage(404)))
}

// internalErrorHandler returns an nginx-style 500 page.
func internalErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(coverErrorPage(500)))
}

func coverErrorPage(code int) string {
	return `<html>
<head><title>` + http.StatusText(code) + `</title></head>
<body>
<center><h1>` + http.StatusText(code) + `</h1></center>
</body>
</html>
`
}
