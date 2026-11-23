package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// dnsRequest is the JSON body for POST /<prefix>/dns.
type dnsRequest struct {
	D string `json:"d"` // base64-encoded raw DNS query
}

// dnsResponse is the JSON response from POST /<prefix>/dns.
type dnsResponse struct {
	D   string `json:"d"`   // base64-encoded raw DNS response
	Rid string `json:"rid"` // random request ID (response padding)
}

// handleDNS proxies raw DNS queries from the client to an upstream DNS resolver.
// The transport is HTTPS, indistinguishable from ordinary API calls.
//
// Protocol:
//
//	POST /<prefix>/dns  →  body {"d":"<base64 raw DNS query>"}
//	← body {"d":"<base64 raw DNS response>","rid":"<hex>"}
func handleDNS(upstreamDNS string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, finish, ok := admitSessionRequest(w, r, ClientIDFromContext(r.Context()))
		if !ok {
			return
		}
		defer finish()
		cipher := CipherFromContext(r.Context())
		if cipher == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		bodyRaw, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req dnsRequest
		if err := json.Unmarshal(bodyRaw, &req); err != nil || req.D == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		encryptedQuery, err := base64.StdEncoding.DecodeString(req.D)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		rawQuery, err := cipher.Decrypt(encryptedQuery)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		rawResponse, err := forwardDNSQuery(rawQuery, upstreamDNS)
		if err != nil {
			logOperationalFailure("dns", "upstream request failed", err)
			http.Error(w, "DNS resolution failed", http.StatusBadGateway)
			return
		}

		encryptedResponse, err := cipher.Encrypt(rawResponse)
		if err != nil {
			http.Error(w, "DNS response encryption failed", http.StatusInternalServerError)
			return
		}
		resp := dnsResponse{
			D:   base64.StdEncoding.EncodeToString(encryptedResponse),
			Rid: randomHex(8),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}

// forwardDNSQuery sends a raw DNS query to upstreamDNS (e.g. "1.1.1.1:53")
// over UDP and returns the raw DNS response.
func forwardDNSQuery(query []byte, upstreamDNS string) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstreamDNS, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial upstream DNS: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}

	return buf[:n], nil
}
