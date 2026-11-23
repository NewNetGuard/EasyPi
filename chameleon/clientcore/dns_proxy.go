package clientcore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"chameleon/shared"
)

// DNSProxy listens on a local UDP port for DNS queries, forwards them through
// the Chameleon HTTPS tunnel to the server, and writes responses back.
//
// On Windows it automatically redirects the system DNS to the local listener
// on Start() and restores the original settings on Stop().
type DNSProxy struct {
	listenAddr    string
	transport     *Transport
	conn          *net.UDPConn
	stopCh        chan struct{}
	wg            sync.WaitGroup
	adapterStates []dnsAdapterState // saved Windows DNS state for restoration
}

// NewDNSProxy creates a new DNS proxy.
// listenAddr is typically "127.0.0.1:53" (requires admin) or "127.0.0.1:5353".
func NewDNSProxy(listenAddr string, transport *Transport) *DNSProxy {
	return &DNSProxy{
		listenAddr: listenAddr,
		transport:  transport,
		stopCh:     make(chan struct{}),
	}
}

// Start begins listening for DNS queries and automatically configures the
// system DNS to point to this proxy.
func (p *DNSProxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("dns proxy: resolve addr %s: %w", p.listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns proxy: bind %s: %w", p.listenAddr, err)
	}

	p.conn = conn
	LogState("dns-proxy", "started")

	// Automatically redirect system DNS to this proxy on Windows.
	states, err := applyWindowsDNS(p.listenAddr)
	if err != nil {
		LogOperationalFailure("dns-cfg", "automatic configuration skipped", err)
	} else if len(states) > 0 {
		p.adapterStates = states
		LogState("dns-cfg", "system DNS redirected")
	}

	p.wg.Add(1)
	go p.serve()

	return nil
}

// Stop shuts down the proxy and restores the original system DNS settings.
func (p *DNSProxy) Stop() {
	close(p.stopCh)
	if p.conn != nil {
		p.conn.Close()
	}
	p.wg.Wait()
	// Restore original Windows DNS settings.
	if len(p.adapterStates) > 0 {
		restoreWindowsDNS(p.adapterStates)
	}
	LogState("dns-proxy", "stopped")
}

func (p *DNSProxy) serve() {
	defer p.wg.Done()

	buf := make([]byte, 4096)
	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-p.stopCh:
				return
			default:
				LogOperationalFailure("dns-proxy", "read failed", err)
				continue
			}
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		// Handle each query concurrently so one slow query doesn't block others.
		p.wg.Add(1)
		go func(q []byte, addr *net.UDPAddr) {
			defer p.wg.Done()
			p.handleQuery(q, addr)
		}(query, clientAddr)
	}
}

func (p *DNSProxy) handleQuery(query []byte, clientAddr *net.UDPAddr) {
	response, err := p.transport.ResolveDNS(query)
	if err != nil {
		LogOperationalFailure("dns-proxy", "resolution failed", err)
		// Send a SERVFAIL response so the caller doesn't hang.
		if len(query) >= 2 {
			fail := makeServfail(query)
			p.conn.WriteToUDP(fail, clientAddr)
		}
		return
	}

	if _, err := p.conn.WriteToUDP(response, clientAddr); err != nil {
		LogOperationalFailure("dns-proxy", "response write failed", err)
	}
}

// makeServfail builds a minimal DNS SERVFAIL message from the original query ID.
func makeServfail(query []byte) []byte {
	resp := make([]byte, 12)
	copy(resp[0:2], query[0:2]) // Query ID
	resp[2] = 0x81              // QR=1 (response), Opcode=0, AA=0, TC=0, RD=1
	resp[3] = 0x82              // RA=1, Z=0, RCODE=2 (SERVFAIL)
	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all 0
	return resp
}

// -- Transport.ResolveDNS ----------------------------------------------------

// dnsQueryBody is the JSON body for POST /<prefix>/dns.
type dnsQueryBody struct {
	D string `json:"d"` // base64-encoded raw DNS query
}

// dnsResponseBody is the JSON response from POST /<prefix>/dns.
type dnsResponseBody struct {
	D string `json:"d"` // base64-encoded raw DNS response
}

// ResolveDNS sends a raw DNS query through the HTTPS tunnel and returns the
// raw DNS response. Called by the local DNS proxy for every inbound query.
func (t *Transport) ResolveDNS(rawQuery []byte) ([]byte, error) {
	t.mu.RLock()
	cipher := t.innerCipher
	t.mu.RUnlock()
	if cipher == nil {
		return nil, fmt.Errorf("dns: inner cipher is not initialized")
	}
	encryptedQuery, err := cipher.Encrypt(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("dns: encrypt query: %w", err)
	}
	body := dnsQueryBody{
		D: base64.StdEncoding.EncodeToString(encryptedQuery),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("dns: marshal: %w", err)
	}

	client, requestCtx, _ := t.currentRequestEpoch()
	if client == nil || requestCtx == nil {
		return nil, fmt.Errorf("dns: transport epoch unavailable")
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost,
		t.serverURL+shared.RouteForPrefix(t.prefix, shared.EndpointSuffixDNS),
		bytes.NewReader(bodyJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("dns: create request: %w", err)
	}

	t.addHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dns: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns: server returned %d", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, fmt.Errorf("dns: read response: %w", err)
	}

	var dr dnsResponseBody
	if err := json.Unmarshal(rawBody, &dr); err != nil {
		return nil, fmt.Errorf("dns: parse response: %w", err)
	}
	if dr.D == "" {
		return nil, fmt.Errorf("dns: response payload is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(dr.D)
	if err != nil {
		return nil, fmt.Errorf("dns: base64 decode: %w", err)
	}

	plaintext, err := cipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("dns: decrypt response: %w", err)
	}
	return plaintext, nil
}
