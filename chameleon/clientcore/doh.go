package clientcore

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DohClient handles DNS over HTTPS polling.
// It now reuses the same uTLS fingerprint as the main transport so both
// connections share an identical TLS JA3/JA4 hash from the same IP.
type DohClient struct {
	client *http.Client
	domain string
}

// NewDohClient creates a new DoH client.
// fp is the shared Fingerprinter — we clone its current profile's transport
// so the DoH TLS fingerprint matches the main transport.
func NewDohClient(domain string, fp *Fingerprinter) *DohClient {
	profile := fp.GetProfile()
	// DoH polling usually doesn't need REALITY as it talks to 1.1.1.1 (Cloudflare).
	// Use cloudflare-dns.com as SNI so certificate verification stays enabled.
	transport := CreateTLSTransport(profile, "1.1.1.1:443", "", nil, nil, "cloudflare-dns.com", nil, true)

	return &DohClient{
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		domain: domain,
	}
}

// DohResponse matches Cloudflare/Google DoH JSON format.
type DohResponse struct {
	Status   int         `json:"Status"`
	Answer   []DohAnswer `json:"Answer"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
}

type DohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"` // 16 for TXT
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

var quotedTXTPartRE = regexp.MustCompile(`"([^"]*)"`)

func normalizeTXTData(data string) string {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return ""
	}

	matches := quotedTXTPartRE.FindAllStringSubmatch(trimmed, -1)
	if len(matches) > 0 {
		var b strings.Builder
		for _, m := range matches {
			if len(m) > 1 {
				b.WriteString(m[1])
			}
		}
		return b.String()
	}

	return strings.Trim(trimmed, "\"")
}

// Poll fetches the latest TXT record for the configured domain via DoH.
func (d *DohClient) Poll() ([]byte, error) {
	if d.domain == "" {
		return nil, fmt.Errorf("DoH domain not configured")
	}

	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=TXT", d.domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dohResp DohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, fmt.Errorf("failed to parse DoH response: %w", err)
	}

	if dohResp.Status != 0 {
		return nil, fmt.Errorf("DNS error code: %d", dohResp.Status)
	}

	for _, ans := range dohResp.Answer {
		if ans.Type == 16 { // TXT
			txtData := normalizeTXTData(ans.Data)
			if txtData == "" {
				continue
			}

			decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(txtData)
			if err != nil {
				decoded, err = base32.StdEncoding.DecodeString(txtData)
				if err != nil {
					continue
				}
			}

			return decoded, nil
		}
	}

	return nil, nil
}
