package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudflareClient handles DNS record updates via Cloudflare API.
type CloudflareClient struct {
	APIToken string
	ZoneID   string
	Domain   string
	client   *http.Client
}

// NewCloudflareClient creates a new Cloudflare client.
func NewCloudflareClient(token, zoneID, domain string) *CloudflareClient {
	return &CloudflareClient{
		APIToken: token,
		ZoneID:   zoneID,
		Domain:   domain,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

const (
	// TXT record single-string limit is 255 chars; keep a margin for compatibility.
	cfTXTChunkSize = 240
	// Keep payload bounded to avoid oversized DNS responses.
	cfTXTMaxChunks = 15
)

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfListResponse struct {
	Success bool         `json:"success"`
	Result  []cfRecord   `json:"result"`
	Errors  []cfAPIError `json:"errors"`
}

type cfRecordResponse struct {
	Success bool         `json:"success"`
	Result  cfRecord     `json:"result"`
	Errors  []cfAPIError `json:"errors"`
}

func formatCFErrors(errs []cfAPIError) string {
	if len(errs) == 0 {
		return "unknown Cloudflare API error"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		if e.Code != 0 {
			parts = append(parts, fmt.Sprintf("code_%d", e.Code))
		} else {
			parts = append(parts, "unclassified")
		}
	}
	return strings.Join(parts, "; ")
}

func buildTXTContent(encoded string) (string, error) {
	if encoded == "" {
		return "\"\"", nil
	}
	chunks := make([]string, 0, (len(encoded)/cfTXTChunkSize)+1)
	for i := 0; i < len(encoded); i += cfTXTChunkSize {
		end := i + cfTXTChunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[i:end])
	}
	if len(chunks) > cfTXTMaxChunks {
		return "", fmt.Errorf("encoded payload too large for TXT transport (%d chunks > %d)", len(chunks), cfTXTMaxChunks)
	}

	quoted := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		quoted = append(quoted, fmt.Sprintf("\"%s\"", chunk))
	}
	return strings.Join(quoted, " "), nil
}

// PublishData sends data to the client via a DNS TXT record.
// Data is Base32 encoded.
func (c *CloudflareClient) PublishData(data []byte) error {
	if c.APIToken == "" || c.ZoneID == "" || c.Domain == "" {
		return fmt.Errorf("Cloudflare not configured")
	}

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	content, err := buildTXTContent(encoded)
	if err != nil {
		return err
	}

	// 1. Find existing record ID
	recordID, err := c.getRecordID()
	if err != nil {
		return err
	}

	// 2. Update record
	return c.updateRecord(recordID, content)
}

func (c *CloudflareClient) getRecordID() (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=TXT&name=%s", c.ZoneID, c.Domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("failed to list records: status=%d", resp.StatusCode)
	}

	var listResp cfListResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return "", err
	}

	if !listResp.Success {
		return "", fmt.Errorf("failed to list records: %s", formatCFErrors(listResp.Errors))
	}

	if len(listResp.Result) > 0 {
		return listResp.Result[0].ID, nil
	}

	// Not found: create a new TXT record and return its ID.
	return c.createRecord()
}

func (c *CloudflareClient) createRecord() (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", c.ZoneID)
	payload := map[string]interface{}{
		"type":    "TXT",
		"name":    c.Domain,
		"content": "\"init\"",
		"ttl":     60, // low TTL for tunnel-ish usage
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("create record failed: status=%d", resp.StatusCode)
	}

	var createResp cfRecordResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		return "", err
	}
	if !createResp.Success {
		return "", fmt.Errorf("create record failed: %s", formatCFErrors(createResp.Errors))
	}
	if createResp.Result.ID == "" {
		return "", fmt.Errorf("create record failed: empty record id in response")
	}

	return createResp.Result.ID, nil
}

func (c *CloudflareClient) updateRecord(recordID, content string) error {
	if recordID == "" {
		// Try to resolve/create and continue.
		id, err := c.getRecordID()
		if err != nil {
			return err
		}
		recordID = id
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", c.ZoneID, recordID)
	payload := map[string]interface{}{
		"type":    "TXT",
		"name":    c.Domain,
		"content": content,
		"ttl":     60,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("update record failed: status=%d", resp.StatusCode)
	}

	var updResp cfRecordResponse
	if err := json.Unmarshal(body, &updResp); err != nil {
		return err
	}
	if !updResp.Success {
		return fmt.Errorf("update record failed: %s", formatCFErrors(updResp.Errors))
	}

	return nil
}
