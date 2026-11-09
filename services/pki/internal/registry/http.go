package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient talks to the Registry's internal API:
//
//	GET  {base}/internal/v1/tenants/{tenant}/devices/{device}            -> Device JSON
//	POST {base}/internal/v1/tenants/{tenant}/devices/{device}/assurance  {"assurance_level": "..."}
//	POST {base}/internal/v1/devices/{device}/enrolled                    Enrollment JSON
//
// Requests carry "Authorization: Bearer <token>"; the HTTP client should be
// configured with the Services CA client certificate for mTLS (§7).
type HTTPClient struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// NewHTTPClient returns a client with a 5 s timeout.
func NewHTTPClient(baseURL, token string, client *http.Client) *HTTPClient {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &HTTPClient{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, Client: client}
}

func (c *HTTPClient) deviceURL(tenantID, deviceID, suffix string) string {
	return fmt.Sprintf("%s/internal/v1/tenants/%s/devices/%s%s", c.BaseURL, url.PathEscape(tenantID), url.PathEscape(deviceID), suffix)
}

func (c *HTTPClient) do(req *http.Request) (*http.Response, error) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Accept", "application/json")
	return c.Client.Do(req)
}

// GetDevice implements Client.
func (c *HTTPClient) GetDevice(ctx context.Context, tenantID, deviceID string) (*Device, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.deviceURL(tenantID, deviceID, ""), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("registry: unexpected status %d", resp.StatusCode)
	}
	var d Device
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("registry: decode device: %w", err)
	}
	if d.DeviceID == "" {
		d.DeviceID = deviceID
	}
	if d.TenantID == "" {
		d.TenantID = tenantID
	}
	if d.State == "" {
		return nil, fmt.Errorf("registry: device %s has no state", deviceID)
	}
	return &d, nil
}

// RecordAssurance implements Client.
func (c *HTTPClient) RecordAssurance(ctx context.Context, tenantID, deviceID, assurance string) error {
	payload, _ := json.Marshal(map[string]string{"assurance_level": assurance})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.deviceURL(tenantID, deviceID, "/assurance"), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("registry: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// RecordEnrollment implements Client:
//
//	POST {base}/internal/v1/devices/{device}/enrolled  Enrollment JSON
//
// 404 maps to ErrNotFound; other 4xx responses except 408 and 429 map to
// ErrRejected (retrying cannot help); everything else is a transient error.
func (c *HTTPClient) RecordEnrollment(ctx context.Context, _, deviceID string, e Enrollment) error {
	e.NotBefore, e.NotAfter = e.NotBefore.UTC(), e.NotAfter.UTC()
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/internal/v1/devices/%s/enrolled", c.BaseURL, url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("registry: enrolled callback returned %d", resp.StatusCode)
	case resp.StatusCode >= 400 && resp.StatusCode <= 499:
		return fmt.Errorf("%w: enrolled callback returned %d", ErrRejected, resp.StatusCode)
	}
	return fmt.Errorf("registry: enrolled callback returned %d", resp.StatusCode)
}
