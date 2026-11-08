package revocation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Wire constants for the Policy service push.
const (
	PublishPath     = "/internal/v1/revocations"
	HeaderSignature = "X-IronMesh-Signature"
	HeaderEventID   = "X-IronMesh-Event-ID"
	DefaultRetries  = 3
	DefaultBackoff  = 500 * time.Millisecond
)

// Event is the JSON revocation event pushed to the Policy service.
type Event struct {
	EventID   string    `json:"event_id"`
	Serial    string    `json:"serial"`
	DeviceID  string    `json:"device_id"`
	TenantID  string    `json:"tenant_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Publisher delivers revocation events.
type Publisher interface {
	Publish(ctx context.Context, ev Event) error
}

// HTTPPublisher POSTs events to PKI_POLICY_URL + /internal/v1/revocations with
// a bearer token and an HMAC-SHA256 signature over the body, retrying on
// transport errors and 5xx responses.
type HTTPPublisher struct {
	URL     string
	Token   string
	HMACKey []byte
	Client  *http.Client
	Retries int
	Backoff time.Duration
	// Sleep is replaced in tests to avoid real waits.
	Sleep  func(time.Duration)
	Logger *slog.Logger
}

// NewHTTPPublisher returns a publisher with 3 retries and 500 ms backoff.
func NewHTTPPublisher(policyURL, token string, hmacKey []byte, client *http.Client) (*HTTPPublisher, error) {
	policyURL = strings.TrimRight(strings.TrimSpace(policyURL), "/")
	if policyURL == "" {
		return nil, errors.New("revocation: policy URL is required")
	}
	if len(hmacKey) == 0 {
		return nil, errors.New("revocation: HMAC key is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	return &HTTPPublisher{URL: policyURL + PublishPath, Token: token, HMACKey: hmacKey, Client: client, Retries: DefaultRetries, Backoff: DefaultBackoff, Sleep: time.Sleep, Logger: slog.Default()}, nil
}

// Sign returns the signature header value for body.
func Sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a signature header against body (used by the Policy
// service and by tests).
func VerifySignature(key, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(key, body)), []byte(header))
}

// Publish implements Publisher.
func (p *HTTPPublisher) Publish(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	sig := Sign(p.HMACKey, body)
	retries := p.Retries
	if retries < 0 {
		retries = 0
	}
	sleep := p.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			sleep(p.Backoff)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderSignature, sig)
		req.Header.Set(HeaderEventID, ev.EventID)
		if p.Token != "" {
			req.Header.Set("Authorization", "Bearer "+p.Token)
		}
		resp, err := p.Client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("revocation: publish attempt %d: %w", attempt+1, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("revocation: publish attempt %d: policy service returned %d", attempt+1, resp.StatusCode)
			continue
		default:
			return fmt.Errorf("revocation: policy service rejected event with %d", resp.StatusCode)
		}
	}
	return lastErr
}

// NoopPublisher logs events instead of delivering them (PKI_POLICY_URL unset).
type NoopPublisher struct {
	Logger *slog.Logger
}

// Publish implements Publisher.
func (n NoopPublisher) Publish(_ context.Context, ev Event) error {
	l := n.Logger
	if l == nil {
		l = slog.Default()
	}
	l.Warn("revocation event not published: PKI_POLICY_URL is not configured", "event_id", ev.EventID, "serial", ev.Serial, "device_id", ev.DeviceID, "tenant_id", ev.TenantID)
	return nil
}
