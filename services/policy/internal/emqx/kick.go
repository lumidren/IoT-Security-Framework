// Package emqx talks to the EMQX 5 management API to terminate live MQTT sessions.
package emqx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Kicker disconnects a connected MQTT client. Implementations must treat an already-offline client
// as success.
type Kicker interface {
	Kick(ctx context.Context, clientID string) error
}

// ErrUnauthorized is returned when the management API rejects the configured credentials. It is
// never retried because retrying cannot fix a configuration problem.
var ErrUnauthorized = errors.New("emqx api: unauthorized (check POLICY_EMQX_API_KEY/SECRET)")

// ErrBadRequest is returned when EMQX rejects the request itself (malformed client id).
var ErrBadRequest = errors.New("emqx api: bad request")

// Client kicks sessions through DELETE /api/v5/clients/{clientid} with HTTP basic auth
// (API key as user, secret as password).
type Client struct {
	base     *url.URL
	key      string
	secret   string
	http     *http.Client
	attempts int
	backoff  time.Duration
	log      *slog.Logger
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client (tests, custom transports).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithAttempts sets the total number of attempts per kick (default 3).
func WithAttempts(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.attempts = n
		}
	}
}

// WithBackoff sets the base delay between attempts (default 200ms, grows linearly).
func WithBackoff(d time.Duration) Option {
	return func(c *Client) {
		if d >= 0 {
			c.backoff = d
		}
	}
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.log = l
		}
	}
}

// NewClient validates baseURL and returns a Client.
func NewClient(baseURL, key, secret string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("emqx api: invalid base URL %q", baseURL)
	}
	if key == "" || secret == "" {
		return nil, errors.New("emqx api: key and secret are required")
	}
	c := &Client{
		base:     u,
		key:      key,
		secret:   secret,
		http:     &http.Client{Timeout: 3 * time.Second},
		attempts: 3,
		backoff:  200 * time.Millisecond,
		log:      slog.Default(),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Kick implements Kicker. A 404 means the client is already offline and counts as success.
// Transport errors and 5xx/429 responses are retried up to the configured number of attempts.
func (c *Client) Kick(ctx context.Context, clientID string) error {
	if clientID == "" {
		return fmt.Errorf("%w: empty client id", ErrBadRequest)
	}
	var last error
	for attempt := 1; attempt <= c.attempts; attempt++ {
		err := c.kickOnce(ctx, clientID)
		if err == nil {
			return nil
		}
		var perm *permanentError
		if errors.As(err, &perm) {
			return perm.err
		}
		last = err
		c.log.Warn("emqx kick attempt failed", "client_id", clientID, "attempt", attempt, "err", err.Error())
		if attempt == c.attempts {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("kick %s: %w (last error: %v)", clientID, ctx.Err(), last)
		case <-time.After(c.backoff * time.Duration(attempt)):
		}
	}
	return fmt.Errorf("kick %s failed after %d attempts: %w", clientID, c.attempts, last)
}

type permanentError struct{ err error }

func (p *permanentError) Error() string { return p.err.Error() }
func (p *permanentError) Unwrap() error { return p.err }

func (c *Client) kickOnce(ctx context.Context, clientID string) error {
	endpoint := c.base.String() + "/api/v5/clients/" + url.PathEscape(clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return &permanentError{err: fmt.Errorf("%w: %v", ErrBadRequest, err)}
	}
	req.SetBasicAuth(c.key, c.secret)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("emqx api request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusNoContent, resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusNotFound:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return &permanentError{err: ErrUnauthorized}
	case resp.StatusCode == http.StatusBadRequest:
		return &permanentError{err: fmt.Errorf("%w: client id %q", ErrBadRequest, clientID)}
	default:
		return fmt.Errorf("emqx api: unexpected status %d", resp.StatusCode)
	}
}
