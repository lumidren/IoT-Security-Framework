// Package registry queries the Registry service for device lifecycle state.
//
// DESIGN_CONTRACT.md section 7: devices move manufactured -> provisioned -> active -> quarantined ->
// active | decommissioned. Only provisioned and active devices may hold a broker session.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Lifecycle is the Registry answer for GET /internal/v1/devices/{id}/lifecycle.
type Lifecycle struct {
	DeviceID       string `json:"device_id"`
	TenantID       string `json:"tenant_id"`
	State          string `json:"state"`
	AssuranceLevel string `json:"assurance_level,omitempty"`
}

// Lifecycle states from the contract.
const (
	StateManufactured   = "manufactured"
	StateProvisioned    = "provisioned"
	StateActive         = "active"
	StateQuarantined    = "quarantined"
	StateDecommissioned = "decommissioned"
)

// KnownState reports whether s is one of the contract lifecycle states.
func KnownState(s string) bool {
	switch s {
	case StateManufactured, StateProvisioned, StateActive, StateQuarantined, StateDecommissioned:
		return true
	}
	return false
}

// MayConnect reports whether a device in this state may authenticate to the broker.
func (l Lifecycle) MayConnect() bool {
	return l.State == StateProvisioned || l.State == StateActive
}

// ErrNotFound is returned when the Registry does not know the device.
var ErrNotFound = errors.New("registry: device not found")

// ErrInconsistent is returned when the Registry answers for a different device id.
var ErrInconsistent = errors.New("registry: response device_id does not match request")

// Lookup is the interface the authn hook depends on.
type Lookup interface {
	Lifecycle(ctx context.Context, deviceID string) (Lifecycle, error)
}

// Client is an HTTP Lookup with a TTL cache. Positive answers and not-found answers are cached;
// transport and server errors are never cached so a recovering Registry is used immediately.
type Client struct {
	base       *url.URL
	token      string
	http       *http.Client
	timeout    time.Duration
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	onLookup   func(result string)

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	lc       Lifecycle
	notFound bool
	expires  time.Time
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithTimeout bounds each lookup (default 2s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithCacheTTL sets the cache lifetime (default 30s).
func WithCacheTTL(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.ttl = d
		}
	}
}

// WithMaxEntries bounds the cache size (default 100000).
func WithMaxEntries(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxEntries = n
		}
	}
}

// WithClock injects a time source (tests).
func WithClock(now func() time.Time) Option {
	return func(c *Client) {
		if now != nil {
			c.now = now
		}
	}
}

// WithLookupHook registers a callback invoked with the outcome of every lookup
// (cache|ok|not_found|error); used to feed metrics without coupling to a registry.
func WithLookupHook(fn func(result string)) Option {
	return func(c *Client) {
		if fn != nil {
			c.onLookup = fn
		}
	}
}

// New creates a Client for the Registry at baseURL.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("registry: invalid base URL %q", baseURL)
	}
	c := &Client{
		base:       u,
		token:      token,
		http:       &http.Client{},
		timeout:    2 * time.Second,
		ttl:        30 * time.Second,
		maxEntries: 100000,
		now:        time.Now,
		onLookup:   func(string) {},
		cache:      make(map[string]cacheEntry),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Lifecycle implements Lookup.
func (c *Client) Lifecycle(ctx context.Context, deviceID string) (Lifecycle, error) {
	if deviceID == "" {
		return Lifecycle{}, errors.New("registry: empty device id")
	}
	if lc, notFound, ok := c.cached(deviceID); ok {
		c.onLookup("cache")
		if notFound {
			return Lifecycle{}, ErrNotFound
		}
		return lc, nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	endpoint := c.base.JoinPath("internal", "v1", "devices", deviceID, "lifecycle")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		c.onLookup("error")
		return Lifecycle{}, fmt.Errorf("registry: build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		c.onLookup("error")
		return Lifecycle{}, fmt.Errorf("registry: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		c.onLookup("error")
		return Lifecycle{}, fmt.Errorf("registry: read response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var lc Lifecycle
		if err := json.Unmarshal(body, &lc); err != nil {
			c.onLookup("error")
			return Lifecycle{}, fmt.Errorf("registry: decode response: %w", err)
		}
		lc.State = strings.ToLower(strings.TrimSpace(lc.State))
		if lc.DeviceID != "" && lc.DeviceID != deviceID {
			c.onLookup("error")
			return Lifecycle{}, ErrInconsistent
		}
		if lc.DeviceID == "" {
			lc.DeviceID = deviceID
		}
		c.store(deviceID, cacheEntry{lc: lc})
		c.onLookup("ok")
		return lc, nil
	case http.StatusNotFound:
		c.store(deviceID, cacheEntry{notFound: true})
		c.onLookup("not_found")
		return Lifecycle{}, ErrNotFound
	default:
		c.onLookup("error")
		return Lifecycle{}, fmt.Errorf("registry: unexpected status %d", resp.StatusCode)
	}
}

// Invalidate drops a cached answer (e.g. after a revocation event names the device).
func (c *Client) Invalidate(deviceID string) {
	c.mu.Lock()
	delete(c.cache, deviceID)
	c.mu.Unlock()
}

func (c *Client) cached(deviceID string) (Lifecycle, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[deviceID]
	if !ok {
		return Lifecycle{}, false, false
	}
	if !c.now().Before(e.expires) {
		delete(c.cache, deviceID)
		return Lifecycle{}, false, false
	}
	return e.lc, e.notFound, true
}

func (c *Client) store(deviceID string, e cacheEntry) {
	now := c.now()
	e.expires = now.Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= c.maxEntries {
		for k, v := range c.cache {
			if !now.Before(v.expires) {
				delete(c.cache, k)
			}
		}
		for k := range c.cache {
			if len(c.cache) < c.maxEntries {
				break
			}
			delete(c.cache, k)
		}
	}
	c.cache[deviceID] = e
}
