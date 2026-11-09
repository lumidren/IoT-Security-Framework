package revocation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Wire constants for the Policy service push.
const (
	PublishPath     = "/internal/v1/revocations"
	HeaderSignature = "X-IronMesh-Signature"
	HeaderEventID   = "X-IronMesh-Event-ID"
	// DefaultRetries is the number of in-call retries of HTTPPublisher. It is
	// zero: retries are owned by the durable outbox Dispatcher, which retries
	// with exponential backoff until every endpoint acknowledged.
	DefaultRetries = 0
	DefaultBackoff = 500 * time.Millisecond
)

// Event kinds on the wire ("event" member). A body without "event" is a
// revocation, so the revocation wire format is unchanged.
const (
	KindRevocation    = "revocation"
	KindDeviceRelease = "device_release"
)

// Event is the JSON event pushed to the Policy service: a certificate
// revocation (Kind empty or KindRevocation) or a device release
// (KindDeviceRelease).
//
// DeviceDeny tells the Policy service to deny-list the whole device id (every
// certificate of the device): it is true for revoke-all (registry quarantine
// and decommission). Single-certificate revocations (supersede on renewal,
// operator revocation of one serial) carry false and deny only that serial,
// so a renewed device is not locked out by the revocation of its previous
// certificate.
//
// A device release ({event_id, event: "device_release", device_id,
// tenant_id, released_at}) lifts the device-level deny again after the
// registry released a quarantined device; serial-level denies stay.
type Event struct {
	EventID    string    `json:"event_id"`
	Kind       string    `json:"event,omitempty"`
	Serial     string    `json:"serial"`
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
	DeviceDeny bool      `json:"device_deny"`
	ReleasedAt time.Time `json:"released_at"`
}

// IsRelease reports whether the event is a device release.
func (e Event) IsRelease() bool { return e.Kind == KindDeviceRelease }

// revocationWire is the (unchanged) revocation body.
type revocationWire struct {
	EventID    string    `json:"event_id"`
	Serial     string    `json:"serial"`
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
	DeviceDeny bool      `json:"device_deny"`
}

// releaseWire is the device_release body.
type releaseWire struct {
	EventID    string    `json:"event_id"`
	Kind       string    `json:"event"`
	DeviceID   string    `json:"device_id"`
	TenantID   string    `json:"tenant_id"`
	ReleasedAt time.Time `json:"released_at"`
}

// MarshalJSON renders the wire body of the event's kind.
func (e Event) MarshalJSON() ([]byte, error) {
	if e.IsRelease() {
		return json.Marshal(releaseWire{EventID: e.EventID, Kind: KindDeviceRelease, DeviceID: e.DeviceID, TenantID: e.TenantID, ReleasedAt: e.ReleasedAt})
	}
	return json.Marshal(revocationWire{EventID: e.EventID, Serial: e.Serial, DeviceID: e.DeviceID, TenantID: e.TenantID, Reason: e.Reason, RevokedAt: e.RevokedAt, DeviceDeny: e.DeviceDeny})
}

// Publisher delivers revocation events. Publish returns nil only when the
// event was acknowledged by every Policy endpoint.
type Publisher interface {
	Publish(ctx context.Context, ev Event) error
}

// Resolver returns the network addresses ("ip:port") of every Policy replica
// for the host and port of PKI_POLICY_URL.
type Resolver func(ctx context.Context, host, port string) ([]string, error)

// DNSResolver resolves host to all of its A/AAAA records (a Kubernetes
// headless Service lists one per ready Policy pod). A nil resolver uses
// net.DefaultResolver.
func DNSResolver(r *net.Resolver) Resolver {
	if r == nil {
		r = net.DefaultResolver
	}
	return func(ctx context.Context, host, port string) ([]string, error) {
		ips, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		var out []string
		for _, ip := range ips {
			addr := net.JoinHostPort(ip.IP.String(), port)
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
		sort.Strings(out)
		return out, nil
	}
}

// HTTPPublisher POSTs events to PKI_POLICY_URL + /internal/v1/revocations with
// a bearer token and an HMAC-SHA256 signature over the body.
//
// Without Resolve it delivers to the single URL. With Resolve (fan-out,
// PKI_POLICY_FANOUT=dns) it resolves the URL host on every call and delivers
// to each address, keeping the original host in the Host header and as TLS
// SNI / verification name; Publish succeeds only when every resolved address
// acknowledged. Addresses that acknowledged an event are remembered, so a
// retry only goes to the endpoints that have not (the Policy service is
// idempotent per event_id anyway).
type HTTPPublisher struct {
	URL     string
	Token   string
	HMACKey []byte
	Client  *http.Client
	// Retries are in-call retries per endpoint (default 0; the outbox
	// Dispatcher retries).
	Retries int
	Backoff time.Duration
	// Sleep is replaced in tests to avoid real waits.
	Sleep  func(time.Duration)
	Logger *slog.Logger
	// Resolve enables fan-out to every address of the URL host.
	Resolve Resolver
	// OnEndpoint, when set, observes the result of every endpoint delivery
	// ("ok" or "error").
	OnEndpoint func(result string)

	mu      sync.Mutex
	clients map[string]*http.Client
	acked   map[string]map[string]bool // event id -> addresses that acknowledged
}

// NewHTTPPublisher returns a single-attempt publisher (retries are owned by
// the Dispatcher).
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
	if p.Resolve == nil {
		err := p.deliver(ctx, p.Client, body, sig, ev.EventID)
		p.observe(err)
		return err
	}
	return p.fanOut(ctx, body, sig, ev.EventID)
}

func (p *HTTPPublisher) observe(err error) {
	if p.OnEndpoint == nil {
		return
	}
	if err != nil {
		p.OnEndpoint("error")
		return
	}
	p.OnEndpoint("ok")
}

// fanOut delivers to every resolved address that has not acknowledged the
// event yet.
func (p *HTTPPublisher) fanOut(ctx context.Context, body []byte, sig, eventID string) error {
	u, err := url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("revocation: policy URL: %w", err)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	addrs, err := p.Resolve(ctx, host, port)
	if err != nil {
		return fmt.Errorf("revocation: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("revocation: %s resolved to no policy endpoints", host)
	}
	p.mu.Lock()
	done := p.acked[eventID]
	var todo []string
	for _, a := range addrs {
		if !done[a] {
			todo = append(todo, a)
		}
	}
	p.mu.Unlock()

	type result struct {
		addr string
		err  error
	}
	results := make(chan result, len(todo))
	var wg sync.WaitGroup
	for _, addr := range todo {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			err := p.deliver(ctx, p.clientFor(addr, host), body, sig, eventID)
			p.observe(err)
			results <- result{addr, err}
		}(addr)
	}
	wg.Wait()
	close(results)

	var failed []string
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.acked == nil {
		p.acked = map[string]map[string]bool{}
	}
	if p.acked[eventID] == nil {
		p.acked[eventID] = map[string]bool{}
	}
	for r := range results {
		if r.err != nil {
			failed = append(failed, r.addr+": "+r.err.Error())
			continue
		}
		p.acked[eventID][r.addr] = true
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("revocation: %d of %d policy endpoints did not acknowledge: %s", len(failed), len(addrs), strings.Join(failed, "; "))
	}
	delete(p.acked, eventID)
	return nil
}

// clientFor returns a client that dials addr while keeping host as the HTTP
// Host and the TLS server name.
func (p *HTTPPublisher) clientFor(addr, host string) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[addr]; ok {
		return c
	}
	base, ok := p.Client.Transport.(*http.Transport)
	if !ok || base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	tr := base.Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tr.TLSClientConfig != nil {
		tlsCfg = tr.TLSClientConfig.Clone()
	}
	tlsCfg.ServerName = host
	tr.TLSClientConfig = tlsCfg
	c := &http.Client{Timeout: p.Client.Timeout, Transport: tr}
	if p.clients == nil {
		p.clients = map[string]*http.Client{}
	}
	p.clients[addr] = c
	return c
}

// deliver POSTs the signed body to p.URL with client, retrying transport
// errors, 408, 429 and 5xx Retries times.
func (p *HTTPPublisher) deliver(ctx context.Context, client *http.Client, body []byte, sig, eventID string) error {
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
		req.Header.Set(HeaderEventID, eventID)
		if p.Token != "" {
			req.Header.Set("Authorization", "Bearer "+p.Token)
		}
		resp, err := client.Do(req)
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
	kind := ev.Kind
	if kind == "" {
		kind = KindRevocation
	}
	l.Warn("policy event not published: PKI_POLICY_URL is not configured", "event_id", ev.EventID, "event", kind, "serial", ev.Serial, "device_id", ev.DeviceID, "tenant_id", ev.TenantID)
	return nil
}
