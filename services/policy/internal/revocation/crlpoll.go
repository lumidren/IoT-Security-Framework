package revocation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/clock"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
)

// SerialApplier receives serials learned from the CRL. *Service implements it.
type SerialApplier interface {
	ApplySerial(serial string, revokedAt time.Time, reason string) (bool, error)
}

// PollerConfig configures the CRL poller.
type PollerConfig struct {
	// URL is the CRL distribution point (POLICY_PKI_CRL_URL).
	URL        string
	HTTPClient *http.Client
	Apply      SerialApplier
	// Issuer, when set, must have signed the CRL; unsigned-verification is logged loudly.
	Issuer   *x509.Certificate
	Interval time.Duration
	Metrics  *metrics.Metrics
	Logger   *slog.Logger
	Clock    clock.Clock
	// MaxBytes bounds the CRL size (default 16 MiB).
	MaxBytes int64
}

// PollStats summarises one poll.
type PollStats struct {
	NotModified bool
	Serials     int
	Added       int
	ThisUpdate  time.Time
	NextUpdate  time.Time
}

// Poller fetches the Device CA CRL periodically and merges its serials into the cache. It is the
// fallback path when the PKI push (POST /internal/v1/revocations) was missed.
type Poller struct {
	url      string
	http     *http.Client
	apply    SerialApplier
	issuer   *x509.Certificate
	interval time.Duration
	metrics  *metrics.Metrics
	log      *slog.Logger
	clock    clock.Clock
	maxBytes int64

	mu          sync.Mutex
	etag        string
	lastSuccess time.Time
	lastSerials int
}

// NewPoller validates cfg and returns a Poller.
func NewPoller(cfg PollerConfig) (*Poller, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("crl poller: invalid URL %q", cfg.URL)
	}
	if cfg.Apply == nil {
		return nil, errors.New("crl poller: applier is required")
	}
	if cfg.Metrics == nil {
		return nil, errors.New("crl poller: metrics are required")
	}
	p := &Poller{
		url:      cfg.URL,
		http:     cfg.HTTPClient,
		apply:    cfg.Apply,
		issuer:   cfg.Issuer,
		interval: cfg.Interval,
		metrics:  cfg.Metrics,
		log:      cfg.Logger,
		clock:    cfg.Clock,
		maxBytes: cfg.MaxBytes,
	}
	if p.http == nil {
		p.http = &http.Client{Timeout: 10 * time.Second}
	}
	if p.interval <= 0 {
		p.interval = 5 * time.Second
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	if p.clock == nil {
		p.clock = clock.Real{}
	}
	if p.maxBytes <= 0 {
		p.maxBytes = 16 << 20
	}
	if p.issuer == nil {
		p.log.Warn("CRL signature verification disabled: set POLICY_CRL_ISSUER_CERT_FILE to the Device CA certificate")
	}
	return p, nil
}

// Run polls immediately and then every interval until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	p.pollAndLog(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollAndLog(ctx)
		}
	}
}

func (p *Poller) pollAndLog(ctx context.Context) {
	stats, err := p.PollOnce(ctx)
	switch {
	case err != nil:
		if ctx.Err() == nil {
			p.log.Warn("CRL poll failed", "url", p.url, "err", err.Error())
		}
	case stats.NotModified:
		p.log.Debug("CRL unchanged", "url", p.url)
	default:
		p.log.Info("CRL applied", "url", p.url, "serials", stats.Serials, "added", stats.Added,
			"this_update", stats.ThisUpdate, "next_update", stats.NextUpdate)
	}
}

// LastSuccess returns the time of the last successful fetch and the number of serials it carried.
func (p *Poller) LastSuccess() (time.Time, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSuccess, p.lastSerials
}

// PollOnce fetches the CRL once, honouring ETag, and merges new serials into the cache.
func (p *Poller) PollOnce(ctx context.Context) (PollStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		p.metrics.CRLPolls.WithLabelValues("error").Inc()
		return PollStats{}, fmt.Errorf("crl poller: build request: %w", err)
	}
	req.Header.Set("Accept", "application/pkix-crl, application/x-pem-file;q=0.9, */*;q=0.1")
	p.mu.Lock()
	etag := p.etag
	p.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		p.metrics.CRLPolls.WithLabelValues("error").Inc()
		return PollStats{}, fmt.Errorf("crl poller: fetch: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		p.metrics.CRLPolls.WithLabelValues("not_modified").Inc()
		return PollStats{NotModified: true}, nil
	case http.StatusOK:
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		p.metrics.CRLPolls.WithLabelValues("error").Inc()
		return PollStats{}, fmt.Errorf("crl poller: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, p.maxBytes+1))
	if err != nil {
		p.metrics.CRLPolls.WithLabelValues("error").Inc()
		return PollStats{}, fmt.Errorf("crl poller: read body: %w", err)
	}
	if int64(len(body)) > p.maxBytes {
		p.metrics.CRLPolls.WithLabelValues("error").Inc()
		return PollStats{}, fmt.Errorf("crl poller: CRL exceeds %d bytes", p.maxBytes)
	}
	crl, err := ParseCRL(body)
	if err != nil {
		p.metrics.CRLPolls.WithLabelValues("error").Inc()
		return PollStats{}, err
	}
	if p.issuer != nil {
		if err := crl.CheckSignatureFrom(p.issuer); err != nil {
			p.metrics.CRLPolls.WithLabelValues("error").Inc()
			return PollStats{}, fmt.Errorf("crl poller: signature check failed: %w", err)
		}
	}
	now := p.clock.Now()
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		p.log.Warn("CRL is stale; applying anyway", "next_update", crl.NextUpdate, "now", now)
	}
	stats := PollStats{Serials: len(crl.RevokedCertificateEntries), ThisUpdate: crl.ThisUpdate, NextUpdate: crl.NextUpdate}
	for _, entry := range crl.RevokedCertificateEntries {
		serial := SerialFromBigInt(entry.SerialNumber)
		added, err := p.apply.ApplySerial(serial, entry.RevocationTime, ReasonString(entry.ReasonCode))
		if err != nil {
			p.log.Error("could not apply CRL serial", "serial", serial, "err", err.Error())
			continue
		}
		if added {
			stats.Added++
		}
	}
	p.mu.Lock()
	p.etag = resp.Header.Get("ETag")
	p.lastSuccess = now
	p.lastSerials = stats.Serials
	p.mu.Unlock()
	p.metrics.CRLPolls.WithLabelValues("updated").Inc()
	p.metrics.CRLSerials.Set(float64(stats.Serials))
	p.metrics.CRLLastSuccess.Set(float64(now.Unix()))
	return stats, nil
}

// ParseCRL parses a DER or PEM ("X509 CRL") encoded certificate revocation list.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("crl poller: unexpected PEM block %q", block.Type)
		}
		der = block.Bytes
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("crl poller: parse: %w", err)
	}
	return crl, nil
}

// LoadIssuer reads a PEM or DER encoded CA certificate used to verify CRL signatures.
func LoadIssuer(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crl issuer: %w", err)
	}
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("crl issuer: unexpected PEM block %q", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crl issuer: parse: %w", err)
	}
	return cert, nil
}

// ReasonString renders an RFC 5280 CRLReason code.
func ReasonString(code int) string {
	switch code {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 8:
		return "removeFromCRL"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	default:
		return fmt.Sprintf("reason(%d)", code)
	}
}
