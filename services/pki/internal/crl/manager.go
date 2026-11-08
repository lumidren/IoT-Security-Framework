// Package crl publishes the Device CA certificate revocation list on the plain
// listener (GET /crl/device-ca.crl). The CRL is regenerated on every
// revocation and at least every 60 s; nextUpdate is 24 h after thisUpdate and
// the CRL number increases monotonically through the store.
package crl

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Wire constants.
const (
	Path            = "/crl/device-ca.crl"
	ContentType     = "application/pkix-crl"
	DefaultInterval = 60 * time.Second
)

// Options tunes the manager.
type Options struct {
	Interval time.Duration
	Clock    func() time.Time
	Metrics  *metrics.Metrics
	Logger   *slog.Logger
}

// Manager generates and serves the CRL.
type Manager struct {
	ca    *ca.CA
	store store.Store
	opts  Options

	mu           sync.RWMutex
	der          []byte
	etag         string
	lastModified time.Time
	number       int64
	entries      int
}

// NewManager returns a manager for the Device CA.
func NewManager(deviceCA *ca.CA, st store.Store, opts Options) (*Manager, error) {
	if deviceCA == nil || deviceCA.Kind() != ca.KindDevice {
		return nil, errors.New("crl: a Device CA is required")
	}
	if st == nil {
		return nil, errors.New("crl: a store is required")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Manager{ca: deviceCA, store: st, opts: opts}, nil
}

// Regenerate builds a fresh CRL from the store.
func (m *Manager) Regenerate(ctx context.Context) error {
	now := m.opts.Clock().UTC()
	revs, err := m.store.ListRevocations(ctx)
	if err != nil {
		return fmt.Errorf("crl: list revocations: %w", err)
	}
	issuerCN := m.ca.Certificate().Subject.CommonName
	var entries []x509.RevocationListEntry
	for _, rev := range revs {
		if rev.IssuerCN != issuerCN || !rev.NotAfter.After(now) {
			continue // other CAs' certs and expired certs stay off the CRL
		}
		serial, _, err := ca.ParseSerial(rev.Serial)
		if err != nil {
			m.opts.Logger.Warn("skipping revocation with unparsable serial", "serial", rev.Serial)
			continue
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: rev.RevokedAt.UTC(), ReasonCode: rev.Reason})
	}
	number, err := m.store.NextCRLNumber(ctx)
	if err != nil {
		return fmt.Errorf("crl: next number: %w", err)
	}
	der, err := m.ca.CreateCRL(number, now, entries)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(der)
	m.mu.Lock()
	m.der, m.etag, m.lastModified, m.number, m.entries = der, `"`+hex.EncodeToString(sum[:16])+`"`, now.Truncate(time.Second), number, len(entries)
	m.mu.Unlock()
	m.opts.Metrics.CRLGenerations.Inc()
	m.opts.Logger.Info("crl regenerated", "number", number, "entries", len(entries), "next_update", now.Add(ca.CRLValidity))
	return nil
}

// Run regenerates the CRL periodically until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Regenerate(ctx); err != nil {
				m.opts.Logger.Error("periodic crl regeneration failed", "error", err.Error())
			}
		}
	}
}

// Current returns the latest CRL, or ok=false before the first generation.
func (m *Manager) Current() (der []byte, etag string, lastModified time.Time, number int64, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.der == nil {
		return nil, "", time.Time{}, 0, false
	}
	return m.der, m.etag, m.lastModified, m.number, true
}

// Register mounts the CRL endpoint on mux.
func (m *Manager) Register(mux *http.ServeMux) {
	mux.Handle("GET "+Path, m)
	mux.Handle("HEAD "+Path, m)
}

// ServeHTTP serves the CRL with ETag / Last-Modified conditional support.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	der, etag, lastMod, _, ok := m.Current()
	if !ok {
		http.Error(w, "CRL not generated yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(m.opts.Interval.Seconds()))+", public")
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !lastMod.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(der)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(der)
	}
}
