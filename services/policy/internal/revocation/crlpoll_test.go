package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/clock"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/emqx"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
)

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "IronMesh Device CA", Organization: []string{"IronMesh"}},
		NotBefore:             t0.Add(-time.Hour),
		NotAfter:              t0.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makeCRL(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, entries []x509.RevocationListEntry, next time.Time) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(7),
		ThisUpdate:                t0,
		NextUpdate:                next,
		RevokedCertificateEntries: entries,
	}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type applied struct {
	serial string
	at     time.Time
	reason string
}

type fakeApplier struct {
	mu    sync.Mutex
	calls []applied
	seen  map[string]bool
	err   error
}

func (f *fakeApplier) ApplySerial(serial string, at time.Time, reason string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	f.calls = append(f.calls, applied{serial, at, reason})
	if f.err != nil {
		return false, f.err
	}
	if f.seen[serial] {
		return false, nil
	}
	f.seen[serial] = true
	return true, nil
}

func (f *fakeApplier) Calls() []applied {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]applied(nil), f.calls...)
}

func newPoller(t *testing.T, url string, apply SerialApplier, issuer *x509.Certificate, mutate func(*PollerConfig)) (*Poller, *metrics.Metrics, *clock.Fake) {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	fc := clock.NewFake(t0.Add(time.Minute))
	cfg := PollerConfig{URL: url, Apply: apply, Issuer: issuer, Metrics: m, Clock: fc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Interval: 10 * time.Millisecond}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := NewPoller(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, m, fc
}

func TestNewPollerValidation(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	if _, err := NewPoller(PollerConfig{URL: "pki:8444/crl", Apply: &fakeApplier{}, Metrics: m}); err == nil {
		t.Error("URL without scheme should fail")
	}
	if _, err := NewPoller(PollerConfig{URL: "http://pki:8444/crl", Metrics: m}); err == nil {
		t.Error("nil applier should fail")
	}
	if _, err := NewPoller(PollerConfig{URL: "http://pki:8444/crl", Apply: &fakeApplier{}}); err == nil {
		t.Error("nil metrics should fail")
	}
	p, err := NewPoller(PollerConfig{URL: "http://pki:8444/crl", Apply: &fakeApplier{}, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	if p.http == nil || p.interval != 5*time.Second || p.maxBytes != 16<<20 || p.log == nil || p.clock == nil {
		t.Errorf("defaults not applied: %+v", p)
	}
}

func TestPollOnceAppliesSerialsAndHonoursETag(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(0xabc), RevocationTime: t0, ReasonCode: 1},
		{SerialNumber: big.NewInt(0xdef), RevocationTime: t0.Add(time.Second), ReasonCode: 4},
	}, t0.Add(24*time.Hour))
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crl)
	}))
	defer srv.Close()

	apply := &fakeApplier{}
	p, m, fc := newPoller(t, srv.URL, apply, ca, nil)
	stats, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if stats.NotModified || stats.Serials != 2 || stats.Added != 2 || !stats.ThisUpdate.Equal(t0) || !stats.NextUpdate.Equal(t0.Add(24*time.Hour)) {
		t.Errorf("stats = %+v", stats)
	}
	calls := apply.Calls()
	if len(calls) != 2 || calls[0].serial != "abc" || calls[0].reason != "keyCompromise" || !calls[0].at.Equal(t0) || calls[1].serial != "def" || calls[1].reason != "superseded" {
		t.Errorf("applied = %+v", calls)
	}

	stats, err = p.PollOnce(context.Background())
	if err != nil || !stats.NotModified {
		t.Fatalf("second poll = %+v, %v; want not modified", stats, err)
	}
	if requests != 2 {
		t.Errorf("requests = %d", requests)
	}
	last, n := p.LastSuccess()
	if !last.Equal(fc.Now()) || n != 2 {
		t.Errorf("LastSuccess = %v, %d", last, n)
	}
	if got := testutil.ToFloat64(m.CRLPolls.WithLabelValues("updated")); got != 1 {
		t.Errorf("updated polls = %v", got)
	}
	if got := testutil.ToFloat64(m.CRLPolls.WithLabelValues("not_modified")); got != 1 {
		t.Errorf("not_modified polls = %v", got)
	}
	if got := testutil.ToFloat64(m.CRLSerials); got != 2 {
		t.Errorf("serial gauge = %v", got)
	}
	if got := testutil.ToFloat64(m.CRLLastSuccess); got != float64(fc.Now().Unix()) {
		t.Errorf("last success gauge = %v", got)
	}
}

func TestPollOncePEMAndNoIssuer(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: t0}}, t0.Add(time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = pem.Encode(w, &pem.Block{Type: "X509 CRL", Bytes: crl})
	}))
	defer srv.Close()
	apply := &fakeApplier{}
	p, _, _ := newPoller(t, srv.URL, apply, nil, nil)
	stats, err := p.PollOnce(context.Background())
	if err != nil || stats.Added != 1 {
		t.Fatalf("PollOnce PEM = %+v, %v", stats, err)
	}
	if calls := apply.Calls(); len(calls) != 1 || calls[0].serial != "2a" || calls[0].reason != "unspecified" {
		t.Errorf("applied = %+v", calls)
	}
}

func TestPollOnceRejectsWrongIssuer(t *testing.T) {
	ca, key := newCA(t)
	other, _ := newCA(t)
	crl := makeCRL(t, ca, key, []x509.RevocationListEntry{{SerialNumber: big.NewInt(1), RevocationTime: t0}}, t0.Add(time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(crl) }))
	defer srv.Close()
	apply := &fakeApplier{}
	p, m, _ := newPoller(t, srv.URL, apply, other, nil)
	if _, err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("CRL signed by another CA must be rejected")
	}
	if len(apply.Calls()) != 0 {
		t.Error("nothing may be applied from an unverified CRL")
	}
	if got := testutil.ToFloat64(m.CRLPolls.WithLabelValues("error")); got != 1 {
		t.Errorf("error polls = %v", got)
	}
}

func TestPollOnceErrors(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, nil, t0.Add(time.Hour))
	var mode atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 0:
			w.WriteHeader(http.StatusInternalServerError)
		case 1:
			_, _ = w.Write([]byte("not a crl"))
		case 2:
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: crl})
		default:
			_, _ = w.Write(crl)
		}
	}))
	apply := &fakeApplier{}
	p, m, _ := newPoller(t, srv.URL, apply, ca, nil)
	for i := int32(0); i < 3; i++ {
		mode.Store(i)
		if _, err := p.PollOnce(context.Background()); err == nil {
			t.Errorf("mode %d: expected error", i)
		}
	}
	mode.Store(3)
	small, _, _ := newPoller(t, srv.URL, apply, ca, func(c *PollerConfig) { c.MaxBytes = 10 })
	if _, err := small.PollOnce(context.Background()); err == nil {
		t.Error("oversized CRL should fail")
	}
	srv.Close()
	if _, err := p.PollOnce(context.Background()); err == nil {
		t.Error("unreachable server should fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.PollOnce(ctx); err == nil {
		t.Error("cancelled context should fail")
	}
	if got := testutil.ToFloat64(m.CRLPolls.WithLabelValues("error")); got < 5 {
		t.Errorf("error polls = %v, want >= 5", got)
	}
	if len(apply.Calls()) != 0 {
		t.Error("no serial should have been applied")
	}
}

func TestPollOnceStaleCRLStillAppliesAndApplierErrorsAreTolerated(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, []x509.RevocationListEntry{{SerialNumber: big.NewInt(5), RevocationTime: t0}}, t0.Add(time.Second))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(crl) }))
	defer srv.Close()
	apply := &fakeApplier{}
	p, _, fc := newPoller(t, srv.URL, apply, ca, nil)
	fc.Set(t0.Add(time.Hour)) // past NextUpdate
	stats, err := p.PollOnce(context.Background())
	if err != nil || stats.Added != 1 {
		t.Fatalf("stale CRL: %+v, %v", stats, err)
	}
	failing := &fakeApplier{err: errors.New("disk full")}
	p2, _, _ := newPoller(t, srv.URL, failing, ca, nil)
	stats, err = p2.PollOnce(context.Background())
	if err != nil || stats.Added != 0 || stats.Serials != 1 {
		t.Fatalf("applier error: %+v, %v", stats, err)
	}
}

func TestRunPollsPeriodically(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, nil, t0.Add(time.Hour))
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requests, 1)
		if n == 2 {
			w.WriteHeader(http.StatusBadGateway) // exercise the error-logging branch
			return
		}
		_, _ = w.Write(crl)
	}))
	defer srv.Close()
	p, _, _ := newPoller(t, srv.URL, &fakeApplier{}, ca, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	waitFor(t, "three polls", func() bool { return atomic.LoadInt32(&requests) >= 3 })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestParseCRLAndLoadIssuer(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, nil, t0.Add(time.Hour))
	if _, err := ParseCRL(crl); err != nil {
		t.Errorf("DER: %v", err)
	}
	if _, err := ParseCRL(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})); err != nil {
		t.Errorf("PEM: %v", err)
	}
	if _, err := ParseCRL(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crl})); err == nil {
		t.Error("wrong PEM type should fail")
	}
	if _, err := ParseCRL([]byte("garbage")); err == nil {
		t.Error("garbage should fail")
	}

	dir := t.TempDir()
	pemPath := filepath.Join(dir, "ca.pem")
	derPath := filepath.Join(dir, "ca.der")
	badType := filepath.Join(dir, "bad.pem")
	garbage := filepath.Join(dir, "garbage.der")
	_ = os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600)
	_ = os.WriteFile(derPath, ca.Raw, 0o600)
	_ = os.WriteFile(badType, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}), 0o600)
	_ = os.WriteFile(garbage, []byte("nope"), 0o600)
	for _, p := range []string{pemPath, derPath} {
		got, err := LoadIssuer(p)
		if err != nil || !got.Equal(ca) {
			t.Errorf("LoadIssuer(%s) = %v, %v", p, got != nil, err)
		}
	}
	for _, p := range []string{badType, garbage, filepath.Join(dir, "missing.pem")} {
		if _, err := LoadIssuer(p); err == nil {
			t.Errorf("LoadIssuer(%s) should fail", p)
		}
	}
}

func TestReasonString(t *testing.T) {
	want := map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded",
		5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise", 99: "reason(99)"}
	for code, s := range want {
		if got := ReasonString(code); got != s {
			t.Errorf("ReasonString(%d) = %q, want %q", code, got, s)
		}
	}
}

func TestPollerFeedsRevocationService(t *testing.T) {
	ca, key := newCA(t)
	crl := makeCRL(t, ca, key, []x509.RevocationListEntry{{SerialNumber: big.NewInt(0xbeef), RevocationTime: t0, ReasonCode: 1}}, t0.Add(time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(crl) }))
	defer srv.Close()

	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)
	p, _, _ := newPoller(t, srv.URL, env.svc, ca, func(c *PollerConfig) { c.Metrics = env.m })
	if _, err := p.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !env.cache.IsRevokedSerial("BEEF") {
		t.Error("serial from CRL should deny future CONNECTs")
	}
	if got := testutil.ToFloat64(env.m.Revocations.WithLabelValues(SourceCRL)); got != 1 {
		t.Errorf("crl revocations = %v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if len(fake.Calls()) != 0 {
		t.Error("CRL path has no device id and must not kick")
	}
}
