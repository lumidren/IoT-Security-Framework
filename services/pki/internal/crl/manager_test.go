package crl_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/crl"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

func TestRegenerateAndServe(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	m, err := crl.NewManager(p.Device, p.Store, crl.Options{Clock: p.Clock, Metrics: p.Metrics, Logger: p.Logger})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, ok := m.Current(); ok {
		t.Fatal("CRL present before generation")
	}
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, crl.Path, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before generation: %d", rec.Code)
	}

	ctx := context.Background()
	now := p.Clock()
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	expired := p.NewOperationalDevice(t, testutil.Tenant)
	boot := p.NewBootstrapDevice(t, testutil.Tenant)
	add := func(c *x509.Certificate, issuer string, notAfter time.Time, reason int) {
		if err := p.Store.AddRevocation(ctx, &store.Revocation{Serial: ca.FormatSerial(c.SerialNumber), DeviceID: c.Subject.CommonName, TenantID: testutil.Tenant, IssuerCN: issuer, NotAfter: notAfter, Reason: reason, RevokedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	add(dev.Cert, "IronMesh Device CA", dev.Cert.NotAfter, ca.ReasonKeyCompromise)
	add(expired.Cert, "IronMesh Device CA", now.Add(-time.Hour), ca.ReasonSuperseded) // expired: dropped
	add(boot.Cert, "IronMesh Factory CA", boot.Cert.NotAfter, ca.ReasonUnspecified)   // other issuer: dropped
	if err := p.Store.AddRevocation(ctx, &store.Revocation{Serial: "zz", IssuerCN: "IronMesh Device CA", NotAfter: now.Add(time.Hour), RevokedAt: now}); err != nil {
		t.Fatal(err) // unparsable serial: skipped with a warning
	}

	if err := m.Regenerate(ctx); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	der, etag, lastMod, number, ok := m.Current()
	if !ok || number != 1 || etag == "" || lastMod.IsZero() {
		t.Fatalf("Current: %v %d %q", ok, number, etag)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.CheckSignatureFrom(p.Device.Certificate()); err != nil {
		t.Fatal(err)
	}
	if len(list.RevokedCertificateEntries) != 1 || list.RevokedCertificateEntries[0].SerialNumber.Cmp(dev.Cert.SerialNumber) != 0 || list.RevokedCertificateEntries[0].ReasonCode != ca.ReasonKeyCompromise {
		t.Fatalf("entries %+v", list.RevokedCertificateEntries)
	}
	if list.NextUpdate.Sub(list.ThisUpdate) != 24*time.Hour {
		t.Fatalf("nextUpdate %s", list.NextUpdate.Sub(list.ThisUpdate))
	}
	if err := m.Regenerate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, _, number, _ = m.Current(); number != 2 {
		t.Fatalf("number %d", number)
	}

	// HTTP: 200 with validators, then conditional 304s and HEAD.
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, crl.Path, nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != crl.ContentType || rec.Header().Get("ETag") == "" || rec.Header().Get("Last-Modified") == "" {
		t.Fatalf("GET: %d %v", rec.Code, rec.Header())
	}
	body, _ := io.ReadAll(rec.Body)
	if _, err := x509.ParseRevocationList(body); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, crl.Path, nil)
	req.Header.Set("If-None-Match", rec.Header().Get("ETag"))
	rec2 := httptest.NewRecorder()
	m.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", rec2.Code)
	}
	req = httptest.NewRequest(http.MethodGet, crl.Path, nil)
	req.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	rec3 := httptest.NewRecorder()
	m.ServeHTTP(rec3, req)
	if rec3.Code != http.StatusNotModified {
		t.Fatalf("If-Modified-Since: %d", rec3.Code)
	}
	req = httptest.NewRequest(http.MethodGet, crl.Path, nil)
	req.Header.Set("If-Modified-Since", "garbage")
	rec4 := httptest.NewRecorder()
	m.ServeHTTP(rec4, req)
	if rec4.Code != 200 {
		t.Fatalf("bad If-Modified-Since: %d", rec4.Code)
	}
	rec5 := httptest.NewRecorder()
	m.ServeHTTP(rec5, httptest.NewRequest(http.MethodHead, crl.Path, nil))
	if rec5.Code != 200 || rec5.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %d", rec5.Code, rec5.Body.Len())
	}
	// Register mounts GET and HEAD.
	mux := http.NewServeMux()
	m.Register(mux)
	rec6 := httptest.NewRecorder()
	mux.ServeHTTP(rec6, httptest.NewRequest(http.MethodGet, crl.Path, nil))
	if rec6.Code != 200 {
		t.Fatalf("mux GET: %d", rec6.Code)
	}
}

func TestRunLoopAndErrors(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	m, err := crl.NewManager(p.Device, p.Store, crl.Options{Interval: 10 * time.Millisecond, Clock: p.Clock, Metrics: p.Metrics, Logger: p.Logger})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, _, n, ok := m.Current(); ok && n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic regeneration did not happen")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	// Store failures propagate.
	failing := &failingStore{Store: p.Store}
	fm, _ := crl.NewManager(p.Device, failing, crl.Options{Clock: p.Clock, Metrics: p.Metrics, Logger: p.Logger})
	failing.listErr = errors.New("db down")
	if err := fm.Regenerate(context.Background()); err == nil {
		t.Fatal("expected list error")
	}
	failing.listErr = nil
	failing.numErr = errors.New("seq down")
	if err := fm.Regenerate(context.Background()); err == nil {
		t.Fatal("expected number error")
	}
	// Constructor validation and defaults.
	if _, err := crl.NewManager(p.Factory, p.Store, crl.Options{}); err == nil {
		t.Fatal("factory CA accepted")
	}
	if _, err := crl.NewManager(p.Device, nil, crl.Options{}); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := crl.NewManager(p.Device, p.Store, crl.Options{}); err != nil {
		t.Fatal(err)
	}
}

type failingStore struct {
	store.Store
	listErr error
	numErr  error
}

func (f *failingStore) ListRevocations(ctx context.Context) ([]*store.Revocation, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.Store.ListRevocations(ctx)
}

func (f *failingStore) NextCRLNumber(ctx context.Context) (int64, error) {
	if f.numErr != nil {
		return 0, f.numErr
	}
	return f.Store.NextCRLNumber(ctx)
}
