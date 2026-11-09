package revocation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

type fakeCRL struct{ calls atomic.Int32 }

func (f *fakeCRL) Regenerate(context.Context) error { f.calls.Add(1); return nil }

type failCRL struct{}

func (failCRL) Regenerate(context.Context) error { return errors.New("crl broken") }

type fakeOCSP struct{ serials []string }

func (f *fakeOCSP) Invalidate(serial string) { f.serials = append(f.serials, serial) }

func TestRevokeFlow(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	policy := testutil.NewFakePolicy(t, 0)
	pub, err := revocation.NewHTTPPublisher(policy.URL, policy.Token, policy.HMACKey, policy.Client())
	if err != nil {
		t.Fatal(err)
	}
	crl := &fakeCRL{}
	ocspInv := &fakeOCSP{}
	svc, err := revocation.NewService(p.Store, revocation.Options{CRL: crl, OCSP: ocspInv, Publisher: pub, Metrics: p.Metrics, Clock: p.Clock, Logger: p.Logger})
	if err != nil {
		t.Fatal(err)
	}
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	serial := ca.FormatSerial(dev.Cert.SerialNumber)

	start := time.Now()
	res, err := svc.Revoke(context.Background(), "0x"+serial, "key_compromise", "svc-console")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !res.Published || res.Serial != serial || res.Reason != ca.ReasonKeyCompromise || res.ReasonName != "keyCompromise" || res.DeviceID != dev.ID || res.TenantID != testutil.Tenant || res.PublishError != "" {
		t.Fatalf("result %+v", res)
	}
	if crl.calls.Load() != 1 || len(ocspInv.serials) != 1 || ocspInv.serials[0] != serial {
		t.Fatalf("hooks: crl=%d ocsp=%v", crl.calls.Load(), ocspInv.serials)
	}
	rev, err := p.Store.GetRevocation(context.Background(), serial)
	if err != nil || rev.Reason != ca.ReasonKeyCompromise || rev.RevokedBy != "svc-console" || rev.IssuerCN != "IronMesh Device CA" || !rev.NotAfter.Equal(dev.Cert.NotAfter) {
		t.Fatalf("stored revocation %+v %v", rev, err)
	}
	events := policy.Events()
	if len(events) != 1 {
		t.Fatalf("events %d", len(events))
	}
	ev := events[0]
	if ev.ReceivedAt.Sub(start) >= time.Second {
		t.Fatalf("publish took %s, want < 1s", ev.ReceivedAt.Sub(start))
	}
	if !ev.SignatureValid || !ev.AuthValid {
		t.Fatalf("event auth: sig=%v auth=%v", ev.SignatureValid, ev.AuthValid)
	}
	if ev.Event.Serial != serial || ev.Event.DeviceID != dev.ID || ev.Event.TenantID != testutil.Tenant || ev.Event.Reason != "keyCompromise" || ev.Event.RevokedAt.IsZero() {
		t.Fatalf("event %+v", ev.Event)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(ev.Event.EventID) || ev.Event.EventID != res.EventID {
		t.Fatalf("event id %q", ev.Event.EventID)
	}
	if promtest.CollectAndCount(p.Metrics.RevocationLatency) != 1 || promtest.ToFloat64(p.Metrics.Revocations.WithLabelValues("keyCompromise")) != 1 {
		t.Fatal("metrics not recorded")
	}

	// Client errors.
	if _, err := svc.Revoke(context.Background(), serial, "superseded", "x"); !errors.Is(err, revocation.ErrAlreadyRevoked) {
		t.Fatalf("already revoked: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), "zz", "superseded", "x"); !errors.Is(err, revocation.ErrInvalidSerial) {
		t.Fatalf("invalid serial: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), serial, "because", "x"); !errors.Is(err, revocation.ErrInvalidReason) {
		t.Fatalf("invalid reason: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), "ffffffffffffffffffffffffffffffff", "superseded", "x"); !errors.Is(err, revocation.ErrNotFound) {
		t.Fatalf("not found: %v", err)
	}
}

func TestRevokePublishFailureAndHooks(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	policy := testutil.NewFakePolicy(t, 10) // never succeeds within retries
	pub, _ := revocation.NewHTTPPublisher(policy.URL, policy.Token, policy.HMACKey, policy.Client())
	pub.Sleep = func(time.Duration) {}
	svc, _ := revocation.NewService(p.Store, revocation.Options{CRL: failCRL{}, Publisher: pub, Metrics: p.Metrics, Clock: p.Clock, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	res, err := svc.Revoke(context.Background(), ca.FormatSerial(dev.Cert.SerialNumber), "", "x")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.Published || res.PublishError == "" || res.ReasonName != "unspecified" {
		t.Fatalf("result %+v", res)
	}
	if policy.Requests() != 4 {
		t.Fatalf("requests %d want 4 (1 + 3 retries)", policy.Requests())
	}
	if promtest.ToFloat64(p.Metrics.RevocationPublishFailures) != 1 {
		t.Fatal("publish failure metric")
	}
	// The revocation itself is durable even though publishing failed.
	if _, err := p.Store.GetRevocation(context.Background(), ca.FormatSerial(dev.Cert.SerialNumber)); err != nil {
		t.Fatal("revocation not stored")
	}
	// Nil store rejected; nil publisher defaults to Noop.
	if _, err := revocation.NewService(nil, revocation.Options{}); err == nil {
		t.Fatal("nil store accepted")
	}
	noop, _ := revocation.NewService(p.Store, revocation.Options{})
	dev2 := p.NewOperationalDevice(t, testutil.Tenant)
	if res, err := noop.Revoke(context.Background(), ca.FormatSerial(dev2.Cert.SerialNumber), "superseded", ""); err != nil || !res.Published {
		t.Fatalf("noop publisher: %+v %v", res, err)
	}
}

func TestRevokeDevice(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	svc, _ := revocation.NewService(p.Store, revocation.Options{Metrics: p.Metrics, Clock: p.Clock, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	ctx := context.Background()
	// Second current certificate, one expired certificate and one already revoked.
	k2 := testutil.P256Key(t)
	c2, _ := p.Device.IssueOperational(ca.DeviceRequest{TenantID: testutil.Tenant, DeviceID: dev.ID, PublicKey: k2.Public()})
	_ = p.Store.PutCertificate(ctx, ca.NewRecord(c2, store.KindOperational, "hardware", p.Clock()))
	expired := ca.NewRecord(c2, store.KindOperational, "hardware", p.Clock())
	expired.Serial = "0000000000000000000000000000ee01"
	expired.NotAfter = p.Clock().Add(-time.Hour)
	_ = p.Store.PutCertificate(ctx, expired)
	k3 := testutil.P256Key(t)
	c3, _ := p.Device.IssueOperational(ca.DeviceRequest{TenantID: testutil.Tenant, DeviceID: dev.ID, PublicKey: k3.Public()})
	_ = p.Store.PutCertificate(ctx, ca.NewRecord(c3, store.KindOperational, "hardware", p.Clock()))
	if _, err := svc.Revoke(ctx, ca.FormatSerial(c3.SerialNumber), "superseded", "x"); err != nil {
		t.Fatal(err)
	}

	results, err := svc.RevokeDevice(ctx, dev.ID, "cessationOfOperation", "svc-registry")
	if err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("revoked %d want 2 (current certs only)", len(results))
	}
	if _, err := p.Store.GetRevocation(ctx, expired.Serial); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired certificate should not be revoked")
	}
	if _, err := svc.RevokeDevice(ctx, dev.ID, "nope", "x"); !errors.Is(err, revocation.ErrInvalidReason) {
		t.Fatalf("invalid reason: %v", err)
	}
	if res, err := svc.RevokeDevice(ctx, "dev-0000000000000000", "superseded", "x"); err != nil || len(res) != 0 {
		t.Fatalf("unknown device: %v %v", res, err)
	}
	_ = p.Store.Close()
	if _, err := svc.RevokeDevice(ctx, dev.ID, "superseded", "x"); err == nil {
		t.Fatal("closed store should fail")
	}
}

func TestHTTPPublisher(t *testing.T) {
	t.Parallel()
	ev := revocation.Event{EventID: "e1", Serial: "01", DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: testutil.Tenant, Reason: "keyCompromise", RevokedAt: time.Now()}

	t.Run("retries on 500 then succeeds", func(t *testing.T) {
		policy := testutil.NewFakePolicy(t, 2)
		pub, _ := revocation.NewHTTPPublisher(policy.URL+"/", policy.Token, policy.HMACKey, nil)
		var slept []time.Duration
		pub.Sleep = func(d time.Duration) { slept = append(slept, d) }
		if err := pub.Publish(context.Background(), ev); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if policy.Requests() != 3 || len(slept) != 2 || slept[0] != revocation.DefaultBackoff {
			t.Fatalf("requests=%d slept=%v", policy.Requests(), slept)
		}
		if evs := policy.Events(); len(evs) != 1 || !evs[0].SignatureValid || !evs[0].AuthValid {
			t.Fatalf("events %+v", evs)
		}
	})
	t.Run("4xx is not retried", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		pub, _ := revocation.NewHTTPPublisher(srv.URL, "", []byte("k"), nil)
		pub.Sleep = func(time.Duration) {}
		if err := pub.Publish(context.Background(), ev); err == nil || hits.Load() != 1 {
			t.Fatalf("err=%v hits=%d", err, hits.Load())
		}
	})
	t.Run("429 is retried", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if hits.Add(1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		pub, _ := revocation.NewHTTPPublisher(srv.URL, "", []byte("k"), nil)
		pub.Sleep = func(time.Duration) {}
		if err := pub.Publish(context.Background(), ev); err != nil || hits.Load() != 2 {
			t.Fatalf("err=%v hits=%d", err, hits.Load())
		}
	})
	t.Run("transport error exhausts retries", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		pub, _ := revocation.NewHTTPPublisher(srv.URL, "", []byte("k"), nil)
		pub.Sleep = func(time.Duration) {}
		pub.Retries = -1 // normalised to 0
		if err := pub.Publish(context.Background(), ev); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("context cancelled", func(t *testing.T) {
		policy := testutil.NewFakePolicy(t, 5)
		pub, _ := revocation.NewHTTPPublisher(policy.URL, "", []byte("k"), nil)
		ctx, cancel := context.WithCancel(context.Background())
		pub.Sleep = func(time.Duration) { cancel() }
		if err := pub.Publish(ctx, ev); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context error, got %v", err)
		}
	})
	t.Run("nil sleep defaults", func(t *testing.T) {
		policy := testutil.NewFakePolicy(t, 0)
		pub, _ := revocation.NewHTTPPublisher(policy.URL, "", []byte("k"), nil)
		pub.Sleep = nil
		if err := pub.Publish(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("validation", func(t *testing.T) {
		if _, err := revocation.NewHTTPPublisher("", "t", []byte("k"), nil); err == nil {
			t.Error("empty URL accepted")
		}
		if _, err := revocation.NewHTTPPublisher("http://x", "t", nil, nil); err == nil {
			t.Error("empty key accepted")
		}
	})
	t.Run("signature helpers", func(t *testing.T) {
		sig := revocation.Sign([]byte("k"), []byte("body"))
		if !revocation.VerifySignature([]byte("k"), []byte("body"), sig) || revocation.VerifySignature([]byte("k"), []byte("other"), sig) {
			t.Fatal("signature helpers")
		}
	})
	t.Run("noop", func(t *testing.T) {
		if err := (revocation.NoopPublisher{}).Publish(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRevokeUndeliveredSkipsPublish(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	policy := testutil.NewFakePolicy(t, 0)
	pub, err := revocation.NewHTTPPublisher(policy.URL, policy.Token, policy.HMACKey, policy.Client())
	if err != nil {
		t.Fatal(err)
	}
	crl := &fakeCRL{}
	ocspInv := &fakeOCSP{}
	svc, _ := revocation.NewService(p.Store, revocation.Options{CRL: crl, OCSP: ocspInv, Publisher: pub, Metrics: p.Metrics, Clock: p.Clock, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	serial := ca.FormatSerial(dev.Cert.SerialNumber)
	res, err := svc.RevokeUndelivered(context.Background(), serial, "cessationOfOperation", "pki:enroll-rollback")
	if err != nil {
		t.Fatalf("RevokeUndelivered: %v", err)
	}
	if res.Published || res.Reason != ca.ReasonCessationOfOperation || res.Serial != serial {
		t.Fatalf("result %+v", res)
	}
	if policy.Requests() != 0 {
		t.Fatalf("policy received %d requests, want none", policy.Requests())
	}
	if crl.calls.Load() != 1 || len(ocspInv.serials) != 1 {
		t.Fatalf("hooks: crl=%d ocsp=%v", crl.calls.Load(), ocspInv.serials)
	}
	rev, err := p.Store.GetRevocation(context.Background(), serial)
	if err != nil || rev.Reason != ca.ReasonCessationOfOperation || rev.RevokedBy != "pki:enroll-rollback" {
		t.Fatalf("stored revocation %+v %v", rev, err)
	}
}
