package est

// Unit tests for the THREAT_MODEL.md controls. They exercise the functions
// directly (the end-to-end behaviour is covered in controls_e2e_test.go).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

const (
	testTenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	testDevice = "dev-8f3a1c2b9d4e5f60"
)

func newTestHandler(t *testing.T, cfg Config) *Handler {
	t.Helper()
	if cfg.Store == nil {
		cfg.Store = store.NewMemory()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg.RateLimit = cfg.RateLimit.withDefaults()
	return &Handler{cfg: cfg, ipLimiter: newLimiter(cfg.RateLimit.IPBurst, cfg.RateLimit.IPPerMinute), deviceLimiter: newLimiter(cfg.RateLimit.DeviceBurst, cfg.RateLimit.DevicePerMinute)}
}

func TestCheckSeTypeAgainstManufactureRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		dev      *registry.Device
		seType   string
		wantCode int
	}{
		{"nil device", nil, "tpm2", 0},
		{"no record", &registry.Device{}, "software", 0},
		{"match", &registry.Device{SeType: "tpm2"}, "tpm2", 0},
		{"mismatch", &registry.Device{SeType: "atecc608"}, "software", http.StatusForbidden},
		{"mismatch tpm", &registry.Device{SeType: "tpm2"}, "atecc608", http.StatusForbidden},
	}
	for _, c := range cases {
		err := checkSeTypeAgainstManufactureRecord(c.dev, c.seType)
		if (err == nil) != (c.wantCode == 0) || (err != nil && err.status != c.wantCode) {
			t.Errorf("%s: got %v want %d", c.name, err, c.wantCode)
		}
	}
}

func TestCheckBootstrapSerialMatchesManufactureRecord(t *testing.T) {
	t.Parallel()
	serial := "0000000000000000000000000000abcd"
	factory := &ClientIdentity{Issuer: ca.KindFactory, ID: &ca.DeviceIdentity{Serial: serial, DeviceID: testDevice}}
	device := &ClientIdentity{Issuer: ca.KindDevice, ID: &ca.DeviceIdentity{Serial: serial, DeviceID: testDevice}}
	cases := []struct {
		name     string
		client   *ClientIdentity
		dev      *registry.Device
		wantCode int
	}{
		{"nil client", nil, &registry.Device{BootstrapSerial: serial}, 0},
		{"nil device", factory, nil, 0},
		{"renewal not constrained", device, &registry.Device{BootstrapSerial: "ffff"}, 0},
		{"no record", factory, &registry.Device{}, 0},
		{"match canonical", factory, &registry.Device{BootstrapSerial: serial}, 0},
		{"match other presentation", factory, &registry.Device{BootstrapSerial: "0xABCD"}, 0},
		{"mismatch", factory, &registry.Device{BootstrapSerial: "ffff"}, http.StatusForbidden},
		{"unparsable record", factory, &registry.Device{BootstrapSerial: "not-hex"}, http.StatusForbidden},
	}
	for _, c := range cases {
		err := checkBootstrapSerialMatchesManufactureRecord(c.client, c.dev)
		if (err == nil) != (c.wantCode == 0) || (err != nil && err.status != c.wantCode) {
			t.Errorf("%s: got %v want %d", c.name, err, c.wantCode)
		}
	}
}

func TestRejectReusedKey(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	h := newTestHandler(t, Config{Store: st})
	ctx := context.Background()
	used, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fresh, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pin, _ := ca.SPKIPin(used.Public())
	if err := st.PutCertificate(ctx, &store.CertificateRecord{Serial: "01", DeviceID: testDevice, TenantID: testTenant, SPKISHA256: hex.EncodeToString(pin), NotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := h.rejectReusedKey(ctx, testDevice, fresh.Public()); err != nil {
		t.Fatalf("fresh key rejected: %v", err)
	}
	if err := h.rejectReusedKey(ctx, testDevice, used.Public()); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("reused key accepted: %v", err)
	}
	// Other devices may legitimately hold the same SPKI history (no cross-device check).
	if err := h.rejectReusedKey(ctx, "dev-0000000000000000", used.Public()); err != nil {
		t.Fatalf("other device: %v", err)
	}
	if err := h.rejectReusedKey(ctx, testDevice, "not a key"); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("junk key: %v", err)
	}
	_ = st.Close()
	if err := h.rejectReusedKey(ctx, testDevice, fresh.Public()); err == nil || err.status != http.StatusServiceUnavailable {
		t.Fatalf("closed store: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	h := newTestHandler(t, Config{Clock: clock, RateLimit: RateLimitConfig{DeviceBurst: 2, DevicePerMinute: 60, IPBurst: 4, IPPerMinute: 60}})

	call := func(remote, device string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, BasePath+"/ironmesh/nonce", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		if h.rateLimit(rec, req, "nonce", device) {
			rec.WriteHeader(http.StatusOK)
		}
		return rec
	}
	// Device bucket: 2 requests allowed, third rejected with Retry-After.
	for i := 0; i < 2; i++ {
		if rec := call("10.0.0.1:5000", testDevice); rec.Code != http.StatusOK {
			t.Fatalf("device request %d: %d", i, rec.Code)
		}
	}
	rec := call("10.0.0.1:5001", testDevice)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("device limit: %d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	if rec.Body.String() != "rate limit exceeded for dev\n" {
		t.Fatalf("body %q", rec.Body.String())
	}
	// Another device from the same IP is still fine (IP burst 4, used 3).
	if rec := call("10.0.0.1:5002", "dev-0000000000000001"); rec.Code != http.StatusOK {
		t.Fatalf("other device: %d", rec.Code)
	}
	// Tokens refill at one per second.
	advance(time.Second)
	if rec := call("10.0.0.1:5003", testDevice); rec.Code != http.StatusOK {
		t.Fatalf("after refill: %d", rec.Code)
	}
	// IP bucket exhausted independently of the device (4 used, 1 refilled, 1 used).
	rec = call("10.0.0.1:5004", "")
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != "rate limit exceeded for ip\n" {
		t.Fatalf("ip limit: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("10.0.0.2:5000", ""); rec.Code != http.StatusOK {
		t.Fatalf("other ip: %d", rec.Code)
	}
	// RemoteAddr without a port still works as a key.
	if rec := call("10.0.0.3", ""); rec.Code != http.StatusOK {
		t.Fatalf("bare ip: %d", rec.Code)
	}
	// Full refill after a minute.
	advance(time.Minute)
	if rec := call("10.0.0.1:5005", testDevice); rec.Code != http.StatusOK {
		t.Fatalf("after full refill: %d", rec.Code)
	}
	// Defaults and the sweep of idle buckets.
	def := RateLimitConfig{}.withDefaults()
	if def.DeviceBurst != DefaultDeviceBurst || def.IPPerMinute != DefaultIPPerMinute {
		t.Fatalf("defaults %+v", def)
	}
	l := newLimiter(1, 60)
	base := time.Now()
	for i := 0; i < 10000; i++ {
		l.allow("k"+string(rune(i)), base.Add(-time.Minute))
	}
	l.allow("fresh", base)
	if l.len() > 2 {
		t.Fatalf("sweep did not drop idle buckets: %d", l.len())
	}
	if ok, wait := l.allow("fresh", base); ok || wait <= 0 || wait > time.Second {
		t.Fatalf("expected wait, got %v %v", ok, wait)
	}
}

type fakeRevoker struct {
	mu    sync.Mutex
	calls []string
	err   error
	done  chan struct{}
}

func (f *fakeRevoker) Revoke(_ context.Context, serial, reason, by string) (*revocation.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, serial+"|"+reason+"|"+by)
	close(f.done)
	return &revocation.Result{Serial: serial}, f.err
}

func TestSupersedePrevious(t *testing.T) {
	t.Parallel()
	client := &ClientIdentity{Issuer: ca.KindDevice, ID: &ca.DeviceIdentity{Serial: "0000000000000000000000000000aaaa", DeviceID: testDevice, TenantID: testTenant}}
	// No revoker configured, bootstrap identity or nil client -> nothing scheduled.
	h := newTestHandler(t, Config{})
	if _, ok := h.supersedePrevious(client, "bbbb"); ok {
		t.Fatal("scheduled without revoker")
	}
	fr := &fakeRevoker{done: make(chan struct{})}
	h = newTestHandler(t, Config{Revoker: fr, SupersedeGrace: 10 * time.Millisecond})
	if _, ok := h.supersedePrevious(&ClientIdentity{Issuer: ca.KindFactory, ID: client.ID}, "bbbb"); ok {
		t.Fatal("bootstrap certificates are not superseded")
	}
	if _, ok := h.supersedePrevious(nil, "bbbb"); ok {
		t.Fatal("nil client scheduled")
	}
	due, ok := h.supersedePrevious(client, "bbbb")
	if !ok || due.IsZero() || due.Before(time.Now().Add(-time.Second)) {
		t.Fatalf("not scheduled: %v %v", due, ok)
	}
	select {
	case <-fr.done:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled revocation did not run")
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if len(fr.calls) != 1 || fr.calls[0] != "0000000000000000000000000000aaaa|superseded|pki:supersede:bbbb" {
		t.Fatalf("calls %v", fr.calls)
	}
	// Errors (other than already revoked) are logged, not fatal.
	for _, e := range []error{store.ErrAlreadyRevoked, errors.New("boom")} {
		fr2 := &fakeRevoker{done: make(chan struct{}), err: e}
		h2 := newTestHandler(t, Config{Revoker: fr2, SupersedeGrace: time.Millisecond})
		if _, ok := h2.supersedePrevious(client, "cccc"); !ok {
			t.Fatal("not scheduled")
		}
		<-fr2.done
	}
}

// Ensure the identity helpers used above keep their contract when given a
// real certificate (guards against refactors of ca.DeviceIdentity).
func TestIdentitySerialCanonical(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xabcd),
		Subject:      pkix.Name{CommonName: testDevice, OrganizationalUnit: []string{testTenant}, Organization: []string{ca.Organization}},
		NotBefore:    time.Now(), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{ca.DeviceURN(testTenant, testDevice)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	id, err := ca.ParseDeviceIdentity(cert)
	if err != nil {
		t.Fatal(err)
	}
	client := &ClientIdentity{Issuer: ca.KindFactory, ID: id, Cert: cert}
	if err := checkBootstrapSerialMatchesManufactureRecord(client, &registry.Device{BootstrapSerial: "ABCD"}); err != nil {
		t.Fatalf("serial presentation mismatch: %v", err)
	}
}
