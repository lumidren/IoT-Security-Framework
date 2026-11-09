package revocation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/clock"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/emqx"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
)

const (
	testToken  = "pki-token"
	testSecret = "hmac-secret"
)

type testEnv struct {
	svc   *Service
	cache *Cache
	m     *metrics.Metrics
	reg   *prometheus.Registry
	clock *clock.Fake
}

func newTestService(t *testing.T, kicker emqx.Kicker, mutate func(*ServiceConfig)) *testEnv {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	fc := clock.NewFake(t0.Add(2500 * time.Millisecond)) // 2.5s after revoked_at
	cache := NewCache(filepath.Join(t.TempDir(), SnapshotName), fc.Now)
	cfg := ServiceConfig{
		Cache:         cache,
		Kicker:        kicker,
		Token:         testToken,
		HMACSecret:    testSecret,
		Clock:         fc,
		Metrics:       m,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		KickTimeout:   time.Second,
		RetryInterval: 20 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{svc: svc, cache: cache, m: m, reg: reg, clock: fc}
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func eventBody(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := json.Marshal(Event{EventID: id, Serial: "0ABC", DeviceID: devA, TenantID: tenant, Reason: "keyCompromise", RevokedAt: t0})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func post(h http.Handler, body []byte, token, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/revocations", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sig != "" {
		req.Header.Set("X-IronMesh-Signature", sig)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func histogram(t *testing.T, reg *prometheus.Registry, name string) (uint64, float64) {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			h := f.GetMetric()[0].GetHistogram()
			return h.GetSampleCount(), h.GetSampleSum()
		}
	}
	t.Fatalf("histogram %s not found", name)
	return 0, 0
}

func TestNewServiceValidation(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	cache := NewCache("", nil)
	base := ServiceConfig{Cache: cache, Kicker: emqx.NewFake(), Token: "t", HMACSecret: "s", Metrics: m}
	cases := map[string]func(*ServiceConfig){
		"nil cache":   func(c *ServiceConfig) { c.Cache = nil },
		"nil kicker":  func(c *ServiceConfig) { c.Kicker = nil },
		"no token":    func(c *ServiceConfig) { c.Token = "" },
		"no secret":   func(c *ServiceConfig) { c.HMACSecret = "" },
		"nil metrics": func(c *ServiceConfig) { c.Metrics = nil },
	}
	for name, mutate := range cases {
		cfg := base
		mutate(&cfg)
		if _, err := NewService(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	svc, err := NewService(base)
	if err != nil {
		t.Fatal(err)
	}
	if cap(svc.queue) != 1024 || svc.kickTimeout != 5*time.Second || svc.retryInterval != 30*time.Second || svc.maxBody != 64<<10 || svc.clock == nil || svc.log == nil {
		t.Errorf("defaults not applied: %+v", svc)
	}
}

func TestEventValidate(t *testing.T) {
	valid := Event{EventID: "e1", Serial: "abc", DeviceID: devA, TenantID: tenant, RevokedAt: t0}
	cases := []struct {
		name   string
		mutate func(*Event)
		ok     bool
	}{
		{"valid", func(e *Event) {}, true},
		{"service identity", func(e *Event) { e.DeviceID = "svc-bridge" }, true},
		{"serial only", func(e *Event) { e.DeviceID = "" }, true},
		{"device only", func(e *Event) { e.Serial = "" }, true},
		{"missing id", func(e *Event) { e.EventID = " " }, false},
		{"long id", func(e *Event) { e.EventID = strings.Repeat("x", 129) }, false},
		{"bad serial", func(e *Event) { e.Serial = "zz" }, false},
		{"neither device nor serial", func(e *Event) { e.Serial, e.DeviceID = "", "" }, false},
		{"bad device", func(e *Event) { e.DeviceID = "dev-XYZ" }, false},
		{"bad tenant", func(e *Event) { e.TenantID = "tenant" }, false},
		{"zero revoked_at", func(e *Event) { e.RevokedAt = time.Time{} }, false},
		{"long reason", func(e *Event) { e.Reason = strings.Repeat("r", 257) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := valid
			tc.mutate(&ev)
			err := ev.Validate()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestHandlerAuthAndSignature(t *testing.T) {
	env := newTestService(t, emqx.NewFake(), nil)
	h := env.svc.Handler()
	body := eventBody(t, "e1")
	good := sign(testSecret, body)

	req := httptest.NewRequest(http.MethodGet, "/internal/v1/revocations", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rec.Code)
	}
	if rec := post(h, body, "", good); rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("missing token: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := post(h, body, "wrong", good); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	if rec := post(h, body, testToken, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing signature: %d", rec.Code)
	}
	if rec := post(h, body, testToken, sign(testSecret, []byte("other"))); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong signature: %d", rec.Code)
	}
	if rec := post(h, body, testToken, "nothex"); rec.Code != http.StatusUnauthorized {
		t.Errorf("non-hex signature: %d", rec.Code)
	}
	if rec := post(h, body, testToken, "sha256="+good); rec.Code != http.StatusAccepted {
		t.Errorf("prefixed signature: %d %s", rec.Code, rec.Body.String())
	}
	if got := testutil.ToFloat64(env.m.AuthFailures.WithLabelValues("revocation_token")); got != 2 {
		t.Errorf("token failures = %v, want 2", got)
	}
	if got := testutil.ToFloat64(env.m.AuthFailures.WithLabelValues("revocation_signature")); got != 3 {
		t.Errorf("signature failures = %v, want 3", got)
	}
}

func TestHandlerBodyErrors(t *testing.T) {
	env := newTestService(t, emqx.NewFake(), func(c *ServiceConfig) { c.MaxBodyBytes = 200 })
	h := env.svc.Handler()

	bad := []byte(`{not json`)
	if rec := post(h, bad, testToken, sign(testSecret, bad)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", rec.Code)
	}
	invalid, _ := json.Marshal(Event{EventID: "e1", DeviceID: devA})
	rec := post(h, invalid, testToken, sign(testSecret, invalid))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid event: %d", rec.Code)
	}
	var prob struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if len(prob.Errors) == 0 {
		t.Errorf("422 should list validation errors: %s", rec.Body.String())
	}
	big := append(eventBody(t, "e1"), bytes.Repeat([]byte(" "), 300)...)
	if rec := post(h, big, testToken, sign(testSecret, big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d", rec.Code)
	}
}

func TestEventTriggersKickWithin100ms(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)

	body := eventBody(t, "e1")
	rec := post(env.svc.Handler(), body, testToken, sign(testSecret, body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "accepted" || resp["kick_queued"] != true || resp["event_id"] != "e1" {
		t.Errorf("response = %v", resp)
	}

	select {
	case id := <-fake.Kicked:
		if id != devA {
			t.Fatalf("kicked %q, want %q", id, devA)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("kick did not happen within 100ms of the revocation event")
	}
	if !env.cache.IsRevokedDevice(devA) || !env.cache.IsRevokedSerial("abc") {
		t.Error("device/serial should be in the deny cache")
	}
	waitFor(t, "kicked flag", func() bool { e, _ := env.cache.Get("e1"); return e.Kicked })

	count, sum := histogram(t, env.reg, "ironmesh_revocation_apply_latency_seconds")
	if count != 1 || sum != 2.5 {
		t.Errorf("apply latency count=%d sum=%v, want 1 / 2.5 (fake clock)", count, sum)
	}
	count, _ = histogram(t, env.reg, "ironmesh_revocation_latency_seconds")
	if count != 1 {
		t.Errorf("contract latency histogram count = %d", count)
	}
	if got := testutil.ToFloat64(env.m.Kicks.WithLabelValues("ok")); got != 1 {
		t.Errorf("kicks ok = %v", got)
	}
	if got := testutil.ToFloat64(env.m.Revocations.WithLabelValues(SourceEvent)); got != 1 {
		t.Errorf("revocations event = %v", got)
	}
	if got := testutil.ToFloat64(env.m.RevokedEntries); got != 1 {
		t.Errorf("revoked entries gauge = %v", got)
	}
	cancel()
	env.svc.Wait()
}

func TestDuplicateEventIsIdempotent(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)
	body := eventBody(t, "e1")
	sig := sign(testSecret, body)
	if rec := post(env.svc.Handler(), body, testToken, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := post(env.svc.Handler(), body, testToken, sig)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"duplicate"`) {
		t.Fatalf("second: %d %s", rec.Code, rec.Body.String())
	}
	<-fake.Kicked
	time.Sleep(50 * time.Millisecond)
	if calls := fake.Calls(); len(calls) != 1 {
		t.Errorf("kick calls = %v, want exactly one", calls)
	}
}

func TestKickRetryAfterFailure(t *testing.T) {
	fake := emqx.NewFake()
	fake.SetErr(errors.New("emqx down"))
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)

	body := eventBody(t, "e1")
	if rec := post(env.svc.Handler(), body, testToken, sign(testSecret, body)); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	select {
	case <-fake.Kicked:
	case <-time.After(time.Second):
		t.Fatal("first kick attempt missing")
	}
	e, _ := env.cache.Get("e1")
	if e.Kicked {
		t.Fatal("failed kick must not be recorded as kicked")
	}
	fake.SetErr(nil)
	waitFor(t, "retry to succeed", func() bool { e, _ := env.cache.Get("e1"); return e.Kicked })
	if got := testutil.ToFloat64(env.m.Kicks.WithLabelValues("error")); got < 1 {
		t.Errorf("kick errors = %v, want >= 1", got)
	}
	if got := testutil.ToFloat64(env.m.Kicks.WithLabelValues("ok")); got != 1 {
		t.Errorf("kick ok = %v, want 1", got)
	}
}

func TestStartRequeuesUnkickedEntries(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	if _, err := env.cache.Upsert(Entry{EventID: "old", DeviceID: devB, RevokedAt: t0}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)
	env.svc.Start(ctx) // idempotent
	select {
	case id := <-fake.Kicked:
		if id != devB {
			t.Fatalf("kicked %q", id)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("unkicked entry was not re-queued on start")
	}
	cancel()
	env.svc.Wait()
}

func TestApplySerial(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)

	added, err := env.svc.ApplySerial("0X0DEF", t0, "superseded")
	if err != nil || !added {
		t.Fatalf("ApplySerial = %v, %v", added, err)
	}
	if added, _ := env.svc.ApplySerial("def", t0, "superseded"); added {
		t.Error("second ApplySerial should be a duplicate")
	}
	if _, err := env.svc.ApplySerial("zz", t0, ""); err == nil {
		t.Error("invalid serial should fail")
	}
	if !env.cache.IsRevokedSerial("def") {
		t.Error("serial should be revoked")
	}
	e, _ := env.cache.Get("crl:def")
	if e.Source != SourceCRL || e.Reason != "superseded" {
		t.Errorf("entry = %+v", e)
	}
	time.Sleep(50 * time.Millisecond)
	if len(fake.Calls()) != 0 {
		t.Error("serial-only entries must not trigger kicks")
	}
	if got := testutil.ToFloat64(env.m.Revocations.WithLabelValues(SourceCRL)); got != 1 {
		t.Errorf("revocations crl = %v", got)
	}
}

func TestApplyQueueFull(t *testing.T) {
	env := newTestService(t, emqx.NewFake(), func(c *ServiceConfig) { c.QueueSize = 1 })
	// Worker not started: the single slot fills with the first event.
	if res, err := env.svc.Apply(context.Background(), Event{EventID: "e1", DeviceID: devA, DeviceDeny: true, RevokedAt: t0}, SourceEvent); err != nil || !res.KickQueued {
		t.Fatalf("first apply = %+v, %v", res, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res, err := env.svc.Apply(ctx, Event{EventID: "e2", DeviceID: devB, DeviceDeny: true, RevokedAt: t0}, SourceEvent)
	if !errors.Is(err, ErrQueueFull) || !res.Added {
		t.Fatalf("second apply = %+v, %v; want added + ErrQueueFull", res, err)
	}
	if !env.cache.IsRevokedDevice(devB) {
		t.Error("device must be denied even when the kick could not be queued")
	}
	body := eventBody(t, "e3")
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/revocations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-IronMesh-Signature", sign(testSecret, body))
	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer rcancel()
	rec := httptest.NewRecorder()
	env.svc.Handler().ServeHTTP(rec, req.WithContext(rctx))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("handler with full queue = %d", rec.Code)
	}
}

func TestSnapshotPersistsAcrossRestart(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	env.svc.Start(ctx)
	body := eventBody(t, "e1")
	post(env.svc.Handler(), body, testToken, sign(testSecret, body))
	waitFor(t, "kick", func() bool { e, _ := env.cache.Get("e1"); return e.Kicked })
	cancel()
	env.svc.Wait()

	restored := NewCache(env.cache.Path(), env.clock.Now)
	if n, err := restored.Load(); err != nil || n != 1 {
		t.Fatalf("Load = %d, %v", n, err)
	}
	if !restored.IsRevokedDevice(devA) {
		t.Error("device should still be revoked after restart")
	}
	fake2 := emqx.NewFake()
	svc2, err := NewService(ServiceConfig{Cache: restored, Kicker: fake2, Token: testToken, HMACSecret: testSecret, Metrics: metrics.New(prometheus.NewRegistry()), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	svc2.Start(ctx2)
	time.Sleep(50 * time.Millisecond)
	if len(fake2.Calls()) != 0 {
		t.Error("already-kicked entries must not be kicked again on restart")
	}
}

type fakeSessions map[string]string

func (f fakeSessions) LiveSerial(id string) (string, bool) {
	s, ok := f[id]
	return s, ok
}

func TestDeviceDenyClassification(t *testing.T) {
	for _, r := range []string{"keyCompromise", "cessationOfOperation", "key_compromise", "CessationOfOperation"} {
		if !DeviceDenyReason(r) {
			t.Errorf("%s should deny the device", r)
		}
	}
	for _, r := range []string{"superseded", "unspecified", "affiliationChanged", ""} {
		if DeviceDenyReason(r) {
			t.Errorf("%s must be serial-scoped", r)
		}
	}
	env := newTestService(t, emqx.NewFake(), nil)
	cases := []struct {
		ev         Event
		deviceDeny bool
	}{
		{Event{EventID: "sup", Serial: "a1", DeviceID: "dev-0000000000000001", Reason: "superseded", RevokedAt: t0}, false},
		{Event{EventID: "one", Serial: "a2", DeviceID: "dev-0000000000000002", Reason: "unspecified", RevokedAt: t0}, false},
		{Event{EventID: "flag", Serial: "a3", DeviceID: "dev-0000000000000003", Reason: "superseded", DeviceDeny: true, RevokedAt: t0}, true},
		{Event{EventID: "kc", Serial: "a4", DeviceID: "dev-0000000000000004", Reason: "keyCompromise", RevokedAt: t0}, true},
		{Event{EventID: "cess", Serial: "a5", DeviceID: "dev-0000000000000005", Reason: "cessationOfOperation", RevokedAt: t0}, true},
		{Event{EventID: "svc", Serial: "a6", DeviceID: "svc-bridge", Reason: "superseded", RevokedAt: t0}, false},
	}
	for _, c := range cases {
		if _, err := env.svc.Apply(context.Background(), c.ev, SourceEvent); err != nil {
			t.Fatal(err)
		}
		if got := env.cache.IsRevokedDevice(c.ev.DeviceID); got != c.deviceDeny {
			t.Errorf("%s: device denied = %v, want %v", c.ev.EventID, got, c.deviceDeny)
		}
		if !env.cache.IsRevokedSerial(c.ev.Serial) {
			t.Errorf("%s: serial must always be denied", c.ev.EventID)
		}
	}
}

// TestSerialScopedKick: a serial-scoped revocation kicks the session only when it runs on the
// revoked certificate or its certificate is unknown; device denies always kick.
func TestSerialScopedKick(t *testing.T) {
	sessions := fakeSessions{devA: "0B02", devB: "a01"}
	fake := emqx.NewFake()
	env := newTestService(t, fake, func(c *ServiceConfig) { c.Sessions = sessions })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)
	apply := func(ev Event) {
		t.Helper()
		if _, err := env.svc.Apply(ctx, ev, SourceEvent); err != nil {
			t.Fatal(err)
		}
	}
	// devA renewed: its live session uses b02, the superseded a01 is not live -> no kick.
	apply(Event{EventID: "renewed", Serial: "a01", DeviceID: devA, Reason: "superseded", RevokedAt: t0})
	waitFor(t, "skip", func() bool { e, _ := env.cache.Get("renewed"); return e.Kicked && e.KickSkipped })
	// devB is still on the revoked certificate -> kicked.
	apply(Event{EventID: "stale", Serial: "0a01", DeviceID: devB, Reason: "superseded", RevokedAt: t0})
	if id := <-fake.Kicked; id != devB {
		t.Fatalf("kicked %q", id)
	}
	// Unknown live session (e.g. admitted by another replica) -> kicked.
	apply(Event{EventID: "unknown", Serial: "c3", DeviceID: "dev-00000000000000c3", Reason: "superseded", RevokedAt: t0})
	if id := <-fake.Kicked; id != "dev-00000000000000c3" {
		t.Fatalf("kicked %q", id)
	}
	// Device-level deny ignores the live serial.
	apply(Event{EventID: "quarantine", Serial: "d4", DeviceID: devA, Reason: "superseded", DeviceDeny: true, RevokedAt: t0})
	if id := <-fake.Kicked; id != devA {
		t.Fatalf("kicked %q", id)
	}
	if got := testutil.ToFloat64(env.m.Kicks.WithLabelValues("skipped")); got != 1 {
		t.Errorf("skipped kicks = %v", got)
	}
	if !env.cache.IsRevokedDevice(devA) || env.cache.IsRevokedDevice(devB) {
		t.Error("device deny state")
	}
}

// TestFanOutRedeliveryIsIdempotent: the PKI redelivers an event to replicas that did not
// acknowledge it; a replica that already applied it answers "duplicate" without a second kick.
func TestFanOutRedeliveryIsIdempotent(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)
	body := []byte(`{"event_id":"9b2f0c4e-1f7a-4c39-9d5e-1a2b3c4d5e6f","serial":"0abc","device_id":"` + devA + `","tenant_id":"` + tenant + `","reason":"cessationOfOperation","revoked_at":"2026-11-03T12:00:00Z","device_deny":true}`)
	sig := sign(testSecret, body)
	for i, want := range []string{`"accepted"`, `"duplicate"`, `"duplicate"`} {
		rec := post(env.svc.Handler(), body, testToken, sig)
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("delivery %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	<-fake.Kicked
	time.Sleep(50 * time.Millisecond)
	if calls := fake.Calls(); len(calls) != 1 {
		t.Fatalf("kicks %v", calls)
	}
	if !env.cache.IsRevokedDevice(devA) {
		t.Fatal("device_deny event must deny the device")
	}
}
