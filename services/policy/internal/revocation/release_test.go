package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/emqx"
)

func releaseBody(t *testing.T, id, device string, at time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"event_id": id, "event": "device_release", "device_id": device, "tenant_id": tenant, "released_at": at})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReleaseEventValidate(t *testing.T) {
	good := Event{EventID: "r1", Kind: KindDeviceRelease, DeviceID: devA, TenantID: tenant, ReleasedAt: t0}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid release: %v", err)
	}
	if good.EventKind() != KindDeviceRelease || (Event{}).EventKind() != KindRevocation {
		t.Fatal("EventKind")
	}
	cases := map[string]Event{
		"no event id":   {Kind: KindDeviceRelease, DeviceID: devA, TenantID: tenant, ReleasedAt: t0},
		"service id":    {EventID: "r", Kind: KindDeviceRelease, DeviceID: "svc-bridge", TenantID: tenant, ReleasedAt: t0},
		"no device":     {EventID: "r", Kind: KindDeviceRelease, TenantID: tenant, ReleasedAt: t0},
		"no tenant":     {EventID: "r", Kind: KindDeviceRelease, DeviceID: devA, ReleasedAt: t0},
		"no time":       {EventID: "r", Kind: KindDeviceRelease, DeviceID: devA, TenantID: tenant},
		"unknown kind":  {EventID: "r", Kind: "device_unrevoke", DeviceID: devA, TenantID: tenant, ReleasedAt: t0},
		"explicit kind": {EventID: "r", Kind: KindRevocation},
	}
	for name, ev := range cases {
		if err := ev.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	explicit := Event{EventID: "r", Kind: KindRevocation, Serial: "0a", DeviceID: devA, RevokedAt: t0}
	if err := explicit.Validate(); err != nil {
		t.Fatalf("explicit revocation kind: %v", err)
	}
}

// TestCacheReleaseSemantics: a release lifts device-level denies revoked at or before
// released_at (also ones that arrive late), keeps every serial deny, and a quarantine after the
// release denies the device again.
func TestCacheReleaseSemantics(t *testing.T) {
	c := NewCache("", fixedNow)
	mustUpsert := func(e Entry) {
		t.Helper()
		if _, err := c.Upsert(e); err != nil {
			t.Fatal(err)
		}
	}
	mustUpsert(Entry{EventID: "sup", Serial: "01", DeviceID: devA, TenantID: tenant, Reason: "superseded", RevokedAt: t0.Add(-time.Hour)})
	mustUpsert(Entry{EventID: "q1", Serial: "02", DeviceID: devA, TenantID: tenant, Reason: "cessationOfOperation", DeviceDeny: true, RevokedAt: t0})
	mustUpsert(Entry{EventID: "other", Serial: "b1", DeviceID: devB, TenantID: tenant, DeviceDeny: true, RevokedAt: t0})
	if !c.IsRevokedDevice(devA) {
		t.Fatal("quarantine must deny the device")
	}

	added, lifted, err := c.Release(Release{EventID: "rel1", DeviceID: devA, TenantID: tenant, ReleasedAt: t0.Add(time.Second)})
	if err != nil || !added || !lifted {
		t.Fatalf("release: added=%v lifted=%v err=%v", added, lifted, err)
	}
	if c.IsRevokedDevice(devA) {
		t.Fatal("device-level deny must be lifted")
	}
	if !c.IsRevokedSerial("01") || !c.IsRevokedSerial("02") {
		t.Fatal("serial denies must stay")
	}
	if !c.IsRevokedDevice(devB) {
		t.Fatal("another device must stay denied")
	}
	if !c.ReleasedAt(devA).Equal(t0.Add(time.Second)) || !c.ReleasedAt(devB).IsZero() {
		t.Fatal("release watermark")
	}
	// Duplicate (same event id) is a no-op; an older release does not move the watermark back.
	if added, _, _ := c.Release(Release{EventID: "rel1", DeviceID: devA, ReleasedAt: t0.Add(time.Hour)}); added {
		t.Fatal("duplicate release added")
	}
	if added, lifted, _ := c.Release(Release{EventID: "rel0", DeviceID: devA, ReleasedAt: t0.Add(-time.Minute)}); !added || lifted {
		t.Fatal("older release")
	}
	if !c.ReleasedAt(devA).Equal(t0.Add(time.Second)) {
		t.Fatal("watermark moved back")
	}
	// A deny revoked before the release but delivered after it stays lifted; its serial is denied.
	mustUpsert(Entry{EventID: "late", Serial: "03", DeviceID: devA, TenantID: tenant, DeviceDeny: true, RevokedAt: t0.Add(500 * time.Millisecond)})
	if c.IsRevokedDevice(devA) || !c.IsRevokedSerial("03") {
		t.Fatal("late, older device deny must not re-deny the released device")
	}
	// A new quarantine after the release denies the device again.
	mustUpsert(Entry{EventID: "q2", Serial: "04", DeviceID: devA, TenantID: tenant, DeviceDeny: true, RevokedAt: t0.Add(time.Minute)})
	if !c.IsRevokedDevice(devA) {
		t.Fatal("re-quarantine must deny the device")
	}
	// A release delivered late that predates the new quarantine does not lift it.
	if _, lifted, _ := c.Release(Release{EventID: "rel-stale", DeviceID: devA, ReleasedAt: t0.Add(30 * time.Second)}); lifted || !c.IsRevokedDevice(devA) {
		t.Fatal("stale release lifted a newer deny")
	}
	// Event ids are unique across kinds.
	if added, _, _ := c.Release(Release{EventID: "q2", DeviceID: devA, ReleasedAt: t0.Add(time.Hour)}); added {
		t.Fatal("release reused a revocation event id")
	}
	if added, _ := c.Upsert(Entry{EventID: "rel1", Serial: "05", DeviceID: devA, RevokedAt: t0}); added {
		t.Fatal("revocation reused a release event id")
	}
	if got := len(c.Releases()); got != 3 {
		t.Fatalf("releases = %d", got)
	}
	for _, bad := range []Release{{DeviceID: devA, ReleasedAt: t0}, {EventID: "x", ReleasedAt: t0}, {EventID: "x", DeviceID: devA}} {
		if _, _, err := c.Release(bad); err == nil {
			t.Errorf("invalid release accepted: %+v", bad)
		}
	}
}

// TestReleaseSurvivesRestart: releases are part of the snapshot, so a restarted replica keeps the
// device admitted (and keeps the lifted entries out of the device index).
func TestReleaseSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), SnapshotName)
	c := NewCache(path, fixedNow)
	if _, err := c.Upsert(Entry{EventID: "q", Serial: "02", DeviceID: devA, TenantID: tenant, DeviceDeny: true, RevokedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Release(Release{EventID: "rel", DeviceID: devA, TenantID: tenant, ReleasedAt: t0.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), `"releases"`) || !strings.Contains(string(raw), `"format": 3`) {
		t.Fatalf("snapshot %s %v", raw, err)
	}
	restored := NewCache(path, fixedNow)
	if n, err := restored.Load(); err != nil || n != 1 {
		t.Fatalf("load %d %v", n, err)
	}
	if restored.IsRevokedDevice(devA) || !restored.IsRevokedSerial("02") || len(restored.Releases()) != 1 {
		t.Fatal("restored state must keep the release")
	}
	// Invalid or duplicate release records in a snapshot are skipped.
	snap := `{"format":3,"entries":[],"releases":[{"event_id":"a","device_id":"` + devA + `","released_at":"2026-11-03T12:00:00Z"},` +
		`{"event_id":"a","device_id":"` + devA + `","released_at":"2026-11-03T12:00:01Z"},{"event_id":"","device_id":"x","released_at":"2026-11-03T12:00:00Z"}]}`
	p2 := filepath.Join(t.TempDir(), SnapshotName)
	if err := os.WriteFile(p2, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	c2 := NewCache(p2, fixedNow)
	if _, err := c2.Load(); err != nil || len(c2.Releases()) != 1 || !c2.ReleasedAt(devA).Equal(t0) {
		t.Fatalf("load releases: %v %+v", err, c2.Releases())
	}
}

// TestReleaseEventOverHTTP drives the PKI push: quarantine (device_deny) -> release -> the device
// is no longer device-denied, its revoked serial is, duplicates are idempotent, and both kinds are
// counted in ironmesh_revocation_events_total{kind}.
func TestReleaseEventOverHTTP(t *testing.T) {
	fake := emqx.NewFake()
	env := newTestService(t, fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.svc.Start(ctx)
	h := env.svc.Handler()

	deny := []byte(`{"event_id":"q-1","serial":"0abc","device_id":"` + devA + `","tenant_id":"` + tenant + `","reason":"cessationOfOperation","revoked_at":"2026-11-03T12:00:00Z","device_deny":true}`)
	if rec := post(h, deny, testToken, sign(testSecret, deny)); rec.Code != http.StatusAccepted {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	<-fake.Kicked
	if !env.cache.IsRevokedDevice(devA) {
		t.Fatal("quarantine")
	}

	rel := releaseBody(t, "rel-1", devA, t0.Add(time.Minute))
	// Same bearer + HMAC verification as revocations.
	if rec := post(h, rel, "wrong", sign(testSecret, rel)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if rec := post(h, rel, testToken, sign("other", rel)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d", rec.Code)
	}
	rec := post(h, rel, testToken, sign(testSecret, rel))
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"accepted"`) || !strings.Contains(rec.Body.String(), `"device_deny_lifted":true`) {
		t.Fatalf("release: %d %s", rec.Code, rec.Body.String())
	}
	if env.cache.IsRevokedDevice(devA) || !env.cache.IsRevokedSerial("0abc") {
		t.Fatal("release must lift the device deny and keep the serial deny")
	}
	rec = post(h, rel, testToken, sign(testSecret, rel))
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"duplicate"`) {
		t.Fatalf("redelivery: %d %s", rec.Code, rec.Body.String())
	}
	bad := releaseBody(t, "rel-2", "svc-bridge", t0)
	if rec := post(h, bad, testToken, sign(testSecret, bad)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid release: %d", rec.Code)
	}
	unknown := []byte(`{"event_id":"x","event":"device_unrevoke","device_id":"` + devA + `"}`)
	if rec := post(h, unknown, testToken, sign(testSecret, unknown)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown kind: %d", rec.Code)
	}
	if got := testutil.ToFloat64(env.m.RevocationEvents.WithLabelValues(KindDeviceRelease)); got != 1 {
		t.Fatalf("release events = %v", got)
	}
	if got := testutil.ToFloat64(env.m.RevocationEvents.WithLabelValues(KindRevocation)); got != 1 {
		t.Fatalf("revocation events = %v", got)
	}
}

// TestReleasedDenyIsNotKicked: an unkicked device-level entry whose deny was lifted by a release
// behaves like a serial-scoped revocation (no kick when the live session uses another certificate)
// and is skipped when it names no serial.
func TestReleasedDenyIsNotKicked(t *testing.T) {
	fake := emqx.NewFake()
	fake.SetErr(errors.New("emqx down"))
	env := newTestService(t, fake, func(c *ServiceConfig) { c.Sessions = fakeSessions{devA: "0new"} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := env.svc.Apply(ctx, Event{EventID: "q", Serial: "0old", DeviceID: devA, TenantID: tenant, DeviceDeny: true, RevokedAt: t0}, SourceEvent); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Apply(ctx, Event{EventID: "legacy", DeviceID: devB, TenantID: tenant, DeviceDeny: true, RevokedAt: t0}, SourceEvent); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{devA, devB} {
		if res, _ := env.svc.ApplyRelease(Event{EventID: "rel-" + d, Kind: KindDeviceRelease, DeviceID: d, TenantID: tenant, ReleasedAt: t0.Add(time.Second)}); !res.Added || !res.Lifted {
			t.Fatalf("release %s: %+v", d, res)
		}
	}
	if res, _ := env.svc.ApplyRelease(Event{EventID: "rel-" + devA, Kind: KindDeviceRelease, DeviceID: devA, ReleasedAt: t0}); !res.Duplicate {
		t.Fatal("duplicate release")
	}
	fake.SetErr(nil)
	env.svc.Start(ctx) // restart recovery re-queues both unkicked entries
	waitFor(t, "both skipped", func() bool {
		a, _ := env.cache.Get("q")
		b, _ := env.cache.Get("legacy")
		return a.KickSkipped && b.KickSkipped
	})
	if calls := fake.Calls(); len(calls) != 0 {
		t.Fatalf("released devices were kicked: %v", calls)
	}
}
