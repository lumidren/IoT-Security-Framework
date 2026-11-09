package revocation_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

const releaseOtherTenant = "0b6f3c1e-2d4a-4e8b-9f10-aa55aa55aa55"

func jsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestEventWireFormats: a device_release body carries exactly the release
// fields; the revocation body is unchanged (no "event" member).
func TestEventWireFormats(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	rel, err := json.Marshal(revocation.Event{EventID: "e1", Kind: revocation.KindDeviceRelease, DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: testutil.Tenant, ReleasedAt: at, Serial: "ignored", DeviceDeny: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(jsonKeys(t, rel), ","); got != "device_id,event,event_id,released_at,tenant_id" {
		t.Fatalf("release keys %s: %s", got, rel)
	}
	var back revocation.Event
	if err := json.Unmarshal(rel, &back); err != nil || !back.IsRelease() || !back.ReleasedAt.Equal(at) || back.DeviceID != "dev-8f3a1c2b9d4e5f60" {
		t.Fatalf("round trip %+v %v", back, err)
	}
	rev, err := json.Marshal(revocation.Event{EventID: "e2", Serial: "0a", DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: testutil.Tenant, Reason: "keyCompromise", RevokedAt: at, DeviceDeny: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(jsonKeys(t, rev), ","); got != "device_deny,device_id,event_id,reason,revoked_at,serial,tenant_id" {
		t.Fatalf("revocation keys %s", got)
	}
	if (revocation.Event{Kind: revocation.KindRevocation}).IsRelease() {
		t.Fatal("revocation is not a release")
	}
}

// TestReleaseQueuedAndRetried: Release writes a device_release row into the
// outbox, makes one inline attempt and leaves retries to the dispatcher.
func TestReleaseQueuedAndRetried(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	clk := newFakeClock()
	pub := &scriptedPublisher{failures: 1}
	m := metrics.New()
	svc, err := revocation.NewService(p.Store, revocation.Options{Publisher: pub, Metrics: m, Clock: clk.Now, Logger: p.Logger})
	if err != nil {
		t.Fatal(err)
	}
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	ctx := context.Background()

	res, err := svc.Release(ctx, dev.ID, testutil.Tenant, "svc-registry")
	if err != nil {
		t.Fatal(err)
	}
	if res.Published || res.PublishError == "" || res.Event != revocation.KindDeviceRelease || res.DeviceID != dev.ID || res.TenantID != testutil.Tenant || !res.ReleasedAt.Equal(clk.Now()) {
		t.Fatalf("first attempt must fail and be reported: %+v", res)
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 1 || promtest.ToFloat64(m.RevocationOutboxPending) != 1 {
		t.Fatalf("pending %d", n)
	}
	clk.Advance(revocation.DefaultBaseBackoff)
	if n, err := svc.Dispatcher().ProcessDue(ctx); err != nil || n != 1 {
		t.Fatalf("retry delivered %d %v", n, err)
	}
	_, events := pub.snapshot()
	if len(events) != 1 || !events[0].IsRelease() || events[0].EventID != res.EventID || events[0].DeviceID != dev.ID || !events[0].ReleasedAt.Equal(res.ReleasedAt) {
		t.Fatalf("delivered %+v", events)
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 0 {
		t.Fatalf("pending after ack %d", n)
	}
	// Releases are not revocations: no revocation latency, no revocation counted.
	if sum := histogramCount(t, m, "ironmesh_revocation_latency_seconds"); sum != 0 {
		t.Fatalf("revocation latency observed for a release: %d", sum)
	}
	if promtest.ToFloat64(m.RevocationPublishAttempts.WithLabelValues("error")) != 1 || promtest.ToFloat64(m.RevocationPublishAttempts.WithLabelValues("ok")) != 1 {
		t.Fatal("attempt metrics")
	}

	// A second release (e.g. a registry retry) is a new, independent event.
	again, err := svc.Release(ctx, dev.ID, testutil.Tenant, "svc-registry")
	if err != nil || !again.Published || again.EventID == res.EventID {
		t.Fatalf("second release %+v %v", again, err)
	}
	// A device without certificates can be released in any tenant.
	if _, err := svc.Release(ctx, "dev-00000000000000ff", releaseOtherTenant, "svc-registry"); err != nil {
		t.Fatalf("release without certificates: %v", err)
	}
}

func histogramCount(t *testing.T, m *metrics.Metrics, name string) uint64 {
	t.Helper()
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetHistogram().GetSampleCount()
		}
	}
	return 0
}

func TestReleaseErrors(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	svc, _ := revocation.NewService(p.Store, revocation.Options{Publisher: &scriptedPublisher{}, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	ctx := context.Background()
	if _, err := svc.Release(ctx, dev.ID, releaseOtherTenant, "svc-registry"); !errors.Is(err, revocation.ErrTenantMismatch) {
		t.Fatalf("tenant mismatch: %v", err)
	}
	if _, err := svc.Release(ctx, "not a device", testutil.Tenant, "x"); err == nil {
		t.Fatal("invalid device id accepted")
	}
	if _, err := svc.Release(ctx, dev.ID, "not-a-uuid", "x"); err == nil {
		t.Fatal("invalid tenant accepted")
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 0 {
		t.Fatalf("rejected releases queued %d events", n)
	}
	closed := store.NewMemory()
	_ = closed.Close()
	broken, _ := revocation.NewService(closed, revocation.Options{Publisher: &scriptedPublisher{}, Logger: p.Logger})
	if _, err := broken.Release(ctx, dev.ID, testutil.Tenant, "x"); err == nil {
		t.Fatal("store failure not reported")
	}
	if err := closed.AddOutboxEvent(ctx, &store.OutboxEvent{EventID: "x"}); err == nil {
		t.Fatal("closed store accepted an outbox event")
	}
	failing, _ := revocation.NewService(&failingAdd{Memory: store.NewMemory()}, revocation.Options{Publisher: &scriptedPublisher{}, Logger: p.Logger})
	if _, err := failing.Release(ctx, dev.ID, testutil.Tenant, "x"); err == nil || !strings.Contains(err.Error(), "outbox down") {
		t.Fatalf("outbox write failure: %v", err)
	}
	// An outbox row of an unknown kind is never delivered.
	st := store.NewMemory()
	pub := &scriptedPublisher{}
	d := revocation.NewDispatcher(st, revocation.DispatcherOptions{Publisher: pub})
	if err := d.Attempt(ctx, &store.OutboxEvent{EventID: "x", Kind: "teleport", Payload: []byte(`{}`)}); err == nil || !strings.Contains(err.Error(), "unknown outbox event kind") {
		t.Fatalf("unknown kind: %v", err)
	}
	if calls, _ := pub.snapshot(); calls != 0 {
		t.Fatal("unknown kind published")
	}
}

// failingAdd is a store whose outbox insert fails.
type failingAdd struct{ *store.Memory }

func (f *failingAdd) AddOutboxEvent(context.Context, *store.OutboxEvent) error {
	return errors.New("outbox down")
}

// TestOutboxErrorIsTruncated: a failed attempt stores at most 1 KiB of the error.
func TestOutboxErrorIsTruncated(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	clk := newFakeClock()
	long := publisherFunc(func(context.Context, revocation.Event) error { return errors.New(strings.Repeat("x", 4096)) })
	svc, _ := revocation.NewService(st, revocation.Options{Publisher: long, Clock: clk.Now})
	ctx := context.Background()
	res, err := svc.Release(ctx, "dev-00000000000000aa", testutil.Tenant, "svc-registry")
	if err != nil || res.Published {
		t.Fatalf("release %+v %v", res, err)
	}
	clk.Advance(time.Hour)
	got, err := st.ClaimOutbox(ctx, clk.Now(), time.Second, 10)
	if err != nil || len(got) != 1 || len(got[0].LastError) != 1024 || got[0].Attempts != 1 || got[0].Kind != store.OutboxKindDeviceRelease {
		t.Fatalf("claimed %+v %v", got, err)
	}
}

func TestRunDispatcherStopsWithContext(t *testing.T) {
	t.Parallel()
	svc, _ := revocation.NewService(store.NewMemory(), revocation.Options{Publisher: &scriptedPublisher{}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { svc.RunDispatcher(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunDispatcher did not stop")
	}
}

// TestReleaseFanOut: a device_release reuses the revocation delivery path,
// including DNS fan-out to every policy replica, signatures and per-replica
// acknowledgement tracking.
func TestReleaseFanOut(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	key := []byte("fanout-key")
	replicas := []*policyReplica{newPolicyReplica(t, 0, key), newPolicyReplica(t, 1, key), newPolicyReplica(t, 0, key)}
	var addrs []string
	for _, r := range replicas {
		addrs = append(addrs, addrOf(t, r.URL))
	}
	pub, err := revocation.NewHTTPPublisher("http://policy-headless.ironmesh.svc:8081", "tok", key, &http.Client{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pub.Resolve = func(context.Context, string, string) ([]string, error) { return addrs, nil }
	clk := newFakeClock()
	svc, _ := revocation.NewService(p.Store, revocation.Options{Publisher: pub, Clock: clk.Now, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	ctx := context.Background()

	res, err := svc.Release(ctx, dev.ID, testutil.Tenant, "svc-registry")
	if err != nil {
		t.Fatal(err)
	}
	if res.Published || !strings.Contains(res.PublishError, "1 of 3 policy endpoints") {
		t.Fatalf("one replica failed, the release must stay pending: %+v", res)
	}
	clk.Advance(revocation.DefaultBaseBackoff)
	if n, err := svc.Dispatcher().ProcessDue(ctx); err != nil || n != 1 {
		t.Fatalf("retry delivered %d %v", n, err)
	}
	for i, r := range replicas {
		evs, hosts := r.received()
		if len(evs) != 1 || !evs[0].IsRelease() || evs[0].EventID != res.EventID || evs[0].DeviceID != dev.ID || evs[0].TenantID != testutil.Tenant {
			t.Fatalf("replica %d received %+v", i, evs)
		}
		if hosts[0] != "policy-headless.ironmesh.svc:8081" {
			t.Fatalf("replica %d Host %q", i, hosts[0])
		}
	}
	if replicas[0].requests.Load() != 1 || replicas[1].requests.Load() != 2 || replicas[2].requests.Load() != 1 {
		t.Fatal("acknowledged replicas were called again")
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 0 {
		t.Fatalf("pending %d", n)
	}
}
