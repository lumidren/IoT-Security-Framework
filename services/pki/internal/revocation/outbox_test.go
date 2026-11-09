package revocation_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// scriptedPublisher fails the first `failures` publishes.
type scriptedPublisher struct {
	mu       sync.Mutex
	failures int
	events   []revocation.Event
	calls    int
}

func (s *scriptedPublisher) Publish(_ context.Context, ev revocation.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failures > 0 {
		s.failures--
		return errors.New("policy unavailable")
	}
	s.events = append(s.events, ev)
	return nil
}

func (s *scriptedPublisher) snapshot() (int, []revocation.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]revocation.Event(nil), s.events...)
}

func TestDispatcherBackoff(t *testing.T) {
	t.Parallel()
	d := revocation.NewDispatcher(store.NewMemory(), revocation.DispatcherOptions{})
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := d.Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %s want %s", i+1, got, w)
		}
	}
	if d.Backoff(0) != 500*time.Millisecond || d.Backoff(1000) != revocation.DefaultMaxBackoff {
		t.Error("backoff bounds")
	}
	if d.Lease() != revocation.DefaultAttemptTimeout+5*time.Second {
		t.Errorf("lease %s", d.Lease())
	}
	// A cap below the base is raised to the base.
	d = revocation.NewDispatcher(store.NewMemory(), revocation.DispatcherOptions{BaseBackoff: 2 * time.Second, MaxBackoff: time.Second, Lease: time.Minute})
	if d.Backoff(1) != 2*time.Second || d.Backoff(5) != 2*time.Second || d.Lease() != time.Minute {
		t.Error("cap normalisation")
	}
}

// TestDispatcherRetriesWithBackoffUntilAcked drives the outbox with a fake
// clock: the first delivery (inline in Revoke) and two retries fail, every
// retry waits for its backoff, and the fourth attempt is acknowledged.
func TestDispatcherRetriesWithBackoffUntilAcked(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	clk := newFakeClock()
	pub := &scriptedPublisher{failures: 3}
	m := metrics.New()
	svc, err := revocation.NewService(p.Store, revocation.Options{Publisher: pub, Metrics: m, Clock: clk.Now, Logger: p.Logger})
	if err != nil {
		t.Fatal(err)
	}
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	ctx := context.Background()
	res, err := svc.Revoke(ctx, ca.FormatSerial(dev.Cert.SerialNumber), "superseded", "test")
	if err != nil || res.Published || res.PublishError == "" {
		t.Fatalf("first attempt must fail but the revocation must succeed: %+v %v", res, err)
	}
	d := svc.Dispatcher()
	steps := []struct {
		advance   time.Duration
		delivered int
		calls     int
	}{
		{0, 0, 1},                            // not due yet (backoff 500 ms)
		{499 * time.Millisecond, 0, 1},       // still not due
		{time.Millisecond, 0, 2},             // attempt 2 fails -> backoff 1 s
		{999 * time.Millisecond, 0, 2},       // not due
		{time.Millisecond, 0, 3},             // attempt 3 fails -> backoff 2 s
		{2 * time.Second, 1, 4},              // attempt 4 acknowledged
		{time.Hour, 0, 4},                    // nothing left
		{revocation.DefaultMaxBackoff, 0, 4}, // still nothing
	}
	for i, st := range steps {
		clk.Advance(st.advance)
		n, err := d.ProcessDue(ctx)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		calls, _ := pub.snapshot()
		if n != st.delivered || calls != st.calls {
			t.Fatalf("step %d: delivered %d calls %d, want %d/%d", i, n, calls, st.delivered, st.calls)
		}
	}
	_, events := pub.snapshot()
	if len(events) != 1 || events[0].EventID != res.EventID || events[0].DeviceDeny || events[0].Reason != "superseded" {
		t.Fatalf("delivered events %+v", events)
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 0 || promtest.ToFloat64(m.RevocationOutboxPending) != 0 {
		t.Fatalf("pending after ack: %d", n)
	}
	if promtest.ToFloat64(m.RevocationPublishAttempts.WithLabelValues("error")) != 3 || promtest.ToFloat64(m.RevocationPublishAttempts.WithLabelValues("ok")) != 1 {
		t.Fatal("attempt metrics")
	}
	// End-to-end latency covers the retries: 500 ms + 1 s + 2 s.
	if promtest.CollectAndCount(m.RevocationLatency) != 1 {
		t.Fatal("latency not observed")
	}
	if sum := histogramSum(t, m, "ironmesh_revocation_latency_seconds"); sum != 3.5 {
		t.Fatalf("latency sum %v want 3.5", sum)
	}
}

func histogramSum(t *testing.T, m *metrics.Metrics, name string) float64 {
	t.Helper()
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetHistogram().GetSampleSum()
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

func TestDispatcherRunLoop(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	pub := &scriptedPublisher{}
	tick := make(chan time.Time)
	clk := newFakeClock()
	d := revocation.NewDispatcher(st, revocation.DispatcherOptions{Publisher: pub, Clock: clk.Now, After: func(time.Duration) <-chan time.Time { return tick }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()

	enqueue := func(id string) {
		payload, _ := json.Marshal(revocation.Event{EventID: id, Serial: "0a", DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: testutil.Tenant, Reason: "superseded", RevokedAt: clk.Now()})
		rev := &store.Revocation{Serial: "s-" + id, DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: testutil.Tenant}
		if err := st.AddRevocationWithEvent(ctx, rev, &store.OutboxEvent{EventID: id, TenantID: testutil.Tenant, Payload: payload, CreatedAt: clk.Now(), NextAttemptAt: clk.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	waitDelivered := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, evs := pub.snapshot(); len(evs) >= n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("not delivered: want %d", n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	enqueue("e1")
	tick <- clk.Now() // timer fires -> next pass
	waitDelivered(1)
	enqueue("e2")
	d.Notify()
	d.Notify() // coalesced
	waitDelivered(2)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// TestOutboxRestartRecovery: events left pending by a process that died
// (after a failed attempt, or in the middle of one) are delivered by the
// next process sharing the store.
func TestOutboxRestartRecovery(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	clk := newFakeClock()
	ctx := context.Background()
	down := &scriptedPublisher{failures: 1000}
	first, _ := revocation.NewService(p.Store, revocation.Options{Publisher: down, Clock: clk.Now, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	res, err := first.Revoke(ctx, ca.FormatSerial(dev.Cert.SerialNumber), "keyCompromise", "test")
	if err != nil || res.Published {
		t.Fatalf("revoke: %+v %v", res, err)
	}
	// Crash in the middle of a delivery: the row is written but no attempt
	// was recorded; it carries the writer's lease.
	dev2 := p.NewOperationalDevice(t, testutil.Tenant)
	payload, _ := json.Marshal(revocation.Event{EventID: "crashed", Serial: ca.FormatSerial(dev2.Cert.SerialNumber), DeviceID: dev2.ID, TenantID: testutil.Tenant, Reason: "superseded", RevokedAt: clk.Now()})
	lease := first.Dispatcher().Lease()
	if err := p.Store.AddRevocationWithEvent(ctx, &store.Revocation{Serial: ca.FormatSerial(dev2.Cert.SerialNumber), DeviceID: dev2.ID, TenantID: testutil.Tenant},
		&store.OutboxEvent{EventID: "crashed", TenantID: testutil.Tenant, Payload: payload, CreatedAt: clk.Now(), NextAttemptAt: clk.Now().Add(lease)}); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 2 {
		t.Fatalf("pending %d", n)
	}

	// "Restart": a new service on the same store with a reachable policy.
	up := &scriptedPublisher{}
	m := metrics.New()
	second, _ := revocation.NewService(p.Store, revocation.Options{Publisher: up, Metrics: m, Clock: clk.Now, Logger: p.Logger})
	clk.Advance(time.Second) // past the backoff of the failed event
	if n, err := second.Dispatcher().ProcessDue(ctx); err != nil || n != 1 {
		t.Fatalf("first pass delivered %d (%v), want the failed event only", n, err)
	}
	clk.Advance(lease)
	if n, err := second.Dispatcher().ProcessDue(ctx); err != nil || n != 1 {
		t.Fatalf("second pass delivered %d (%v), want the crashed event after its lease", n, err)
	}
	_, events := up.snapshot()
	if len(events) != 2 || events[0].EventID != res.EventID || events[1].EventID != "crashed" {
		t.Fatalf("redelivered %+v", events)
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 0 || promtest.ToFloat64(m.RevocationOutboxPending) != 0 {
		t.Fatalf("pending after recovery %d", n)
	}
}

// policyReplica is a Policy replica stub that can fail its first requests.
type policyReplica struct {
	*httptest.Server
	failures atomic.Int32
	requests atomic.Int32
	mu       sync.Mutex
	events   []revocation.Event
	hosts    []string
}

func newPolicyReplica(t *testing.T, failures int32, key []byte) *policyReplica {
	t.Helper()
	r := &policyReplica{}
	r.failures.Store(failures)
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.requests.Add(1)
		body, _ := io.ReadAll(req.Body)
		if r.failures.Add(-1) >= 0 {
			http.Error(w, "restarting", http.StatusServiceUnavailable)
			return
		}
		if req.URL.Path != revocation.PublishPath || !revocation.VerifySignature(key, body, req.Header.Get(revocation.HeaderSignature)) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var ev revocation.Event
		_ = json.Unmarshal(body, &ev)
		r.mu.Lock()
		r.events = append(r.events, ev)
		r.hosts = append(r.hosts, req.Host)
		r.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *policyReplica) received() ([]revocation.Event, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]revocation.Event(nil), r.events...), append([]string(nil), r.hosts...)
}

func addrOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestFanOutToEveryReplica: with fan-out the event goes to all three
// replicas behind the headless Service name; one replica fails the first
// delivery, so the outbox row stays pending until a retry reaches it, and
// replicas that already acknowledged are not called again.
func TestFanOutToEveryReplica(t *testing.T) {
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
	var resolvedHost, resolvedPort string
	pub.Resolve = func(_ context.Context, host, port string) ([]string, error) {
		resolvedHost, resolvedPort = host, port
		return addrs, nil
	}
	m := metrics.New()
	pub.OnEndpoint = func(result string) { m.RevocationPublishEndpoints.WithLabelValues(result).Inc() }
	clk := newFakeClock()
	svc, _ := revocation.NewService(p.Store, revocation.Options{Publisher: pub, Metrics: m, Clock: clk.Now, Logger: p.Logger})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	ctx := context.Background()

	res, err := svc.Revoke(ctx, ca.FormatSerial(dev.Cert.SerialNumber), "superseded", "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Published || !strings.Contains(res.PublishError, "1 of 3 policy endpoints") {
		t.Fatalf("one replica failed, the event must stay pending: %+v", res)
	}
	if resolvedHost != "policy-headless.ironmesh.svc" || resolvedPort != "8081" {
		t.Fatalf("resolved %q %q", resolvedHost, resolvedPort)
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 1 {
		t.Fatalf("pending %d", n)
	}
	clk.Advance(revocation.DefaultBaseBackoff)
	if n, err := svc.Dispatcher().ProcessDue(ctx); err != nil || n != 1 {
		t.Fatalf("retry delivered %d %v", n, err)
	}
	for i, r := range replicas {
		evs, hosts := r.received()
		if len(evs) != 1 || evs[0].EventID != res.EventID {
			t.Fatalf("replica %d received %+v", i, evs)
		}
		if hosts[0] != "policy-headless.ironmesh.svc:8081" {
			t.Fatalf("replica %d saw Host %q, want the service name", i, hosts[0])
		}
	}
	if replicas[0].requests.Load() != 1 || replicas[1].requests.Load() != 2 || replicas[2].requests.Load() != 1 {
		t.Fatalf("acknowledged replicas were called again: %d %d %d", replicas[0].requests.Load(), replicas[1].requests.Load(), replicas[2].requests.Load())
	}
	if n, _ := p.Store.CountPendingOutbox(ctx); n != 0 {
		t.Fatalf("pending after all replicas acked: %d", n)
	}
	if promtest.ToFloat64(m.RevocationPublishEndpoints.WithLabelValues("ok")) != 3 || promtest.ToFloat64(m.RevocationPublishEndpoints.WithLabelValues("error")) != 1 {
		t.Fatal("endpoint metrics")
	}
}

func TestFanOutTLSKeepsServerName(t *testing.T) {
	t.Parallel()
	key := []byte("k")
	var host atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host.Store(r.Host + "|" + r.TLS.ServerName)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	// httptest's certificate is valid for example.com: verification only
	// succeeds if the original host name is used as SNI / verify name.
	pub, _ := revocation.NewHTTPPublisher("https://example.com", "", key, srv.Client())
	pub.Resolve = func(context.Context, string, string) ([]string, error) { return []string{addrOf(t, srv.URL)}, nil }
	ev := revocation.Event{EventID: "e1", Serial: "01", RevokedAt: time.Now()}
	if err := pub.Publish(context.Background(), ev); err != nil {
		t.Fatalf("publish over TLS: %v", err)
	}
	if got := host.Load(); got != "example.com|example.com" {
		t.Fatalf("host|sni = %v", got)
	}
	// A second event reuses the cached per-address client.
	ev.EventID = "e2"
	if err := pub.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}

func TestFanOutErrors(t *testing.T) {
	t.Parallel()
	ev := revocation.Event{EventID: "e1", Serial: "01", RevokedAt: time.Now()}
	pub, _ := revocation.NewHTTPPublisher("http://policy:8081", "", []byte("k"), nil)
	pub.Resolve = func(context.Context, string, string) ([]string, error) { return nil, errors.New("SERVFAIL") }
	if err := pub.Publish(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("resolver error: %v", err)
	}
	pub.Resolve = func(context.Context, string, string) ([]string, error) { return nil, nil }
	if err := pub.Publish(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "no policy endpoints") {
		t.Fatalf("empty resolution: %v", err)
	}
	// Default ports by scheme.
	var ports []string
	for _, raw := range []string{"http://policy", "https://policy"} {
		p, _ := revocation.NewHTTPPublisher(raw, "", []byte("k"), &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("unused")
		})})
		p.Resolve = func(_ context.Context, _, port string) ([]string, error) {
			ports = append(ports, port)
			return nil, nil
		}
		_ = p.Publish(context.Background(), ev)
	}
	if strings.Join(ports, ",") != "80,443" {
		t.Fatalf("default ports %v", ports)
	}
	bad := &revocation.HTTPPublisher{URL: "http://[::1", HMACKey: []byte("k"), Client: http.DefaultClient, Resolve: func(context.Context, string, string) ([]string, error) { return nil, nil }}
	if err := bad.Publish(context.Background(), ev); err == nil {
		t.Fatal("unparsable URL accepted")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDNSResolver(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := revocation.DNSResolver(nil)(ctx, "localhost", "8081")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("localhost: %v %v", addrs, err)
	}
	for _, a := range addrs {
		host, port, err := net.SplitHostPort(a)
		if err != nil || port != "8081" || !net.ParseIP(host).IsLoopback() {
			t.Fatalf("address %q", a)
		}
	}
	if _, err := revocation.DNSResolver(&net.Resolver{PreferGo: true})(ctx, "bad host name with spaces", "1"); err == nil {
		t.Fatal("invalid host resolved")
	}
}

// failingOutbox wraps a store and fails selected outbox calls.
type failingOutbox struct {
	*store.Memory
	claimErr, recordErr, ackErr, countErr error
}

func (f *failingOutbox) ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*store.OutboxEvent, error) {
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	return f.Memory.ClaimOutbox(ctx, now, lease, limit)
}

func (f *failingOutbox) RecordOutboxAttempt(ctx context.Context, id string, n int, next time.Time, e string) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	return f.Memory.RecordOutboxAttempt(ctx, id, n, next, e)
}

func (f *failingOutbox) AckOutbox(ctx context.Context, id string, at time.Time) error {
	if f.ackErr != nil {
		return f.ackErr
	}
	return f.Memory.AckOutbox(ctx, id, at)
}

func (f *failingOutbox) CountPendingOutbox(ctx context.Context) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return f.Memory.CountPendingOutbox(ctx)
}

func TestDispatcherFailurePaths(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("db down")
	st := &failingOutbox{Memory: store.NewMemory(), claimErr: boom, countErr: boom}
	pub := &scriptedPublisher{}
	d := revocation.NewDispatcher(st, revocation.DispatcherOptions{Publisher: pub})
	if _, err := d.ProcessDue(ctx); !errors.Is(err, boom) {
		t.Fatalf("claim error: %v", err)
	}

	// Undecodable payload: recorded as a failed attempt, never published.
	st.claimErr, st.countErr = nil, nil
	_ = st.AddRevocationWithEvent(ctx, &store.Revocation{Serial: "01"}, &store.OutboxEvent{EventID: "bad", Payload: []byte("{"), NextAttemptAt: time.Now().Add(-time.Second)})
	if n, err := d.ProcessDue(ctx); err != nil || n != 0 {
		t.Fatalf("bad payload delivered: %d %v", n, err)
	}
	if calls, _ := pub.snapshot(); calls != 0 {
		t.Fatal("bad payload published")
	}

	// Bookkeeping failures are logged; delivery still reports the outcome.
	st.ackErr, st.recordErr = boom, boom
	ok := &store.OutboxEvent{EventID: "ok", Payload: []byte(`{"event_id":"ok"}`)}
	if err := d.Attempt(ctx, ok); err != nil {
		t.Fatalf("ack failure must not turn a delivery into an error: %v", err)
	}
	pub.failures = 1
	if err := d.Attempt(ctx, ok); err == nil {
		t.Fatal("failed delivery reported as success")
	}

	// A second attempt of an in-flight event is refused.
	block := make(chan struct{})
	started := make(chan struct{})
	slow := revocation.NewDispatcher(store.NewMemory(), revocation.DispatcherOptions{Publisher: publisherFunc(func(context.Context, revocation.Event) error {
		close(started)
		<-block
		return nil
	})})
	ev := &store.OutboxEvent{EventID: "slow", Payload: []byte(`{"event_id":"slow"}`)}
	errCh := make(chan error, 1)
	go func() { errCh <- slow.Attempt(ctx, ev) }()
	<-started
	if err := slow.Attempt(ctx, ev); !errors.Is(err, revocation.ErrInFlight) {
		t.Fatalf("concurrent attempt: %v", err)
	}
	close(block)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	// Cancelled context stops a pass between events.
	ctx2, cancel := context.WithCancel(ctx)
	cancel()
	mem := store.NewMemory()
	_ = mem.AddRevocationWithEvent(ctx, &store.Revocation{Serial: "02"}, &store.OutboxEvent{EventID: "x", Payload: []byte(`{}`)})
	if _, err := revocation.NewDispatcher(mem, revocation.DispatcherOptions{}).ProcessDue(ctx2); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled pass: %v", err)
	}
}

type publisherFunc func(context.Context, revocation.Event) error

func (f publisherFunc) Publish(ctx context.Context, ev revocation.Event) error { return f(ctx, ev) }

// TestSupersedeEventIsSerialScoped: the event emitted for a superseded
// certificate denies only that serial, while revoke-all denies the device.
func TestSupersedeEventIsSerialScoped(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	pub := &scriptedPublisher{}
	svc, _ := revocation.NewService(p.Store, revocation.Options{Publisher: pub, Logger: p.Logger})
	ctx := context.Background()
	old := p.NewOperationalDevice(t, testutil.Tenant)
	if _, err := svc.Revoke(ctx, ca.FormatSerial(old.Cert.SerialNumber), "superseded", "pki:supersede:x"); err != nil {
		t.Fatal(err)
	}
	other := p.NewOperationalDevice(t, testutil.Tenant)
	if _, err := svc.RevokeDevice(ctx, other.ID, "cessationOfOperation", "svc-registry"); err != nil {
		t.Fatal(err)
	}
	_, evs := pub.snapshot()
	if len(evs) != 2 || evs[0].DeviceDeny || !evs[1].DeviceDeny || evs[1].DeviceID != other.ID {
		t.Fatalf("events %+v", evs)
	}
	raw, _ := json.Marshal(evs[0])
	if !strings.Contains(string(raw), `"device_deny":false`) {
		t.Fatalf("device_deny must always be on the wire: %s", raw)
	}
}
