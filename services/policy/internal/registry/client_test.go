package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const dev = "dev-8f3a1c2b9d4e5f60"

type recorder struct {
	mu      sync.Mutex
	results []string
}

func (r *recorder) hook(res string) {
	r.mu.Lock()
	r.results = append(r.results, res)
	r.mu.Unlock()
}

func (r *recorder) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.results...)
}

func TestNewValidation(t *testing.T) {
	if _, err := New("registry:8000", "t"); err == nil {
		t.Error("expected error for URL without scheme")
	}
	if _, err := New("mailto:x", "t"); err == nil {
		t.Error("expected error for unsupported scheme")
	}
	c, err := New("http://registry:8000/", "t", WithTimeout(0), WithCacheTTL(0), WithMaxEntries(0), WithClock(nil), WithLookupHook(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.timeout != 2*time.Second || c.ttl != 30*time.Second || c.maxEntries != 100000 || c.now == nil || c.onLookup == nil {
		t.Errorf("zero options should keep defaults: %+v", c)
	}
}

func TestLifecycleHappyPathAndCache(t *testing.T) {
	var calls int32
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_id":"` + dev + `","tenant_id":"7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11","state":"Active","assurance_level":"hardware"}`))
	}))
	defer srv.Close()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	rec := &recorder{}
	c, err := New(srv.URL, "tok", WithClock(clock), WithLookupHook(rec.hook), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	lc, err := c.Lifecycle(context.Background(), dev)
	if err != nil {
		t.Fatalf("Lifecycle: %v", err)
	}
	if lc.State != StateActive || !lc.MayConnect() || lc.TenantID == "" || lc.DeviceID != dev {
		t.Errorf("unexpected lifecycle %+v", lc)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPath != "/internal/v1/devices/"+dev+"/lifecycle" {
		t.Errorf("path = %q", gotPath)
	}

	// Second call within TTL is served from cache.
	if _, err := c.Lifecycle(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (cached)", calls)
	}

	// After 30s the entry expires.
	mu.Lock()
	now = now.Add(31 * time.Second)
	mu.Unlock()
	if _, err := c.Lifecycle(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (expired)", calls)
	}

	// Invalidate forces a refetch.
	c.Invalidate(dev)
	if _, err := c.Lifecycle(context.Background(), dev); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (invalidated)", calls)
	}
	want := []string{"ok", "cache", "ok", "ok"}
	if got := rec.get(); len(got) != len(want) {
		t.Errorf("hook results = %v, want %v", got, want)
	}
}

func TestLifecycleNotFoundIsCached(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "")
	for i := 0; i < 2; i++ {
		if _, err := c.Lifecycle(context.Background(), dev); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestLifecycleErrorsAreNotCached(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch n {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			_, _ = w.Write([]byte(`{not json`))
		case 3:
			_, _ = w.Write([]byte(`{"device_id":"dev-0000000000000000","state":"active"}`))
		default:
			_, _ = w.Write([]byte(`{"state":"provisioned"}`))
		}
	}))
	defer srv.Close()
	rec := &recorder{}
	c, _ := New(srv.URL, "", WithLookupHook(rec.hook))

	if _, err := c.Lifecycle(context.Background(), dev); err == nil {
		t.Fatal("expected error for 500")
	}
	if _, err := c.Lifecycle(context.Background(), dev); err == nil {
		t.Fatal("expected error for bad JSON")
	}
	if _, err := c.Lifecycle(context.Background(), dev); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("err = %v, want ErrInconsistent", err)
	}
	lc, err := c.Lifecycle(context.Background(), dev)
	if err != nil {
		t.Fatalf("4th call: %v", err)
	}
	if lc.DeviceID != dev || lc.State != StateProvisioned || !lc.MayConnect() {
		t.Errorf("lifecycle = %+v", lc)
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 4", calls)
	}
	got := rec.get()
	if len(got) != 4 || got[0] != "error" || got[1] != "error" || got[2] != "error" || got[3] != "ok" {
		t.Errorf("hook results = %v", got)
	}
}

func TestLifecycleTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c, _ := New(srv.URL, "", WithTimeout(50*time.Millisecond))
	start := time.Now()
	_, err := c.Lifecycle(context.Background(), dev)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("lookup took %v, timeout not enforced", elapsed)
	}
}

func TestLifecycleEmptyID(t *testing.T) {
	c, _ := New("http://registry", "")
	if _, err := c.Lifecycle(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestCacheBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state":"active"}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "", WithMaxEntries(3))
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if _, err := c.Lifecycle(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	n := len(c.cache)
	c.mu.Unlock()
	if n > 3 {
		t.Errorf("cache holds %d entries, want <= 3", n)
	}
}

func TestKnownStateAndMayConnect(t *testing.T) {
	for _, s := range []string{StateManufactured, StateProvisioned, StateActive, StateQuarantined, StateDecommissioned} {
		if !KnownState(s) {
			t.Errorf("KnownState(%q) = false", s)
		}
	}
	if KnownState("retired") {
		t.Error("KnownState(retired) should be false")
	}
	for s, want := range map[string]bool{StateManufactured: false, StateProvisioned: true, StateActive: true, StateQuarantined: false, StateDecommissioned: false, "": false} {
		if got := (Lifecycle{State: s}).MayConnect(); got != want {
			t.Errorf("MayConnect(%q) = %v, want %v", s, got, want)
		}
	}
}
