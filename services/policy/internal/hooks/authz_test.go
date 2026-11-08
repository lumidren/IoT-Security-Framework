package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
)

func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	e, err := engine.New(context.Background(), engine.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type authzEnv struct {
	authz      *Authz
	identities *IdentityCache
	m          *metrics.Metrics
	mu         sync.Mutex
	now        time.Time
}

func (e *authzEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *authzEnv) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func newAuthzEnv(t *testing.T, ev Evaluator, mutate func(*AuthzConfig)) *authzEnv {
	t.Helper()
	env := &authzEnv{now: fixedNow}
	if ev == nil {
		ev = newEngine(t)
	}
	env.identities = NewIdentityCache(time.Hour, 100, env.clock)
	env.m = metrics.New(prometheus.NewRegistry())
	cfg := AuthzConfig{
		Engine:     ev,
		Identities: env.identities,
		Metrics:    env.m,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:      env.clock,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := NewAuthz(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env.authz = a
	return env
}

func devAuthz(action, topic string, qos int, retain bool) AuthzRequest {
	return AuthzRequest{
		ClientID: dev, Username: dev, Topic: topic, Action: action, QoS: FlexInt(qos), Retain: FlexBool(retain),
		ClientAttrs: engine.Attrs{TenantID: tenant, DeviceID: dev, Kind: "device"},
	}
}

func own(class string) string { return "im/v1/" + tenant + "/" + dev + "/" + class }

type failingEvaluator struct{}

func (failingEvaluator) Evaluate(context.Context, engine.Input) (engine.Decision, error) {
	return engine.Decision{}, errors.New("boom")
}

func TestNewAuthzValidation(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	if _, err := NewAuthz(AuthzConfig{Metrics: m}); err == nil {
		t.Error("missing engine should fail")
	}
	if _, err := NewAuthz(AuthzConfig{Engine: failingEvaluator{}}); err == nil {
		t.Error("missing metrics should fail")
	}
	a, err := NewAuthz(AuthzConfig{Engine: failingEvaluator{}, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	if a.log == nil || a.maxBody != 64<<10 || a.cache.ttl != 10*time.Second || a.cache.max != 100000 {
		t.Errorf("defaults not applied: %+v cache=%+v", a, a.cache)
	}
}

func TestDecideAllowDenyAndCache(t *testing.T) {
	env := newAuthzEnv(t, nil, nil)
	ctx := context.Background()

	allow, reason := env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 1, false))
	if !allow || reason != "policy" {
		t.Fatalf("own telemetry = %v %s", allow, reason)
	}
	allow, reason = env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 1, false))
	if !allow || reason != "cached" {
		t.Fatalf("second call should hit the cache: %v %s", allow, reason)
	}
	if hits := testutil.ToFloat64(env.m.AuthzCache.WithLabelValues("hit")); hits != 1 {
		t.Errorf("cache hits = %v", hits)
	}

	// QoS and retain are part of the key: a QoS 2 publish must not reuse the QoS 1 allow.
	allow, reason = env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 2, false))
	if allow || reason != "qos_too_high" {
		t.Fatalf("qos 2 = %v %s", allow, reason)
	}
	allow, reason = env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 1, true))
	if allow || reason != "retain_not_allowed" {
		t.Fatalf("retain = %v %s", allow, reason)
	}
	allow, reason = env.authz.Decide(ctx, devAuthz("publish", "im/v1/"+otherTenant+"/"+dev+"/telemetry", 1, false))
	if allow || reason != "not_owner" {
		t.Fatalf("cross tenant = %v %s", allow, reason)
	}

	env.advance(11 * time.Second)
	if _, reason := env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 1, false)); reason != "policy" {
		t.Errorf("entry should have expired after TTL, reason = %s", reason)
	}
	env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 1, false))
	env.authz.FlushCache()
	if _, reason := env.authz.Decide(ctx, devAuthz("publish", own("telemetry"), 1, false)); reason != "policy" {
		t.Errorf("flush should drop entries, reason = %s", reason)
	}
	if got := testutil.ToFloat64(env.m.AuthzDecisions.WithLabelValues("allow", "publish")); got < 3 {
		t.Errorf("allow publish decisions = %v", got)
	}
	if got := testutil.ToFloat64(env.m.AuthzDecisions.WithLabelValues("deny", "publish")); got != 3 {
		t.Errorf("deny publish decisions = %v", got)
	}
}

func TestDecideIdentityResolution(t *testing.T) {
	env := newAuthzEnv(t, nil, nil)
	ctx := context.Background()

	// Flat attributes are accepted when the nested object is absent.
	flat := AuthzRequest{ClientID: dev, Topic: own("cmd/req"), Action: "subscribe", QoS: 1, TenantID: tenant, DeviceID: dev, Kind: "device"}
	if allow, reason := env.authz.Decide(ctx, flat); !allow {
		t.Errorf("flat attrs = %v %s", allow, reason)
	}

	// Without any attrs the identity cache (populated at authn) is consulted.
	bare := AuthzRequest{ClientID: dev, Topic: own("telemetry"), Action: "publish", QoS: 1}
	if allow, reason := env.authz.Decide(ctx, bare); allow || reason != "unknown_identity" {
		t.Errorf("unknown identity = %v %s", allow, reason)
	}
	env.identities.Put(dev, engine.Attrs{TenantID: tenant, DeviceID: dev, Kind: "device"})
	if allow, reason := env.authz.Decide(ctx, bare); !allow {
		t.Errorf("identity cache fallback = %v %s", allow, reason)
	}

	// Attributes claiming another device are rejected before evaluation.
	mismatch := devAuthz("publish", own("telemetry"), 1, false)
	mismatch.ClientAttrs.DeviceID = otherDev
	if allow, reason := env.authz.Decide(ctx, mismatch); allow || reason != "attrs_mismatch" {
		t.Errorf("attrs mismatch = %v %s", allow, reason)
	}

	if allow, reason := env.authz.Decide(ctx, devAuthz("read", own("telemetry"), 1, false)); allow || reason != "bad_action" {
		t.Errorf("bad action = %v %s", allow, reason)
	}
	if allow, reason := env.authz.Decide(ctx, devAuthz("publish", "", 1, false)); allow || reason != "bad_request" {
		t.Errorf("empty topic = %v %s", allow, reason)
	}
	if got := testutil.ToFloat64(env.m.AuthzDecisions.WithLabelValues("deny", "other")); got != 1 {
		t.Errorf("deny other = %v", got)
	}

	noIdentities := newAuthzEnv(t, nil, func(c *AuthzConfig) { c.Identities = nil })
	if allow, reason := noIdentities.authz.Decide(ctx, bare); allow || reason != "unknown_identity" {
		t.Errorf("no identity cache = %v %s", allow, reason)
	}
}

func TestDecideEvaluatorErrorIsDenyAndNotCached(t *testing.T) {
	env := newAuthzEnv(t, failingEvaluator{}, nil)
	for i := 0; i < 2; i++ {
		allow, reason := env.authz.Decide(context.Background(), devAuthz("publish", own("telemetry"), 1, false))
		if allow || reason != "eval_error" {
			t.Fatalf("call %d = %v %s", i, allow, reason)
		}
	}
	if env.authz.cache.size() != 0 {
		t.Error("errors must not be cached")
	}
}

func TestDecisionCacheBound(t *testing.T) {
	c := newDecisionCache(time.Minute, 2, func() time.Time { return fixedNow })
	for i, topic := range []string{"a", "b", "c", "d"} {
		c.put(cacheKey{clientID: dev, topic: topic}, i%2 == 0)
	}
	if c.size() > 2 {
		t.Errorf("size = %d, want <= 2", c.size())
	}
	if _, ok := c.get(cacheKey{clientID: dev, topic: "d"}); !ok {
		t.Error("latest entry should be present")
	}
}

func TestFlexTypes(t *testing.T) {
	for raw, want := range map[string]int{`1`: 1, `"2"`: 2, `""`: 0, `null`: 0, `0.0`: 0, `" 1 "`: 1} {
		var f FlexInt
		if err := json.Unmarshal([]byte(raw), &f); err != nil || int(f) != want {
			t.Errorf("FlexInt(%s) = %d, %v; want %d", raw, f, err, want)
		}
	}
	var f FlexInt
	if err := json.Unmarshal([]byte(`"one"`), &f); err == nil {
		t.Error("FlexInt should reject non-numeric strings")
	}
	for raw, want := range map[string]bool{`true`: true, `false`: false, `"true"`: true, `"FALSE"`: false, `"1"`: true, `"0"`: false, `""`: false, `null`: false} {
		var b FlexBool
		if err := json.Unmarshal([]byte(raw), &b); err != nil || bool(b) != want {
			t.Errorf("FlexBool(%s) = %v, %v; want %v", raw, b, err, want)
		}
	}
	var b FlexBool
	if err := json.Unmarshal([]byte(`"maybe"`), &b); err == nil {
		t.Error("FlexBool should reject unknown strings")
	}
}

func TestAuthzServeHTTP(t *testing.T) {
	env := newAuthzEnv(t, nil, nil)
	srv := httptest.NewServer(env.authz)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/emqx/authz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", resp.StatusCode)
	}
	post := func(body string) (int, string) {
		t.Helper()
		resp, err := http.Post(srv.URL+"/emqx/authz", "application/json", bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out AuthzResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out.Result
	}
	if status, result := post("{bad"); status != http.StatusOK || result != "deny" {
		t.Errorf("bad json: %d %s", status, result)
	}
	// EMQX renders qos/retain as strings; nested client_attrs.
	body := `{"clientid":"` + dev + `","username":"` + dev + `","topic":"` + own("telemetry") + `","action":"publish","qos":"1","retain":"false","client_attrs":{"tenant_id":"` + tenant + `","device_id":"` + dev + `","kind":"device"}}`
	if status, result := post(body); status != http.StatusOK || result != "allow" {
		t.Errorf("string-typed allow: %d %s", status, result)
	}
	body = `{"clientid":"` + dev + `","topic":"` + own("telemetry") + `","action":"publish","qos":1,"retain":true,"client_attrs":{"tenant_id":"` + tenant + `","device_id":"` + dev + `","kind":"device"}}`
	if status, result := post(body); status != http.StatusOK || result != "deny" {
		t.Errorf("retain deny: %d %s", status, result)
	}
	body = `{"clientid":"svc-bridge","topic":"$share/bridge/im/v1/#","action":"subscribe","qos":"1","retain":"","kind":"service"}`
	if status, result := post(body); status != http.StatusOK || result != "allow" {
		t.Errorf("bridge flat attrs: %d %s", status, result)
	}
	if status, result := post(`{"clientid":"` + dev + `","topic":"x","action":"publish","qos":"many"}`); status != http.StatusOK || result != "deny" {
		t.Errorf("unparseable qos: %d %s", status, result)
	}
}
