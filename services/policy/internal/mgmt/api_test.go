package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/auth"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/hooks"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
)

const (
	tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	dev    = "dev-8f3a1c2b9d4e5f60"
)

var fixedNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type env struct {
	t      *testing.T
	signer *auth.Signer
	engine *engine.Engine
	cache  *revocation.Cache
	authz  *hooks.Authz
	srv    *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	signer, err := auth.GenerateSigner("test")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := signer.PublicKeyPEM()
	verifier, err := auth.NewVerifier(pub, "policy", auth.WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := engine.New(context.Background(), engine.Options{StateDir: t.TempDir(), Clock: func() time.Time { return fixedNow }, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	cache := revocation.NewCache("", func() time.Time { return fixedNow })
	m := metrics.New(prometheus.NewRegistry())
	authz, err := hooks.NewAuthz(hooks.AuthzConfig{Engine: eng, Metrics: m, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	eng.OnSwap(authz.FlushCache)

	api, err := New(Config{Engine: eng, Revocations: cache, Guard: verifier.Guard(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api.Register(mux)
	mux.Handle("POST /emqx/authz", authz)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{t: t, signer: signer, engine: eng, cache: cache, authz: authz, srv: srv}
}

func (e *env) token(role string) string {
	e.t.Helper()
	tok, err := e.signer.Sign(map[string]any{"sub": "user-" + role, "aud": "policy", "role": role, "iat": fixedNow.Unix(), "exp": fixedNow.Add(5 * time.Minute).Unix(), "jti": fmt.Sprintf("%s-%d", role, time.Now().UnixNano()), "tenant_id": tenant})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) do(method, path, role string, body any) (*http.Response, []byte) {
	e.t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		e.t.Fatal(err)
	}
	if role != "" {
		req.Header.Set("Authorization", "Bearer "+e.token(role))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func decode(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("invalid JSON %q: %v", raw, err)
	}
}

func extendedPolicy(t *testing.T) string {
	t.Helper()
	src, _, err := engine.EmbeddedSources()
	if err != nil {
		t.Fatal(err)
	}
	return src + "\nallow if {\n\tis_bridge\n\taction == \"subscribe\"\n\tinput.topic == \"$share/bridge/im/v2/#\"\n\tqos <= 1\n}\n"
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("missing dependencies should fail")
	}
}

func TestAuthRejections(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		method, path, role string
		body               any
		want               int
	}{
		{"GET", "/v1/policy", "", nil, 401},
		{"GET", "/v1/policy", "viewer", nil, 403},
		{"GET", "/v1/policy", "operator", nil, 403},
		{"GET", "/v1/policy", "admin", nil, 200},
		{"GET", "/v1/policy", "owner", nil, 200},
		{"PUT", "/v1/policy", "admin", map[string]string{"rego": "x"}, 403},
		{"POST", "/v1/policy/evaluate", "viewer", nil, 403},
		{"POST", "/v1/policy/evaluate", "", nil, 401},
		{"GET", "/v1/policy/history", "", nil, 401},
		{"GET", "/v1/policy/history", "viewer", nil, 200},
		{"GET", "/v1/revocations", "", nil, 401},
		{"GET", "/v1/revocations", "viewer", nil, 200},
	}
	for _, tc := range cases {
		resp, raw := e.do(tc.method, tc.path, tc.role, tc.body)
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s as %q = %d (%s), want %d", tc.method, tc.path, tc.role, resp.StatusCode, raw, tc.want)
		}
		if tc.want == 401 || tc.want == 403 {
			if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("%s %s: content-type %q", tc.method, tc.path, ct)
			}
		}
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage token = %d", resp.StatusCode)
	}
	if resp, _ := e.do("DELETE", "/v1/policy", "owner", nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d", resp.StatusCode)
	}
}

func TestGetPolicy(t *testing.T) {
	e := newEnv(t)
	resp, raw := e.do("GET", "/v1/policy", "admin", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var doc policyDoc
	decode(t, raw, &doc)
	src, _, _ := engine.EmbeddedSources()
	if doc.Version != 1 || doc.UpdatedBy != engine.EmbeddedAuthor || doc.Rego != src || len(doc.SHA256) != 64 || !doc.UpdatedAt.Equal(fixedNow) {
		t.Errorf("policy = %+v", doc)
	}
}

func TestPutPolicyRejections(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name  string
		body  any
		want  int
		field string
	}{
		{"bad json", "{nope", 400, ""},
		{"missing rego", map[string]string{"message": "x"}, 422, "rego is required"},
		{"long message", map[string]string{"rego": "package ironmesh.mqtt", "message": strings.Repeat("m", 513)}, 422, "message"},
		{"syntax error", map[string]string{"rego": "package ironmesh.mqtt\nallow if {", "message": "oops"}, 422, "rego_parse_error"},
		{"wrong package", map[string]string{"rego": "package other\nallow := true"}, 422, "package must be"},
		{"invariants fail", map[string]string{"rego": "package ironmesh.mqtt\n\ndefault allow := false\n\nallow := true\n\ndecision := {\"allow\": allow, \"reasons\": set()}\n"}, 422, "invariant tests failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, raw := e.do("PUT", "/v1/policy", "owner", tc.body)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d: %s", resp.StatusCode, raw)
			}
			if tc.want == 422 {
				var prob struct {
					Errors []string `json:"errors"`
				}
				decode(t, raw, &prob)
				if len(prob.Errors) == 0 || !strings.Contains(strings.Join(prob.Errors, "\n"), tc.field) {
					t.Errorf("diagnostics %v do not mention %q", prob.Errors, tc.field)
				}
			}
		})
	}
	if e.engine.Current().Version != 1 {
		t.Error("rejected updates must not change the active version")
	}
	big := `{"rego":"` + strings.Repeat("#", engine.MaxSourceBytes+70<<10) + `"}`
	if resp, _ := e.do("PUT", "/v1/policy", "owner", big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d", resp.StatusCode)
	}
}

func TestPutPolicyHotSwapTakesEffectOnNextAuthzCall(t *testing.T) {
	e := newEnv(t)
	authzBody := `{"clientid":"svc-bridge","username":"svc-bridge","topic":"$share/bridge/im/v2/#","action":"subscribe","qos":1,"retain":false,"client_attrs":{"kind":"service"}}`
	authz := func() string {
		t.Helper()
		_, raw := e.do("POST", "/emqx/authz", "", authzBody)
		var out struct {
			Result string `json:"result"`
		}
		decode(t, raw, &out)
		return out.Result
	}
	if authz() != "deny" {
		t.Fatal("v2 filter must be denied before the update")
	}
	if authz() != "deny" {
		t.Fatal("cached deny expected")
	}

	resp, raw := e.do("PUT", "/v1/policy", "owner", map[string]string{"rego": extendedPolicy(t), "message": "allow v2 pilot"})
	if resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Version int    `json:"version"`
		SHA     string `json:"sha256_hex"`
	}
	decode(t, raw, &out)
	if out.Version != 2 || len(out.SHA) != 64 {
		t.Errorf("response = %+v", out)
	}
	if authz() != "allow" {
		t.Fatal("hot swap must take effect on the very next authz call (cache flushed)")
	}

	_, raw = e.do("GET", "/v1/policy", "admin", nil)
	var doc policyDoc
	decode(t, raw, &doc)
	if doc.Version != 2 || doc.UpdatedBy != "user-owner" || doc.SHA256 != out.SHA {
		t.Errorf("active policy = %+v", doc)
	}

	// Idempotent re-publish keeps version 2.
	resp, raw = e.do("PUT", "/v1/policy", "owner", map[string]string{"rego": extendedPolicy(t)})
	decode(t, raw, &out)
	if resp.StatusCode != 200 || out.Version != 2 {
		t.Errorf("idempotent PUT = %d %+v", resp.StatusCode, out)
	}
}

func TestEvaluate(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{"input": map[string]any{
		"clientid": dev, "username": dev, "tenant_id": tenant, "device_id": dev, "kind": "device",
		"topic": "im/v1/" + tenant + "/" + dev + "/telemetry", "action": "publish", "qos": 1, "retain": false,
	}}
	resp, raw := e.do("POST", "/v1/policy/evaluate", "operator", body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var out evaluateResponse
	decode(t, raw, &out)
	if out.Result != "allow" || out.EvaluatedVersion != 1 || len(out.Trace) == 0 || len(out.MatchedRules) == 0 || out.Reasons == nil {
		t.Errorf("evaluate = result:%s version:%d trace:%d rules:%d", out.Result, out.EvaluatedVersion, len(out.Trace), len(out.MatchedRules))
	}
	if !strings.Contains(strings.Join(out.MatchedRules, "\n"), "allow (") {
		t.Errorf("matched rules %v should name the allow rule", out.MatchedRules)
	}

	// String-typed qos/retain and a deny with reasons.
	body["input"].(map[string]any)["retain"] = "true"
	body["input"].(map[string]any)["qos"] = "1"
	_, raw = e.do("POST", "/v1/policy/evaluate", "operator", body)
	decode(t, raw, &out)
	if out.Result != "deny" || len(out.Reasons) == 0 {
		t.Errorf("retained telemetry = %+v", out)
	}

	// Dry-run is never cached: swapping the policy changes the answer immediately even though
	// the same input was just evaluated.
	v2 := map[string]any{"input": map[string]any{"clientid": "svc-bridge", "kind": "service", "topic": "$share/bridge/im/v2/#", "action": "subscribe", "qos": 1}}
	_, raw = e.do("POST", "/v1/policy/evaluate", "operator", v2)
	decode(t, raw, &out)
	if out.Result != "deny" {
		t.Fatalf("v2 before update = %s", out.Result)
	}
	if resp, raw := e.do("PUT", "/v1/policy", "owner", map[string]string{"rego": extendedPolicy(t)}); resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, raw)
	}
	_, raw = e.do("POST", "/v1/policy/evaluate", "operator", v2)
	decode(t, raw, &out)
	if out.Result != "allow" || out.EvaluatedVersion != 2 {
		t.Errorf("v2 after update = %+v", out)
	}

	for name, bad := range map[string]any{
		"bad json":       "{",
		"missing action": map[string]any{"input": map[string]any{"clientid": dev, "topic": "t"}},
		"missing topic":  map[string]any{"input": map[string]any{"clientid": dev, "action": "publish"}},
		"missing client": map[string]any{"input": map[string]any{"topic": "t", "action": "publish"}},
		"bad qos":        map[string]any{"input": map[string]any{"clientid": dev, "topic": "t", "action": "publish", "qos": 7}},
	} {
		resp, _ := e.do("POST", "/v1/policy/evaluate", "operator", bad)
		want := 422
		if name == "bad json" {
			want = 400
		}
		if resp.StatusCode != want {
			t.Errorf("%s = %d, want %d", name, resp.StatusCode, want)
		}
	}
}

func TestHistoryPagination(t *testing.T) {
	e := newEnv(t)
	src := extendedPolicy(t)
	for i, msg := range []string{"second", "third"} {
		if resp, raw := e.do("PUT", "/v1/policy", "owner", map[string]string{"rego": src + strings.Repeat("\n", i+1) + "# " + msg + "\n", "message": msg}); resp.StatusCode != 200 {
			t.Fatalf("PUT %s = %d: %s", msg, resp.StatusCode, raw)
		}
	}
	type page struct {
		Items      []historyItem `json:"items"`
		NextCursor *string       `json:"next_cursor"`
	}
	resp, raw := e.do("GET", "/v1/policy/history?limit=2", "viewer", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var p page
	decode(t, raw, &p)
	if len(p.Items) != 2 || p.Items[0].Version != 3 || p.Items[1].Version != 2 || p.NextCursor == nil {
		t.Fatalf("page 1 = %+v", p)
	}
	if p.Items[0].Message != "third" || p.Items[0].UpdatedBy != "user-owner" || len(p.Items[0].SHA256) != 64 {
		t.Errorf("item = %+v", p.Items[0])
	}
	resp, raw = e.do("GET", "/v1/policy/history?limit=2&cursor="+*p.NextCursor, "viewer", nil)
	decode(t, raw, &p)
	if resp.StatusCode != 200 || len(p.Items) != 1 || p.Items[0].Version != 1 || p.NextCursor != nil {
		t.Fatalf("page 2 = %d %+v", resp.StatusCode, p)
	}
	_, raw = e.do("GET", "/v1/policy/history", "viewer", nil)
	decode(t, raw, &p)
	if len(p.Items) != 3 || p.NextCursor != nil {
		t.Errorf("default page = %+v", p)
	}
	for _, q := range []string{"?cursor=!!!", "?cursor=bm9wZQ", "?limit=0", "?limit=201", "?limit=abc"} {
		if resp, _ := e.do("GET", "/v1/policy/history"+q, "viewer", nil); resp.StatusCode != 422 {
			t.Errorf("history%s = %d, want 422", q, resp.StatusCode)
		}
	}
}

func TestRevocationsPagination(t *testing.T) {
	e := newEnv(t)
	base := fixedNow.Add(-time.Hour)
	for i, id := range []string{"e1", "e2", "e3"} {
		if _, err := e.cache.Upsert(revocation.Entry{EventID: id, Serial: "0" + string(rune('a'+i)), DeviceID: dev, TenantID: tenant, Reason: "keyCompromise", RevokedAt: base.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.cache.MarkKicked("e1"); err != nil {
		t.Fatal(err)
	}
	type page struct {
		Items      []revocationItem `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	resp, raw := e.do("GET", "/v1/revocations?limit=2", "viewer", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, raw)
	}
	var p page
	decode(t, raw, &p)
	if len(p.Items) != 2 || p.Items[0].EventID != "e1" || p.Items[1].EventID != "e2" || p.NextCursor == nil {
		t.Fatalf("page 1 = %+v", p)
	}
	first := p.Items[0]
	if first.SerialHex != "a" || first.DeviceID != dev || first.TenantID != tenant || first.Reason != "keyCompromise" || !first.Kicked || first.KickedAt == nil || !first.AppliedAt.Equal(fixedNow) || !first.RevokedAt.Equal(base) {
		t.Errorf("item = %+v", first)
	}
	if p.Items[1].Kicked {
		t.Error("e2 must not be kicked")
	}
	resp, raw = e.do("GET", "/v1/revocations?limit=2&cursor="+*p.NextCursor, "viewer", nil)
	decode(t, raw, &p)
	if resp.StatusCode != 200 || len(p.Items) != 1 || p.Items[0].EventID != "e3" || p.NextCursor != nil {
		t.Fatalf("page 2 = %d %+v", resp.StatusCode, p)
	}
	for _, q := range []string{"?cursor=!!", "?cursor=e30", "?limit=-1"} {
		if resp, _ := e.do("GET", "/v1/revocations"+q, "viewer", nil); resp.StatusCode != 422 {
			t.Errorf("revocations%s = %d, want 422", q, resp.StatusCode)
		}
	}
}

func TestOpenAPIDocument(t *testing.T) {
	e := newEnv(t)
	resp, raw := e.do("GET", "/openapi.json", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var doc map[string]any
	decode(t, raw, &doc)
	paths, _ := doc["paths"].(map[string]any)
	for _, p := range []string{"/v1/policy", "/v1/policy/evaluate", "/v1/policy/history", "/v1/revocations", "/emqx/authn", "/emqx/authz"} {
		if _, ok := paths[p]; !ok {
			t.Errorf("openapi is missing %s", p)
		}
	}
}

type brokenEngine struct{ engine.Version }

func (b brokenEngine) Current() engine.Version   { return b.Version }
func (b brokenEngine) History() []engine.Version { return []engine.Version{b.Version} }
func (brokenEngine) Update(context.Context, string, string, string) (engine.Version, error) {
	return engine.Version{}, errors.New("disk on fire")
}
func (brokenEngine) Explain(context.Context, engine.Input) (engine.Explanation, error) {
	return engine.Explanation{}, errors.New("tracer exploded")
}

func TestInternalErrors(t *testing.T) {
	signer, _ := auth.GenerateSigner("t")
	pub, _ := signer.PublicKeyPEM()
	verifier, _ := auth.NewVerifier(pub, "policy", auth.WithClock(func() time.Time { return fixedNow }))
	api, err := New(Config{Engine: brokenEngine{engine.Version{Version: 1}}, Revocations: revocation.NewCache("", nil), Guard: verifier.Guard(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api.Register(mux)
	tok, _ := signer.Sign(map[string]any{"sub": "o", "aud": "policy", "role": "owner", "iat": fixedNow.Unix(), "exp": fixedNow.Add(5 * time.Minute).Unix(), "jti": "internal-errors"})
	call := func(method, path string, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call("PUT", "/v1/policy", `{"rego":"package ironmesh.mqtt"}`); got != http.StatusInternalServerError {
		t.Errorf("PUT with failing engine = %d", got)
	}
	if got := call("POST", "/v1/policy/evaluate", `{"input":{"clientid":"a","topic":"t","action":"publish"}}`); got != http.StatusInternalServerError {
		t.Errorf("evaluate with failing engine = %d", got)
	}
}

func TestRevocationsScopedToTokenTenant(t *testing.T) {
	e := newEnv(t)
	const otherTenant = "0b6f3c1e-2d4a-4e8b-9f10-aa55aa55aa55"
	base := fixedNow.Add(-time.Hour)
	for i, tn := range []string{tenant, otherTenant, ""} {
		id := string(rune('a' + i))
		if _, err := e.cache.Upsert(revocation.Entry{EventID: "ev-" + id, Serial: "1" + id, DeviceID: "dev-000000000000000" + id, TenantID: tn, Reason: "keyCompromise", RevokedAt: base.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	call := func(claims map[string]any) []revocationItem {
		t.Helper()
		tok, err := e.signer.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/revocations", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}
		var p struct {
			Items []revocationItem `json:"items"`
		}
		decode(t, raw, &p)
		return p.Items
	}
	exp, iat := fixedNow.Add(5*time.Minute).Unix(), fixedNow.Unix()
	got := call(map[string]any{"sub": "u", "aud": "policy", "role": "viewer", "iat": iat, "exp": exp, "jti": "scoped-1", "tenant_id": tenant})
	if len(got) != 1 || got[0].TenantID != tenant {
		t.Fatalf("tenant-scoped = %+v", got)
	}
	// A service token without tenant_id sees every tenant (and CRL-sourced entries).
	if got := call(map[string]any{"sub": "registry", "aud": "policy", "role": "viewer", "iat": iat, "exp": exp, "jti": "scoped-2"}); len(got) != 3 {
		t.Fatalf("service view = %+v", got)
	}
}
