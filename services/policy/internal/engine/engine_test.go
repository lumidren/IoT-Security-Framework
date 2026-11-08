package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
)

const (
	tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	dev    = "dev-8f3a1c2b9d4e5f60"
)

var fixedTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const permissivePolicy = `package ironmesh.mqtt

default allow := false

allow := true

decision := {"allow": allow, "reasons": set()}
`

func newEngine(t *testing.T, dir string) *Engine {
	t.Helper()
	e, err := New(context.Background(), Options{
		StateDir: dir,
		Clock:    func() time.Time { return fixedTime },
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func deviceInput(action, topic string, qos int, retain bool) Input {
	return Input{ClientID: dev, Username: dev, Topic: topic, Action: action, QoS: qos, Retain: retain,
		ClientAttrs: Attrs{TenantID: tenant, DeviceID: dev, Kind: "device"}}
}

func bridgeInput(topic string) Input {
	return Input{ClientID: "svc-bridge", Username: "svc-bridge", Topic: topic, Action: "subscribe", QoS: 1,
		ClientAttrs: Attrs{Kind: "service"}}
}

// extendedPolicy keeps every invariant but additionally lets the bridge subscribe to a v2 filter,
// an observable change used to prove hot swaps take effect.
func extendedPolicy(t *testing.T) string {
	t.Helper()
	src, _, err := EmbeddedSources()
	if err != nil {
		t.Fatal(err)
	}
	return src + "\n# v2 pilot\nallow if {\n\tis_bridge\n\taction == \"subscribe\"\n\tinput.topic == \"$share/bridge/im/v2/#\"\n\tqos <= 1\n}\n"
}

func TestEmbeddedSources(t *testing.T) {
	src, tests, err := EmbeddedSources()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, "package ironmesh.mqtt") {
		t.Error("embedded policy missing package declaration")
	}
	if _, ok := tests["mqtt_acl_test.rego"]; !ok || len(tests) != 1 {
		t.Errorf("tests = %v", tests)
	}
}

func TestNewLoadsEmbeddedVersion(t *testing.T) {
	e := newEngine(t, t.TempDir())
	src, _, _ := EmbeddedSources()
	sum := sha256.Sum256([]byte(src))
	cur := e.Current()
	if cur.Version != 1 || cur.UpdatedBy != EmbeddedAuthor || cur.SHA256 != hex.EncodeToString(sum[:]) || !cur.UpdatedAt.Equal(fixedTime) || cur.Rego != src {
		t.Errorf("current = %+v", cur)
	}
	if h := e.History(); len(h) != 1 || h[0].Version != 1 {
		t.Errorf("history = %+v", h)
	}
	e2 := newEngine(t, "")
	if e2.Current().Version != 1 {
		t.Error("in-memory engine should start at version 1")
	}
}

// TestEmbeddedInvariantSuitePasses runs the Rego unit tests in policy/rego/mqtt_acl_test.rego
// through the OPA Go test runner so `go test` covers them.
func TestEmbeddedInvariantSuitePasses(t *testing.T) {
	src, tests, err := EmbeddedSources()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunInvariants(context.Background(), src, tests)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Failures) != 0 {
		t.Fatalf("Rego invariant tests failed:\n%s", strings.Join(rep.Failures, "\n"))
	}
	if rep.Total < 45 {
		t.Errorf("expected at least 45 Rego tests, ran %d", rep.Total)
	}
	t.Logf("ran %d Rego unit tests", rep.Total)
}

func TestRunInvariantsReportsFailures(t *testing.T) {
	_, tests, _ := EmbeddedSources()
	rep, err := RunInvariants(context.Background(), permissivePolicy, tests)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Failures) == 0 || !strings.Contains(strings.Join(rep.Failures, "\n"), "test_device_publish_cross_device_denied") {
		t.Errorf("permissive policy should fail invariants, got %v", rep.Failures)
	}
	rep, _ = RunInvariants(context.Background(), "package ironmesh.mqtt\nallow if {", tests)
	if len(rep.Failures) != 1 || rep.Total != 0 {
		t.Errorf("syntax error should be a single failure: %+v", rep)
	}
	rep, _ = RunInvariants(context.Background(), "   ", tests)
	if len(rep.Failures) != 1 {
		t.Errorf("empty source: %+v", rep)
	}
	if _, err := RunInvariants(context.Background(), permissivePolicy, map[string]string{"bad_test.rego": "package x\ntest_a if {"}); err == nil {
		t.Error("broken embedded test module should be an internal error")
	}
	rep, _ = RunInvariants(context.Background(), permissivePolicy, map[string]string{"none_test.rego": "package ironmesh.mqtt_test\n\nhelper := 1\n"})
	if len(rep.Failures) == 0 {
		t.Error("a suite without tests must be reported")
	}
}

func TestEvaluate(t *testing.T) {
	e := newEngine(t, "")
	ctx := context.Background()
	dec, err := e.Evaluate(ctx, deviceInput("publish", "im/v1/"+tenant+"/"+dev+"/telemetry", 1, false))
	if err != nil || !dec.Allow || len(dec.Reasons) != 0 {
		t.Errorf("own telemetry: %+v, %v", dec, err)
	}
	dec, err = e.Evaluate(ctx, deviceInput("publish", "im/v1/1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9/"+dev+"/telemetry", 1, false))
	if err != nil || dec.Allow || len(dec.Reasons) != 1 || dec.Reasons[0] != "not_owner" {
		t.Errorf("cross tenant: %+v, %v", dec, err)
	}
	dec, err = e.Evaluate(ctx, Input{})
	if err != nil || dec.Allow {
		t.Errorf("empty input: %+v, %v", dec, err)
	}
}

func TestExplain(t *testing.T) {
	e := newEngine(t, "")
	ctx := context.Background()
	ex, err := e.Explain(ctx, deviceInput("publish", "im/v1/"+tenant+"/"+dev+"/telemetry", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	if !ex.Allow || ex.Version != 1 || len(ex.Trace) == 0 {
		t.Errorf("explanation = allow:%v version:%d trace:%d", ex.Allow, ex.Version, len(ex.Trace))
	}
	joined := strings.Join(ex.MatchedRules, "\n")
	if !strings.Contains(joined, "allow (mqtt_acl.rego:") || !strings.Contains(joined, "is_device (") {
		t.Errorf("matched rules = %v", ex.MatchedRules)
	}
	if !strings.Contains(strings.Join(ex.Trace, "\n"), "Enter") {
		t.Errorf("trace should contain Enter events: %v", ex.Trace[:min(5, len(ex.Trace))])
	}
	ex, err = e.Explain(ctx, deviceInput("publish", "im/v1/1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9/"+dev+"/telemetry", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	if ex.Allow || !strings.Contains(strings.Join(ex.MatchedRules, "\n"), `reasons["not_owner"]`) {
		t.Errorf("deny explanation = allow:%v rules:%v", ex.Allow, ex.MatchedRules)
	}
}

func TestUpdateRejectsInvalidSources(t *testing.T) {
	dir := t.TempDir()
	e := newEngine(t, dir)
	ctx := context.Background()
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"syntax error", "package ironmesh.mqtt\nallow if {", "rego_parse_error"},
		{"wrong package", "package other\n\nallow := true\n", "package must be ironmesh.mqtt"},
		{"compile error", "package ironmesh.mqtt\n\nallow if { undefined_fn(1) }\n", "undefined"},
		{"invariants fail", permissivePolicy, "invariant tests failed"},
		{"empty", "  \n", "empty"},
		{"too large", strings.Repeat("#", MaxSourceBytes+1), "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.Update(ctx, tc.src, "owner", "bad")
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("err = %v, want ValidationError", err)
			}
			if !strings.Contains(strings.ToLower(verr.Error()), strings.ToLower(tc.want)) {
				t.Errorf("diagnostics %v do not mention %q", verr.Diagnostics, tc.want)
			}
		})
	}
	if e.Current().Version != 1 || len(e.History()) != 1 {
		t.Error("rejected updates must not change state")
	}
	if _, err := os.Stat(filepath.Join(dir, HistoryFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("no history file should be written for rejected updates")
	}
}

func TestUpdateHotSwapsPersistsAndRestores(t *testing.T) {
	dir := t.TempDir()
	e := newEngine(t, dir)
	ctx := context.Background()
	swaps := 0
	e.OnSwap(func() { swaps++ })
	e.OnSwap(nil)

	in := bridgeInput("$share/bridge/im/v2/#")
	if dec, _ := e.Evaluate(ctx, in); dec.Allow {
		t.Fatal("v2 filter must be denied by the embedded policy")
	}
	src := extendedPolicy(t)
	v, err := e.Update(ctx, src, "owner@example.com", "pilot v2 topics")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	sum := sha256.Sum256([]byte(src))
	if v.Version != 2 || v.UpdatedBy != "owner@example.com" || v.Message != "pilot v2 topics" || v.SHA256 != hex.EncodeToString(sum[:]) || !v.UpdatedAt.Equal(fixedTime) {
		t.Errorf("version = %+v", v)
	}
	if dec, _ := e.Evaluate(ctx, in); !dec.Allow {
		t.Error("hot swap did not take effect")
	}
	if swaps != 1 || e.Current().Version != 2 {
		t.Errorf("swaps = %d current = %d", swaps, e.Current().Version)
	}
	if h := e.History(); len(h) != 2 || h[0].Version != 2 || h[1].Version != 1 {
		t.Errorf("history = %+v", h)
	}
	ex, err := e.Explain(ctx, in)
	if err != nil || !ex.Allow || ex.Version != 2 {
		t.Errorf("explain after swap = %+v, %v", ex, err)
	}

	// Re-publishing the active source is idempotent.
	again, err := e.Update(ctx, src, "someone", "again")
	if err != nil || again.Version != 2 || swaps != 1 || len(e.History()) != 2 {
		t.Errorf("idempotent update = %+v, %v, swaps=%d", again, err, swaps)
	}

	raw, err := os.ReadFile(filepath.Join(dir, HistoryFile))
	if err != nil {
		t.Fatal(err)
	}
	var h historyFile
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.Format != historyFormat || len(h.Versions) != 1 || h.Versions[0].Version != 2 {
		t.Errorf("persisted history = %+v", h)
	}

	restored := newEngine(t, dir)
	if restored.Current().Version != 2 || len(restored.History()) != 2 {
		t.Errorf("restored current = %d history = %d", restored.Current().Version, len(restored.History()))
	}
	if dec, _ := restored.Evaluate(ctx, in); !dec.Allow {
		t.Error("restored engine should run version 2")
	}

	// Reverting to the embedded source creates version 3 (history is append-only).
	embedded, _, _ := EmbeddedSources()
	v3, err := restored.Update(ctx, embedded, "owner", "revert")
	if err != nil || v3.Version != 3 {
		t.Errorf("revert = %+v, %v", v3, err)
	}
	if dec, _ := restored.Evaluate(ctx, in); dec.Allow {
		t.Error("revert should deny the v2 filter again")
	}
}

func TestNewSkipsInvalidPersistedVersions(t *testing.T) {
	dir := t.TempDir()
	valid := extendedPolicy(t)
	write := func(versions []Version) {
		t.Helper()
		raw, _ := json.Marshal(historyFile{Format: historyFormat, Versions: versions})
		if err := os.WriteFile(filepath.Join(dir, HistoryFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write([]Version{
		{Version: 2, UpdatedAt: fixedTime, UpdatedBy: "x", Rego: "garbage {"},
		{Version: 3, UpdatedAt: fixedTime, UpdatedBy: "y", Rego: valid},
		{Version: 4, UpdatedAt: fixedTime, UpdatedBy: "z", Rego: permissivePolicy},
	})
	e := newEngine(t, dir)
	if e.Current().Version != 3 {
		t.Errorf("active version = %d, want 3 (newest valid)", e.Current().Version)
	}
	if len(e.History()) != 4 {
		t.Errorf("history should keep every record, got %d", len(e.History()))
	}
	if dec, _ := e.Evaluate(context.Background(), bridgeInput("$share/bridge/im/v2/#")); !dec.Allow {
		t.Error("version 3 should be active")
	}
	if v, err := e.Update(context.Background(), permissivePolicy+"\n", "o", "m"); err == nil {
		t.Errorf("permissive update accepted: %+v", v)
	}
	v, err := e.Update(context.Background(), valid+"\n# tweak\n", "o", "m")
	if err != nil || v.Version != 5 {
		t.Errorf("next version = %+v, %v; want 5", v, err)
	}

	write([]Version{{Version: 2, UpdatedAt: fixedTime, Rego: "garbage {"}, {Version: 1, Rego: "ignored"}})
	e2 := newEngine(t, dir)
	if e2.Current().Version != 1 || len(e2.History()) != 2 {
		t.Errorf("only-invalid history: current=%d history=%d", e2.Current().Version, len(e2.History()))
	}
}

func TestNewRejectsCorruptHistory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, HistoryFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), Options{StateDir: dir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
		t.Fatal("corrupt history must fail startup")
	}
	if _, err := loadHistory(dir); err == nil {
		t.Error("reading a directory as history should fail")
	}
}

func TestUpdatePersistFailureLeavesStateUnchanged(t *testing.T) {
	e := newEngine(t, t.TempDir())
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.path = filepath.Join(blocker, HistoryFile)
	swaps := 0
	e.OnSwap(func() { swaps++ })
	_, err := e.Update(context.Background(), extendedPolicy(t), "o", "m")
	var verr *ValidationError
	if err == nil || errors.As(err, &verr) {
		t.Fatalf("expected a persistence error, got %v", err)
	}
	if e.Current().Version != 1 || swaps != 0 || len(e.History()) != 1 {
		t.Error("failed persistence must not swap or record the version")
	}
}

func TestInputMapAndDecisionFrom(t *testing.T) {
	m := deviceInput("publish", "t", 1, true).Map()
	if m["clientid"] != dev || m["retain"] != true || m["qos"] != 1 {
		t.Errorf("map = %v", m)
	}
	attrs, _ := m["client_attrs"].(map[string]any)
	if attrs["tenant_id"] != tenant || attrs["kind"] != "device" {
		t.Errorf("attrs = %v", attrs)
	}
	if d := decisionFrom(nil); d.Allow || d.Reasons != nil {
		t.Errorf("decisionFrom(nil) = %+v", d)
	}
}

func TestRuleLabel(t *testing.T) {
	mod, err := ast.ParseModuleWithOpts("f.rego", "package p\n\ndefault allow := false\n\nallow if { true }\n\nreasons contains \"x\" if { true }\n", ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"default allow (f.rego:3)", "allow (f.rego:5)", `reasons["x"] (f.rego:7)`}
	for i, r := range mod.Rules {
		if got := ruleLabel(r); got != want[i] {
			t.Errorf("rule %d label = %q, want %q", i, got, want[i])
		}
	}
	if got := ruleLabel(&ast.Rule{}); got != "<anonymous>" {
		t.Errorf("anonymous label = %q", got)
	}
}
