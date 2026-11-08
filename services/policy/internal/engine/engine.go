// Package engine owns the compiled Rego policy: it evaluates authorization decisions, explains
// them with OPA tracing, and manages versioned, hot-swappable policy updates gated by the embedded
// invariant test suite (API_CONTRACT.md section 4).
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/open-policy-agent/opa/v1/topdown"

	policyfs "github.com/lumidren/IoT-Security-Framework/services/policy/policy"
)

const (
	// Package is the Rego package every policy version must declare.
	Package = "ironmesh.mqtt"
	// Query is evaluated for every decision.
	Query = "data.ironmesh.mqtt.decision"
	// ModuleName is the file name the policy source is compiled under.
	ModuleName = "mqtt_acl.rego"
	// HistoryFile holds operator-published versions inside POLICY_STATE_DIR.
	HistoryFile = "policy_history.json"
	// EmbeddedAuthor marks the version compiled into the binary.
	EmbeddedAuthor = "embedded"
	// MaxSourceBytes bounds a policy upload.
	MaxSourceBytes = 1 << 20
	maxTraceLines  = 5000
	historyFormat  = 1
)

// Attrs are the session attributes attached by the authn hook.
type Attrs struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"`
}

// Input is the OPA input document for one authorization request.
type Input struct {
	ClientID    string
	Username    string
	Topic       string
	Action      string
	QoS         int
	Retain      bool
	ClientAttrs Attrs
}

// Map renders the input as the document the Rego policy expects.
func (in Input) Map() map[string]any {
	return map[string]any{
		"clientid": in.ClientID,
		"username": in.Username,
		"topic":    in.Topic,
		"action":   in.Action,
		"qos":      in.QoS,
		"retain":   in.Retain,
		"client_attrs": map[string]any{
			"tenant_id": in.ClientAttrs.TenantID,
			"device_id": in.ClientAttrs.DeviceID,
			"kind":      in.ClientAttrs.Kind,
		},
	}
}

// Decision is the policy outcome.
type Decision struct {
	Allow   bool
	Reasons []string
}

// Version describes one policy version.
type Version struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Message   string    `json:"message"`
	SHA256    string    `json:"sha256_hex"`
	Rego      string    `json:"rego"`
}

// Explanation is a traced dry-run decision.
type Explanation struct {
	Allow        bool
	Reasons      []string
	MatchedRules []string
	Trace        []string
	Version      int
}

// InvariantReport is the result of running the embedded test suite against a candidate policy.
type InvariantReport struct {
	Total    int
	Failures []string
}

// ValidationError reports why a candidate policy was refused (HTTP 422).
type ValidationError struct {
	Diagnostics []string
}

func (e *ValidationError) Error() string {
	return "policy validation failed: " + strings.Join(e.Diagnostics, "; ")
}

type compiled struct {
	version  Version
	compiler *ast.Compiler
	query    rego.PreparedEvalQuery
}

// Options configure an Engine.
type Options struct {
	// StateDir persists operator-published versions (empty: in-memory only).
	StateDir string
	Clock    func() time.Time
	Logger   *slog.Logger
}

// Engine evaluates the active policy and manages versions.
type Engine struct {
	mu       sync.Mutex // serialises updates and version bookkeeping
	current  atomic.Pointer[compiled]
	versions []Version // ascending; index 0 is the embedded version
	path     string
	tests    map[string]string
	now      func() time.Time
	log      *slog.Logger

	swapMu sync.RWMutex
	onSwap []func()
}

// EmbeddedSources returns the embedded policy source and the embedded test modules.
func EmbeddedSources() (string, map[string]string, error) {
	entries, err := fs.ReadDir(policyfs.FS, policyfs.Dir)
	if err != nil {
		return "", nil, fmt.Errorf("engine: read embedded policies: %w", err)
	}
	var policies []string
	tests := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		raw, err := fs.ReadFile(policyfs.FS, policyfs.Dir+"/"+e.Name())
		if err != nil {
			return "", nil, fmt.Errorf("engine: read %s: %w", e.Name(), err)
		}
		if strings.HasSuffix(e.Name(), "_test.rego") {
			tests[e.Name()] = string(raw)
			continue
		}
		policies = append(policies, string(raw))
	}
	if len(policies) != 1 {
		return "", nil, fmt.Errorf("engine: expected exactly one embedded policy module, found %d", len(policies))
	}
	if len(tests) == 0 {
		return "", nil, errors.New("engine: no embedded invariant tests found")
	}
	return policies[0], tests, nil
}

// New compiles the embedded policy (version 1), then restores operator-published versions from
// the state directory and activates the newest one that still compiles and satisfies the
// invariant suite.
func New(ctx context.Context, opts Options) (*Engine, error) {
	src, tests, err := EmbeddedSources()
	if err != nil {
		return nil, err
	}
	e := &Engine{tests: tests, now: opts.Clock, log: opts.Logger}
	if e.now == nil {
		e.now = time.Now
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	if opts.StateDir != "" {
		e.path = filepath.Join(opts.StateDir, HistoryFile)
	}
	embedded, err := e.compileVersion(ctx, Version{
		Version:   1,
		UpdatedAt: e.now().UTC(),
		UpdatedBy: EmbeddedAuthor,
		Message:   "embedded default policy",
		Rego:      src,
	})
	if err != nil {
		return nil, fmt.Errorf("engine: embedded policy is invalid: %w", err)
	}
	e.versions = []Version{embedded.version}
	e.current.Store(embedded)

	persisted, err := loadHistory(e.path)
	if err != nil {
		return nil, err
	}
	for _, v := range persisted {
		if v.Version < 2 {
			continue
		}
		e.versions = append(e.versions, v)
	}
	sort.Slice(e.versions, func(i, j int) bool { return e.versions[i].Version < e.versions[j].Version })
	for i := len(e.versions) - 1; i >= 1; i-- {
		c, err := e.compileVersion(ctx, e.versions[i])
		if err != nil {
			e.log.Error("persisted policy version is invalid; skipping", "version", e.versions[i].Version, "err", err.Error())
			continue
		}
		e.current.Store(c)
		break
	}
	cur := e.current.Load().version
	e.log.Info("policy engine ready", "active_version", cur.Version, "sha256", cur.SHA256, "versions", len(e.versions))
	return e, nil
}

// Current returns the active version (including its source).
func (e *Engine) Current() Version { return e.current.Load().version }

// History returns every known version, newest first.
func (e *Engine) History() []Version {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Version, len(e.versions))
	for i, v := range e.versions {
		out[len(e.versions)-1-i] = v
	}
	return out
}

// OnSwap registers fn to run after every successful hot swap (used to flush decision caches).
func (e *Engine) OnSwap(fn func()) {
	if fn == nil {
		return
	}
	e.swapMu.Lock()
	e.onSwap = append(e.onSwap, fn)
	e.swapMu.Unlock()
}

// Evaluate runs the active policy. Any error must be treated as deny by callers.
func (e *Engine) Evaluate(ctx context.Context, in Input) (Decision, error) {
	c := e.current.Load()
	rs, err := c.query.Eval(ctx, rego.EvalInput(in.Map()))
	if err != nil {
		return Decision{}, fmt.Errorf("engine: eval: %w", err)
	}
	return decisionFrom(rs), nil
}

// Explain evaluates in with tracing enabled and never consults any cache.
func (e *Engine) Explain(ctx context.Context, in Input) (Explanation, error) {
	c := e.current.Load()
	buf := topdown.NewBufferTracer()
	rs, err := rego.New(
		rego.Compiler(c.compiler),
		rego.Query(Query),
		rego.Input(in.Map()),
		rego.QueryTracer(buf),
	).Eval(ctx)
	if err != nil {
		return Explanation{}, fmt.Errorf("engine: explain: %w", err)
	}
	dec := decisionFrom(rs)
	ex := Explanation{Allow: dec.Allow, Reasons: dec.Reasons, Version: c.version.Version}
	seen := map[string]bool{}
	for _, ev := range *buf {
		if ev.Op != topdown.ExitOp {
			continue
		}
		rule, ok := ev.Node.(*ast.Rule)
		if !ok {
			continue
		}
		label := ruleLabel(rule)
		if !seen[label] {
			seen[label] = true
			ex.MatchedRules = append(ex.MatchedRules, label)
		}
	}
	var sb strings.Builder
	topdown.PrettyTraceWithLocation(&sb, *buf)
	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	if len(lines) > maxTraceLines {
		lines = append(lines[:maxTraceLines], fmt.Sprintf("... %d more lines truncated", len(lines)-maxTraceLines))
	}
	ex.Trace = lines
	return ex, nil
}

// Update validates src (parse, compile, invariant suite), persists it as a new version and swaps
// it in atomically. Publishing a source identical to the active version is a no-op that returns
// the active version.
func (e *Engine) Update(ctx context.Context, src, updatedBy, message string) (Version, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if strings.TrimSpace(src) == "" {
		return Version{}, &ValidationError{Diagnostics: []string{"rego source is empty"}}
	}
	if len(src) > MaxSourceBytes {
		return Version{}, &ValidationError{Diagnostics: []string{fmt.Sprintf("rego source exceeds %d bytes", MaxSourceBytes)}}
	}
	cur := e.current.Load()
	if cur.version.SHA256 == sha256Hex(src) {
		return cur.version, nil
	}
	next := Version{
		Version:   e.versions[len(e.versions)-1].Version + 1,
		UpdatedAt: e.now().UTC(),
		UpdatedBy: updatedBy,
		Message:   message,
		Rego:      src,
	}
	c, err := e.compileVersion(ctx, next)
	if err != nil {
		return Version{}, err
	}
	persisted := make([]Version, 0, len(e.versions))
	for _, v := range e.versions {
		if v.Version >= 2 {
			persisted = append(persisted, v)
		}
	}
	persisted = append(persisted, c.version)
	if err := saveHistory(e.path, persisted); err != nil {
		return Version{}, err
	}
	e.versions = append(e.versions, c.version)
	e.current.Store(c)
	e.fireSwap()
	e.log.Info("policy hot-swapped", "version", c.version.Version, "sha256", c.version.SHA256, "updated_by", updatedBy)
	return c.version, nil
}

// RunInvariants executes the embedded test suite against candidate source.
func RunInvariants(ctx context.Context, candidate string, tests map[string]string) (InvariantReport, error) {
	opts := ast.ParserOptions{RegoVersion: ast.RegoV1}
	modules := map[string]*ast.Module{}
	m, err := ast.ParseModuleWithOpts(ModuleName, candidate, opts)
	if err != nil {
		return InvariantReport{Failures: []string{err.Error()}}, nil
	}
	if m == nil {
		return InvariantReport{Failures: []string{"rego source is empty"}}, nil
	}
	modules[ModuleName] = m
	for name, src := range tests {
		tm, err := ast.ParseModuleWithOpts(name, src, opts)
		if err != nil {
			return InvariantReport{}, fmt.Errorf("engine: embedded test %s: %w", name, err)
		}
		modules[name] = tm
	}
	runner := tester.NewRunner().SetModules(modules).SetDefaultRegoVersion(ast.RegoV1).SetTimeout(30 * time.Second)
	ch, err := runner.RunTests(ctx, nil)
	if err != nil {
		return InvariantReport{Failures: []string{"invariant suite could not be compiled against the policy: " + err.Error()}}, nil
	}
	var rep InvariantReport
	for r := range ch {
		if r.Skip {
			continue
		}
		rep.Total++
		switch {
		case r.Error != nil:
			rep.Failures = append(rep.Failures, fmt.Sprintf("%s.%s: error: %v", r.Package, r.Name, r.Error))
		case r.Fail:
			rep.Failures = append(rep.Failures, fmt.Sprintf("%s.%s: FAIL", r.Package, r.Name))
		}
	}
	if rep.Total == 0 {
		rep.Failures = append(rep.Failures, "invariant suite produced no test results")
	}
	return rep, nil
}

func (e *Engine) compileVersion(ctx context.Context, v Version) (*compiled, error) {
	module, err := ast.ParseModuleWithOpts(ModuleName, v.Rego, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, &ValidationError{Diagnostics: splitLines(err.Error())}
	}
	if module == nil {
		return nil, &ValidationError{Diagnostics: []string{"rego source is empty"}}
	}
	if got := module.Package.Path.String(); got != "data."+Package {
		return nil, &ValidationError{Diagnostics: []string{fmt.Sprintf("package must be %s, got %s", Package, strings.TrimPrefix(got, "data."))}}
	}
	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{ModuleName: module})
	if compiler.Failed() {
		var diags []string
		for _, cerr := range compiler.Errors {
			diags = append(diags, cerr.Error())
		}
		return nil, &ValidationError{Diagnostics: diags}
	}
	rep, err := RunInvariants(ctx, v.Rego, e.tests)
	if err != nil {
		return nil, err
	}
	if len(rep.Failures) > 0 {
		return nil, &ValidationError{Diagnostics: append([]string{fmt.Sprintf("%d of %d invariant tests failed", len(rep.Failures), rep.Total)}, rep.Failures...)}
	}
	pq, err := rego.New(rego.Compiler(compiler), rego.Query(Query)).PrepareForEval(ctx)
	if err != nil {
		return nil, &ValidationError{Diagnostics: []string{"prepare query: " + err.Error()}}
	}
	v.SHA256 = sha256Hex(v.Rego)
	return &compiled{version: v, compiler: compiler, query: pq}, nil
}

func (e *Engine) fireSwap() {
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	for _, fn := range e.onSwap {
		fn()
	}
}

func decisionFrom(rs rego.ResultSet) Decision {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{}
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{}
	}
	dec := Decision{}
	dec.Allow, _ = doc["allow"].(bool)
	if raw, ok := doc["reasons"].([]any); ok {
		for _, r := range raw {
			if s, ok := r.(string); ok {
				dec.Reasons = append(dec.Reasons, s)
			}
		}
		sort.Strings(dec.Reasons)
	}
	return dec
}

func ruleLabel(rule *ast.Rule) string {
	var name string
	switch {
	case rule.Head == nil:
		name = "<anonymous>"
	case len(rule.Head.Reference) > 0:
		name = rule.Head.Reference.String()
	default:
		name = rule.Head.Name.String()
	}
	if rule.Head != nil && rule.Head.Key != nil && rule.Head.Value == nil {
		name += "[" + rule.Head.Key.String() + "]"
	}
	if rule.Default {
		name = "default " + name
	}
	if rule.Location != nil {
		name += fmt.Sprintf(" (%s:%d)", rule.Location.File, rule.Location.Row)
	}
	return name
}

type historyFile struct {
	Format   int       `json:"format"`
	Versions []Version `json:"versions"`
}

func loadHistory(path string) ([]Version, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("engine: read history: %w", err)
	}
	var h historyFile
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("engine: decode history: %w", err)
	}
	for i := range h.Versions {
		h.Versions[i].SHA256 = sha256Hex(h.Versions[i].Rego)
	}
	return h.Versions, nil
}

func saveHistory(path string, versions []Version) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(historyFile{Format: historyFormat, Versions: versions}, "", "  ")
	if err != nil {
		return fmt.Errorf("engine: encode history: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("engine: persist history: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".policy-history-*.tmp")
	if err != nil {
		return fmt.Errorf("engine: persist history: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("engine: persist history: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("engine: persist history: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("engine: persist history: %w", err)
	}
	return nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
