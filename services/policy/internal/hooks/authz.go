package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
)

// AuthzRequest is the body EMQX posts to /emqx/authz. qos and retain are accepted as numbers,
// booleans or strings because EMQX renders template placeholders as strings on some versions.
// client_attrs may be nested (preferred) or flattened into tenant_id/device_id/kind.
type AuthzRequest struct {
	ClientID    string       `json:"clientid"`
	Username    string       `json:"username"`
	Topic       string       `json:"topic"`
	Action      string       `json:"action"`
	QoS         FlexInt      `json:"qos"`
	Retain      FlexBool     `json:"retain"`
	ClientAttrs engine.Attrs `json:"client_attrs"`
	TenantID    string       `json:"tenant_id,omitempty"`
	DeviceID    string       `json:"device_id,omitempty"`
	Kind        string       `json:"kind,omitempty"`
}

// FlexInt decodes from a JSON number or a numeric string.
type FlexInt int

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(b)), `"`))
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("qos: %q is not a number", s)
	}
	*f = FlexInt(int(n))
	return nil
}

// FlexBool decodes from a JSON boolean or the strings true/false/1/0.
type FlexBool bool

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexBool) UnmarshalJSON(b []byte) error {
	s := strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(string(b)), `"`)))
	switch s {
	case "", "null", "false", "0":
		*f = false
	case "true", "1":
		*f = true
	default:
		return fmt.Errorf("retain: %q is not a boolean", s)
	}
	return nil
}

// AuthzResponse is the EMQX HTTP authorizer response.
type AuthzResponse struct {
	Result string `json:"result"`
}

// Evaluator evaluates policy input. *engine.Engine implements it.
type Evaluator interface {
	Evaluate(ctx context.Context, in engine.Input) (engine.Decision, error)
}

// AuthzConfig configures the authz hook.
type AuthzConfig struct {
	Engine     Evaluator
	Identities *IdentityCache
	Metrics    *metrics.Metrics
	Logger     *slog.Logger
	// CacheTTL is the decision cache lifetime (default 10s).
	CacheTTL time.Duration
	// CacheSize bounds the decision cache (default 100000 entries).
	CacheSize    int
	Clock        func() time.Time
	MaxBodyBytes int64
}

// Authz is the EMQX authorization backend.
type Authz struct {
	engine     Evaluator
	identities *IdentityCache
	metrics    *metrics.Metrics
	log        *slog.Logger
	cache      *decisionCache
	maxBody    int64
}

// NewAuthz validates cfg and returns the hook.
func NewAuthz(cfg AuthzConfig) (*Authz, error) {
	if cfg.Engine == nil || cfg.Metrics == nil {
		return nil, errors.New("authz: engine and metrics are required")
	}
	a := &Authz{engine: cfg.Engine, identities: cfg.Identities, metrics: cfg.Metrics, log: cfg.Logger, maxBody: cfg.MaxBodyBytes}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.maxBody <= 0 {
		a.maxBody = 64 << 10
	}
	a.cache = newDecisionCache(cfg.CacheTTL, cfg.CacheSize, cfg.Clock)
	return a, nil
}

// FlushCache drops every cached decision (called after a policy hot swap).
func (a *Authz) FlushCache() { a.cache.flush() }

// ServeHTTP handles POST /emqx/authz with an explicit allow/deny result.
func (a *Authz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, AuthzResponse{Result: "deny"})
		return
	}
	var req AuthzRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.maxBody))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		a.metrics.AuthzDecisions.WithLabelValues("deny", "other").Inc()
		a.log.Warn("authz request rejected", "reason", "bad_request", "err", err.Error())
		writeJSON(w, http.StatusOK, AuthzResponse{Result: "deny"})
		return
	}
	allow, _ := a.Decide(r.Context(), req)
	result := "deny"
	if allow {
		result = "allow"
	}
	writeJSON(w, http.StatusOK, AuthzResponse{Result: result})
}

// Decide resolves the client identity, consults the decision cache and evaluates the policy.
func (a *Authz) Decide(ctx context.Context, req AuthzRequest) (bool, string) {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	label := "other"
	if action == "publish" || action == "subscribe" {
		label = action
	}
	allow, reason := a.decide(ctx, req, action)
	result := "deny"
	if allow {
		result = "allow"
	}
	a.metrics.AuthzDecisions.WithLabelValues(result, label).Inc()
	if !allow {
		a.log.Info("authz deny", "client_id", req.ClientID, "topic", req.Topic, "action", action,
			"qos", int(req.QoS), "retain", bool(req.Retain), "reason", reason)
	} else {
		a.log.Debug("authz allow", "client_id", req.ClientID, "topic", req.Topic, "action", action, "reason", reason)
	}
	return allow, reason
}

func (a *Authz) decide(ctx context.Context, req AuthzRequest, action string) (bool, string) {
	if action != "publish" && action != "subscribe" {
		return false, "bad_action"
	}
	if req.ClientID == "" || req.Topic == "" {
		return false, "bad_request"
	}
	attrs := req.ClientAttrs
	if attrs.Kind == "" {
		attrs = engine.Attrs{TenantID: req.TenantID, DeviceID: req.DeviceID, Kind: req.Kind}
	}
	if attrs.Kind == "" && a.identities != nil {
		if cached, ok := a.identities.Get(req.ClientID); ok {
			attrs = cached
		}
	}
	if attrs.Kind == "" {
		return false, "unknown_identity"
	}
	if attrs.Kind == "device" && attrs.DeviceID != req.ClientID {
		return false, "attrs_mismatch"
	}
	key := cacheKey{clientID: req.ClientID, topic: req.Topic, action: action, retain: bool(req.Retain), qos: int(req.QoS), attrs: attrs}
	if allow, ok := a.cache.get(key); ok {
		a.metrics.AuthzCache.WithLabelValues("hit").Inc()
		return allow, "cached"
	}
	a.metrics.AuthzCache.WithLabelValues("miss").Inc()
	dec, err := a.engine.Evaluate(ctx, engine.Input{
		ClientID:    req.ClientID,
		Username:    req.Username,
		Topic:       req.Topic,
		Action:      action,
		QoS:         int(req.QoS),
		Retain:      bool(req.Retain),
		ClientAttrs: attrs,
	})
	if err != nil {
		a.log.Error("policy evaluation failed; denying", "client_id", req.ClientID, "topic", req.Topic, "err", err.Error())
		return false, "eval_error"
	}
	a.cache.put(key, dec.Allow)
	if dec.Allow {
		return true, "policy"
	}
	if len(dec.Reasons) == 0 {
		return false, "policy"
	}
	return false, strings.Join(dec.Reasons, ",")
}

// cacheKey covers everything the decision depends on. The contract names (clientid, topic, action,
// retain); qos and the session attributes are included as well so a cached allow can never be
// reused for a different QoS or by a request carrying different identity attributes.
type cacheKey struct {
	clientID string
	topic    string
	action   string
	retain   bool
	qos      int
	attrs    engine.Attrs
}

type cacheVal struct {
	allow   bool
	expires time.Time
}

type decisionCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[cacheKey]cacheVal
}

func newDecisionCache(ttl time.Duration, max int, now func() time.Time) *decisionCache {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	if max <= 0 {
		max = 100000
	}
	if now == nil {
		now = time.Now
	}
	return &decisionCache{ttl: ttl, max: max, now: now, entries: make(map[cacheKey]cacheVal)}
}

func (c *decisionCache) get(k cacheKey) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[k]
	if !ok {
		return false, false
	}
	if !c.now().Before(v.expires) {
		delete(c.entries, k)
		return false, false
	}
	return v.allow, true
}

func (c *decisionCache) put(k cacheKey, allow bool) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		for key, v := range c.entries {
			if !now.Before(v.expires) {
				delete(c.entries, key)
			}
		}
		for key := range c.entries {
			if len(c.entries) < c.max {
				break
			}
			delete(c.entries, key)
		}
	}
	c.entries[k] = cacheVal{allow: allow, expires: now.Add(c.ttl)}
}

func (c *decisionCache) flush() {
	c.mu.Lock()
	c.entries = make(map[cacheKey]cacheVal)
	c.mu.Unlock()
}

func (c *decisionCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
