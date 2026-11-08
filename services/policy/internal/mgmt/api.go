// Package mgmt serves the policy management API from API_CONTRACT.md section 4: inspect, publish
// and dry-run the Rego policy, browse its history, and list the revocation cache. Every route is
// protected by the ES256 bearer-token Guard with per-route minimum roles.
package mgmt

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/auth"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/hooks"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/problem"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
)

//go:embed openapi.json
var openAPI []byte

// RevocationLister exposes the revocation cache entries. *revocation.Cache implements it.
type RevocationLister interface {
	Entries() []revocation.Entry
}

// PolicyEngine is the engine surface the API needs. *engine.Engine implements it.
type PolicyEngine interface {
	Current() engine.Version
	History() []engine.Version
	Update(ctx context.Context, src, updatedBy, message string) (engine.Version, error)
	Explain(ctx context.Context, in engine.Input) (engine.Explanation, error)
}

// Config configures the API.
type Config struct {
	Engine       PolicyEngine
	Revocations  RevocationLister
	Guard        auth.Guard
	Logger       *slog.Logger
	MaxBodyBytes int64
}

// API holds the handlers.
type API struct {
	engine  PolicyEngine
	revoked RevocationLister
	guard   auth.Guard
	log     *slog.Logger
	maxBody int64
}

// New validates cfg and returns the API.
func New(cfg Config) (*API, error) {
	if cfg.Engine == nil || cfg.Revocations == nil || cfg.Guard == nil {
		return nil, errors.New("mgmt: engine, revocations and guard are required")
	}
	a := &API{engine: cfg.Engine, revoked: cfg.Revocations, guard: cfg.Guard, log: cfg.Logger, maxBody: cfg.MaxBodyBytes}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.maxBody <= 0 {
		a.maxBody = engine.MaxSourceBytes + 64<<10
	}
	return a, nil
}

// Register mounts the routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /v1/policy", a.guard(auth.RoleAdmin, http.HandlerFunc(a.getPolicy)))
	mux.Handle("PUT /v1/policy", a.guard(auth.RoleOwner, http.HandlerFunc(a.putPolicy)))
	mux.Handle("POST /v1/policy/evaluate", a.guard(auth.RoleOperator, http.HandlerFunc(a.evaluate)))
	mux.Handle("GET /v1/policy/history", a.guard(auth.RoleViewer, http.HandlerFunc(a.history)))
	mux.Handle("GET /v1/revocations", a.guard(auth.RoleViewer, http.HandlerFunc(a.revocations)))
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(openAPI)
	})
}

type policyDoc struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Rego      string    `json:"rego"`
	SHA256    string    `json:"sha256_hex"`
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	v := a.engine.Current()
	writeJSON(w, http.StatusOK, policyDoc{Version: v.Version, UpdatedAt: v.UpdatedAt, UpdatedBy: v.UpdatedBy, Rego: v.Rego, SHA256: v.SHA256})
}

type putPolicyRequest struct {
	Rego    string `json:"rego"`
	Message string `json:"message"`
}

func (a *API) putPolicy(w http.ResponseWriter, r *http.Request) {
	var req putPolicyRequest
	if !a.decodeBody(w, r, &req) {
		return
	}
	var errs []string
	if strings.TrimSpace(req.Rego) == "" {
		errs = append(errs, "rego is required")
	}
	if len(req.Message) > 512 {
		errs = append(errs, "message must be at most 512 characters")
	}
	if len(errs) > 0 {
		problem.Write(w, r, http.StatusUnprocessableEntity, "request failed validation", errs...)
		return
	}
	claims, _ := auth.ClaimsFromContext(r.Context())
	actor := claims.Subject
	if actor == "" {
		actor = "unknown"
	}
	v, err := a.engine.Update(r.Context(), req.Rego, actor, req.Message)
	if err != nil {
		var verr *engine.ValidationError
		if errors.As(err, &verr) {
			a.audit(r, "policy.update", "failure", "validation failed")
			problem.Write(w, r, http.StatusUnprocessableEntity, "policy rejected: it does not compile or violates the embedded invariant tests", verr.Diagnostics...)
			return
		}
		a.audit(r, "policy.update", "failure", err.Error())
		a.log.Error("policy update failed", "err", err.Error())
		problem.Write(w, r, http.StatusInternalServerError, "policy could not be stored")
		return
	}
	a.audit(r, "policy.update", "success", "version "+strconv.Itoa(v.Version))
	writeJSON(w, http.StatusOK, map[string]any{"version": v.Version, "sha256_hex": v.SHA256})
}

type evaluateRequest struct {
	Input struct {
		ClientID string         `json:"clientid"`
		Username string         `json:"username"`
		TenantID string         `json:"tenant_id"`
		DeviceID string         `json:"device_id"`
		Kind     string         `json:"kind"`
		Topic    string         `json:"topic"`
		Action   string         `json:"action"`
		QoS      hooks.FlexInt  `json:"qos"`
		Retain   hooks.FlexBool `json:"retain"`
	} `json:"input"`
}

type evaluateResponse struct {
	Result           string   `json:"result"`
	MatchedRules     []string `json:"matched_rules"`
	Trace            []string `json:"trace"`
	EvaluatedVersion int      `json:"evaluated_version"`
	Reasons          []string `json:"reasons"`
}

func (a *API) evaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateRequest
	if !a.decodeBody(w, r, &req) {
		return
	}
	in := req.Input
	var errs []string
	if in.ClientID == "" {
		errs = append(errs, "input.clientid is required")
	}
	if in.Topic == "" {
		errs = append(errs, "input.topic is required")
	}
	action := strings.ToLower(in.Action)
	if action != "publish" && action != "subscribe" {
		errs = append(errs, "input.action must be publish or subscribe")
	}
	if in.QoS < 0 || in.QoS > 2 {
		errs = append(errs, "input.qos must be 0, 1 or 2")
	}
	if len(errs) > 0 {
		problem.Write(w, r, http.StatusUnprocessableEntity, "request failed validation", errs...)
		return
	}
	ex, err := a.engine.Explain(r.Context(), engine.Input{
		ClientID: in.ClientID,
		Username: in.Username,
		Topic:    in.Topic,
		Action:   action,
		QoS:      int(in.QoS),
		Retain:   bool(in.Retain),
		ClientAttrs: engine.Attrs{
			TenantID: in.TenantID,
			DeviceID: in.DeviceID,
			Kind:     in.Kind,
		},
	})
	if err != nil {
		a.log.Error("dry-run evaluation failed", "err", err.Error())
		problem.Write(w, r, http.StatusInternalServerError, "evaluation failed", err.Error())
		return
	}
	result := "deny"
	if ex.Allow {
		result = "allow"
	}
	writeJSON(w, http.StatusOK, evaluateResponse{
		Result:           result,
		MatchedRules:     nonNil(ex.MatchedRules),
		Trace:            nonNil(ex.Trace),
		EvaluatedVersion: ex.Version,
		Reasons:          nonNil(ex.Reasons),
	})
}

type historyItem struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Message   string    `json:"message"`
	SHA256    string    `json:"sha256_hex"`
}

type historyCursor struct {
	Before int `json:"before"`
}

func (a *API) history(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		problem.Write(w, r, http.StatusUnprocessableEntity, err.Error())
		return
	}
	before := 0
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		var c historyCursor
		if err := decodeCursor(raw, &c); err != nil || c.Before <= 0 {
			problem.Write(w, r, http.StatusUnprocessableEntity, ErrBadCursor.Error())
			return
		}
		before = c.Before
	}
	items := make([]historyItem, 0, limit)
	var next *string
	for _, v := range a.engine.History() { // newest first
		if before > 0 && v.Version >= before {
			continue
		}
		if len(items) == limit {
			cur, _ := encodeCursor(historyCursor{Before: items[len(items)-1].Version})
			next = &cur
			break
		}
		items = append(items, historyItem{Version: v.Version, UpdatedAt: v.UpdatedAt, UpdatedBy: v.UpdatedBy, Message: v.Message, SHA256: v.SHA256})
	}
	writeJSON(w, http.StatusOK, Page{Items: items, NextCursor: next})
}

type revocationItem struct {
	SerialHex string     `json:"serial_hex"`
	DeviceID  string     `json:"device_id"`
	TenantID  string     `json:"tenant_id"`
	Reason    string     `json:"reason"`
	RevokedAt time.Time  `json:"revoked_at"`
	AppliedAt time.Time  `json:"applied_at"`
	Kicked    bool       `json:"kicked"`
	KickedAt  *time.Time `json:"kicked_at,omitempty"`
	Source    string     `json:"source"`
	EventID   string     `json:"event_id"`
}

type revocationCursor struct {
	RevokedAt time.Time `json:"revoked_at"`
	EventID   string    `json:"event_id"`
}

func (a *API) revocations(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		problem.Write(w, r, http.StatusUnprocessableEntity, err.Error())
		return
	}
	var after *revocationCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		var c revocationCursor
		if err := decodeCursor(raw, &c); err != nil || c.EventID == "" {
			problem.Write(w, r, http.StatusUnprocessableEntity, ErrBadCursor.Error())
			return
		}
		after = &c
	}
	items := make([]revocationItem, 0, limit)
	var next *string
	for _, e := range a.revoked.Entries() { // ascending by revoked_at, event id
		if after != nil && !entryAfter(e, *after) {
			continue
		}
		if len(items) == limit {
			last := items[len(items)-1]
			cur, _ := encodeCursor(revocationCursor{RevokedAt: last.RevokedAt, EventID: last.EventID})
			next = &cur
			break
		}
		items = append(items, revocationItem{
			SerialHex: e.Serial, DeviceID: e.DeviceID, TenantID: e.TenantID, Reason: e.Reason,
			RevokedAt: e.RevokedAt, AppliedAt: e.AppliedAt, Kicked: e.Kicked, KickedAt: e.KickedAt,
			Source: e.Source, EventID: e.EventID,
		})
	}
	writeJSON(w, http.StatusOK, Page{Items: items, NextCursor: next})
}

func entryAfter(e revocation.Entry, c revocationCursor) bool {
	if !e.RevokedAt.Equal(c.RevokedAt) {
		return e.RevokedAt.After(c.RevokedAt)
	}
	return e.EventID > c.EventID
}

func (a *API) decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			problem.Write(w, r, http.StatusRequestEntityTooLarge, "body exceeds limit")
			return false
		}
		problem.Write(w, r, http.StatusBadRequest, "could not read body")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		problem.Write(w, r, http.StatusBadRequest, "body is not valid JSON", err.Error())
		return false
	}
	return true
}

func (a *API) audit(r *http.Request, action, outcome, detail string) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	a.log.Info("audit event",
		"audit", true,
		"action", action,
		"outcome", outcome,
		"actor_id", claims.Subject,
		"actor_role", string(claims.Role),
		"tenant_id", claims.TenantID,
		"target", "policy",
		"detail", detail,
		"remote_addr", r.RemoteAddr,
	)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
