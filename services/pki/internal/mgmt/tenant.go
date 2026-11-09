package mgmt

// Tenant policy API (API_CONTRACT §5): what the EST trust bundle carries and
// what enrollment allows. Each field has exactly one owning service:
//
//	PUT /v1/tenants/{tenant}/command-key    (registry) {"public_key_b64": "<32-byte Ed25519>"}         -> 204
//	PUT /v1/tenants/{tenant}/firmware-keys  (ota)      {"public_keys_b64": ["<Ed25519|ML-DSA-65>", ..]} -> 204
//	PUT /v1/tenants/{tenant}/enrollment     (registry) {"allow_software_keys": bool}                    -> 204
//	GET /v1/tenants/{tenant}/policy         -> {command_key_b64, firmware_keys_b64, allow_software_keys, updated_at}
//
// Ownership is decided by the caller's service identity: the Services CA
// client certificate CN (svc-registry, svc-ota) or the service JWT sub
// (registry / svc-registry, ota / svc-ota). Reads are open to every caller
// allowed on the management API and to the owning services. Changes are
// stored with PutTenantPolicy and picked up by the EST bundle builder on the
// next enrollment.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Owning services of the tenant policy fields.
const (
	OwnerCommandKey   = "registry"
	OwnerFirmwareKeys = "ota"
	OwnerEnrollment   = "registry"
)

// Key sizes accepted by the tenant policy API.
const (
	// MLDSA65PublicKeySize is the encoded ML-DSA-65 public key size (FIPS 204).
	MLDSA65PublicKeySize = 1952
	// MaxFirmwareKeys bounds the firmware signing key list.
	MaxFirmwareKeys = 16

	maxTenantBody = 64 << 10
)

// tenantPolicyView is the body of GET /v1/tenants/{tenant}/policy.
type tenantPolicyView struct {
	CommandKeyB64     string     `json:"command_key_b64"`
	FirmwareKeysB64   []string   `json:"firmware_keys_b64"`
	AllowSoftwareKeys bool       `json:"allow_software_keys"`
	UpdatedAt         *time.Time `json:"updated_at"`
}

type commandKeyBody struct {
	PublicKeyB64 *string `json:"public_key_b64"`
}

type firmwareKeysBody struct {
	PublicKeysB64 []string `json:"public_keys_b64"`
}

type enrollmentBody struct {
	AllowSoftwareKeys *bool `json:"allow_software_keys"`
}

// fieldError is one entry of the problem "errors" member.
type fieldError struct {
	Field  string `json:"field"`
	Detail string `json:"detail"`
}

// problem is an RFC 9457 problem details body (API_CONTRACT §0).
type problem struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail,omitempty"`
	Instance string       `json:"instance,omitempty"`
	Errors   []fieldError `json:"errors,omitempty"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, detail string, errs ...fieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Detail: detail, Instance: r.URL.Path, Errors: errs})
}

// tenantAuth authenticates the caller and authorizes it for a tenant policy
// operation: owner != "" requires that service; owner == "" (reads) admits
// allow-listed callers and every owning service.
func (h *Handler) tenantAuth(owner string, next func(http.ResponseWriter, *http.Request, *Principal)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := logging.FromContext(r.Context())
		p, err := h.cfg.Auth.Identify(r)
		if err != nil {
			h.cfg.Metrics.AuthFailures.Inc()
			log.Warn("tenant policy request rejected", "path", r.URL.Path, "status", http.StatusUnauthorized, "error", err.Error())
			w.Header().Set("WWW-Authenticate", `Bearer realm="pki"`)
			writeProblem(w, r, http.StatusUnauthorized, "a Services CA client certificate or a service JWT (aud=pki) is required")
			return
		}
		svc := p.Service()
		var ok bool
		if owner == "" {
			ok = p.Allowed || svc == OwnerCommandKey || svc == OwnerFirmwareKeys || svc == OwnerEnrollment
		} else {
			ok = svc == owner
		}
		if !ok {
			h.cfg.Metrics.AuthFailures.Inc()
			log.Warn("tenant policy request forbidden", "audit", true, "outcome", "failure", "path", r.URL.Path, "method", r.Method,
				"actor", p.Subject, "auth_method", p.Method, "required_owner", owner, "tenant_id", r.PathValue("tenant"))
			detail := "caller is not authorized to read tenant policies"
			if owner != "" {
				detail = fmt.Sprintf("this field is owned by the %s service", owner)
			}
			writeProblem(w, r, http.StatusForbidden, detail)
			return
		}
		next(w, r, p)
	})
}

// registerTenantRoutes mounts the tenant policy endpoints.
func (h *Handler) registerTenantRoutes(mux *http.ServeMux) {
	mux.Handle("PUT /v1/tenants/{tenant}/command-key", h.tenantAuth(OwnerCommandKey, h.putCommandKey))
	mux.Handle("PUT /v1/tenants/{tenant}/firmware-keys", h.tenantAuth(OwnerFirmwareKeys, h.putFirmwareKeys))
	mux.Handle("PUT /v1/tenants/{tenant}/enrollment", h.tenantAuth(OwnerEnrollment, h.putEnrollment))
	mux.Handle("GET /v1/tenants/{tenant}/policy", h.tenantAuth("", h.getTenantPolicy))
}

// decodeStrict reads a bounded JSON body that must contain exactly one object
// without unknown fields.
func decodeStrict(r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxTenantBody))
	if err != nil {
		return fmt.Errorf("cannot read body: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if dec.More() {
		return errors.New("invalid JSON body: trailing data")
	}
	return nil
}

// decodeKey decodes standard or URL-safe base64, padded or not.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

func fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// tenantFrom validates the {tenant} path value.
func tenantFrom(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant := r.PathValue("tenant")
	if err := ca.ValidateTenantID(tenant); err != nil {
		writeProblem(w, r, http.StatusUnprocessableEntity, "invalid tenant id", fieldError{Field: "tenant", Detail: err.Error()})
		return "", false
	}
	return tenant, true
}

// updateTenantPolicy applies mod to the stored policy (or a fresh one with
// the service defaults) and stores it. A process-wide lock serializes the
// read-modify-write so concurrent owners of different fields cannot lose
// each other's updates within one replica.
func (h *Handler) updateTenantPolicy(ctx context.Context, tenant string, mod func(*store.TenantPolicy)) (*store.TenantPolicy, error) {
	h.tenantMu.Lock()
	defer h.tenantMu.Unlock()
	pol, err := h.cfg.Store.GetTenantPolicy(ctx, tenant)
	switch {
	case errors.Is(err, store.ErrNotFound):
		pol = &store.TenantPolicy{TenantID: tenant, AllowSoftwareKeys: h.cfg.DefaultAllowSoftwareKeys}
	case err != nil:
		return nil, err
	}
	mod(pol)
	pol.TenantID = tenant
	pol.UpdatedAt = h.cfg.Clock().UTC()
	if err := h.cfg.Store.PutTenantPolicy(ctx, pol); err != nil {
		return nil, err
	}
	return pol, nil
}

func (h *Handler) finishUpdate(w http.ResponseWriter, r *http.Request, p *Principal, tenant, action string, err error, attrs ...any) {
	log := logging.FromContext(r.Context())
	if err != nil {
		log.Error("tenant policy update failed", append([]any{"audit", true, "outcome", "failure", "action", action,
			"actor", p.Subject, "auth_method", p.Method, "tenant_id", tenant, "error", err.Error()}, attrs...)...)
		writeProblem(w, r, http.StatusServiceUnavailable, "tenant policy could not be stored")
		return
	}
	log.Info("tenant policy updated", append([]any{"audit", true, "outcome", "success", "action", action,
		"actor", p.Subject, "auth_method", p.Method, "tenant_id", tenant}, attrs...)...)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) putCommandKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenant, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	var body commandKeyBody
	if err := decodeStrict(r, &body); err != nil {
		writeProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if body.PublicKeyB64 == nil {
		writeProblem(w, r, http.StatusUnprocessableEntity, "public_key_b64 is required", fieldError{Field: "public_key_b64", Detail: "required"})
		return
	}
	key, err := decodeKey(*body.PublicKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize || bytes.Equal(key, make([]byte, ed25519.PublicKeySize)) {
		writeProblem(w, r, http.StatusUnprocessableEntity, "public_key_b64 must be a base64 32-byte Ed25519 public key",
			fieldError{Field: "public_key_b64", Detail: fmt.Sprintf("decoded to %d bytes; want %d", len(key), ed25519.PublicKeySize)})
		return
	}
	_, err = h.updateTenantPolicy(r.Context(), tenant, func(tp *store.TenantPolicy) { tp.TenantCmdPubKey = key })
	h.finishUpdate(w, r, p, tenant, "pki.tenant_policy.command_key.set", err, "key_sha256_prefix", fingerprint(key))
}

func (h *Handler) putFirmwareKeys(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenant, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	var body firmwareKeysBody
	if err := decodeStrict(r, &body); err != nil {
		writeProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	var errs []fieldError
	if len(body.PublicKeysB64) == 0 {
		errs = append(errs, fieldError{Field: "public_keys_b64", Detail: "at least one Ed25519 key is required"})
	}
	if len(body.PublicKeysB64) > MaxFirmwareKeys {
		errs = append(errs, fieldError{Field: "public_keys_b64", Detail: fmt.Sprintf("at most %d keys", MaxFirmwareKeys)})
	}
	keys := make([][]byte, 0, len(body.PublicKeysB64))
	seen := map[string]bool{}
	ed := 0
	for i, s := range body.PublicKeysB64 {
		field := fmt.Sprintf("public_keys_b64[%d]", i)
		key, err := decodeKey(s)
		switch {
		case err != nil:
			errs = append(errs, fieldError{Field: field, Detail: "not valid base64"})
			continue
		case len(key) == ed25519.PublicKeySize:
			ed++
		case len(key) == MLDSA65PublicKeySize:
		default:
			errs = append(errs, fieldError{Field: field, Detail: fmt.Sprintf("decoded to %d bytes; want %d (Ed25519) or %d (ML-DSA-65)", len(key), ed25519.PublicKeySize, MLDSA65PublicKeySize)})
			continue
		}
		if seen[string(key)] {
			errs = append(errs, fieldError{Field: field, Detail: "duplicate key"})
			continue
		}
		seen[string(key)] = true
		keys = append(keys, key)
	}
	if len(body.PublicKeysB64) > 0 && ed == 0 {
		errs = append(errs, fieldError{Field: "public_keys_b64", Detail: "at least one Ed25519 key is required (DESIGN_CONTRACT §6)"})
	}
	if len(errs) > 0 {
		writeProblem(w, r, http.StatusUnprocessableEntity, "invalid firmware signing keys", errs...)
		return
	}
	prints := make([]string, len(keys))
	for i, k := range keys {
		prints[i] = fingerprint(k)
	}
	_, err := h.updateTenantPolicy(r.Context(), tenant, func(tp *store.TenantPolicy) { tp.FwSigningPubKeys = keys })
	h.finishUpdate(w, r, p, tenant, "pki.tenant_policy.firmware_keys.set", err, "key_sha256_prefixes", prints)
}

func (h *Handler) putEnrollment(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenant, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	var body enrollmentBody
	if err := decodeStrict(r, &body); err != nil {
		writeProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if body.AllowSoftwareKeys == nil {
		writeProblem(w, r, http.StatusUnprocessableEntity, "allow_software_keys is required", fieldError{Field: "allow_software_keys", Detail: "required boolean"})
		return
	}
	allow := *body.AllowSoftwareKeys
	_, err := h.updateTenantPolicy(r.Context(), tenant, func(tp *store.TenantPolicy) { tp.AllowSoftwareKeys = allow })
	h.finishUpdate(w, r, p, tenant, "pki.tenant_policy.enrollment.set", err, "allow_software_keys", allow)
}

func (h *Handler) getTenantPolicy(w http.ResponseWriter, r *http.Request, _ *Principal) {
	tenant, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	view := tenantPolicyView{FirmwareKeysB64: []string{}, AllowSoftwareKeys: h.cfg.DefaultAllowSoftwareKeys}
	pol, err := h.cfg.Store.GetTenantPolicy(r.Context(), tenant)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		logging.FromContext(r.Context()).Error("tenant policy lookup failed", "tenant_id", tenant, "error", err.Error())
		writeProblem(w, r, http.StatusServiceUnavailable, "tenant policy lookup failed")
		return
	default:
		if len(pol.TenantCmdPubKey) > 0 {
			view.CommandKeyB64 = base64.StdEncoding.EncodeToString(pol.TenantCmdPubKey)
		}
		for _, k := range pol.FwSigningPubKeys {
			view.FirmwareKeysB64 = append(view.FirmwareKeysB64, base64.StdEncoding.EncodeToString(k))
		}
		view.AllowSoftwareKeys = pol.AllowSoftwareKeys
		if !pol.UpdatedAt.IsZero() {
			at := pol.UpdatedAt.UTC()
			view.UpdatedAt = &at
		}
	}
	writeJSON(w, http.StatusOK, view)
}
