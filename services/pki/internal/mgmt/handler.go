// Package mgmt implements the management API on the mTLS listener:
//
//	POST /v1/certificates/{serial}/revoke      {"reason": "keyCompromise"}
//	GET  /v1/certificates/{serial}
//	GET  /v1/devices/{device_id}/certificates
//	POST /v1/devices/{device_id}/revoke-all    {"reason": "..."}
//	GET  /v1/ca/chain                          PEM bundle
//	GET  /v1/stats                             expiring counts (24h/72h/7d)
//	POST /v1/devices/{device_id}/release       (registry) {"tenant_id": "..."}
//	PUT  /v1/tenants/{tenant}/command-key      (registry) tenant command key
//	PUT  /v1/tenants/{tenant}/firmware-keys    (ota) firmware signing keys
//	PUT  /v1/tenants/{tenant}/enrollment       (registry) allow_software_keys
//	GET  /v1/tenants/{tenant}/policy
//
// Callers authenticate with a Services CA client certificate whose CN is on
// the allow list or with an ES256 JWT (aud=pki). The tenant policy endpoints
// authorize by owning service instead (see tenant.go).
package mgmt

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Revoker is satisfied by *revocation.Service.
type Revoker interface {
	Revoke(ctx context.Context, serial, reason, revokedBy string) (*revocation.Result, error)
	RevokeDevice(ctx context.Context, deviceID, reason, revokedBy string) ([]*revocation.Result, error)
}

// Releaser is satisfied by *revocation.Service.
type Releaser interface {
	Release(ctx context.Context, deviceID, tenantID, releasedBy string) (*revocation.ReleaseResult, error)
}

// Config wires the handler.
type Config struct {
	Auth    *Authenticator
	Revoker Revoker
	// Releaser serves POST /v1/devices/{device_id}/release; when nil the
	// Revoker is used if it implements Releaser (otherwise 501).
	Releaser Releaser
	Store    store.Store
	// Chain is returned by /v1/ca/chain (root, factory, device, services).
	Chain   []*x509.Certificate
	Metrics *metrics.Metrics
	Clock   func() time.Time
	// DefaultAllowSoftwareKeys seeds allow_software_keys when a tenant policy
	// is first created through the tenant policy API (PKI_DEFAULT_ALLOW_SOFTWARE_KEYS).
	DefaultAllowSoftwareKeys bool
}

// Handler serves the management API.
type Handler struct {
	cfg      Config
	tenantMu sync.Mutex
}

// NewHandler validates the configuration.
func NewHandler(cfg Config) (*Handler, error) {
	switch {
	case cfg.Auth == nil:
		return nil, errors.New("mgmt: an authenticator is required")
	case cfg.Revoker == nil:
		return nil, errors.New("mgmt: a revoker is required")
	case cfg.Store == nil:
		return nil, errors.New("mgmt: a store is required")
	case cfg.Metrics == nil:
		return nil, errors.New("mgmt: metrics are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Releaser == nil {
		if r, ok := cfg.Revoker.(Releaser); ok {
			cfg.Releaser = r
		}
	}
	return &Handler{cfg: cfg}, nil
}

// Register mounts the endpoints on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/certificates/{serial}/revoke", h.auth(h.revoke))
	mux.Handle("GET /v1/certificates/{serial}", h.auth(h.getCertificate))
	mux.Handle("GET /v1/devices/{device_id}/certificates", h.auth(h.listDeviceCertificates))
	mux.Handle("POST /v1/devices/{device_id}/revoke-all", h.auth(h.revokeDevice))
	mux.Handle("GET /v1/ca/chain", h.auth(h.chain))
	mux.Handle("GET /v1/stats", h.auth(h.stats))
	mux.Handle("POST /v1/devices/{device_id}/release", h.ownerAuth(OwnerRelease, h.releaseDevice))
	h.registerTenantRoutes(mux)
}

type principalKey struct{}

func (h *Handler) auth(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := h.cfg.Auth.Authenticate(r)
		if err != nil {
			h.cfg.Metrics.AuthFailures.Inc()
			status := http.StatusUnauthorized
			if errors.Is(err, ErrForbidden) {
				status = http.StatusForbidden
			}
			logging.FromContext(r.Context()).Warn("management request rejected", "path", r.URL.Path, "status", status, "error", err.Error())
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="pki"`)
			}
			writeJSON(w, status, map[string]string{"error": http.StatusText(status)})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func principalFrom(ctx context.Context) *Principal {
	if p, ok := ctx.Value(principalKey{}).(*Principal); ok {
		return p
	}
	return &Principal{Subject: "unknown"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func readReason(r *http.Request) (string, error) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 4096))
	if err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "unspecified", nil
	}
	var rb reasonBody
	if err := json.Unmarshal(body, &rb); err != nil {
		return "", err
	}
	if rb.Reason == "" {
		rb.Reason = "unspecified"
	}
	return rb.Reason, nil
}

// certificateView is the JSON representation of a certificate record.
type certificateView struct {
	Serial     string          `json:"serial"`
	DeviceID   string          `json:"device_id"`
	TenantID   string          `json:"tenant_id"`
	Kind       string          `json:"kind"`
	Issuer     string          `json:"issuer"`
	NotBefore  time.Time       `json:"not_before"`
	NotAfter   time.Time       `json:"not_after"`
	Assurance  string          `json:"assurance_level,omitempty"`
	Status     string          `json:"status"` // valid | revoked | expired
	Revocation *revocationView `json:"revocation,omitempty"`
	PEM        string          `json:"certificate_pem,omitempty"`
}

type revocationView struct {
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	RevokedBy string    `json:"revoked_by,omitempty"`
}

func (h *Handler) view(ctx context.Context, rec *store.CertificateRecord, includePEM bool) certificateView {
	now := h.cfg.Clock().UTC()
	v := certificateView{
		Serial: rec.Serial, DeviceID: rec.DeviceID, TenantID: rec.TenantID, Kind: rec.Kind, Issuer: rec.IssuerCN,
		NotBefore: rec.NotBefore, NotAfter: rec.NotAfter, Assurance: rec.Assurance, Status: "valid",
	}
	if !rec.NotAfter.After(now) {
		v.Status = "expired"
	}
	if rev, err := h.cfg.Store.GetRevocation(ctx, rec.Serial); err == nil {
		v.Status = "revoked"
		v.Revocation = &revocationView{Reason: ca.ReasonString(rev.Reason), RevokedAt: rev.RevokedAt, RevokedBy: rev.RevokedBy}
	}
	if includePEM {
		if cert, err := x509.ParseCertificate(rec.DER); err == nil {
			v.PEM = string(ca.EncodeCertPEM(cert))
		}
	}
	return v
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	reason, err := readReason(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	p := principalFrom(r.Context())
	res, err := h.cfg.Revoker.Revoke(r.Context(), r.PathValue("serial"), reason, p.Subject)
	switch {
	case errors.Is(err, revocation.ErrInvalidSerial), errors.Is(err, revocation.ErrInvalidReason):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, revocation.ErrNotFound):
		writeError(w, http.StatusNotFound, "certificate not found")
	case errors.Is(err, revocation.ErrAlreadyRevoked):
		writeError(w, http.StatusConflict, "certificate already revoked")
	case err != nil:
		logging.FromContext(r.Context()).Error("revocation failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "revocation failed")
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

func (h *Handler) getCertificate(w http.ResponseWriter, r *http.Request) {
	_, canonical, err := ca.ParseSerial(r.PathValue("serial"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid serial")
		return
	}
	rec, err := h.cfg.Store.GetCertificate(r.Context(), canonical)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, h.view(r.Context(), rec, true))
}

func (h *Handler) listDeviceCertificates(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device_id")
	if err := ca.ValidateDeviceID(deviceID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	recs, err := h.cfg.Store.ListCertificatesByDevice(r.Context(), deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	views := make([]certificateView, 0, len(recs))
	for _, rec := range recs {
		views = append(views, h.view(r.Context(), rec, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_id": deviceID, "certificates": views})
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device_id")
	if err := ca.ValidateDeviceID(deviceID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	reason, err := readReason(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	p := principalFrom(r.Context())
	results, err := h.cfg.Revoker.RevokeDevice(r.Context(), deviceID, reason, p.Subject)
	if errors.Is(err, revocation.ErrInvalidReason) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		logging.FromContext(r.Context()).Error("device revocation failed", "device_id", deviceID, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_id": deviceID, "revoked": results, "count": len(results)})
}

func (h *Handler) chain(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ca.EncodeChainPEM(h.cfg.Chain...))
}

// StatsResponse is the body of GET /v1/stats.
type StatsResponse struct {
	Certificates store.Stats    `json:"certificates"`
	Expiring     map[string]int `json:"expiring"`
	GeneratedAt  time.Time      `json:"generated_at"`
}

// Stats computes the statistics and updates the expiring gauges.
func (h *Handler) Stats(ctx context.Context) (*StatsResponse, error) {
	return ComputeStats(ctx, h.cfg.Store, h.cfg.Metrics, h.cfg.Clock().UTC())
}

// ComputeStats computes certificate statistics and refreshes
// ironmesh_cert_expiring_total{window}.
func ComputeStats(ctx context.Context, st store.Store, m *metrics.Metrics, now time.Time) (*StatsResponse, error) {
	stats, err := st.Stats(ctx, now)
	if err != nil {
		return nil, err
	}
	windows := map[string]time.Duration{"24h": 24 * time.Hour, "72h": 72 * time.Hour, "7d": 7 * 24 * time.Hour}
	out := &StatsResponse{Certificates: *stats, Expiring: map[string]int{}, GeneratedAt: now}
	for _, name := range metrics.Windows {
		n, err := st.CountExpiring(ctx, now, now.Add(windows[name]))
		if err != nil {
			return nil, err
		}
		out.Expiring[name] = n
		m.CertExpiring.WithLabelValues(name).Set(float64(n))
	}
	return out, nil
}

func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	res, err := h.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats unavailable")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
