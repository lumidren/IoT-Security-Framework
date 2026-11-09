package mgmt

// Device release (API_CONTRACT §5):
//
//	POST /v1/devices/{device_id}/release  (registry) {"tenant_id": "<uuid>", "note": "..."}
//	  -> 202 {event_id, event: "device_release", device_id, tenant_id, released_at, published, publish_error?}
//
// The registry calls it when an admin releases a quarantined device. The PKI
// writes a device_release event into the revocation outbox (same signed push,
// retries and DNS fan-out as revocations); the Policy service then lifts the
// device-level deny the quarantine installed. Certificates revoked by the
// quarantine stay revoked (serial-level denies remain), so the device must
// re-enroll. Only the registry may call it: a Services CA client certificate
// with CN svc-registry or a service JWT whose sub is registry/svc-registry,
// independently of PKI_MGMT_ALLOWED_CNS.

import (
	"errors"
	"net/http"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
)

// OwnerRelease is the only service allowed to release devices.
const OwnerRelease = "registry"

// maxReleaseNote bounds the optional audit note.
const maxReleaseNote = 1024

type releaseBody struct {
	TenantID *string `json:"tenant_id"`
	Note     string  `json:"note,omitempty"`
}

// ownerAuth authenticates the caller (Identify, no CN allow list) and admits
// only the owning service.
func (h *Handler) ownerAuth(owner string, next func(http.ResponseWriter, *http.Request, *Principal)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := logging.FromContext(r.Context())
		p, err := h.cfg.Auth.Identify(r)
		if err != nil {
			h.cfg.Metrics.AuthFailures.Inc()
			log.Warn("management request rejected", "path", r.URL.Path, "status", http.StatusUnauthorized, "error", err.Error())
			w.Header().Set("WWW-Authenticate", `Bearer realm="pki"`)
			writeProblem(w, r, http.StatusUnauthorized, "a Services CA client certificate or a service JWT (aud=pki) is required")
			return
		}
		if p.Service() != owner {
			h.cfg.Metrics.AuthFailures.Inc()
			log.Warn("management request forbidden", "audit", true, "outcome", "failure", "path", r.URL.Path, "method", r.Method,
				"actor", p.Subject, "auth_method", p.Method, "required_owner", owner)
			writeProblem(w, r, http.StatusForbidden, "only the "+owner+" service may call this endpoint")
			return
		}
		next(w, r, p)
	})
}

func (h *Handler) releaseDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	log := logging.FromContext(r.Context())
	deviceID := r.PathValue("device_id")
	if err := ca.ValidateDeviceID(deviceID); err != nil {
		writeProblem(w, r, http.StatusUnprocessableEntity, "invalid device id", fieldError{Field: "device_id", Detail: err.Error()})
		return
	}
	var body releaseBody
	if err := decodeStrict(r, &body); err != nil {
		writeProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	var errs []fieldError
	switch {
	case body.TenantID == nil:
		errs = append(errs, fieldError{Field: "tenant_id", Detail: "required"})
	default:
		if err := ca.ValidateTenantID(*body.TenantID); err != nil {
			errs = append(errs, fieldError{Field: "tenant_id", Detail: err.Error()})
		}
	}
	if len(body.Note) > maxReleaseNote {
		errs = append(errs, fieldError{Field: "note", Detail: "at most 1024 bytes"})
	}
	if len(errs) > 0 {
		writeProblem(w, r, http.StatusUnprocessableEntity, "validation failed", errs...)
		return
	}
	tenant := *body.TenantID
	audit := []any{"audit", true, "action", "pki.device.release", "actor", p.Subject, "auth_method", p.Method,
		"device_id", deviceID, "tenant_id", tenant, "note", body.Note}
	if h.cfg.Releaser == nil {
		writeProblem(w, r, http.StatusNotImplemented, "device release is not available")
		return
	}
	res, err := h.cfg.Releaser.Release(r.Context(), deviceID, tenant, p.Subject)
	switch {
	case errors.Is(err, revocation.ErrTenantMismatch):
		log.Warn("device release refused", append(audit, "outcome", "failure", "error", err.Error())...)
		writeProblem(w, r, http.StatusConflict, "the device's certificates belong to another tenant")
		return
	case err != nil:
		log.Error("device release failed", append(audit, "outcome", "failure", "error", err.Error())...)
		writeProblem(w, r, http.StatusServiceUnavailable, "device release could not be queued")
		return
	}
	log.Info("device release queued", append(audit, "outcome", "success", "event_id", res.EventID, "published", res.Published)...)
	writeJSON(w, http.StatusAccepted, res)
}
