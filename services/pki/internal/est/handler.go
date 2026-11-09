// Package est implements the RFC 7030 EST endpoints with IronMesh's
// attestation extension (DESIGN_CONTRACT §3) on the mTLS listener:
//
//	GET  /.well-known/est/cacerts          certs-only PKCS#7 of the CA hierarchy
//	GET  /.well-known/est/csrattrs         CsrAttrs (ecPublicKey, P-256, ecdsa-with-SHA256)
//	GET  /.well-known/est/ironmesh/nonce   single-use 32-byte attestation nonce (120 s)
//	POST /.well-known/est/simpleenroll     first enrollment with a Factory CA bootstrap cert
//	POST /.well-known/est/simplereenroll   renewal with the current Device CA cert
//
// Besides the contract checks, the handler implements the THREAT_MODEL.md
// controls: per-device and per-IP rate limits, rejection of reused keys,
// consistency of the attested se_type and bootstrap serial with the
// manufacture record, and revocation of the superseded certificate after a
// grace period on renewal.
package est

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Wire constants.
const (
	BasePath            = "/.well-known/est"
	ContentTypePKCS10   = "application/pkcs10"
	ContentTypePKCS7    = "application/pkcs7-mime; smime-type=certs-only"
	ContentTypeCSRAttrs = "application/csrattrs"
	HeaderAttestation   = "X-IronMesh-Attestation"
	HeaderBundle        = "X-IronMesh-Bundle"
	// HeaderSupersedes tells a renewing device when its previous certificate
	// will be revoked (RFC 3339).
	HeaderSupersedes = "X-IronMesh-Previous-Revoked-At"
	DefaultNonceTTL  = 120 * time.Second
	// DefaultSupersedeGrace is how long a superseded operational certificate
	// stays valid after a successful renewal.
	DefaultSupersedeGrace = time.Hour
	// DefaultRegistryRetries / DefaultRegistryBackoff bound the synchronous
	// enrolled callback to the Registry (API_CONTRACT §5).
	DefaultRegistryRetries = 3
	DefaultRegistryBackoff = 500 * time.Millisecond
	// DefaultEnrollRetryAfter is the Retry-After of a 503 caused by a failed
	// enrolled callback.
	DefaultEnrollRetryAfter = 30 * time.Second
	// RollbackRevokedBy is recorded as the revoker of a certificate revoked
	// because the Registry could not record its enrollment.
	RollbackRevokedBy = "pki:enroll-rollback"

	maxBodySize = 64 << 10
)

// Revoker revokes certificates; *revocation.Service satisfies it.
type Revoker interface {
	Revoke(ctx context.Context, serial, reason, revokedBy string) (*revocation.Result, error)
}

// RollbackRevoker revokes a certificate that was issued but never delivered
// to the device; *revocation.Service satisfies it (RevokeUndelivered writes
// the revocation, regenerates the CRL and invalidates OCSP without pushing a
// device deny-list event to the Policy service).
type RollbackRevoker interface {
	RevokeUndelivered(ctx context.Context, serial, reason, revokedBy string) (*revocation.Result, error)
}

// Config wires the EST handler.
type Config struct {
	DeviceCA  *ca.CA
	FactoryCA *x509.Certificate
	// CACerts are returned by /cacerts (root, factory, device, services).
	CACerts  []*x509.Certificate
	Store    store.Store
	Registry registry.Client
	Bundler  *Bundler
	Metrics  *metrics.Metrics
	Logger   *slog.Logger
	Clock    func() time.Time
	NonceTTL time.Duration
	// DefaultAllowSoftwareKeys applies to tenants without a stored policy.
	DefaultAllowSoftwareKeys bool
	// DefaultAKRoots and DefaultPCRDigests are merged into every tenant policy.
	DefaultAKRoots    []*x509.Certificate
	DefaultPCRDigests []string
	// Revoker, when set, revokes the superseded certificate after
	// SupersedeGrace on successful re-enrollment.
	Revoker        Revoker
	SupersedeGrace time.Duration
	// Rollback revokes (reason cessationOfOperation) a just-issued
	// certificate when the Registry cannot record the enrollment. When nil
	// the revocation is written to the store directly (CRL and OCSP pick it
	// up on their next refresh).
	Rollback RollbackRevoker
	// RateLimit bounds nonce and enrollment requests per device and per IP.
	RateLimit RateLimitConfig
	// RegistryRetries is how many times the enrolled callback to the Registry
	// is retried after the first attempt (0 = DefaultRegistryRetries,
	// negative = no retries). RegistryBackoff is the pause between attempts.
	RegistryRetries int
	RegistryBackoff time.Duration
	// EnrollRetryAfter is the Retry-After sent with the 503 returned when the
	// Registry cannot record an enrollment (default DefaultEnrollRetryAfter).
	EnrollRetryAfter time.Duration
}

// Handler serves the EST endpoints.
type Handler struct {
	cfg           Config
	ipLimiter     *limiter
	deviceLimiter *limiter
}

// NewHandler validates the configuration and returns a Handler.
func NewHandler(cfg Config) (*Handler, error) {
	switch {
	case cfg.DeviceCA == nil || cfg.DeviceCA.Kind() != ca.KindDevice:
		return nil, errors.New("est: a Device CA is required")
	case cfg.FactoryCA == nil:
		return nil, errors.New("est: the Factory CA certificate is required")
	case cfg.Store == nil:
		return nil, errors.New("est: a store is required")
	case cfg.Registry == nil:
		return nil, errors.New("est: a registry client is required")
	case cfg.Bundler == nil:
		return nil, errors.New("est: a bundler is required")
	case cfg.Metrics == nil:
		return nil, errors.New("est: metrics are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = DefaultNonceTTL
	}
	if cfg.SupersedeGrace <= 0 {
		cfg.SupersedeGrace = DefaultSupersedeGrace
	}
	cfg = cfg.withRegistryDefaults()
	if len(cfg.CACerts) == 0 {
		cfg.CACerts = append([]*x509.Certificate{cfg.FactoryCA}, cfg.DeviceCA.Chain()...)
	}
	cfg.RateLimit = cfg.RateLimit.withDefaults()
	return &Handler{
		cfg:           cfg,
		ipLimiter:     newLimiter(cfg.RateLimit.IPBurst, cfg.RateLimit.IPPerMinute),
		deviceLimiter: newLimiter(cfg.RateLimit.DeviceBurst, cfg.RateLimit.DevicePerMinute),
	}, nil
}

// Register mounts the endpoints on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+BasePath+"/cacerts", h.cacerts)
	mux.HandleFunc("GET "+BasePath+"/csrattrs", h.csrattrs)
	mux.HandleFunc("GET "+BasePath+"/ironmesh/nonce", h.nonce)
	mux.HandleFunc("POST "+BasePath+"/simpleenroll", func(w http.ResponseWriter, r *http.Request) { h.enroll(w, r, false) })
	mux.HandleFunc("POST "+BasePath+"/simplereenroll", func(w http.ResponseWriter, r *http.Request) { h.enroll(w, r, true) })
}

func (h *Handler) now() time.Time { return h.cfg.Clock().UTC() }

func (h *Handler) count(op string, status int) {
	h.cfg.Metrics.ESTRequests.WithLabelValues(op, strconv.Itoa(status)).Inc()
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		h.cfg.Metrics.AuthFailures.Inc()
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, op string, e *httpError, attrs ...any) {
	l := logging.FromContext(r.Context())
	attrs = append(attrs, "op", op, "status", e.status, "reason", e.msg)
	if e.cause != nil {
		attrs = append(attrs, "error", e.cause.Error())
	}
	if e.status >= 500 {
		l.Error("est request failed", attrs...)
	} else {
		l.Warn("est request rejected", attrs...)
	}
	h.count(op, e.status)
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int((e.retryAfter+time.Second-1)/time.Second)))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, e.msg, e.status)
}

func (h *Handler) cacerts(w http.ResponseWriter, r *http.Request) {
	der, err := EncodeCertsOnly(h.cfg.CACerts)
	if err != nil {
		h.fail(w, r, "cacerts", errInternal("cannot encode CA certificates", err))
		return
	}
	h.count("cacerts", http.StatusOK)
	writeBase64(w, ContentTypePKCS7, der)
}

func (h *Handler) csrattrs(w http.ResponseWriter, r *http.Request) {
	der, err := EncodeCSRAttrs(CSRAttrsOIDs())
	if err != nil {
		h.fail(w, r, "csrattrs", errInternal("cannot encode CSR attributes", err))
		return
	}
	h.count("csrattrs", http.StatusOK)
	writeBase64(w, ContentTypeCSRAttrs, der)
}

func writeBase64(w http.ResponseWriter, contentType string, der []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, encodeBase64Lines(der))
}

// nonceResponse is the JSON body of GET /ironmesh/nonce.
type nonceResponse struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) nonce(w http.ResponseWriter, r *http.Request) {
	const op = "nonce"
	if !h.rateLimit(w, r, op, "") {
		return
	}
	now := h.now()
	id, herr := Identify(r.Context(), r, h.cfg.FactoryCA, h.cfg.DeviceCA.Certificate(), h.cfg.Store, now)
	if herr != nil {
		h.fail(w, r, op, herr)
		return
	}
	if !h.rateLimit(w, r, op, id.ID.DeviceID) {
		return
	}
	raw := make([]byte, attest.NonceSize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		h.fail(w, r, op, errInternal("cannot generate nonce", err))
		return
	}
	n := &store.Nonce{
		Value:     base64.RawURLEncoding.EncodeToString(raw),
		DeviceID:  id.ID.DeviceID,
		TenantID:  id.ID.TenantID,
		IssuedAt:  now,
		ExpiresAt: now.Add(h.cfg.NonceTTL),
	}
	if err := h.cfg.Store.PutNonce(r.Context(), n); err != nil {
		h.fail(w, r, op, errUnavailable("cannot store nonce", err), "device_id", id.ID.DeviceID, "tenant_id", id.ID.TenantID)
		return
	}
	h.count(op, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(nonceResponse{Nonce: n.Value, ExpiresAt: n.ExpiresAt})
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request, reenroll bool) {
	op := "simpleenroll"
	if reenroll {
		op = "simplereenroll"
	}
	if !h.rateLimit(w, r, op, "") {
		return
	}
	ctx := r.Context()
	now := h.now()

	// 1. TLS client identity, issuer and revocation state.
	client, herr := Identify(ctx, r, h.cfg.FactoryCA, h.cfg.DeviceCA.Certificate(), h.cfg.Store, now)
	if herr != nil {
		h.fail(w, r, op, herr)
		return
	}
	deviceID, tenantID := client.ID.DeviceID, client.ID.TenantID
	attrs := []any{"device_id", deviceID, "tenant_id", tenantID}
	if !h.rateLimit(w, r, op, deviceID) {
		return
	}
	if reenroll && client.Issuer != ca.KindDevice {
		h.fail(w, r, op, errForbidden("simplereenroll requires the current operational certificate issued by the Device CA"), attrs...)
		return
	}
	if !reenroll && client.Issuer != ca.KindFactory {
		h.fail(w, r, op, errForbidden("simpleenroll requires a bootstrap certificate issued by the Factory CA"), attrs...)
		return
	}

	// 2. CSR.
	csrDER, csr, herr := h.readCSR(w, r)
	if herr != nil {
		h.fail(w, r, op, herr, attrs...)
		return
	}
	if csr.Subject.CommonName != deviceID {
		h.fail(w, r, op, errForbidden("CSR subject CN does not match the client certificate device id"), attrs...)
		return
	}
	if !containsOnly(csr.Subject.OrganizationalUnit, tenantID) {
		h.fail(w, r, op, errForbidden("CSR subject OU must be the tenant id of the client certificate"), attrs...)
		return
	}
	csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || csrPub.Curve != elliptic.P256() {
		h.fail(w, r, op, errBadRequest("CSR public key must be ECDSA P-256", nil), attrs...)
		return
	}
	if csrPub.Equal(client.Cert.PublicKey) {
		h.fail(w, r, op, errBadRequest("CSR must use a freshly generated key, not the current identity key", nil), attrs...)
		return
	}
	if herr := h.rejectReusedKey(ctx, deviceID, csrPub); herr != nil {
		h.fail(w, r, op, herr, attrs...)
		return
	}
	for _, u := range csr.URIs {
		if t, d, err := ca.ParseDeviceURN(u); err != nil || t != tenantID || d != deviceID {
			h.fail(w, r, op, errForbidden("CSR SAN URI does not match the device identity"), attrs...)
			return
		}
	}

	// 3. Attestation: signature by the current identity key, kid, nonce, CSR binding.
	hdr := r.Header.Get(HeaderAttestation)
	if hdr == "" {
		h.fail(w, r, op, errUnauthorized(HeaderAttestation+" header is required"), attrs...)
		return
	}
	rawAtt, err := decodeBase64(hdr)
	if err != nil {
		h.fail(w, r, op, errBadRequest("attestation header is not valid base64", err), attrs...)
		return
	}
	st, err := attest.Parse(rawAtt)
	if err != nil {
		h.failAttestation(w, r, op, err, attrs)
		return
	}
	clientPub, _ := client.Cert.PublicKey.(*ecdsa.PublicKey)
	if err := st.VerifySignature(clientPub); err != nil {
		h.failAttestation(w, r, op, err, attrs)
		return
	}
	if err := st.VerifyTimestamp(now); err != nil {
		h.failAttestation(w, r, op, err, attrs)
		return
	}
	if err := st.VerifyKeyID(client.Cert.SerialNumber.Bytes()); err != nil {
		h.failAttestation(w, r, op, err, attrs)
		return
	}
	nonceValue := base64.RawURLEncoding.EncodeToString(st.Nonce)
	nonce, err := h.cfg.Store.ConsumeNonce(ctx, nonceValue, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.fail(w, r, op, errUnauthorized("nonce is unknown or has already been used"), attrs...)
		return
	case errors.Is(err, store.ErrNonceExpired):
		h.fail(w, r, op, errUnauthorized("nonce has expired"), attrs...)
		return
	case err != nil:
		h.fail(w, r, op, errUnavailable("nonce lookup failed", err), attrs...)
		return
	case nonce.DeviceID != deviceID || nonce.TenantID != tenantID:
		h.fail(w, r, op, errUnauthorized("nonce was issued to a different device"), attrs...)
		return
	}
	if err := st.VerifyBinding(csrDER); err != nil {
		h.failAttestation(w, r, op, err, attrs)
		return
	}

	// 4. Tenant policy: se_type assurance and TPM evidence.
	tenantPolicy, attestPolicy, herr := h.policyFor(ctx, tenantID)
	if herr != nil {
		h.fail(w, r, op, herr, attrs...)
		return
	}
	result, err := st.VerifyEvidence(attestPolicy, now)
	if err != nil {
		h.failAttestation(w, r, op, err, attrs)
		return
	}

	// 5. Device lifecycle state and manufacture record from the Registry.
	dev, err := h.cfg.Registry.GetDevice(ctx, tenantID, deviceID)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		h.fail(w, r, op, errForbidden("device is not registered"), attrs...)
		return
	case err != nil:
		h.fail(w, r, op, errUnavailable("registry lookup failed", err), attrs...)
		return
	case dev.TenantID != "" && dev.TenantID != tenantID:
		h.fail(w, r, op, errForbidden("device belongs to a different tenant"), attrs...)
		return
	case !dev.State.EnrollmentAllowed():
		h.fail(w, r, op, errForbidden(fmt.Sprintf("device lifecycle state %q does not permit enrollment", dev.State)), attrs...)
		return
	}
	if herr := checkBootstrapSerialMatchesManufactureRecord(client, dev); herr != nil {
		h.fail(w, r, op, herr, attrs...)
		return
	}
	if herr := checkSeTypeAgainstManufactureRecord(dev, result.SeType); herr != nil {
		h.fail(w, r, op, herr, attrs...)
		return
	}

	// 6. Issue, record, bundle, report to the Registry, supersede.
	cert, err := h.cfg.DeviceCA.IssueOperational(ca.DeviceRequest{TenantID: tenantID, DeviceID: deviceID, PublicKey: csrPub, Assurance: result.Assurance})
	if err != nil {
		h.fail(w, r, op, errInternal("certificate issuance failed", err), attrs...)
		return
	}
	rec := ca.NewRecord(cert, store.KindOperational, result.Assurance, now)
	if err := h.cfg.Store.PutCertificate(ctx, rec); err != nil {
		h.fail(w, r, op, errUnavailable("cannot record certificate", err), attrs...)
		return
	}
	newSerial := ca.FormatSerial(cert.SerialNumber)
	bundleHdr, err := h.cfg.Bundler.BuildHeader(tenantPolicy)
	if err != nil {
		h.rollback(ctx, rec, attrs)
		h.fail(w, r, op, errInternal("cannot build trust bundle", err), attrs...)
		return
	}
	der, err := EncodeCertsOnly([]*x509.Certificate{cert})
	if err != nil {
		h.rollback(ctx, rec, attrs)
		h.fail(w, r, op, errInternal("cannot encode certificate", err), attrs...)
		return
	}
	enrollment := registry.Enrollment{
		SerialHex: newSerial, NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
		SeType: result.SeType, AssuranceLevel: result.Assurance, FwVersion: result.FwVersion,
	}
	if len(result.FwHash) > 0 {
		enrollment.FwHashHex = hex.EncodeToString(result.FwHash)
	}
	if err := h.recordEnrollment(ctx, tenantID, deviceID, enrollment); err != nil {
		h.rollback(ctx, rec, attrs)
		e := errUnavailable("the registry could not record the enrollment; the certificate was revoked, retry later", err)
		e.retryAfter = h.cfg.EnrollRetryAfter
		h.fail(w, r, op, e, append(attrs, "serial", newSerial)...)
		return
	}
	if err := h.cfg.Registry.RecordAssurance(ctx, tenantID, deviceID, result.Assurance); err != nil {
		logging.FromContext(ctx).Error("recording assurance level in registry failed", append(attrs, "error", err.Error())...)
	}
	if reenroll {
		if due, ok := h.supersedePrevious(client, newSerial); ok {
			w.Header().Set(HeaderSupersedes, due.Format(time.RFC3339))
		}
	}
	h.cfg.Metrics.CertsIssued.WithLabelValues(store.KindOperational).Inc()
	h.count(op, http.StatusOK)
	logging.FromContext(ctx).Info("operational certificate issued", append(attrs,
		"op", op, "serial", newSerial, "se_type", result.SeType, "assurance", result.Assurance,
		"fw_version", result.FwVersion, "not_after", cert.NotAfter)...)
	w.Header().Set(HeaderBundle, bundleHdr)
	w.Header().Set("Cache-Control", "no-store")
	writeBase64(w, ContentTypePKCS7, der)
}

func (c Config) withRegistryDefaults() Config {
	switch {
	case c.RegistryRetries == 0:
		c.RegistryRetries = DefaultRegistryRetries
	case c.RegistryRetries < 0:
		c.RegistryRetries = 0
	}
	if c.RegistryBackoff <= 0 {
		c.RegistryBackoff = DefaultRegistryBackoff
	}
	if c.EnrollRetryAfter <= 0 {
		c.EnrollRetryAfter = DefaultEnrollRetryAfter
	}
	return c
}

// recordEnrollment calls the Registry's enrolled callback, retrying
// transient failures RegistryRetries times with RegistryBackoff between
// attempts. ErrNotFound and ErrRejected are not retried.
func (h *Handler) recordEnrollment(ctx context.Context, tenantID, deviceID string, e registry.Enrollment) error {
	var err error
	for attempt := 0; attempt <= h.cfg.RegistryRetries; attempt++ {
		if attempt > 0 {
			t := time.NewTimer(h.cfg.RegistryBackoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return errors.Join(err, ctx.Err())
			case <-t.C:
			}
		}
		if err = h.cfg.Registry.RecordEnrollment(ctx, tenantID, deviceID, e); err == nil {
			return nil
		}
		logging.FromContext(ctx).Warn("registry enrolled callback failed", "device_id", deviceID, "tenant_id", tenantID,
			"serial", e.SerialHex, "attempt", attempt+1, "error", err.Error())
		if errors.Is(err, registry.ErrNotFound) || errors.Is(err, registry.ErrRejected) {
			return err
		}
	}
	return err
}

// rollback revokes a certificate that was recorded but will not be
// delivered, so a device is never active in the PKI while unknown to (or
// not activated by) the Registry. It runs detached from the request context
// so a client disconnect cannot leave the certificate valid.
func (h *Handler) rollback(ctx context.Context, rec *store.CertificateRecord, attrs []any) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	log := logging.FromContext(ctx)
	const reason = "cessationOfOperation"
	var err error
	if h.cfg.Rollback != nil {
		_, err = h.cfg.Rollback.RevokeUndelivered(ctx, rec.Serial, reason, RollbackRevokedBy)
	} else {
		err = h.cfg.Store.AddRevocation(ctx, &store.Revocation{
			Serial: rec.Serial, DeviceID: rec.DeviceID, TenantID: rec.TenantID, IssuerCN: rec.IssuerCN, NotAfter: rec.NotAfter,
			Reason: ca.ReasonCessationOfOperation, RevokedAt: h.now(), RevokedBy: RollbackRevokedBy,
		})
	}
	if err != nil && !errors.Is(err, store.ErrAlreadyRevoked) {
		log.Error("revocation of undelivered certificate failed", append(attrs, "serial", rec.Serial, "error", err.Error())...)
		return
	}
	log.Warn("undelivered certificate revoked", append(attrs, "serial", rec.Serial, "reason", reason)...)
}

// supersedePrevious schedules revocation (reason superseded) of the
// operational certificate a device just renewed from, after the configured
// grace period, so a stolen-but-renewed certificate cannot be used
// indefinitely. It returns the scheduled time and whether it was scheduled.
func (h *Handler) supersedePrevious(client *ClientIdentity, newSerial string) (time.Time, bool) {
	if h.cfg.Revoker == nil || client == nil || client.Issuer != ca.KindDevice {
		return time.Time{}, false
	}
	previous := client.ID.Serial
	due := h.now().Add(h.cfg.SupersedeGrace)
	logger := h.cfg.Logger.With("device_id", client.ID.DeviceID, "tenant_id", client.ID.TenantID, "serial", previous, "superseded_by", newSerial)
	logger.Info("previous certificate scheduled for revocation", "revoke_at", due)
	time.AfterFunc(h.cfg.SupersedeGrace, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := h.cfg.Revoker.Revoke(ctx, previous, "superseded", "pki:supersede:"+newSerial); err != nil && !errors.Is(err, store.ErrAlreadyRevoked) {
			logger.Error("revocation of superseded certificate failed", "error", err.Error())
			return
		}
		logger.Info("superseded certificate revoked")
	})
	return due, true
}

// checkSeTypeAgainstManufactureRecord rejects attestations whose se_type
// differs from the secure element type the Registry recorded at manufacture.
// Devices without a recorded se_type (legacy records) are not constrained.
func checkSeTypeAgainstManufactureRecord(dev *registry.Device, seType string) *httpError {
	if dev == nil || dev.SeType == "" {
		return nil
	}
	if dev.SeType != seType {
		return errForbidden(fmt.Sprintf("attested se_type %q does not match the manufacture record (%q)", seType, dev.SeType))
	}
	return nil
}

// rejectReusedKey refuses a CSR whose public key was already certified for
// the device (bootstrap or any earlier operational certificate): every
// enrollment must use a freshly generated key.
func (h *Handler) rejectReusedKey(ctx context.Context, deviceID string, pub crypto.PublicKey) *httpError {
	pin, err := ca.SPKIPin(pub)
	if err != nil {
		return errBadRequest("cannot encode CSR public key", err)
	}
	spki := hex.EncodeToString(pin)
	recs, err := h.cfg.Store.ListCertificatesByDevice(ctx, deviceID)
	if err != nil {
		return errUnavailable("certificate history lookup failed", err)
	}
	for _, rec := range recs {
		if rec.SPKISHA256 == spki {
			return errBadRequest(fmt.Sprintf("CSR public key was already certified for this device (serial %s); generate a fresh key", rec.Serial), nil)
		}
	}
	return nil
}

func (h *Handler) failAttestation(w http.ResponseWriter, r *http.Request, op string, err error, attrs []any) {
	code := attest.CodeOf(err)
	h.cfg.Metrics.AttestationFailures.WithLabelValues(code.String()).Inc()
	var e *httpError
	switch code {
	case attest.CodeUnauthorized:
		e = errUnauthorized(err.Error())
	case attest.CodeForbidden:
		e = errForbidden(err.Error())
	default:
		e = errBadRequest(err.Error(), nil)
	}
	h.fail(w, r, op, e, attrs...)
}

func (h *Handler) readCSR(w http.ResponseWriter, r *http.Request) ([]byte, *x509.CertificateRequest, *httpError) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != ContentTypePKCS10 {
		return nil, nil, errUnsupportedMedia("Content-Type must be " + ContentTypePKCS10)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		return nil, nil, errBadRequest("cannot read request body", err)
	}
	var der []byte
	if len(body) > 0 && body[0] == 0x30 {
		der = body // raw DER tolerated
	} else if der, err = decodeBase64(string(body)); err != nil {
		return nil, nil, errBadRequest("request body is not valid base64", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, errBadRequest("malformed PKCS#10 request", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, errBadRequest("CSR signature is invalid", err)
	}
	return der, csr, nil
}

func containsOnly(values []string, want string) bool {
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if v != want {
			return false
		}
	}
	return true
}

// policyFor resolves the stored tenant policy (or the defaults) into an
// attestation policy.
func (h *Handler) policyFor(ctx context.Context, tenantID string) (*store.TenantPolicy, attest.Policy, *httpError) {
	tp, err := h.cfg.Store.GetTenantPolicy(ctx, tenantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		tp = &store.TenantPolicy{TenantID: tenantID, AllowSoftwareKeys: h.cfg.DefaultAllowSoftwareKeys}
	case err != nil:
		return nil, attest.Policy{}, errUnavailable("tenant policy lookup failed", err)
	}
	ap := attest.Policy{
		AllowSoftwareKeys: tp.AllowSoftwareKeys,
		AllowedPCRDigests: append(append([]string(nil), tp.AllowedPCRDigests...), h.cfg.DefaultPCRDigests...),
	}
	pool := x509.NewCertPool()
	n := 0
	for _, c := range h.cfg.DefaultAKRoots {
		pool.AddCert(c)
		n++
	}
	if tp.AKCAPEM != "" {
		certs, err := ca.ParseCertsPEM([]byte(tp.AKCAPEM))
		if err != nil {
			return nil, attest.Policy{}, errInternal("tenant policy has an invalid attestation CA bundle", err)
		}
		for _, c := range certs {
			pool.AddCert(c)
			n++
		}
	}
	if n > 0 {
		ap.AKRoots = pool
	}
	return tp, ap, nil
}
