package hooks

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/identity"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
)

// AuthnRequest is the body EMQX posts to /emqx/authn. cert_serial and cert_pem are optional and
// used when the EMQX template provides them.
type AuthnRequest struct {
	ClientID       string `json:"clientid"`
	Username       string `json:"username"`
	PeerHost       string `json:"peerhost"`
	CertCommonName string `json:"cert_common_name"`
	CertSubject    string `json:"cert_subject"`
	CertSerial     string `json:"cert_serial,omitempty"`
	CertPEM        string `json:"cert_pem,omitempty"`
}

// AuthnResponse is the EMQX HTTP authenticator response.
type AuthnResponse struct {
	Result      string        `json:"result"`
	IsSuperuser *bool         `json:"is_superuser,omitempty"`
	ClientAttrs *engine.Attrs `json:"client_attrs,omitempty"`
	// ExpireAt (unix seconds) makes EMQX disconnect the session when the certificate expires.
	ExpireAt *int64 `json:"expire_at,omitempty"`
}

// RevocationChecker answers deny-list lookups. *revocation.Cache implements it.
type RevocationChecker interface {
	IsRevokedDevice(deviceID string) bool
	IsRevokedSerial(serial string) bool
}

// AuthnConfig configures the authn hook.
type AuthnConfig struct {
	Registry   registry.Lookup
	Revoked    RevocationChecker
	Identities *IdentityCache
	Metrics    *metrics.Metrics
	Logger     *slog.Logger
	// FailOpen admits devices when the Registry cannot be reached (POLICY_REGISTRY_FAIL_OPEN).
	FailOpen bool
	// ServiceCIDRs are the networks service principals may connect from (default
	// DefaultServiceCIDRs).
	ServiceCIDRs []*net.IPNet
	Clock        func() time.Time
	MaxBodyBytes int64
}

// Authn is the EMQX authentication backend.
type Authn struct {
	registry     registry.Lookup
	revoked      RevocationChecker
	identities   *IdentityCache
	metrics      *metrics.Metrics
	log          *slog.Logger
	failOpen     bool
	serviceCIDRs []*net.IPNet
	now          func() time.Time
	maxBody      int64
}

// NewAuthn validates cfg and returns the hook.
func NewAuthn(cfg AuthnConfig) (*Authn, error) {
	if cfg.Registry == nil || cfg.Revoked == nil || cfg.Metrics == nil {
		return nil, errors.New("authn: registry, revocation checker and metrics are required")
	}
	a := &Authn{
		registry:     cfg.Registry,
		revoked:      cfg.Revoked,
		identities:   cfg.Identities,
		metrics:      cfg.Metrics,
		log:          cfg.Logger,
		failOpen:     cfg.FailOpen,
		serviceCIDRs: cfg.ServiceCIDRs,
		now:          cfg.Clock,
		maxBody:      cfg.MaxBodyBytes,
	}
	if len(a.serviceCIDRs) == 0 {
		nets, err := ParseCIDRs(DefaultServiceCIDRs)
		if err != nil {
			return nil, err
		}
		a.serviceCIDRs = nets
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.maxBody <= 0 {
		a.maxBody = 64 << 10
	}
	if a.failOpen {
		a.log.Error("POLICY_REGISTRY_FAIL_OPEN=true: devices will be ADMITTED when the Registry is unreachable; never run production with this setting")
	}
	return a, nil
}

var deny = AuthnResponse{Result: "deny"}

// ServeHTTP handles POST /emqx/authn. Every failure path answers an explicit deny so the chain is
// fail-closed regardless of how EMQX treats non-200 responses.
func (a *Authn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, deny)
		return
	}
	var req AuthnRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.maxBody))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		a.metrics.AuthFailures.WithLabelValues("bad_request").Inc()
		a.metrics.AuthnDecisions.WithLabelValues("deny", "unknown").Inc()
		a.log.Warn("authn request rejected", "reason", "bad_request", "err", err.Error())
		writeJSON(w, http.StatusOK, deny)
		return
	}
	resp, reason := a.Decide(r.Context(), req)
	writeJSON(w, http.StatusOK, resp)
	_ = reason
}

// Decide applies the CONNECT rules and returns the response plus a bounded reason label.
func (a *Authn) Decide(ctx context.Context, req AuthnRequest) (AuthnResponse, string) {
	kind, resp, reason := a.decide(ctx, req)
	if resp.Result == "allow" {
		a.metrics.AuthnDecisions.WithLabelValues("allow", kind).Inc()
		a.log.Debug("authn allow", "client_id", req.ClientID, "peerhost", req.PeerHost, "kind", kind,
			"tenant_id", attrOr(resp.ClientAttrs).TenantID, "device_id", attrOr(resp.ClientAttrs).DeviceID)
		return resp, "allow"
	}
	a.metrics.AuthnDecisions.WithLabelValues("deny", kind).Inc()
	a.metrics.AuthFailures.WithLabelValues(reason).Inc()
	a.log.Info("authn deny", "client_id", req.ClientID, "username", req.Username, "peerhost", req.PeerHost,
		"cert_cn", req.CertCommonName, "kind", kind, "reason", reason)
	return deny, reason
}

func (a *Authn) decide(ctx context.Context, req AuthnRequest) (kind string, resp AuthnResponse, reason string) {
	kind = "unknown"
	cn := req.CertCommonName
	if cn == "" {
		return kind, deny, "no_client_cert"
	}
	if req.ClientID == "" || req.ClientID != cn {
		return kind, deny, "clientid_mismatch"
	}
	if req.Username != "" && req.Username != cn {
		return kind, deny, "username_mismatch"
	}
	dn, err := identity.ParseDN(req.CertSubject)
	if err != nil {
		return kind, deny, "bad_subject"
	}
	if dn.CN != "" && dn.CN != cn {
		return kind, deny, "bad_subject"
	}
	serial := revocation.NormalizeSerial(req.CertSerial)
	var expireAt *int64
	if req.CertPEM != "" {
		cert, err := parseCertPEM(req.CertPEM)
		if err != nil {
			return kind, deny, "cert_pem_invalid"
		}
		if cert.Subject.CommonName != cn {
			return kind, deny, "cert_cn_mismatch"
		}
		if a.now().After(cert.NotAfter) {
			return kind, deny, "cert_expired"
		}
		dn = identity.DNFromName(cert.Subject)
		serial = revocation.SerialFromBigInt(cert.SerialNumber)
		exp := cert.NotAfter.Unix()
		expireAt = &exp
	}

	switch {
	case identity.IsDeviceID(cn):
		kind = string(identity.KindDevice)
		if !dn.HasO(identity.Organization) {
			return kind, deny, "bad_subject"
		}
		tenant, err := dn.Tenant()
		switch {
		case errors.Is(err, identity.ErrBootstrap):
			return kind, deny, "bootstrap_cert"
		case err != nil:
			return kind, deny, "no_tenant"
		}
		if a.revoked.IsRevokedDevice(cn) {
			return kind, deny, "revoked"
		}
		if serial != "" && a.revoked.IsRevokedSerial(serial) {
			return kind, deny, "revoked_serial"
		}
		lc, err := a.registry.Lifecycle(ctx, cn)
		switch {
		case errors.Is(err, registry.ErrNotFound):
			return kind, deny, "registry_unknown"
		case err != nil && !a.failOpen:
			a.log.Error("registry lookup failed; denying (fail-closed)", "device_id", cn, "err", err.Error())
			return kind, deny, "registry_error"
		case err != nil:
			a.log.Error("registry lookup failed; ADMITTING because POLICY_REGISTRY_FAIL_OPEN=true", "device_id", cn, "tenant_id", tenant, "err", err.Error())
		default:
			if !lc.MayConnect() {
				return kind, deny, lifecycleReason(lc.State)
			}
			if lc.TenantID != "" && lc.TenantID != tenant {
				return kind, deny, "tenant_mismatch"
			}
		}
		attrs := engine.Attrs{TenantID: tenant, DeviceID: cn, Kind: kind}
		if a.identities != nil {
			a.identities.Put(cn, attrs)
		}
		return kind, allowResponse(attrs, expireAt), "allow"

	case identity.IsServiceCN(cn):
		kind = string(identity.KindService)
		if ok, detail := a.checkServicePrincipalOrigin(req.PeerHost, dn); !ok {
			a.log.Warn("service principal rejected", "client_id", cn, "peerhost", req.PeerHost, "detail", detail)
			return kind, deny, "service_origin"
		}
		if a.revoked.IsRevokedDevice(cn) {
			return kind, deny, "revoked"
		}
		if serial != "" && a.revoked.IsRevokedSerial(serial) {
			return kind, deny, "revoked_serial"
		}
		attrs := engine.Attrs{Kind: kind}
		if a.identities != nil {
			a.identities.Put(cn, attrs)
		}
		return kind, allowResponse(attrs, expireAt), "allow"
	}
	return kind, deny, "unknown_identity"
}

// DefaultServiceCIDRs are the networks service principals may connect from when
// POLICY_SERVICE_CIDRS is not set (THREAT_MODEL.md: service identities are confined to the
// cluster/VPC networks).
var DefaultServiceCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}

// ParseCIDRs parses a list of CIDR strings.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one service CIDR is required")
	}
	return out, nil
}

// checkServicePrincipalOrigin decides whether a service identity (svc-bridge, svc-registry) may
// authenticate: the peer host must fall inside one of the configured service CIDRs and the
// certificate subject must carry O=IronMesh and OU=services. Any other combination is rejected
// (reason service_origin); detail explains why for the logs.
func (a *Authn) checkServicePrincipalOrigin(peerHost string, dn identity.DN) (bool, string) {
	if !dn.HasO(identity.Organization) || !dn.HasOU(identity.ServicesOU) {
		return false, "subject must carry O=IronMesh and OU=services"
	}
	host := strings.TrimSpace(peerHost)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false, "peerhost is not an IP address"
	}
	for _, n := range a.serviceCIDRs {
		if n.Contains(ip) {
			return true, ""
		}
	}
	return false, "peerhost outside service CIDRs"
}

func allowResponse(attrs engine.Attrs, expireAt *int64) AuthnResponse {
	superuser := false
	return AuthnResponse{Result: "allow", IsSuperuser: &superuser, ClientAttrs: &attrs, ExpireAt: expireAt}
}

func lifecycleReason(state string) string {
	if registry.KnownState(state) {
		return "lifecycle_" + state
	}
	return "lifecycle_other"
}

func attrOr(a *engine.Attrs) engine.Attrs {
	if a == nil {
		return engine.Attrs{}
	}
	return *a
}

func parseCertPEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
