package mgmt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
)

// RequiredAudience is the JWT audience the management API requires.
const RequiredAudience = "pki"

var (
	// ErrUnauthenticated means no acceptable credential was presented (401).
	ErrUnauthenticated = errors.New("mgmt: authentication required")
	// ErrForbidden means the credential is valid but not authorized (403).
	ErrForbidden = errors.New("mgmt: not authorized")
	// ErrReplayed means the token's jti was already used on this instance.
	ErrReplayed = errors.New("mgmt: token already used (jti replay)")
	// ErrSubjectMismatch means a JWT presented together with a Services CA
	// client certificate names a different service than the certificate.
	ErrSubjectMismatch = errors.New("mgmt: token subject does not match the client certificate")
)

// Principal is an authenticated management caller.
type Principal struct {
	Subject string
	Method  string // "mtls" or "jwt"
	// Allowed reports whether the caller may use the general management API:
	// a Services CA certificate whose CN is on the allow list, or any valid
	// bearer JWT. Tenant policy endpoints authorize by Service() instead.
	Allowed bool `json:"-"`
}

// Service returns the calling service's name ("registry", "ota", ...): the
// Services CA client certificate CN without its "svc-" prefix, or the JWT
// sub (with or without the prefix). It is empty for an mTLS identity that is
// not a svc-* service.
func (p *Principal) Service() string {
	if p == nil {
		return ""
	}
	if p.Method == "mtls" {
		if !strings.HasPrefix(p.Subject, "svc-") {
			return ""
		}
		return strings.TrimPrefix(p.Subject, "svc-")
	}
	return strings.TrimPrefix(p.Subject, "svc-")
}

// Authenticator accepts either a Services CA client certificate whose CN is on
// the allow list, or a bearer ES256 JWT with aud=pki signed by a trusted key.
// A caller presenting both must present a JWT whose sub names the same
// service as the certificate CN (ignoring the "svc-" prefix).
type Authenticator struct {
	ServicesCA *x509.Certificate
	AllowedCNs map[string]bool
	JWTKeys    []*ecdsa.PublicKey
	Clock      func() time.Time
	// Replay, when set, makes every service JWT single-use on this instance
	// (PKI_MGMT_JWT_SINGLE_USE).
	Replay *ReplayCache
}

// NewAuthenticator builds an Authenticator from a CN list.
func NewAuthenticator(servicesCA *x509.Certificate, allowedCNs []string, jwtKeys []*ecdsa.PublicKey, clock func() time.Time) *Authenticator {
	a := &Authenticator{ServicesCA: servicesCA, AllowedCNs: map[string]bool{}, JWTKeys: jwtKeys, Clock: clock}
	for _, cn := range allowedCNs {
		if cn = strings.TrimSpace(cn); cn != "" {
			a.AllowedCNs[cn] = true
		}
	}
	if a.Clock == nil {
		a.Clock = time.Now
	}
	return a
}

// Authenticate returns the caller's principal or ErrUnauthenticated /
// ErrForbidden.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	p, err := a.Identify(r)
	if err != nil {
		return nil, err
	}
	if !p.Allowed {
		// A service identity that is not on the allow list cannot fall
		// back to a token: it is explicitly not authorized.
		return nil, ErrForbidden
	}
	return p, nil
}

// Identify authenticates the caller without applying the CN allow list: any
// currently valid Services CA client certificate yields a principal (Allowed
// tells whether its CN is allow-listed); otherwise a bearer ES256 JWT with
// aud=pki is required. When a Services CA certificate and a bearer token are
// both presented (and JWT keys are configured), the token must verify, its
// jti must be unused and its sub must name the certificate's service.
func (a *Authenticator) Identify(r *http.Request) (*Principal, error) {
	now := a.Clock()
	token, hasToken, tokErr := bearerToken(r.Header.Get("Authorization"))
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && a.ServicesCA != nil {
		leaf := r.TLS.PeerCertificates[0]
		if ca.IssuedBy(leaf, a.ServicesCA) && len(r.TLS.VerifiedChains) > 0 {
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return nil, errors.New("mgmt: client certificate expired")
			}
			cn := leaf.Subject.CommonName
			if hasToken && len(a.JWTKeys) > 0 {
				if tokErr != nil {
					return nil, tokErr
				}
				claims, err := a.verifyJWT(token, now)
				if err != nil {
					return nil, err
				}
				if ServiceName(claims.Subject) == "" || ServiceName(claims.Subject) != ServiceName(cn) {
					return nil, errors.Join(ErrUnauthenticated, ErrSubjectMismatch)
				}
			}
			return &Principal{Subject: cn, Method: "mtls", Allowed: a.AllowedCNs[cn]}, nil
		}
	}
	if !hasToken || tokErr != nil || len(a.JWTKeys) == 0 {
		return nil, ErrUnauthenticated
	}
	claims, err := a.verifyJWT(token, now)
	if err != nil {
		return nil, err
	}
	subject := claims.Subject
	if subject == "" {
		subject = claims.Issuer
	}
	if subject == "" {
		subject = "jwt"
	}
	return &Principal{Subject: subject, Method: "jwt", Allowed: true}, nil
}

// verifyJWT verifies the token and consumes its jti.
func (a *Authenticator) verifyJWT(token string, now time.Time) (*Claims, error) {
	claims, err := VerifyES256(token, a.JWTKeys, RequiredAudience, now)
	if err != nil {
		return nil, errors.Join(ErrUnauthenticated, err)
	}
	if a.Replay != nil && !a.Replay.Use(claims.Issuer+"\x00"+claims.ID, time.Unix(claims.ExpiresAt, 0).Add(ClockLeeway), now) {
		return nil, errors.Join(ErrUnauthenticated, ErrReplayed)
	}
	return claims, nil
}

// ServiceName normalises a service identity: "svc-registry" and "registry"
// both yield "registry".
func ServiceName(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "svc-") }

// bearerToken extracts a bearer token. present reports whether an
// Authorization header was sent; err is set for a malformed one.
func bearerToken(header string) (token string, present bool, err error) {
	if header == "" {
		return "", false, nil
	}
	scheme, tok, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
		return "", true, ErrUnauthenticated
	}
	return strings.TrimSpace(tok), true, nil
}
