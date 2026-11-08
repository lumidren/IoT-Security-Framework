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
)

// Principal is an authenticated management caller.
type Principal struct {
	Subject string
	Method  string // "mtls" or "jwt"
}

// Authenticator accepts either a Services CA client certificate whose CN is on
// the allow list, or a bearer ES256 JWT with aud=pki signed by a trusted key.
type Authenticator struct {
	ServicesCA *x509.Certificate
	AllowedCNs map[string]bool
	JWTKeys    []*ecdsa.PublicKey
	Clock      func() time.Time
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
	now := a.Clock()
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && a.ServicesCA != nil {
		leaf := r.TLS.PeerCertificates[0]
		if ca.IssuedBy(leaf, a.ServicesCA) && len(r.TLS.VerifiedChains) > 0 {
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return nil, errors.New("mgmt: client certificate expired")
			}
			if a.AllowedCNs[leaf.Subject.CommonName] {
				return &Principal{Subject: leaf.Subject.CommonName, Method: "mtls"}, nil
			}
			// A service identity that is not on the allow list cannot fall
			// back to a token: it is explicitly not authorized.
			return nil, ErrForbidden
		}
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, ErrUnauthenticated
	}
	scheme, token, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return nil, ErrUnauthenticated
	}
	if len(a.JWTKeys) == 0 {
		return nil, ErrUnauthenticated
	}
	claims, err := VerifyES256(strings.TrimSpace(token), a.JWTKeys, RequiredAudience, now)
	if err != nil {
		return nil, errors.Join(ErrUnauthenticated, err)
	}
	subject := claims.Subject
	if subject == "" {
		subject = claims.Issuer
	}
	if subject == "" {
		subject = "jwt"
	}
	return &Principal{Subject: subject, Method: "jwt"}, nil
}
