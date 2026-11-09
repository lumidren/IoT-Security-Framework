package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/problem"
)

type ctxKey struct{}

// WithClaims stores verified claims on ctx.
func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// ClaimsFromContext returns the claims stored by the Guard.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// Guard wraps next so that only callers holding a valid token with at least min may reach it.
type Guard func(min Role, next http.Handler) http.Handler

// TokenVerifier verifies a bearer token. *Verifier (ES256 service JWTs) and *OIDCVerifier
// (console access tokens) implement it.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (Claims, error)
}

// VerifyToken implements TokenVerifier.
func (v *Verifier) VerifyToken(_ context.Context, token string) (Claims, error) {
	return v.Verify(token)
}

// Guard returns the middleware enforcing bearer-token authentication (401) and role (403) with
// RFC 9457 problem responses.
func (v *Verifier) Guard() Guard { return NewGuard(v) }

// NewGuard returns the middleware accepting a token that any of verifiers accepts (tried in
// order; the first success wins).
func NewGuard(verifiers ...TokenVerifier) Guard {
	return func(min Role, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearer(r.Header.Get("Authorization"))
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ironmesh-policy"`)
				problem.Write(w, r, http.StatusUnauthorized, "missing bearer token")
				return
			}
			claims, err := verifyAny(r.Context(), verifiers, token)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ironmesh-policy", error="invalid_token"`)
				problem.Write(w, r, http.StatusUnauthorized, "invalid bearer token", err.Error())
				return
			}
			if claims.Role == "" {
				problem.Write(w, r, http.StatusForbidden, "token carries no recognised role")
				return
			}
			if !claims.Role.AtLeast(min) {
				problem.Write(w, r, http.StatusForbidden, "role "+string(claims.Role)+" is below the required role "+string(min))
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

func verifyAny(ctx context.Context, verifiers []TokenVerifier, token string) (Claims, error) {
	if len(verifiers) == 0 {
		return Claims{}, ErrNoKeys
	}
	var errs []error
	for _, v := range verifiers {
		c, err := v.VerifyToken(ctx, token)
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return Claims{}, errors.Join(errs...)
}

// DisabledGuard rejects every call with 503; used when no verification key is configured so the
// management API fails closed instead of open.
func DisabledGuard(detail string) Guard {
	return func(_ Role, _ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			problem.Write(w, r, http.StatusServiceUnavailable, detail)
		})
	}
}

func bearer(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(prefix):])
	return tok, tok != ""
}
