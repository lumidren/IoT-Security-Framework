// Package auth verifies the ES256 bearer JWTs that protect the policy management API
// (API_CONTRACT.md section 0) and enforces the viewer < operator < admin < owner role ladder.
//
// Only ES256 is accepted; the algorithm is taken from configuration, never from the token header,
// so algorithm-confusion attacks are structurally impossible.
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Role is a tenant RBAC role.
type Role string

// Roles in ascending order of privilege.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleOwner    Role = "owner"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3, RoleOwner: 4}

// ParseRole normalises s into a known Role.
func ParseRole(s string) (Role, bool) {
	r := Role(strings.ToLower(strings.TrimSpace(s)))
	_, ok := roleRank[r]
	return r, ok
}

// AtLeast reports whether r grants at least the privileges of min. Unknown roles grant nothing.
func (r Role) AtLeast(min Role) bool {
	have, ok := roleRank[r]
	want, ok2 := roleRank[min]
	return ok && ok2 && have >= want
}

// Claims are the verified token claims the API relies on.
type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	Role      Role
	TenantID  string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	// ID is the jti claim.
	ID string
	// Source is SourceService (ES256 service JWT) or SourceOIDC (console access token).
	Source string
}

// Token sources.
const (
	SourceService = "service"
	SourceOIDC    = "oidc"
)

// MaxServiceTokenLifetime bounds exp - iat of service JWTs (DESIGN_CONTRACT section 7: 5 minute
// tokens; THREAT_MODEL T-50).
const MaxServiceTokenLifetime = 300 * time.Second

// Verification errors.
var (
	ErrMalformed   = errors.New("jwt: malformed token")
	ErrAlgorithm   = errors.New("jwt: algorithm must be ES256")
	ErrSignature   = errors.New("jwt: signature verification failed")
	ErrExpired     = errors.New("jwt: token expired")
	ErrNotYetValid = errors.New("jwt: token not yet valid")
	ErrAudience    = errors.New("jwt: audience mismatch")
	ErrIssuer      = errors.New("jwt: issuer mismatch")
	ErrNoKeys      = errors.New("jwt: no verification keys configured")
	ErrLifetime    = errors.New("jwt: service token lifetime (exp - iat) must be positive and at most 300s")
	ErrReplay      = errors.New("jwt: token already used (jti replay)")
	// ErrSubjectMismatch means a token presented with a Services CA client certificate names a
	// different service than the certificate CN.
	ErrSubjectMismatch = errors.New("jwt: token subject does not match the client certificate")
)

// Verifier validates ES256 tokens against one or more P-256 public keys.
type Verifier struct {
	keys     []*ecdsa.PublicKey
	audience string
	issuer   string
	now      func() time.Time
	leeway   time.Duration
	replay   *ReplayCache
}

// VerifierOption customises a Verifier.
type VerifierOption func(*Verifier)

// WithClock injects a time source.
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) {
		if now != nil {
			v.now = now
		}
	}
}

// WithIssuer requires the iss claim to equal iss.
func WithIssuer(iss string) VerifierOption { return func(v *Verifier) { v.issuer = iss } }

// WithReplayCache makes every service JWT single-use on this instance (POLICY_JWT_SINGLE_USE):
// a jti is remembered until exp + leeway.
func WithReplayCache(c *ReplayCache) VerifierOption { return func(v *Verifier) { v.replay = c } }

// WithLeeway tolerates clock skew of d on exp/nbf (default 30s).
func WithLeeway(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		if d >= 0 {
			v.leeway = d
		}
	}
}

// NewVerifier parses a PEM bundle of PUBLIC KEY and/or CERTIFICATE blocks (P-256 only) and
// returns a Verifier requiring aud to contain audience.
func NewVerifier(pemBundle, audience string, opts ...VerifierOption) (*Verifier, error) {
	keys, err := ParsePublicKeys(pemBundle)
	if err != nil {
		return nil, err
	}
	if audience == "" {
		return nil, errors.New("jwt: audience is required")
	}
	v := &Verifier{keys: keys, audience: audience, now: time.Now, leeway: 30 * time.Second}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// ParsePublicKeys extracts every P-256 public key from a PEM bundle.
func ParsePublicKeys(pemBundle string) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	rest := []byte(pemBundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		var pub any
		switch block.Type {
		case "PUBLIC KEY":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse public key: %w", err)
			}
			pub = k
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse certificate: %w", err)
			}
			pub = cert.PublicKey
		default:
			return nil, fmt.Errorf("jwt: unsupported PEM block %q", block.Type)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return nil, errors.New("jwt: verification key must be an ECDSA P-256 key")
		}
		keys = append(keys, ec)
	}
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	return keys, nil
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Verify checks the signature and the claims of a compact service JWT: exp, iat and jti are
// required, exp - iat must not exceed MaxServiceTokenLifetime, iat must not lie in the future,
// nbf/aud/iss are honoured and, with a ReplayCache, the jti must not have been used before.
func (v *Verifier) Verify(token string) (Claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	headRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header", ErrMalformed)
	}
	var h header
	if err := json.Unmarshal(headRaw, &h); err != nil {
		return Claims{}, fmt.Errorf("%w: header", ErrMalformed)
	}
	if h.Alg != "ES256" {
		return Claims{}, ErrAlgorithm
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return Claims{}, fmt.Errorf("%w: signature", ErrMalformed)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	verified := false
	for _, k := range v.keys {
		if ecdsa.Verify(k, digest[:], r, s) {
			verified = true
			break
		}
	}
	if !verified {
		return Claims{}, ErrSignature
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload", ErrMalformed)
	}
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(string(payloadRaw)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Claims{}, fmt.Errorf("%w: payload", ErrMalformed)
	}
	claims, err := claimsFromMap(raw)
	if err != nil {
		return Claims{}, err
	}
	now := v.now()
	if claims.ExpiresAt.IsZero() {
		return Claims{}, fmt.Errorf("%w: exp is required", ErrMalformed)
	}
	if now.After(claims.ExpiresAt.Add(v.leeway)) {
		return Claims{}, ErrExpired
	}
	if !claims.NotBefore.IsZero() && now.Add(v.leeway).Before(claims.NotBefore) {
		return Claims{}, ErrNotYetValid
	}
	if !containsString(claims.Audience, v.audience) {
		return Claims{}, ErrAudience
	}
	if v.issuer != "" && claims.Issuer != v.issuer {
		return Claims{}, ErrIssuer
	}
	if claims.IssuedAt.IsZero() {
		return Claims{}, fmt.Errorf("%w: iat is required", ErrMalformed)
	}
	if claims.IssuedAt.After(now.Add(v.leeway)) {
		return Claims{}, fmt.Errorf("%w: iat is in the future", ErrNotYetValid)
	}
	if life := claims.ExpiresAt.Sub(claims.IssuedAt); life <= 0 || life > MaxServiceTokenLifetime {
		return Claims{}, ErrLifetime
	}
	if strings.TrimSpace(claims.ID) == "" || len(claims.ID) > 256 {
		return Claims{}, fmt.Errorf("%w: jti is required", ErrMalformed)
	}
	claims.Source = SourceService
	if v.replay != nil && !v.replay.Use(claims.Issuer+"\x00"+claims.ID, claims.ExpiresAt.Add(v.leeway), now) {
		return Claims{}, ErrReplay
	}
	return claims, nil
}

func claimsFromMap(raw map[string]any) (Claims, error) {
	var c Claims
	c.Subject, _ = raw["sub"].(string)
	c.Issuer, _ = raw["iss"].(string)
	c.TenantID, _ = raw["tenant_id"].(string)
	c.ID, _ = raw["jti"].(string)
	if role, ok := raw["role"].(string); ok {
		if r, known := ParseRole(role); known {
			c.Role = r
		}
	}
	switch aud := raw["aud"].(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	}
	var err error
	if c.ExpiresAt, err = numericDate(raw["exp"]); err != nil {
		return Claims{}, fmt.Errorf("%w: exp", ErrMalformed)
	}
	if c.IssuedAt, err = numericDate(raw["iat"]); err != nil {
		return Claims{}, fmt.Errorf("%w: iat", ErrMalformed)
	}
	if c.NotBefore, err = numericDate(raw["nbf"]); err != nil {
		return Claims{}, fmt.Errorf("%w: nbf", ErrMalformed)
	}
	return c, nil
}

func numericDate(v any) (time.Time, error) {
	switch n := v.(type) {
	case nil:
		return time.Time{}, nil
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, err
		}
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), nil
	case float64:
		sec := int64(n)
		return time.Unix(sec, int64((n-float64(sec))*1e9)).UTC(), nil
	default:
		return time.Time{}, errors.New("not a numeric date")
	}
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
