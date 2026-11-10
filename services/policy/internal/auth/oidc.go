package auth

// OIDC bearer verification for console access tokens (API_CONTRACT.md §0 and §4): the console
// forwards the user's access token, which is verified against the IdP's JWKS (discovered from
// <issuer>/.well-known/openid-configuration), must carry aud ironmesh-api, and yields the role
// (claim `role`, configurable) and tenant (`tenant_id`).
//
// Accepted algorithms are RS256, PS256 (RSA >= 2048 bits) and ES256 (P-256). The algorithm in
// the token header only selects among those three, and the key must be of the matching type (and
// match the JWK "alg" when the IdP publishes one), so alg=none / HS256 / key-type confusion is
// rejected before any signature check.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDC defaults.
const (
	DefaultOIDCAudience  = "ironmesh-api"
	DefaultOIDCRoleClaim = "role"
	// DefaultJWKSMaxAge is how long a fetched key set is used before it is refreshed.
	DefaultJWKSMaxAge = time.Hour
	// DefaultJWKSMinRefresh rate-limits refreshes triggered by tokens with an unknown kid.
	DefaultJWKSMinRefresh = 30 * time.Second

	maxTokenBytes = 16 << 10
	maxDocBytes   = 1 << 20
	minRSABits    = 2048
)

// OIDC verification errors.
var (
	ErrUnknownKey = errors.New("jwt: no matching key in the issuer JWKS")
	ErrDiscovery  = errors.New("oidc: discovery failed")
)

// OIDCConfig configures an OIDCVerifier.
type OIDCConfig struct {
	// Issuer is the IdP issuer URL (POLICY_OIDC_ISSUER); tokens must carry exactly this iss.
	Issuer string
	// JWKSURL, when set (POLICY_OIDC_JWKS_URL), is used instead of discovery. It is needed when the
	// issuer URL in tokens is the browser-facing address and is not reachable from the service
	// (for example http://localhost:8180 in docker compose). The iss check is unchanged.
	JWKSURL string
	// Audience must be contained in aud (POLICY_OIDC_AUDIENCE, default ironmesh-api).
	Audience string
	// RoleClaim names the claim holding the role (POLICY_OIDC_ROLE_CLAIM, default role). Dotted
	// paths such as realm_access.roles address nested objects; string and array values are
	// accepted (the highest known role of an array wins).
	RoleClaim string
	// HTTPClient fetches discovery and JWKS documents (default: 5 s timeout).
	HTTPClient *http.Client
	// Clock, Leeway: token time validation (default time.Now, 30 s).
	Clock  func() time.Time
	Leeway time.Duration
	// MaxAge and MinRefresh tune the JWKS cache (defaults DefaultJWKSMaxAge, DefaultJWKSMinRefresh).
	MaxAge     time.Duration
	MinRefresh time.Duration
}

type jwk struct {
	kid string
	alg string // optional JWK "alg"
	key crypto.PublicKey
}

// OIDCVerifier verifies IdP-issued access tokens.
type OIDCVerifier struct {
	cfg    OIDCConfig
	issuer string // normalised (no trailing slash)

	mu        sync.Mutex // guards the fields below and serialises refreshes
	jwksURI   string
	keys      []jwk
	fetchedAt time.Time
	triedAt   time.Time
	lastErr   error
}

// NewOIDCVerifier validates cfg. Discovery is lazy (first token) so the service starts while the
// IdP is unreachable; management calls then answer 401 until it is back.
func NewOIDCVerifier(cfg OIDCConfig) (*OIDCVerifier, error) {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("oidc: issuer must be an http(s) URL, got %q", cfg.Issuer)
	}
	if cfg.JWKSURL != "" {
		ju, err := url.Parse(cfg.JWKSURL)
		if err != nil || ju.Host == "" || (ju.Scheme != "https" && ju.Scheme != "http") {
			return nil, fmt.Errorf("oidc: JWKS URL must be an http(s) URL, got %q", cfg.JWKSURL)
		}
	}
	if cfg.Audience == "" {
		cfg.Audience = DefaultOIDCAudience
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = DefaultOIDCRoleClaim
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultJWKSMaxAge
	}
	if cfg.MinRefresh <= 0 {
		cfg.MinRefresh = DefaultJWKSMinRefresh
	}
	return &OIDCVerifier{cfg: cfg, issuer: strings.TrimRight(cfg.Issuer, "/"), jwksURI: cfg.JWKSURL}, nil
}

// VerifyToken implements TokenVerifier.
func (v *OIDCVerifier) VerifyToken(ctx context.Context, token string) (Claims, error) {
	token = strings.TrimSpace(token)
	if len(token) > maxTokenBytes {
		return Claims{}, fmt.Errorf("%w: token too large", ErrMalformed)
	}
	parts := strings.Split(token, ".")
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
	switch h.Alg {
	case "RS256", "PS256", "ES256":
	default:
		return Claims{}, fmt.Errorf("%w: %q is not RS256, PS256 or ES256", ErrAlgorithm, h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return Claims{}, fmt.Errorf("%w: signature", ErrMalformed)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	keys, err := v.keysFor(ctx, h.Kid)
	if err != nil {
		return Claims{}, err
	}
	verified, candidates := false, 0
	for _, k := range keys {
		if k.alg != "" && k.alg != h.Alg {
			continue
		}
		ok, usable := verifySig(h.Alg, k.key, digest[:], sig)
		if usable {
			candidates++
		}
		if ok {
			verified = true
			break
		}
	}
	if candidates == 0 {
		return Claims{}, ErrUnknownKey
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
	claims.Role = roleFromClaim(raw, v.cfg.RoleClaim)
	now := v.cfg.Clock()
	switch {
	case claims.ExpiresAt.IsZero():
		return Claims{}, fmt.Errorf("%w: exp is required", ErrMalformed)
	case now.After(claims.ExpiresAt.Add(v.cfg.Leeway)):
		return Claims{}, ErrExpired
	case !claims.NotBefore.IsZero() && now.Add(v.cfg.Leeway).Before(claims.NotBefore):
		return Claims{}, ErrNotYetValid
	case strings.TrimRight(claims.Issuer, "/") != v.issuer:
		return Claims{}, ErrIssuer
	case !containsString(claims.Audience, v.cfg.Audience):
		return Claims{}, ErrAudience
	}
	// Browser access tokens are reused across requests: no jti single use, exp/aud/iss only.
	claims.Source = SourceOIDC
	return claims, nil
}

// verifySig checks sig with key for alg. usable reports whether the key type fits alg at all.
func verifySig(alg string, key crypto.PublicKey, digest, sig []byte) (ok, usable bool) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg {
		case "RS256":
			return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig) == nil, true
		case "PS256":
			return rsa.VerifyPSS(k, crypto.SHA256, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil, true
		}
	case *ecdsa.PublicKey:
		if alg == "ES256" && k.Curve == elliptic.P256() {
			if len(sig) != 64 {
				return false, true
			}
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			return ecdsa.Verify(k, digest, r, s), true
		}
	}
	return false, false
}

// roleFromClaim resolves a (dotted) claim path to the highest known role it names.
func roleFromClaim(raw map[string]any, path string) Role {
	var cur any = raw
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[seg]
	}
	best := Role("")
	consider := func(v any) {
		s, ok := v.(string)
		if !ok {
			return
		}
		if r, known := ParseRole(s); known && (best == "" || roleRank[r] > roleRank[best]) {
			best = r
		}
	}
	switch v := cur.(type) {
	case string:
		consider(v)
	case []any:
		for _, e := range v {
			consider(e)
		}
	}
	return best
}

// keysFor returns the cached keys for kid (all keys when kid is empty), refreshing the JWKS when
// it is missing, older than MaxAge, or does not contain kid (rate-limited by MinRefresh). A failed
// refresh keeps serving the previous key set.
func (v *OIDCVerifier) keysFor(ctx context.Context, kid string) ([]jwk, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.cfg.Clock()
	match := func() []jwk {
		var out []jwk
		for _, k := range v.keys {
			if kid == "" || k.kid == kid {
				out = append(out, k)
			}
		}
		return out
	}
	stale := v.fetchedAt.IsZero() || now.Sub(v.fetchedAt) > v.cfg.MaxAge
	found := match()
	if !stale && len(found) > 0 {
		return found, nil
	}
	if !v.triedAt.IsZero() && now.Sub(v.triedAt) < v.cfg.MinRefresh {
		switch {
		case len(found) > 0:
			return found, nil
		case v.fetchedAt.IsZero() && v.lastErr != nil:
			return nil, v.lastErr // IdP unreachable; do not hammer it
		}
		return nil, ErrUnknownKey
	}
	v.triedAt = now
	if err := v.refreshLocked(ctx); err != nil {
		v.lastErr = err
		if len(found) > 0 {
			return found, nil // stale but usable
		}
		return nil, err
	}
	v.lastErr = nil
	v.fetchedAt = now
	if found = match(); len(found) == 0 {
		return nil, ErrUnknownKey
	}
	return found, nil
}

func (v *OIDCVerifier) refreshLocked(ctx context.Context) error {
	if v.jwksURI == "" {
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.getJSON(ctx, v.issuer+"/.well-known/openid-configuration", &doc); err != nil {
			return err
		}
		if strings.TrimRight(doc.Issuer, "/") != v.issuer {
			return fmt.Errorf("%w: discovery document issuer %q does not match %q", ErrDiscovery, doc.Issuer, v.issuer)
		}
		u, err := url.Parse(doc.JWKSURI)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && strings.HasPrefix(v.issuer, "http://"))) {
			return fmt.Errorf("%w: invalid jwks_uri %q", ErrDiscovery, doc.JWKSURI)
		}
		v.jwksURI = doc.JWKSURI
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := v.getJSON(ctx, v.jwksURI, &set); err != nil {
		return err
	}
	keys := make([]jwk, 0, len(set.Keys))
	for _, raw := range set.Keys {
		if k, ok := parseJWK(raw); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: JWKS %s contains no usable signing keys", ErrDiscovery, v.jwksURI)
	}
	v.keys = keys
	return nil
}

// getJSON fetches the discovery document or the JWKS. u is never request-derived: it is the
// configured issuer (POLICY_OIDC_ISSUER) or JWKS URL, or the jwks_uri of the issuer's own
// discovery document, which refreshLocked accepts only after the issuer matches and the scheme is
// https (http only for an http issuer in development).
func (v *OIDCVerifier) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) // #nosec G704 -- operator-configured IdP URL, see above
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.cfg.HTTPClient.Do(req) // #nosec G704 -- operator-configured IdP URL, see above
	if err != nil {
		return fmt.Errorf("%w: GET %s: %v", ErrDiscovery, u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: GET %s: status %d", ErrDiscovery, u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocBytes)).Decode(out); err != nil {
		return fmt.Errorf("%w: GET %s: %v", ErrDiscovery, u, err)
	}
	return nil
}

// parseJWK converts an RSA or EC P-256 signing JWK; encryption keys and other types are skipped.
func parseJWK(raw map[string]any) (jwk, bool) {
	str := func(k string) string { s, _ := raw[k].(string); return s }
	b64 := func(k string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(str(k), "="))
		if err != nil {
			return nil
		}
		return b
	}
	if use := str("use"); use != "" && use != "sig" {
		return jwk{}, false
	}
	k := jwk{kid: str("kid"), alg: str("alg")}
	switch str("kty") {
	case "RSA":
		n, e := b64("n"), b64("e")
		if len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return jwk{}, false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < minRSABits || pub.E < 3 {
			return jwk{}, false
		}
		k.key = pub
	case "EC":
		if str("crv") != "P-256" {
			return jwk{}, false
		}
		x, y := b64("x"), b64("y")
		if len(x) != 32 || len(y) != 32 {
			return jwk{}, false
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return jwk{}, false
		}
		k.key = pub
	default:
		return jwk{}, false
	}
	return k, true
}
