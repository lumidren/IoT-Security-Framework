package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
	rsaKey2 *rsa.PrivateKey
)

func testRSAKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	rsaOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if rsaKey2, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return rsaKey, rsaKey2
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid, alg string, k *rsa.PublicKey) map[string]any {
	m := map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(int64(k.E)).Bytes())}
	if alg != "" {
		m["alg"] = alg
	}
	return m
}

func ecJWK(kid string, k *ecdsa.PublicKey) map[string]any {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "kid": kid, "crv": "P-256", "x": b64u(x), "y": b64u(y)}
}

// signJWT builds a compact JWT; key is *rsa.PrivateKey (RS256/PS256), *ecdsa.PrivateKey (ES256)
// or []byte (HS256).
func signJWT(t *testing.T, alg, kid string, key any, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		h["kid"] = kid
	}
	hr, _ := json.Marshal(h)
	pr, _ := json.Marshal(claims)
	input := b64u(hr) + "." + b64u(pr)
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	var err error
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		r, s, e := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
		err = e
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case "HS256":
		m := hmac.New(sha256.New, key.([]byte))
		m.Write([]byte(input))
		sig = m.Sum(nil)
	case "none":
		return input + "."
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

type idp struct {
	srv        *httptest.Server
	mu         sync.Mutex
	keys       []map[string]any
	issuer     string // advertised issuer (defaults to the server URL)
	jwksURI    string // advertised jwks_uri override
	jwksStatus int
	discovery  atomic.Int32
	jwks       atomic.Int32
}

func newIDP(t *testing.T, keys ...map[string]any) *idp {
	t.Helper()
	p := &idp{keys: keys, jwksStatus: http.StatusOK}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		switch r.URL.Path {
		case "/realms/ironmesh/.well-known/openid-configuration":
			p.discovery.Add(1)
			iss := p.issuer
			if iss == "" {
				iss = p.srv.URL + "/realms/ironmesh"
			}
			uri := p.jwksURI
			if uri == "" {
				uri = p.srv.URL + "/realms/ironmesh/certs"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": uri})
		case "/realms/ironmesh/certs":
			p.jwks.Add(1)
			if p.jwksStatus != http.StatusOK {
				w.WriteHeader(p.jwksStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": p.keys})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) setKeys(keys ...map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = keys
}

func (p *idp) issuerURL() string { return p.srv.URL + "/realms/ironmesh" }

type clockT struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clockT) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clockT) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (p *idp) claims(extra map[string]any) map[string]any {
	c := map[string]any{
		"iss": p.issuerURL(), "sub": "user-42", "aud": []string{"ironmesh-api", "account"},
		"exp": fixedNow.Add(5 * time.Minute).Unix(), "iat": fixedNow.Unix(),
		"role": "admin", "tenant_id": "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11",
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func newOIDC(t *testing.T, p *idp, clk *clockT, mod func(*OIDCConfig)) *OIDCVerifier {
	t.Helper()
	cfg := OIDCConfig{Issuer: p.issuerURL() + "/", Clock: clk.Now}
	if mod != nil {
		mod(&cfg)
	}
	v, err := NewOIDCVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOIDCAlgorithmsAndClaims(t *testing.T) {
	k1, _ := testRSAKeys(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey), ecJWK("ec-1", &ec.PublicKey))
	clk := &clockT{now: fixedNow}
	v := newOIDC(t, p, clk, nil)
	ctx := context.Background()
	for _, c := range []struct {
		alg, kid string
		key      any
	}{{"RS256", "rsa-1", k1}, {"PS256", "rsa-1", k1}, {"ES256", "ec-1", ec}, {"ES256", "", ec}, {"RS256", "", k1}} {
		claims, err := v.VerifyToken(ctx, signJWT(t, c.alg, c.kid, c.key, p.claims(nil)))
		if err != nil {
			t.Fatalf("%s/%s: %v", c.alg, c.kid, err)
		}
		if claims.Role != RoleAdmin || claims.TenantID != "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11" || claims.Subject != "user-42" {
			t.Fatalf("claims %+v", claims)
		}
	}
	if p.discovery.Load() != 1 || p.jwks.Load() != 1 {
		t.Fatalf("discovery=%d jwks=%d, want one fetch each (cached)", p.discovery.Load(), p.jwks.Load())
	}
	// The cache expires after MaxAge.
	clk.Add(DefaultJWKSMaxAge + time.Minute)
	tok := signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"exp": clk.Now().Add(time.Minute).Unix()}))
	if _, err := v.VerifyToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if p.jwks.Load() != 2 || p.discovery.Load() != 1 {
		t.Fatalf("after max age: jwks=%d discovery=%d", p.jwks.Load(), p.discovery.Load())
	}
}

func TestOIDCKeyRotation(t *testing.T) {
	k1, k2 := testRSAKeys(t)
	p := newIDP(t, rsaJWK("old", "RS256", &k1.PublicKey))
	clk := &clockT{now: fixedNow}
	v := newOIDC(t, p, clk, func(c *OIDCConfig) { c.MinRefresh = time.Minute })
	ctx := context.Background()
	if _, err := v.VerifyToken(ctx, signJWT(t, "RS256", "old", k1, p.claims(nil))); err != nil {
		t.Fatal(err)
	}
	// The IdP rotates: a token with the new kid triggers exactly one refresh.
	p.setKeys(rsaJWK("old", "RS256", &k1.PublicKey), rsaJWK("new", "RS256", &k2.PublicKey))
	clk.Add(2 * time.Minute)
	if _, err := v.VerifyToken(ctx, signJWT(t, "RS256", "new", k2, p.claims(nil))); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if p.jwks.Load() != 2 {
		t.Fatalf("jwks fetches %d", p.jwks.Load())
	}
	// Unknown kids are rate limited: no refetch within MinRefresh of the last attempt...
	bogus := func() {
		t.Helper()
		if _, err := v.VerifyToken(ctx, signJWT(t, "RS256", "bogus", k2, p.claims(nil))); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("unknown kid: %v", err)
		}
	}
	bogus()
	if p.jwks.Load() != 2 {
		t.Fatalf("jwks fetches %d, want 2 (rate limited)", p.jwks.Load())
	}
	// ...and one refetch per MinRefresh afterwards.
	clk.Add(2 * time.Minute)
	for i := 0; i < 3; i++ {
		bogus()
	}
	if p.jwks.Load() != 3 {
		t.Fatalf("jwks fetches %d, want 3 (one refresh for the unknown kid)", p.jwks.Load())
	}
	// The IdP goes down: cached keys keep working, unknown kids fail.
	p.mu.Lock()
	p.jwksStatus = http.StatusInternalServerError
	p.mu.Unlock()
	clk.Add(DefaultJWKSMaxAge + time.Minute)
	tok := signJWT(t, "RS256", "new", k2, p.claims(map[string]any{"exp": clk.Now().Add(time.Minute).Unix()}))
	if _, err := v.VerifyToken(ctx, tok); err != nil {
		t.Fatalf("stale cache while IdP down: %v", err)
	}
}

func TestOIDCRejections(t *testing.T) {
	k1, k2 := testRSAKeys(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey), rsaJWK("rs-only", "RS256", &k2.PublicKey), ecJWK("ec-1", &ec.PublicKey))
	clk := &clockT{now: fixedNow}
	v := newOIDC(t, p, clk, nil)
	ctx := context.Background()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]struct {
		token string
		want  error
	}{
		"alg none":            {signJWT(t, "none", "rsa-1", nil, p.claims(nil)), ErrAlgorithm},
		"alg HS256":           {signJWT(t, "HS256", "rsa-1", k1.PublicKey.N.Bytes(), p.claims(nil)), ErrAlgorithm},
		"wrong audience":      {signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"aud": "policy"})), ErrAudience},
		"wrong issuer":        {signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"iss": "https://evil.example"})), ErrIssuer},
		"expired":             {signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"exp": fixedNow.Add(-time.Hour).Unix()})), ErrExpired},
		"not yet valid":       {signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"nbf": fixedNow.Add(time.Hour).Unix()})), ErrNotYetValid},
		"no exp":              {signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"exp": nil})), ErrMalformed},
		"bad exp":             {signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"exp": "soon"})), ErrMalformed},
		"wrong key":           {signJWT(t, "RS256", "rsa-1", k2, p.claims(nil)), ErrSignature},
		"ec wrong key":        {signJWT(t, "ES256", "ec-1", other, p.claims(nil)), ErrSignature},
		"key type mismatch":   {signJWT(t, "ES256", "rsa-1", ec, p.claims(nil)), ErrUnknownKey},
		"jwk alg mismatch":    {signJWT(t, "PS256", "rs-only", k2, p.claims(nil)), ErrUnknownKey},
		"two parts":           {"abc.def", ErrMalformed},
		"bad header b64":      {"!!.e30.sig", ErrMalformed},
		"bad header json":     {b64u([]byte("x")) + ".e30.c2ln", ErrMalformed},
		"bad signature b64":   {strings.Join(strings.Split(signJWT(t, "RS256", "rsa-1", k1, p.claims(nil)), ".")[:2], ".") + ".!!", ErrMalformed},
		"oversized":           {strings.Repeat("a", maxTokenBytes+1), ErrMalformed},
		"es256 short sig":     {strings.Join(strings.Split(signJWT(t, "ES256", "ec-1", ec, p.claims(nil)), ".")[:2], ".") + "." + b64u([]byte("short")), ErrSignature},
		"payload not json":    {forgePayload(t, k1, "rsa-1", "not json"), ErrMalformed},
		"payload bad base64 ": {forgeRawPayload(t, k1, "rsa-1", "!!"), ErrMalformed},
	}
	for name, c := range cases {
		if _, err := v.VerifyToken(ctx, c.token); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
}

// forgePayload signs an arbitrary (non-JSON) payload with RS256.
func forgePayload(t *testing.T, k *rsa.PrivateKey, kid, payload string) string {
	t.Helper()
	return forgeRawPayload(t, k, kid, b64u([]byte(payload)))
}

func forgeRawPayload(t *testing.T, k *rsa.PrivateKey, kid, encodedPayload string) string {
	t.Helper()
	hr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	input := b64u(hr) + "." + encodedPayload
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

func TestOIDCRoleClaimAndAudience(t *testing.T) {
	k1, _ := testRSAKeys(t)
	p := newIDP(t, rsaJWK("rsa-1", "RS256", &k1.PublicKey))
	clk := &clockT{now: fixedNow}
	ctx := context.Background()
	v := newOIDC(t, p, clk, func(c *OIDCConfig) { c.RoleClaim = "realm_access.roles"; c.Audience = "console-api" })
	tok := signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{
		"aud": "console-api", "role": nil, "realm_access": map[string]any{"roles": []any{"offline_access", "viewer", "owner", 7}},
	}))
	claims, err := v.VerifyToken(ctx, tok)
	if err != nil || claims.Role != RoleOwner {
		t.Fatalf("nested roles: %+v %v", claims, err)
	}
	for name, extra := range map[string]map[string]any{
		"missing":       {"aud": "console-api", "role": nil},
		"not an object": {"aud": "console-api", "realm_access": "admin"},
		"unknown role":  {"aud": "console-api", "realm_access": map[string]any{"roles": "superuser"}},
	} {
		claims, err := v.VerifyToken(ctx, signJWT(t, "RS256", "rsa-1", k1, p.claims(extra)))
		if err != nil || claims.Role != "" {
			t.Errorf("%s: role %q err %v", name, claims.Role, err)
		}
	}
}

func TestOIDCDiscoveryFailures(t *testing.T) {
	k1, _ := testRSAKeys(t)
	ctx := context.Background()
	tokenFor := func(p *idp) string { return signJWT(t, "RS256", "rsa-1", k1, p.claims(nil)) }

	p := newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey))
	p.issuer = "https://other-issuer.example"
	if _, err := newOIDC(t, p, &clockT{now: fixedNow}, nil).VerifyToken(ctx, tokenFor(p)); !errors.Is(err, ErrDiscovery) {
		t.Errorf("issuer mismatch: %v", err)
	}
	p = newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey))
	p.jwksURI = "ftp://keys.example/certs"
	if _, err := newOIDC(t, p, &clockT{now: fixedNow}, nil).VerifyToken(ctx, tokenFor(p)); !errors.Is(err, ErrDiscovery) {
		t.Errorf("bad jwks_uri: %v", err)
	}
	p = newIDP(t, map[string]any{"kty": "oct", "k": "c2VjcmV0"})
	if _, err := newOIDC(t, p, &clockT{now: fixedNow}, nil).VerifyToken(ctx, tokenFor(p)); !errors.Is(err, ErrDiscovery) {
		t.Errorf("no usable keys: %v", err)
	}
	// IdP down: the error is cached for MinRefresh instead of hammering the IdP.
	p = newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey))
	p.jwksStatus = http.StatusBadGateway
	clk := &clockT{now: fixedNow}
	v := newOIDC(t, p, clk, nil)
	for i := 0; i < 3; i++ {
		if _, err := v.VerifyToken(ctx, tokenFor(p)); !errors.Is(err, ErrDiscovery) {
			t.Fatalf("down %d: %v", i, err)
		}
	}
	if p.jwks.Load() != 1 {
		t.Fatalf("jwks fetches while down: %d", p.jwks.Load())
	}
	p.mu.Lock()
	p.jwksStatus = http.StatusOK
	p.mu.Unlock()
	clk.Add(DefaultJWKSMinRefresh + time.Second)
	if _, err := v.VerifyToken(ctx, signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"exp": clk.Now().Add(time.Minute).Unix()}))); err != nil {
		t.Fatalf("recovered IdP: %v", err)
	}
	// Unreachable issuer and malformed discovery JSON.
	dead := &OIDCVerifier{cfg: OIDCConfig{HTTPClient: &http.Client{Timeout: time.Second}, Clock: time.Now, MinRefresh: time.Second, MaxAge: time.Hour}, issuer: "http://127.0.0.1:1"}
	if _, err := dead.keysFor(ctx, "x"); !errors.Is(err, ErrDiscovery) {
		t.Errorf("unreachable: %v", err)
	}
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{not json")) }))
	defer junk.Close()
	bad := &OIDCVerifier{cfg: OIDCConfig{HTTPClient: junk.Client(), Clock: time.Now, MinRefresh: time.Second, MaxAge: time.Hour}, issuer: junk.URL}
	if _, err := bad.keysFor(ctx, ""); !errors.Is(err, ErrDiscovery) {
		t.Errorf("junk discovery: %v", err)
	}
	if err := bad.getJSON(ctx, "http://bad\x7f", nil); !errors.Is(err, ErrDiscovery) {
		t.Errorf("bad url: %v", err)
	}
}

func TestParseJWK(t *testing.T) {
	t.Parallel()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := ecJWK("e", &ec.PublicKey)
	if _, ok := parseJWK(good); !ok {
		t.Fatal("valid EC key rejected")
	}
	badX := ecJWK("e", &ec.PublicKey)
	badX["x"] = b64u([]byte{1, 2, 3})
	offCurve := ecJWK("e", &ec.PublicKey)
	offCurve["y"] = b64u(make([]byte, 32))
	enc := ecJWK("e", &ec.PublicKey)
	enc["use"] = "enc"
	for name, raw := range map[string]map[string]any{
		"rsa 1024":     rsaJWK("r", "", &small.PublicKey),
		"p-384":        {"kty": "EC", "crv": "P-384", "x": b64u(p384.X.Bytes()), "y": b64u(p384.Y.Bytes())},
		"bad x":        badX,
		"off curve":    offCurve,
		"encryption":   enc,
		"oct":          {"kty": "oct", "k": "abc"},
		"rsa no n":     {"kty": "RSA", "e": "AQAB"},
		"rsa big e":    {"kty": "RSA", "n": b64u(make([]byte, 256)), "e": b64u([]byte{1, 2, 3, 4, 5})},
		"rsa bad b64":  {"kty": "RSA", "n": "!!", "e": "AQAB"},
		"rsa e too lo": {"kty": "RSA", "n": b64u(small.N.Bytes()), "e": b64u([]byte{1})},
	} {
		if _, ok := parseJWK(raw); ok {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewOIDCVerifier(OIDCConfig{Issuer: "not a url"}); err == nil {
		t.Error("bad issuer accepted")
	}
	if _, err := NewOIDCVerifier(OIDCConfig{Issuer: "ftp://idp"}); err == nil {
		t.Error("ftp issuer accepted")
	}
	v, err := NewOIDCVerifier(OIDCConfig{Issuer: "https://idp.example/realms/x/"})
	if err != nil || v.cfg.Audience != DefaultOIDCAudience || v.cfg.RoleClaim != DefaultOIDCRoleClaim || v.issuer != "https://idp.example/realms/x" {
		t.Fatalf("defaults %+v %v", v, err)
	}
}

func TestGuardCombinesServiceAndOIDC(t *testing.T) {
	k1, _ := testRSAKeys(t)
	p := newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey))
	oidc := newOIDC(t, p, &clockT{now: fixedNow}, nil)
	s, pemKey := newSigner(t)
	service := newVerifier(t, pemKey)
	guard := NewGuard(service, oidc)
	var seen Claims
	h := guard(RoleOperator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/policy/evaluate", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call(mustSign(t, s, baseClaims("operator"))); c != http.StatusNoContent || seen.Issuer != "ironmesh-idp" {
		t.Fatalf("service token: %d %+v", c, seen)
	}
	if c := call(signJWT(t, "RS256", "rsa-1", k1, p.claims(nil))); c != http.StatusNoContent || seen.Subject != "user-42" || seen.TenantID == "" {
		t.Fatalf("oidc token: %d %+v", c, seen)
	}
	if c := call(signJWT(t, "RS256", "rsa-1", k1, p.claims(map[string]any{"role": "viewer"}))); c != http.StatusForbidden {
		t.Fatalf("oidc viewer on operator route: %d", c)
	}
	if c := call("garbage.token.here"); c != http.StatusUnauthorized {
		t.Fatalf("garbage: %d", c)
	}
	// An OIDC token is not accepted by the service verifier alone (different key and audience).
	req0 := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	req0.Header.Set("Authorization", "Bearer "+signJWT(t, "RS256", "rsa-1", k1, p.claims(nil)))
	rec0 := httptest.NewRecorder()
	NewGuard(service)(RoleViewer, h).ServeHTTP(rec0, req0)
	if rec0.Code != http.StatusUnauthorized {
		t.Fatalf("oidc token on service-only guard: %d", rec0.Code)
	}
	none := NewGuard()(RoleViewer, h)
	req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer a.b.c")
	rec := httptest.NewRecorder()
	none.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no verifiers: %d", rec.Code)
	}
}

func TestOIDCExplicitJWKSURLSkipsDiscovery(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newIDP(t, ecJWK("ec-1", &ec.PublicKey))
	clk := &clockT{now: fixedNow}
	// Tokens name a browser-facing issuer the service cannot reach; keys come from the
	// in-cluster JWKS URL instead, and the iss claim is still checked exactly.
	const browserIssuer = "http://localhost:8180/realms/ironmesh"
	v, err := NewOIDCVerifier(OIDCConfig{Issuer: browserIssuer, JWKSURL: p.issuerURL() + "/certs", Clock: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	claims, err := v.VerifyToken(ctx, signJWT(t, "ES256", "ec-1", ec, p.claims(map[string]any{"iss": browserIssuer})))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Role != RoleAdmin {
		t.Fatalf("claims %+v", claims)
	}
	if p.discovery.Load() != 0 || p.jwks.Load() != 1 {
		t.Fatalf("discovery=%d jwks=%d, want discovery skipped", p.discovery.Load(), p.jwks.Load())
	}
	if _, err := v.VerifyToken(ctx, signJWT(t, "ES256", "ec-1", ec, p.claims(nil))); !errors.Is(err, ErrIssuer) {
		t.Fatalf("token from the in-cluster issuer must still fail the iss check: %v", err)
	}
	if _, err := NewOIDCVerifier(OIDCConfig{Issuer: browserIssuer, JWKSURL: "ftp://idp/certs"}); err == nil {
		t.Fatal("non-http JWKS URL accepted")
	}
}
