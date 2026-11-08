package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func newSigner(t *testing.T) (*Signer, string) {
	t.Helper()
	s, err := GenerateSigner("k1")
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return s, pemKey
}

func baseClaims(role string) map[string]any {
	return map[string]any{
		"sub":  "user-1",
		"iss":  "ironmesh-idp",
		"aud":  "policy",
		"role": role,
		"exp":  fixedNow.Add(5 * time.Minute).Unix(),
		"iat":  fixedNow.Unix(),
	}
}

func mustSign(t *testing.T, s *Signer, claims map[string]any) string {
	t.Helper()
	tok, err := s.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newVerifier(t *testing.T, pemKey string, opts ...VerifierOption) *Verifier {
	t.Helper()
	opts = append([]VerifierOption{WithClock(func() time.Time { return fixedNow })}, opts...)
	v, err := NewVerifier(pemKey, "policy", opts...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRoles(t *testing.T) {
	if r, ok := ParseRole(" Admin "); !ok || r != RoleAdmin {
		t.Errorf("ParseRole = %q %v", r, ok)
	}
	if _, ok := ParseRole("root"); ok {
		t.Error("root should be unknown")
	}
	cases := []struct {
		have, min Role
		want      bool
	}{
		{RoleViewer, RoleViewer, true}, {RoleViewer, RoleOperator, false}, {RoleOperator, RoleViewer, true},
		{RoleAdmin, RoleOwner, false}, {RoleOwner, RoleAdmin, true}, {RoleOwner, RoleOwner, true},
		{Role("bogus"), RoleViewer, false}, {RoleOwner, Role("bogus"), false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.min); got != c.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", c.have, c.min, got, c.want)
		}
	}
}

func TestVerifyValidToken(t *testing.T) {
	s, pemKey := newSigner(t)
	v := newVerifier(t, pemKey, WithIssuer("ironmesh-idp"))
	claims := baseClaims("operator")
	claims["tenant_id"] = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	claims["nbf"] = fixedNow.Add(-time.Minute).Unix()
	got, err := v.Verify(mustSign(t, s, claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "user-1" || got.Role != RoleOperator || got.TenantID != "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11" || got.Issuer != "ironmesh-idp" {
		t.Errorf("claims = %+v", got)
	}
	if !got.ExpiresAt.Equal(fixedNow.Add(5*time.Minute)) || !got.IssuedAt.Equal(fixedNow) || !got.NotBefore.Equal(fixedNow.Add(-time.Minute)) {
		t.Errorf("times = %+v", got)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "policy" {
		t.Errorf("aud = %v", got.Audience)
	}
}

func TestVerifyAudienceArrayAndUnknownRole(t *testing.T) {
	s, pemKey := newSigner(t)
	v := newVerifier(t, pemKey)
	claims := baseClaims("superuser")
	claims["aud"] = []string{"registry", "policy"}
	got, err := v.Verify(mustSign(t, s, claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Role != "" {
		t.Errorf("unknown role should be empty, got %q", got.Role)
	}
	if len(got.Audience) != 2 {
		t.Errorf("aud = %v", got.Audience)
	}
}

func TestVerifyRejections(t *testing.T) {
	s, pemKey := newSigner(t)
	other, _ := newSigner(t)
	v := newVerifier(t, pemKey, WithIssuer("ironmesh-idp"))

	expired := baseClaims("viewer")
	expired["exp"] = fixedNow.Add(-2 * time.Minute).Unix()
	future := baseClaims("viewer")
	future["nbf"] = fixedNow.Add(2 * time.Minute).Unix()
	wrongAud := baseClaims("viewer")
	wrongAud["aud"] = "registry"
	wrongIss := baseClaims("viewer")
	wrongIss["iss"] = "someone-else"
	noExp := baseClaims("viewer")
	delete(noExp, "exp")
	badExp := baseClaims("viewer")
	badExp["exp"] = "tomorrow"

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"expired", mustSign(t, s, expired), ErrExpired},
		{"not yet valid", mustSign(t, s, future), ErrNotYetValid},
		{"wrong audience", mustSign(t, s, wrongAud), ErrAudience},
		{"wrong issuer", mustSign(t, s, wrongIss), ErrIssuer},
		{"missing exp", mustSign(t, s, noExp), ErrMalformed},
		{"bad exp", mustSign(t, s, badExp), ErrMalformed},
		{"wrong key", mustSign(t, other, baseClaims("viewer")), ErrSignature},
		{"two parts", "a.b", ErrMalformed},
		{"bad header b64", "!!!.b.c", ErrMalformed},
		{"bad header json", base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".b.c", ErrMalformed},
		{"alg none", forgeAlg(t, s, "none"), ErrAlgorithm},
		{"alg hs256", forgeAlg(t, s, "HS256"), ErrAlgorithm},
		{"short signature", strings.Join(strings.Split(mustSign(t, s, baseClaims("viewer")), ".")[:2], ".") + ".AAAA", ErrMalformed},
		{"tampered payload", tamper(t, mustSign(t, s, baseClaims("viewer"))), ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// forgeAlg rebuilds the token header with a different alg while keeping a 64-byte signature.
func forgeAlg(t *testing.T, s *Signer, alg string) string {
	t.Helper()
	tok := mustSign(t, s, baseClaims("viewer"))
	parts := strings.Split(tok, ".")
	head, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	parts[0] = base64.RawURLEncoding.EncodeToString(head)
	return strings.Join(parts, ".")
}

func tamper(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["role"] = "owner"
	raw, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

func TestVerifyLeeway(t *testing.T) {
	s, pemKey := newSigner(t)
	claims := baseClaims("viewer")
	claims["exp"] = fixedNow.Add(-10 * time.Second).Unix()
	tok := mustSign(t, s, claims)
	if _, err := newVerifier(t, pemKey).Verify(tok); err != nil {
		t.Errorf("30s default leeway should accept a token expired 10s ago: %v", err)
	}
	if _, err := newVerifier(t, pemKey, WithLeeway(0)).Verify(tok); !errors.Is(err, ErrExpired) {
		t.Errorf("zero leeway should reject: %v", err)
	}
}

func TestKeyRotationBundleAndCertificate(t *testing.T) {
	s1, pem1 := newSigner(t)
	s2, pem2 := newSigner(t)
	v := newVerifier(t, pem1+pem2)
	for _, s := range []*Signer{s1, s2} {
		if _, err := v.Verify(mustSign(t, s, baseClaims("viewer"))); err != nil {
			t.Errorf("token from rotated key rejected: %v", err)
		}
	}

	// A CERTIFICATE block is accepted as a key source too.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: fixedNow.Add(-time.Hour), NotAfter: fixedNow.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	certSigner, _ := NewSigner(key, "cert")
	if _, err := newVerifier(t, certPEM).Verify(mustSign(t, certSigner, baseClaims("viewer"))); err != nil {
		t.Errorf("certificate-backed verification failed: %v", err)
	}
}

func TestNewVerifierErrors(t *testing.T) {
	_, pemKey := newSigner(t)
	if _, err := NewVerifier("", "policy"); !errors.Is(err, ErrNoKeys) {
		t.Errorf("empty bundle err = %v", err)
	}
	if _, err := NewVerifier(pemKey, ""); err == nil {
		t.Error("empty audience should fail")
	}
	if _, err := NewVerifier("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "policy"); err == nil {
		t.Error("unsupported block should fail")
	}
	if _, err := NewVerifier("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "policy"); err == nil {
		t.Error("garbage key should fail")
	}
	if _, err := NewVerifier("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "policy"); err == nil {
		t.Error("garbage certificate should fail")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := NewVerifier(bundle, "policy"); err == nil {
		t.Error("P-384 key should be rejected")
	}
	if _, err := NewSigner(p384, ""); err == nil {
		t.Error("P-384 signer should be rejected")
	}
	if _, err := NewSigner(nil, ""); err == nil {
		t.Error("nil signer key should be rejected")
	}
	s, _ := newSigner(t)
	if _, err := s.Sign(map[string]any{"bad": make(chan int)}); err == nil {
		t.Error("unencodable claims should fail")
	}
}

func TestGuard(t *testing.T) {
	s, pemKey := newSigner(t)
	v := newVerifier(t, pemKey)
	guard := v.Guard()
	var seen Claims
	handler := guard(RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	call := func(auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := call(""); rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != "application/problem+json" || rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("missing token: %d %q", rec.Code, rec.Header())
	}
	if rec := call("Basic abc"); rec.Code != http.StatusUnauthorized {
		t.Errorf("basic auth: %d", rec.Code)
	}
	if rec := call("Bearer "); rec.Code != http.StatusUnauthorized {
		t.Errorf("empty bearer: %d", rec.Code)
	}
	if rec := call("Bearer not.a.jwt"); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: %d", rec.Code)
	}
	if rec := call("Bearer " + mustSign(t, s, baseClaims("viewer"))); rec.Code != http.StatusForbidden {
		t.Errorf("viewer on admin route: %d", rec.Code)
	}
	if rec := call("Bearer " + mustSign(t, s, baseClaims("mystery"))); rec.Code != http.StatusForbidden {
		t.Errorf("unknown role: %d", rec.Code)
	}
	if rec := call("bearer " + mustSign(t, s, baseClaims("owner"))); rec.Code != http.StatusNoContent {
		t.Errorf("owner on admin route: %d %s", rec.Code, rec.Body.String())
	}
	if seen.Role != RoleOwner || seen.Subject != "user-1" {
		t.Errorf("claims not propagated: %+v", seen)
	}
	if _, ok := ClaimsFromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok {
		t.Error("ClaimsFromContext on plain context should be false")
	}
}

func TestDisabledGuard(t *testing.T) {
	handler := DisabledGuard("management API disabled")(RoleViewer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler must not run")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/revocations", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
}
