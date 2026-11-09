package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServiceTokenClaimRequirements(t *testing.T) {
	s, pemKey := newSigner(t)
	v := newVerifier(t, pemKey)
	mod := func(f func(c map[string]any)) string {
		c := baseClaims("viewer")
		f(c)
		return mustSign(t, s, c)
	}
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"lifetime 301s", mod(func(c map[string]any) { c["exp"] = fixedNow.Add(301 * time.Second).Unix() }), ErrLifetime},
		{"exp before iat", mod(func(c map[string]any) {
			c["iat"] = fixedNow.Add(10 * time.Second).Unix()
			c["exp"] = fixedNow.Add(5 * time.Second).Unix()
		}), ErrLifetime},
		{"missing iat", mod(func(c map[string]any) { delete(c, "iat") }), ErrMalformed},
		{"iat in the future", mod(func(c map[string]any) {
			c["iat"] = fixedNow.Add(2 * time.Minute).Unix()
			c["exp"] = fixedNow.Add(6 * time.Minute).Unix()
		}), ErrNotYetValid},
		{"missing jti", mod(func(c map[string]any) { delete(c, "jti") }), ErrMalformed},
		{"empty jti", mod(func(c map[string]any) { c["jti"] = " " }), ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(tc.token); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v want %v", err, tc.want)
			}
		})
	}
	got, err := v.Verify(mod(func(c map[string]any) { c["exp"] = fixedNow.Add(300 * time.Second).Unix() }))
	if err != nil || got.Source != SourceService || got.ID == "" {
		t.Fatalf("300 s token: %+v %v", got, err)
	}
}

func TestServiceTokenSingleUse(t *testing.T) {
	s, pemKey := newSigner(t)
	cache := NewReplayCache(0)
	v := newVerifier(t, pemKey, WithReplayCache(cache))
	tok := mustSign(t, s, baseClaims("viewer"))
	if _, err := v.Verify(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := v.Verify(mustSign(t, s, baseClaims("viewer"))); err != nil {
		t.Fatalf("fresh jti refused: %v", err)
	}
	// The same jti from another issuer is a different token.
	other := baseClaims("viewer")
	other["iss"] = "registry"
	other["jti"] = "shared"
	again := baseClaims("viewer")
	again["jti"] = "shared"
	if _, err := v.Verify(mustSign(t, s, other)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(mustSign(t, s, again)); err != nil {
		t.Fatalf("jti is scoped per issuer: %v", err)
	}
	if cache.Len() != 4 {
		t.Fatalf("cache len %d", cache.Len())
	}
}

func TestReplayCacheBounds(t *testing.T) {
	now := fixedNow
	c := NewReplayCache(3)
	if !c.Use("a", now.Add(time.Minute), now) || c.Use("a", now.Add(time.Minute), now.Add(59*time.Second)) {
		t.Fatal("second use within the lifetime must be refused")
	}
	if !c.Use("a", now.Add(3*time.Minute), now.Add(time.Minute)) {
		t.Fatal("expired id not forgotten")
	}
	c.Use("b", now.Add(10*time.Minute), now.Add(time.Minute))
	c.Use("c", now.Add(10*time.Minute), now.Add(time.Minute))
	if !c.Use("d", now.Add(10*time.Minute), now.Add(time.Minute)) || c.Len() != 3 {
		t.Fatalf("eviction: len %d", c.Len())
	}
	if c.Use("b", now.Add(10*time.Minute), now.Add(2*time.Minute)) {
		t.Fatal("b must still be remembered")
	}
	big := NewReplayCache(0)
	for i := 0; i < 3000; i++ {
		big.Use(fmt.Sprint(i), now.Add(time.Second), now)
	}
	if !big.Use("late", now.Add(time.Hour), now.Add(2*time.Second)) || big.Len() != 1 {
		t.Fatalf("expired entries not purged: %d", big.Len())
	}
}

// TestOIDCTokensAreNotSingleUse: console access tokens are reused by browsers and stay valid
// until exp even when service JWTs are single-use.
func TestOIDCTokensAreNotSingleUse(t *testing.T) {
	k1, _ := testRSAKeys(t)
	p := newIDP(t, rsaJWK("rsa-1", "", &k1.PublicKey))
	oidc := newOIDC(t, p, &clockT{now: fixedNow}, nil)
	s, pemKey := newSigner(t)
	service := newVerifier(t, pemKey, WithReplayCache(NewReplayCache(0)))
	h := NewGuard(service, oidc)(RoleViewer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/revocations", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	user := signJWT(t, "RS256", "rsa-1", k1, p.claims(nil))
	for i := 0; i < 3; i++ {
		if c := call(user); c != http.StatusNoContent {
			t.Fatalf("OIDC token use %d: %d", i, c)
		}
	}
	svc := mustSign(t, s, baseClaims("viewer"))
	if c := call(svc); c != http.StatusNoContent {
		t.Fatalf("service token first use: %d", c)
	}
	if c := call(svc); c != http.StatusUnauthorized {
		t.Fatalf("service token replay: %d", c)
	}
}

type pkiCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newPKICA(t *testing.T, cn string) *pkiCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &pkiCA{cert: cert, key: key}
}

func (ca *pkiCA) leaf(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"policy.test"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// TestGuardBindsTokenSubjectToServiceCertificate: a caller presenting a Services CA client
// certificate must present a service JWT for the same service.
func TestGuardBindsTokenSubjectToServiceCertificate(t *testing.T) {
	s, pemKey := newSigner(t)
	// Real clock: the TLS handshake verifies certificates against time.Now.
	v, err := NewVerifier(pemKey, "policy")
	if err != nil {
		t.Fatal(err)
	}
	servicesCA, deviceCA := newPKICA(t, "IronMesh Services CA"), newPKICA(t, "IronMesh Device CA")
	servicesPool := x509.NewCertPool()
	servicesPool.AddCert(servicesCA.cert)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(servicesCA.cert)
	clientCAs.AddCert(deviceCA.cert)

	h := NewBoundGuard(servicesPool, v)(RoleViewer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{servicesCA.leaf(t, "policy", true)}, ClientCAs: clientCAs, ClientAuth: tls.VerifyClientCertIfGiven}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(servicesCA.cert)
	client := func(cert *tls.Certificate) *http.Client {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "policy.test"}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	}
	token := func(sub string) string {
		c := map[string]any{"aud": "policy", "role": "viewer", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": nextJTI()}
		if sub != "" {
			c["sub"] = sub
		}
		return mustSign(t, s, c)
	}
	registryCert := servicesCA.leaf(t, "svc-registry", false)
	deviceCert := deviceCA.leaf(t, "dev-8f3a1c2b9d4e5f60", false)
	cases := []struct {
		name   string
		cert   *tls.Certificate
		sub    string
		status int
	}{
		{"matching sub", &registryCert, "registry", http.StatusNoContent},
		{"matching sub with prefix", &registryCert, "svc-registry", http.StatusNoContent},
		{"other service", &registryCert, "ota", http.StatusUnauthorized},
		{"no sub", &registryCert, "", http.StatusUnauthorized},
		{"no client certificate", nil, "anything", http.StatusNoContent},
		{"non-service certificate", &deviceCert, "registry", http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/policy", nil)
			req.Header.Set("Authorization", "Bearer "+token(tc.sub))
			c := client(tc.cert)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			c.CloseIdleConnections()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d want %d", resp.StatusCode, tc.status)
			}
		})
	}
	if _, ok := ServiceCertCN(httptest.NewRequest(http.MethodGet, "/", nil), servicesPool); ok {
		t.Fatal("plain request has no certificate")
	}
	if ServiceName(" svc-bridge ") != "bridge" || ServiceName("bridge") != "bridge" {
		t.Fatal("ServiceName")
	}
}
