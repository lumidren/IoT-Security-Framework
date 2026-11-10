package mgmt_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

type mgmtEnv struct {
	p       *testutil.PKI
	s       *testutil.Server
	admin   *http.Client
	jwtKey  *ecdsa.PrivateKey
	svcCert *x509.Certificate
	svcKey  *ecdsa.PrivateKey
}

func newEnv(t *testing.T) *mgmtEnv {
	t.Helper()
	p := testutil.New(t)
	jwtKey := testutil.P256Key(t)
	s := p.StartServer(t, testutil.ServerOptions{AllowedCNs: []string{"svc-console", "svc-registry"}, JWTKeys: []crypto.PublicKey{jwtKey.Public()}})
	cert, key := p.NewServiceClient(t, "svc-console")
	return &mgmtEnv{p: p, s: s, admin: s.Client(cert, key), jwtKey: jwtKey, svcCert: cert, svcKey: key}
}

func do(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			data, _ := json.Marshal(b)
			rd = bytes.NewReader(data)
		}
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data
}

func TestAuthentication(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	url := e.s.MTLS.URL + "/v1/ca/chain"
	now := time.Now().Unix()
	token := func(t *testing.T, key *ecdsa.PrivateKey, claims mgmt.Claims) string {
		t.Helper()
		tok, err := mgmt.SignES256(key, claims)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	otherKey := testutil.P256Key(t)
	dev := e.p.NewBootstrapDevice(t, testutil.Tenant)
	deniedCert, deniedKey := e.p.NewServiceClient(t, "svc-bridge")
	good := func(sub string) mgmt.Claims {
		return mgmt.Claims{Subject: sub, Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 300, IssuedAt: now, ID: testJTI()}
	}
	goodClaims := good("svc-registry")
	replayed := token(t, e.jwtKey, good("registry"))

	cases := []struct {
		name   string
		client *http.Client
		auth   string
		status int
	}{
		{"no credentials", e.s.Client(nil, nil), "", http.StatusUnauthorized},
		{"device certificate", e.s.DeviceClient(dev), "", http.StatusUnauthorized},
		{"service cert not allow-listed", e.s.Client(deniedCert, deniedKey), "", http.StatusForbidden},
		{"service cert allow-listed", e.admin, "", http.StatusOK},
		{"valid jwt", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, goodClaims), http.StatusOK},
		{"jwt aud array", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Audience: mgmt.Audience{"registry", "pki"}, ExpiresAt: now + 60, IssuedAt: now, ID: testJTI()}), http.StatusOK},
		{"jwt first use", e.s.Client(nil, nil), "Bearer " + replayed, http.StatusOK},
		{"jwt replayed", e.s.Client(nil, nil), "Bearer " + replayed, http.StatusUnauthorized},
		{"jwt without iat", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 60, ID: testJTI()}), http.StatusUnauthorized},
		{"jwt without jti", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 60, IssuedAt: now}), http.StatusUnauthorized},
		{"jwt lifetime 301s", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 301, IssuedAt: now, ID: testJTI()}), http.StatusUnauthorized},
		{"jwt lifetime 300s", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 300, IssuedAt: now, ID: testJTI()}), http.StatusOK},
		{"jwt exp before iat", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 60, IssuedAt: now + 61, ID: testJTI()}), http.StatusUnauthorized},
		{"jwt iat in the future", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 200, IssuedAt: now + 120, ID: testJTI()}), http.StatusUnauthorized},
		{"service cert plus matching jwt", e.admin, "Bearer " + token(t, e.jwtKey, good("console")), http.StatusOK},
		{"service cert plus matching jwt with prefix", e.admin, "Bearer " + token(t, e.jwtKey, good("svc-console")), http.StatusOK},
		{"service cert plus jwt of another service", e.admin, "Bearer " + token(t, e.jwtKey, good("registry")), http.StatusUnauthorized},
		{"service cert plus jwt without sub", e.admin, "Bearer " + token(t, e.jwtKey, good("")), http.StatusUnauthorized},
		{"service cert plus invalid jwt", e.admin, "Bearer abc.def", http.StatusUnauthorized},
		{"service cert plus non-bearer authorization", e.admin, "Basic dXNlcjpwYXNz", http.StatusUnauthorized},
		{"denied service cert plus its own jwt", e.s.Client(deniedCert, deniedKey), "Bearer " + token(t, e.jwtKey, good("bridge")), http.StatusForbidden},
		{"jwt wrong aud", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Audience: mgmt.Audience{"ota"}, ExpiresAt: now + 60}), http.StatusUnauthorized},
		{"jwt expired", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Audience: mgmt.Audience{"pki"}, ExpiresAt: now - 1}), http.StatusUnauthorized},
		{"jwt no exp", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Audience: mgmt.Audience{"pki"}}), http.StatusUnauthorized},
		{"jwt future nbf", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 600, NotBefore: now + 300}), http.StatusUnauthorized},
		{"jwt too long lived", e.s.Client(nil, nil), "Bearer " + token(t, e.jwtKey, mgmt.Claims{Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 7200, IssuedAt: now, ID: testJTI()}), http.StatusUnauthorized},
		{"jwt wrong key", e.s.Client(nil, nil), "Bearer " + token(t, otherKey, goodClaims), http.StatusUnauthorized},
		{"jwt malformed", e.s.Client(nil, nil), "Bearer abc.def", http.StatusUnauthorized},
		{"jwt alg none", e.s.Client(nil, nil), "Bearer " + noneToken(), http.StatusUnauthorized},
		{"basic auth scheme", e.s.Client(nil, nil), "Basic dXNlcjpwYXNz", http.StatusUnauthorized},
		{"empty bearer", e.s.Client(nil, nil), "Bearer ", http.StatusUnauthorized},
		{"device cert plus valid jwt", e.s.DeviceClient(dev), "Bearer " + token(t, e.jwtKey, good("svc-registry")), http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers := map[string]string{}
			if c.auth != "" {
				headers["Authorization"] = c.auth
			}
			resp, body := do(t, c.client, http.MethodGet, url, nil, headers)
			if resp.StatusCode != c.status {
				t.Fatalf("status %d want %d: %s", resp.StatusCode, c.status, body)
			}
			if c.status == http.StatusUnauthorized && !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
				t.Fatal("missing WWW-Authenticate")
			}
			if c.status == http.StatusOK {
				certs, err := ca.ParseCertsPEM(body)
				if err != nil || len(certs) != 4 || resp.Header.Get("Content-Type") != "application/x-pem-file" {
					t.Fatalf("chain: %d certs, %v", len(certs), err)
				}
			}
		})
	}
	if promtest.ToFloat64(e.p.Metrics.AuthFailures) < 10 {
		t.Fatal("auth failures not counted")
	}
	// Server without JWT keys rejects tokens outright.
	s2 := e.p.StartServer(t, testutil.ServerOptions{})
	resp, _ := do(t, s2.Client(nil, nil), http.MethodGet, s2.MTLS.URL+"/v1/ca/chain", nil, map[string]string{"Authorization": "Bearer " + token(t, e.jwtKey, goodClaims)})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no jwt keys: %d", resp.StatusCode)
	}
}

// noneToken builds an unsigned token with alg=none.
func noneToken() string {
	hdr := base64url(`{"alg":"none","typ":"JWT"}`)
	claims := base64url(`{"aud":"pki","exp":9999999999}`)
	return hdr + "." + claims + "."
}

func base64url(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		cnt := 0
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(b) {
				n |= uint32(b[i+j])
				cnt++
			}
		}
		for j := 0; j < cnt+1; j++ {
			out.WriteByte(alphabet[(n>>(18-6*uint(j)))&0x3f])
		}
	}
	return out.String()
}

func TestCertificateEndpoints(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	base := e.s.MTLS.URL
	dev := e.p.NewOperationalDevice(t, testutil.Tenant)
	serial := ca.FormatSerial(dev.Cert.SerialNumber)
	jsonHdr := map[string]string{"Content-Type": "application/json"}

	// GET certificate: valid.
	resp, body := do(t, e.admin, http.MethodGet, base+"/v1/certificates/"+strings.ToUpper(serial), nil, nil)
	var view map[string]any
	if resp.StatusCode != 200 || json.Unmarshal(body, &view) != nil || view["status"] != "valid" || view["device_id"] != dev.ID || view["certificate_pem"] == "" {
		t.Fatalf("GET cert: %d %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, e.admin, http.MethodGet, base+"/v1/certificates/zz", nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad serial: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodGet, base+"/v1/certificates/ffffffffffffffffffffffffffffffff", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown serial: %d", resp.StatusCode)
	}

	// Revoke: bad body, bad reason, success, conflict, not found, bad serial.
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/certificates/"+serial+"/revoke", "{not json", jsonHdr); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/certificates/"+serial+"/revoke", map[string]string{"reason": "meh"}, jsonHdr); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad reason: %d", resp.StatusCode)
	}
	start := time.Now()
	resp, body = do(t, e.admin, http.MethodPost, base+"/v1/certificates/"+serial+"/revoke", map[string]string{"reason": "keyCompromise"}, jsonHdr)
	var result map[string]any
	if resp.StatusCode != 200 || json.Unmarshal(body, &result) != nil || result["published"] != true || result["reason"] != "keyCompromise" {
		t.Fatalf("revoke: %d %s", resp.StatusCode, body)
	}
	events := e.s.Policy.Events()
	if len(events) != 1 || events[0].ReceivedAt.Sub(start) >= time.Second || !events[0].SignatureValid {
		t.Fatalf("policy events %+v", events)
	}
	// CRL now lists the serial and OCSP says revoked.
	der, _, _, _, _ := e.s.CRL.Current()
	list, _ := x509.ParseRevocationList(der)
	found := false
	for _, en := range list.RevokedCertificateEntries {
		if en.SerialNumber.Cmp(dev.Cert.SerialNumber) == 0 && en.ReasonCode == ca.ReasonKeyCompromise {
			found = true
		}
	}
	if !found {
		t.Fatal("CRL does not list the revoked serial")
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/certificates/"+serial+"/revoke", nil, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("second revoke: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/certificates/ffffffffffffffffffffffffffffffff/revoke", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke unknown: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/certificates/xyz/revoke", nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke bad serial: %d", resp.StatusCode)
	}
	resp, body = do(t, e.admin, http.MethodGet, base+"/v1/certificates/"+serial, nil, nil)
	if json.Unmarshal(body, &view) != nil || view["status"] != "revoked" || view["revocation"] == nil {
		t.Fatalf("GET revoked: %s", body)
	}

	// Device certificate listing and revoke-all.
	k2 := testutil.P256Key(t)
	c2, _ := e.p.Device.IssueOperational(ca.DeviceRequest{TenantID: testutil.Tenant, DeviceID: dev.ID, PublicKey: k2.Public()})
	_ = e.p.Store.PutCertificate(context.Background(), ca.NewRecord(c2, store.KindOperational, "hardware", e.p.Clock()))
	resp, body = do(t, e.admin, http.MethodGet, base+"/v1/devices/"+dev.ID+"/certificates", nil, nil)
	var listing struct {
		DeviceID     string           `json:"device_id"`
		Certificates []map[string]any `json:"certificates"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &listing) != nil || len(listing.Certificates) != 2 || listing.DeviceID != dev.ID {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, e.admin, http.MethodGet, base+"/v1/devices/bad/certificates", nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("list bad id: %d", resp.StatusCode)
	}
	resp, body = do(t, e.admin, http.MethodPost, base+"/v1/devices/"+dev.ID+"/revoke-all", map[string]string{"reason": "cessationOfOperation"}, jsonHdr)
	var all struct {
		Count int `json:"count"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &all) != nil || all.Count != 1 {
		t.Fatalf("revoke-all: %d %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/devices/bad/revoke-all", nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke-all bad id: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/devices/"+dev.ID+"/revoke-all", map[string]string{"reason": "nope"}, jsonHdr); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke-all bad reason: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/devices/"+dev.ID+"/revoke-all", "{", jsonHdr); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke-all bad json: %d", resp.StatusCode)
	}

	// Stats and the expiring gauge.
	resp, body = do(t, e.admin, http.MethodGet, base+"/v1/stats", nil, nil)
	var stats mgmt.StatsResponse
	if resp.StatusCode != 200 || json.Unmarshal(body, &stats) != nil || stats.Certificates.Total != 2 || stats.Certificates.Revoked != 2 || len(stats.Expiring) != 3 {
		t.Fatalf("stats: %d %s", resp.StatusCode, body)
	}
	if promtest.ToFloat64(e.p.Metrics.CertExpiring.WithLabelValues("7d")) != 0 {
		t.Fatal("expiring gauge")
	}
	// A non-revoked certificate expiring soon shows up in the windows.
	soon := ca.NewRecord(c2, store.KindOperational, "hardware", e.p.Clock())
	soon.Serial = "00000000000000000000000000000001"
	soon.NotAfter = e.p.Clock().Add(12 * time.Hour)
	_ = e.p.Store.PutCertificate(context.Background(), soon)
	_, body = do(t, e.admin, http.MethodGet, base+"/v1/stats", nil, nil)
	_ = json.Unmarshal(body, &stats)
	if stats.Expiring["24h"] != 1 || stats.Expiring["72h"] != 1 || stats.Expiring["7d"] != 1 {
		t.Fatalf("expiring %+v", stats.Expiring)
	}
	if promtest.ToFloat64(e.p.Metrics.CertExpiring.WithLabelValues("24h")) != 1 {
		t.Fatal("expiring gauge not updated")
	}
	// Expired certificates report status expired.
	resp, body = do(t, e.admin, http.MethodGet, base+"/v1/certificates/"+soon.Serial, nil, nil)
	e.p.Advance(13 * time.Hour)
	_, body = do(t, e.admin, http.MethodGet, base+"/v1/certificates/"+soon.Serial, nil, nil)
	_ = json.Unmarshal(body, &view)
	if view["status"] != "expired" {
		t.Fatalf("expired status: %s", body)
	}
	e.p.Advance(-13 * time.Hour)

	// Store outage -> 500s.
	_ = e.p.Store.Close()
	for _, u := range []string{base + "/v1/certificates/" + serial, base + "/v1/devices/" + dev.ID + "/certificates", base + "/v1/stats"} {
		if resp, _ := do(t, e.admin, http.MethodGet, u, nil, nil); resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("%s with closed store: %d", u, resp.StatusCode)
		}
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/certificates/"+serial+"/revoke", nil, nil); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("revoke with closed store: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.admin, http.MethodPost, base+"/v1/devices/"+dev.ID+"/revoke-all", nil, nil); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("revoke-all with closed store: %d", resp.StatusCode)
	}
}

func TestJWTHelpers(t *testing.T) {
	t.Parallel()
	key := testutil.P256Key(t)
	now := time.Now()
	tok, err := mgmt.SignES256(key, mgmt.Claims{Issuer: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now.Unix() + 60, IssuedAt: now.Unix(), ID: testJTI()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := mgmt.VerifyES256(tok, []*ecdsa.PublicKey{nil, &key.PublicKey}, "pki", now)
	if err != nil || claims.Issuer != "registry" {
		t.Fatalf("VerifyES256: %v", err)
	}
	// aud marshal forms.
	single, _ := json.Marshal(mgmt.Audience{"pki"})
	multi, _ := json.Marshal(mgmt.Audience{"a", "b"})
	if string(single) != `"pki"` || string(multi) != `["a","b"]` {
		t.Fatalf("aud marshal %s %s", single, multi)
	}
	var aud mgmt.Audience
	if err := json.Unmarshal([]byte(`5`), &aud); err == nil {
		t.Fatal("numeric aud accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := mgmt.SignES256(p384, mgmt.Claims{}); err == nil {
		t.Fatal("P-384 signer accepted")
	}
	if _, err := mgmt.SignES256(nil, mgmt.Claims{}); err == nil {
		t.Fatal("nil signer accepted")
	}
	parts := strings.Split(tok, ".")
	bad := []string{
		"a.b",
		"!!!." + parts[1] + "." + parts[2],
		base64url("{") + "." + parts[1] + "." + parts[2],
		parts[0] + ".!!!." + parts[2],
		parts[0] + "." + base64url("{") + "." + parts[2],
		parts[0] + "." + parts[1] + ".!!!",
		parts[0] + "." + parts[1] + "." + base64url("short"),
	}
	for i, b := range bad {
		if _, err := mgmt.VerifyES256(b, []*ecdsa.PublicKey{&key.PublicKey}, "pki", now); err == nil {
			t.Errorf("bad token %d accepted", i)
		}
	}
	// Subject falls back to issuer and then to "jwt".
	auth := mgmt.NewAuthenticator(nil, []string{" svc-a ", ""}, []*ecdsa.PublicKey{&key.PublicKey}, nil)
	if !auth.AllowedCNs["svc-a"] || len(auth.AllowedCNs) != 1 {
		t.Fatalf("allowed CNs %v", auth.AllowedCNs)
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	pr, err := auth.Authenticate(req)
	if err != nil || pr.Subject != "registry" || pr.Method != "jwt" {
		t.Fatalf("principal %+v %v", pr, err)
	}
	anon, _ := mgmt.SignES256(key, mgmt.Claims{Audience: mgmt.Audience{"pki"}, ExpiresAt: now.Unix() + 60, IssuedAt: now.Unix(), ID: testJTI()})
	req.Header.Set("Authorization", "bearer "+anon)
	if pr, err := auth.Authenticate(req); err != nil || pr.Subject != "jwt" {
		t.Fatalf("anonymous principal %+v %v", pr, err)
	}
}

func testJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestReplayCache(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	c := mgmt.NewReplayCache(3)
	if !c.Use("a", now.Add(time.Minute), now) || c.Use("a", now.Add(time.Minute), now.Add(59*time.Second)) {
		t.Fatal("second use within the lifetime must be refused")
	}
	// After expiry the id may be used again (the token itself is expired by then).
	if !c.Use("a", now.Add(3*time.Minute), now.Add(time.Minute)) {
		t.Fatal("expired id not forgotten")
	}
	if !c.Use("b", now.Add(10*time.Minute), now.Add(time.Minute)) || !c.Use("c", now.Add(10*time.Minute), now.Add(time.Minute)) {
		t.Fatal("fresh ids refused")
	}
	if c.Len() != 3 {
		t.Fatalf("len %d", c.Len())
	}
	// Full: the oldest live id ("a") is evicted to make room.
	if !c.Use("d", now.Add(10*time.Minute), now.Add(time.Minute)) || c.Len() != 3 {
		t.Fatalf("eviction: len %d", c.Len())
	}
	if c.Use("b", now.Add(10*time.Minute), now.Add(2*time.Minute)) {
		t.Fatal("b must still be remembered")
	}
	// Expired entries are purged before anything live is evicted.
	c2 := mgmt.NewReplayCache(0)
	for i := 0; i < 3000; i++ {
		c2.Use(fmt.Sprint(i), now.Add(time.Second), now)
	}
	if !c2.Use("late", now.Add(time.Hour), now.Add(2*time.Second)) || c2.Len() != 1 {
		t.Fatalf("expired entries not purged: %d", c2.Len())
	}
}

func TestNewHandlerValidation(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	auth := mgmt.NewAuthenticator(p.Services.Certificate(), nil, nil, nil)
	good := mgmt.Config{Auth: auth, Revoker: fakeRevoker{}, Store: p.Store, Metrics: p.Metrics}
	if _, err := mgmt.NewHandler(good); err != nil {
		t.Fatal(err)
	}
	mods := map[string]func(*mgmt.Config){
		"auth":    func(c *mgmt.Config) { c.Auth = nil },
		"revoker": func(c *mgmt.Config) { c.Revoker = nil },
		"store":   func(c *mgmt.Config) { c.Store = nil },
		"metrics": func(c *mgmt.Config) { c.Metrics = nil },
	}
	for name, mod := range mods {
		c := good
		mod(&c)
		if _, err := mgmt.NewHandler(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

type fakeRevoker struct{}

func (fakeRevoker) Revoke(context.Context, string, string, string) (*revocationResult, error) {
	return nil, nil
}

func (fakeRevoker) RevokeDevice(context.Context, string, string, string) ([]*revocationResult, error) {
	return nil, nil
}
