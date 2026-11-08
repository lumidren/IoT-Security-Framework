package ocsp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	xocsp "golang.org/x/crypto/ocsp"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ocsp"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

func newResponder(t *testing.T, p *testutil.PKI, opts ocsp.Options) *ocsp.Responder {
	t.Helper()
	if opts.Clock == nil {
		opts.Clock = p.Clock
	}
	opts.Metrics = p.Metrics
	r, err := ocsp.NewResponder(p.Device, p.Store, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func request(t *testing.T, cert, issuer *x509.Certificate, nonce []byte) []byte {
	t.Helper()
	der, err := ocsp.CreateRequest(cert, issuer, crypto.SHA256, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestStatuses(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	r := newResponder(t, p, ocsp.Options{})
	ctx := context.Background()
	good := p.NewOperationalDevice(t, testutil.Tenant)
	revokedDev := p.NewOperationalDevice(t, testutil.Tenant)
	revokedAt := p.Clock().Add(-time.Minute).Truncate(time.Second)
	if err := p.Store.AddRevocation(ctx, &store.Revocation{Serial: ca.FormatSerial(revokedDev.Cert.SerialNumber), DeviceID: revokedDev.ID, TenantID: testutil.Tenant, IssuerCN: "IronMesh Device CA", NotAfter: revokedDev.Cert.NotAfter, Reason: ca.ReasonKeyCompromise, RevokedAt: revokedAt}); err != nil {
		t.Fatal(err)
	}
	unknownKey := testutil.P256Key(t)
	unknownCert, err := p.Device.IssueOperational(ca.DeviceRequest{TenantID: testutil.Tenant, DeviceID: "dev-00000000000000aa", PublicKey: unknownKey.Public()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		cert   *x509.Certificate
		status int
		label  string
	}{
		{"good", good.Cert, xocsp.Good, "good"},
		{"revoked", revokedDev.Cert, xocsp.Revoked, "revoked"},
		{"unknown", unknownCert, xocsp.Unknown, "unknown"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			nonce := []byte("nonce-" + c.name)
			der, label := r.Respond(ctx, request(t, c.cert, p.Device.Certificate(), nonce))
			if label != c.label {
				t.Fatalf("label %q", label)
			}
			resp, err := xocsp.ParseResponseForCert(der, c.cert, p.Device.Certificate())
			if err != nil {
				t.Fatalf("x/crypto parse: %v", err)
			}
			if resp.Status != c.status {
				t.Fatalf("status %d want %d", resp.Status, c.status)
			}
			if resp.Certificate == nil || resp.Certificate.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning || !ca.IssuedBy(resp.Certificate, p.Device.Certificate()) {
				t.Fatal("response must be signed by a delegated OCSP signer issued by the Device CA")
			}
			if resp.NextUpdate.Sub(resp.ThisUpdate) != ocsp.DefaultValidity {
				t.Fatalf("validity %s", resp.NextUpdate.Sub(resp.ThisUpdate))
			}
			if c.status == xocsp.Revoked && (!resp.RevokedAt.Equal(revokedAt) || resp.RevocationReason != ca.ReasonKeyCompromise) {
				t.Fatalf("revocation info %v %d", resp.RevokedAt, resp.RevocationReason)
			}
			echoed, err := ocsp.ParseResponseNonce(der)
			if err != nil || !bytes.Equal(echoed, nonce) {
				t.Fatalf("nonce echo: %x %v", echoed, err)
			}
		})
	}

	// Nonce-less responses are cached for the TTL and invalidated on revocation.
	plain := request(t, good.Cert, p.Device.Certificate(), nil)
	first, _ := r.Respond(ctx, plain)
	second, _ := r.Respond(ctx, plain)
	if !bytes.Equal(first, second) {
		t.Fatal("expected cached response")
	}
	if n, _ := ocsp.ParseResponseNonce(first); n != nil {
		t.Fatal("nonce-less request must not get a nonce")
	}
	if err := p.Store.AddRevocation(ctx, &store.Revocation{Serial: ca.FormatSerial(good.Cert.SerialNumber), DeviceID: good.ID, TenantID: testutil.Tenant, IssuerCN: "IronMesh Device CA", NotAfter: good.Cert.NotAfter, Reason: ca.ReasonSuperseded, RevokedAt: p.Clock()}); err != nil {
		t.Fatal(err)
	}
	if cached, label := r.Respond(ctx, plain); label != "good" || !bytes.Equal(cached, first) {
		t.Fatal("cache should still serve the stale answer until invalidated")
	}
	r.Invalidate(ca.FormatSerial(good.Cert.SerialNumber))
	r.Invalidate("not-a-serial") // ignored
	if _, label := r.Respond(ctx, plain); label != "revoked" {
		t.Fatalf("after invalidation: %s", label)
	}
	// Cache expiry.
	p.Advance(ocsp.DefaultCacheTTL + time.Second)
	after, label := r.Respond(ctx, plain)
	if label != "revoked" || bytes.Equal(after, first) {
		t.Fatal("expired cache entry served")
	}
}

func TestErrorResponses(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	r := newResponder(t, p, ocsp.Options{})
	ctx := context.Background()
	dev := p.NewOperationalDevice(t, testutil.Tenant)

	if resp, label := r.Respond(ctx, []byte{1, 2, 3}); label != "malformed" || resp[4] != 1 {
		t.Fatalf("malformed: %s %x", label, resp)
	}
	// Request about another issuer -> unauthorized (6).
	if resp, label := r.Respond(ctx, request(t, dev.Cert, p.Factory.Certificate(), nil)); label != "unauthorized" || resp[4] != 6 {
		t.Fatalf("unauthorized: %s %x", label, resp)
	}
	// SHA-1 certIDs (OpenSSL default) are accepted.
	der, err := ocsp.CreateRequest(dev.Cert, p.Device.Certificate(), crypto.SHA1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, label := r.Respond(ctx, der); label != "good" {
		t.Fatalf("sha1 request: %s", label)
	}
	if _, err := ocsp.CreateRequest(nil, nil, crypto.SHA256, nil); err == nil {
		t.Error("nil certs accepted")
	}
	if _, err := ocsp.CreateRequest(dev.Cert, p.Device.Certificate(), crypto.MD5, nil); err == nil {
		t.Error("MD5 accepted")
	}
	// Store failures surface as internalError (2).
	failing := &failingStore{Store: p.Store}
	fr, err := ocsp.NewResponder(p.Device, failing, ocsp.Options{Metrics: p.Metrics, Clock: p.Clock})
	if err != nil {
		t.Fatal(err)
	}
	failing.revErr = errors.New("db down")
	if resp, label := fr.Respond(ctx, request(t, dev.Cert, p.Device.Certificate(), nil)); label != "error" || resp[4] != 2 {
		t.Fatalf("store error: %s %x", label, resp)
	}
	failing.revErr = nil
	failing.certErr = errors.New("db down")
	if _, label := fr.Respond(ctx, request(t, dev.Cert, p.Device.Certificate(), nil)); label != "error" {
		t.Fatalf("cert store error: %s", label)
	}

	// ParseRequest / ParseResponseNonce edge cases.
	if _, err := ocsp.ParseRequest(append(request(t, dev.Cert, p.Device.Certificate(), nil), 0)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ocsp.ParseResponseNonce([]byte{1}); err == nil {
		t.Error("garbage response accepted")
	}
	if _, err := ocsp.ParseResponseNonce([]byte{0x30, 0x03, 0x0a, 0x01, 0x01}); err == nil {
		t.Error("error response accepted as nonce carrier")
	}
	// Constructor validation.
	if _, err := ocsp.NewResponder(p.Factory, p.Store, ocsp.Options{}); err == nil {
		t.Error("factory CA accepted")
	}
	if _, err := ocsp.NewResponder(p.Device, nil, ocsp.Options{}); err == nil {
		t.Error("nil store accepted")
	}
	// Defaults apply when options are zero.
	if _, err := ocsp.NewResponder(p.Device, p.Store, ocsp.Options{}); err != nil {
		t.Error(err)
	}
}

func TestSignerRotation(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	r := newResponder(t, p, ocsp.Options{SignerTTL: time.Hour})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	first := r.SignerCertificate()
	if first.NotAfter.Sub(first.NotBefore) != time.Hour {
		t.Fatalf("signer ttl %s", first.NotAfter.Sub(first.NotBefore))
	}
	req := request(t, dev.Cert, p.Device.Certificate(), []byte("n"))
	r.Respond(context.Background(), req)
	if r.SignerCertificate().SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("signer rotated too early")
	}
	p.Advance(31 * time.Minute)
	der, _ := r.Respond(context.Background(), req)
	second := r.SignerCertificate()
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("signer should rotate after half its lifetime")
	}
	resp, err := xocsp.ParseResponseForCert(der, dev.Cert, p.Device.Certificate())
	if err != nil || resp.Certificate.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf("response not signed by the rotated signer: %v", err)
	}
}

func TestHTTPEndpoints(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	client := s.Client(nil, nil)
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	nonce := []byte("http-nonce")
	reqDER := request(t, dev.Cert, p.Device.Certificate(), nonce)

	post := func(t *testing.T, body []byte, contentType string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, s.MTLS.URL+"/ocsp", bytes.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, data
	}
	resp, data := post(t, reqDER, ocsp.ContentTypeRequest)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ocsp.ContentTypeResponse || !strings.HasPrefix(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("POST: %d %v", resp.StatusCode, resp.Header)
	}
	parsed, err := xocsp.ParseResponseForCert(data, dev.Cert, p.Device.Certificate())
	if err != nil || parsed.Status != xocsp.Good {
		t.Fatalf("POST parse: %v", err)
	}
	if echoed, _ := ocsp.ParseResponseNonce(data); !bytes.Equal(echoed, nonce) {
		t.Fatal("nonce not echoed over HTTP")
	}
	if resp, _ := post(t, reqDER, "text/plain"); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content type: %d", resp.StatusCode)
	}
	if resp, _ := post(t, make([]byte, 9000), ocsp.ContentTypeRequest); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized: %d", resp.StatusCode)
	}
	if resp, data := post(t, []byte{1, 2, 3}, ""); resp.StatusCode != 200 || data[4] != 1 {
		t.Fatalf("malformed over HTTP: %d %x", resp.StatusCode, data)
	}

	// GET with the URL-escaped base64 request (RFC 6960 A.1); nonce-less so cacheable.
	plain := request(t, dev.Cert, p.Device.Certificate(), nil)
	getURL := s.MTLS.URL + "/ocsp/" + url.PathEscape(base64.StdEncoding.EncodeToString(plain))
	resp, err = client.Get(getURL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Cache-Control"), "max-age=60") {
		t.Fatalf("GET: %d %v", resp.StatusCode, resp.Header)
	}
	if parsed, err := xocsp.ParseResponseForCert(data, dev.Cert, p.Device.Certificate()); err != nil || parsed.Status != xocsp.Good {
		t.Fatalf("GET parse: %v", err)
	}
	// Unescaped '/' inside the base64 is tolerated via the trailing wildcard.
	resp, err = client.Get(s.MTLS.URL + "/ocsp/" + base64.StdEncoding.EncodeToString(plain))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET raw: %d", resp.StatusCode)
	}
	resp, err = client.Get(s.MTLS.URL + "/ocsp/%%%")
	if err == nil {
		resp.Body.Close()
	}
	resp, err = client.Get(s.MTLS.URL + "/ocsp/!!!notbase64")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || data[4] != 1 {
		t.Fatalf("GET bad base64: %d %x", resp.StatusCode, data)
	}
	// Serial-based lookups ignore the hash algorithm in the cache key only
	// per algorithm; a SHA-1 request after a SHA-256 one still answers.
	sha1Req, _ := ocsp.CreateRequest(dev.Cert, p.Device.Certificate(), crypto.SHA1, nil)
	resp, _ = post(t, sha1Req, ocsp.ContentTypeRequest)
	if resp.StatusCode != 200 {
		t.Fatal("sha1 over http")
	}
	// Big serial that is unknown.
	big := new(big.Int).Lsh(big.NewInt(1), 100)
	fake := *dev.Cert
	fake.SerialNumber = big
	unknownReq := request(t, &fake, p.Device.Certificate(), nil)
	resp, data = post(t, unknownReq, ocsp.ContentTypeRequest)
	if parsed, err := xocsp.ParseResponse(data, p.Device.Certificate()); err != nil || parsed.Status != xocsp.Unknown {
		t.Fatalf("unknown serial: %v", err)
	}
}

type failingStore struct {
	store.Store
	revErr  error
	certErr error
}

func (f *failingStore) GetRevocation(ctx context.Context, serial string) (*store.Revocation, error) {
	if f.revErr != nil {
		return nil, f.revErr
	}
	return f.Store.GetRevocation(ctx, serial)
}

func (f *failingStore) GetCertificate(ctx context.Context, serial string) (*store.CertificateRecord, error) {
	if f.certErr != nil {
		return nil, f.certErr
	}
	return f.Store.GetCertificate(ctx, serial)
}
