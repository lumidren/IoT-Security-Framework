package hooks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: []string{"IronMesh"}},
		NotBefore: fixedNow.Add(-time.Hour), NotAfter: fixedNow.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

// issue returns the PEM of a leaf issued by ca.
func (ca *testCA) issue(t *testing.T, cn string, ou []string, serial int64) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"IronMesh"}, OrganizationalUnit: ou},
		NotBefore:    fixedNow.Add(-time.Hour), NotAfter: fixedNow.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestRequireCertSerial(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *AuthnRequest)
		reason string
	}{
		{"device without serial", func(r *AuthnRequest) { r.CertSerial = "" }, "no_cert_serial"},
		{"service without serial", func(r *AuthnRequest) { *r = serviceReq("svc-bridge"); r.CertSerial = "" }, "no_cert_serial"},
		{"unrendered placeholders", func(r *AuthnRequest) { r.CertSerial = "${client_attrs.cert_serial}"; r.CertPEM = "${cert_pem}" }, "no_cert_serial"},
		{"undefined values", func(r *AuthnRequest) { r.CertSerial = "undefined"; r.CertPEM = " null " }, "no_cert_serial"},
		{"non-hex serial", func(r *AuthnRequest) { r.CertSerial = "not-a-serial" }, "cert_serial_invalid"},
		{"serial disagrees with cert_pem", func(r *AuthnRequest) {
			r.CertPEM = makeDeviceCert(t, dev, []string{tenant}, fixedNow.Add(time.Hour), 0x77)
		}, "cert_serial_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newAuthnEnv(t, nil)
			req := deviceReq()
			tc.mutate(&req)
			if _, reason := env.authn.Decide(context.Background(), req); reason != tc.reason {
				t.Fatalf("reason = %q want %q", reason, tc.reason)
			}
		})
	}

	// cert_serial and cert_pem in different spellings of the same serial agree.
	env := newAuthnEnv(t, nil)
	req := deviceReq()
	req.CertSerial = "0x77"
	req.CertPEM = makeDeviceCert(t, dev, []string{tenant}, fixedNow.Add(time.Hour), 0x77)
	if _, reason := env.authn.Decide(context.Background(), req); reason != "allow" {
		t.Fatalf("matching serials: %s", reason)
	}
	// POLICY_REQUIRE_CERT_SERIAL=false keeps the legacy behaviour.
	legacy := newAuthnEnv(t, func(c *AuthnConfig) { c.AllowMissingSerial = true })
	req = deviceReq()
	req.CertSerial = ""
	if _, reason := legacy.authn.Decide(context.Background(), req); reason != "allow" {
		t.Fatalf("legacy mode: %s", reason)
	}
	if _, known := legacy.identities.LiveSerial(dev); known {
		t.Fatal("no serial must be recorded for a CONNECT without one")
	}
	if _, known := legacy.identities.LiveSerial("dev-unknown"); known {
		t.Fatal("unknown client has no live serial")
	}
}

func TestTrustedIssuers(t *testing.T) {
	deviceCA := newTestCA(t, "IronMesh Device CA")
	servicesCA := newTestCA(t, "IronMesh Services CA")
	rogue := newTestCA(t, "IronMesh Device CA") // same name, different key
	env := newAuthnEnv(t, func(c *AuthnConfig) {
		c.DeviceCAs = []*x509.Certificate{deviceCA.cert}
		c.ServicesCAs = []*x509.Certificate{servicesCA.cert}
	})
	decide := func(req AuthnRequest) string {
		_, reason := env.authn.Decide(context.Background(), req)
		return reason
	}
	dreq := func(pemText string) AuthnRequest {
		r := deviceReq()
		r.CertSerial = ""
		r.CertPEM = pemText
		return r
	}
	sreq := func(pemText string) AuthnRequest {
		r := serviceReq("svc-bridge")
		r.CertSerial = ""
		r.CertPEM = pemText
		return r
	}
	if got := decide(dreq(deviceCA.issue(t, dev, []string{tenant}, 0x1001))); got != "allow" {
		t.Fatalf("device CA leaf: %s", got)
	}
	if got := decide(dreq(rogue.issue(t, dev, []string{tenant}, 0x1002))); got != "untrusted_issuer" {
		t.Fatalf("look-alike CA: %s", got)
	}
	if got := decide(dreq(servicesCA.issue(t, dev, []string{tenant}, 0x1003))); got != "untrusted_issuer" {
		t.Fatalf("device identity from the Services CA: %s", got)
	}
	if got := decide(sreq(servicesCA.issue(t, "svc-bridge", []string{"services"}, 0x2001))); got != "allow" {
		t.Fatalf("services CA leaf: %s", got)
	}
	if got := decide(sreq(deviceCA.issue(t, "svc-bridge", []string{"services"}, 0x2002))); got != "untrusted_issuer" {
		t.Fatalf("service identity from the Device CA: %s", got)
	}
}

// TestRevokedServiceCertificateAtConnect: a stolen svc-bridge certificate is refused at CONNECT
// once its serial is revoked (T-37), while the re-issued bridge certificate connects.
func TestRevokedServiceCertificateAtConnect(t *testing.T) {
	servicesCA := newTestCA(t, "IronMesh Services CA")
	cache := revocation.NewCache("", func() time.Time { return fixedNow })
	env := newAuthnEnv(t, func(c *AuthnConfig) {
		c.Revoked = cache
		c.ServicesCAs = []*x509.Certificate{servicesCA.cert}
	})
	stolen := serviceReq("svc-bridge")
	stolen.CertSerial = ""
	stolen.CertPEM = servicesCA.issue(t, "svc-bridge", []string{"services"}, 0xb1)
	if _, reason := env.authn.Decide(context.Background(), stolen); reason != "allow" {
		t.Fatalf("before revocation: %s", reason)
	}
	if _, err := cache.Upsert(revocation.Entry{EventID: "e-bridge", Serial: "b1", DeviceID: "svc-bridge", Reason: "superseded", RevokedAt: fixedNow}); err != nil {
		t.Fatal(err)
	}
	if _, reason := env.authn.Decide(context.Background(), stolen); reason != "revoked_serial" {
		t.Fatalf("stolen certificate after revocation: %s", reason)
	}
	reissued := serviceReq("svc-bridge")
	reissued.CertSerial = "b2"
	if _, reason := env.authn.Decide(context.Background(), reissued); reason != "allow" {
		t.Fatalf("re-issued bridge certificate: %s", reason)
	}
}

// TestRenewedDeviceNotLockedOut is the policy half of the supersede flow: the PKI revokes the
// previous certificate with reason superseded (device_deny=false); afterwards the old serial is
// refused at CONNECT and the renewed certificate is admitted.
func TestRenewedDeviceNotLockedOut(t *testing.T) {
	cache := revocation.NewCache("", func() time.Time { return fixedNow })
	env := newAuthnEnv(t, func(c *AuthnConfig) { c.Revoked = cache })
	old, renewed := deviceReq(), deviceReq()
	old.CertSerial, renewed.CertSerial = "01aa", "02bb"
	if _, err := cache.Upsert(revocation.Entry{EventID: "sup", Serial: "01aa", DeviceID: dev, TenantID: tenant, Reason: "superseded", RevokedAt: fixedNow}); err != nil {
		t.Fatal(err)
	}
	if _, reason := env.authn.Decide(context.Background(), old); reason != "revoked_serial" {
		t.Fatalf("superseded certificate: %s", reason)
	}
	if _, reason := env.authn.Decide(context.Background(), renewed); reason != "allow" {
		t.Fatalf("renewed device locked out: %s", reason)
	}
	// A quarantine (revoke-all, device_deny) does lock the device out.
	if _, err := cache.Upsert(revocation.Entry{EventID: "q", Serial: "02bb", DeviceID: dev, TenantID: tenant, Reason: "cessationOfOperation", DeviceDeny: true, RevokedAt: fixedNow}); err != nil {
		t.Fatal(err)
	}
	if _, reason := env.authn.Decide(context.Background(), renewed); reason != "revoked" {
		t.Fatalf("device deny: %s", reason)
	}
}
