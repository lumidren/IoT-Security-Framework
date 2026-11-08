package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateIDs(t *testing.T) {
	t.Parallel()
	tenants := map[string]bool{
		"7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11": true,
		"7E4B1A9C-3C2E-4A4F-9C1B-0F0D2D7A6A11": false, // upper case
		"7e4b1a9c-3c2e-1a4f-9c1b-0f0d2d7a6a11": false, // not v4
		"7e4b1a9c-3c2e-4a4f-1c1b-0f0d2d7a6a11": false, // bad variant
		"7e4b1a9c3c2e4a4f9c1b0f0d2d7a6a11":     false, // no hyphens
		"":                                     false,
	}
	for in, ok := range tenants {
		if err := ValidateTenantID(in); (err == nil) != ok {
			t.Errorf("ValidateTenantID(%q) ok=%v err=%v", in, ok, err)
		}
	}
	devices := map[string]bool{
		"dev-8f3a1c2b9d4e5f60":    true,
		"dev-8F3A1C2B9D4E5F60":    false,
		"dev-8f3a1c2b9d4e5f6":     false,
		"dev-8f3a1c2b9d4e5f601":   false,
		"device-8f3a1c2b9d4e5f60": false,
		"":                        false,
	}
	for in, ok := range devices {
		if err := ValidateDeviceID(in); (err == nil) != ok {
			t.Errorf("ValidateDeviceID(%q) ok=%v err=%v", in, ok, err)
		}
	}
}

func TestDeviceURN(t *testing.T) {
	t.Parallel()
	u := DeviceURN(tenant, device)
	if u.String() != "urn:ironmesh:tenant:"+tenant+":device:"+device {
		t.Fatalf("URN = %s", u)
	}
	tt, dd, err := ParseDeviceURN(u)
	if err != nil || tt != tenant || dd != device {
		t.Fatalf("ParseDeviceURN = %q %q %v", tt, dd, err)
	}
	bad := []*url.URL{
		nil,
		{Scheme: "https", Host: "x"},
		{Scheme: "urn", Opaque: "ironmesh:tenant:" + tenant},
		{Scheme: "urn", Opaque: "other:tenant:" + tenant + ":device:" + device},
		{Scheme: "urn", Opaque: "ironmesh:tenant:BAD:device:" + device},
		{Scheme: "urn", Opaque: "ironmesh:tenant:" + tenant + ":device:BAD"},
		{Scheme: "urn", Opaque: "ironmesh:tenant:" + tenant + ":dev:" + device},
	}
	for _, b := range bad {
		if _, _, err := ParseDeviceURN(b); err == nil {
			t.Errorf("ParseDeviceURN(%v) should fail", b)
		}
	}
}

func TestSerials(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		s, err := NewSerial()
		if err != nil {
			t.Fatal(err)
		}
		if s.Sign() <= 0 || s.BitLen() > 128 || s.BitLen() < 100 {
			t.Fatalf("serial %s has %d bits", s, s.BitLen())
		}
		f := FormatSerial(s)
		if len(f) != 32 || strings.ToLower(f) != f {
			t.Fatalf("FormatSerial = %q", f)
		}
		if seen[f] {
			t.Fatalf("duplicate serial %s", f)
		}
		seen[f] = true
	}
	// Formatting pads small numbers and parsing accepts common presentations.
	small := big.NewInt(0xabc)
	if FormatSerial(small) != "00000000000000000000000000000abc" {
		t.Fatalf("FormatSerial(small) = %q", FormatSerial(small))
	}
	if FormatSerial(nil) != "" {
		t.Fatal("FormatSerial(nil)")
	}
	for _, in := range []string{"abc", "ABC", "0xabc", "0a:bc", " 00000000000000000000000000000abc "} {
		n, canon, err := ParseSerial(in)
		if err != nil || n.Int64() != 0xabc || canon != FormatSerial(small) {
			t.Errorf("ParseSerial(%q) = %v %q %v", in, n, canon, err)
		}
	}
	for _, in := range []string{"", "zz", "0", "-1", strings.Repeat("f", 41)} {
		if _, _, err := ParseSerial(in); err == nil {
			t.Errorf("ParseSerial(%q) should fail", in)
		}
	}
	// A random source returning zeros is rejected instead of looping forever.
	if _, err := newSerial(zeroReader{}); err == nil {
		t.Fatal("zero serial accepted")
	}
	if _, err := newSerial(errReader{}); err == nil {
		t.Fatal("reader error ignored")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestReasons(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"": ReasonUnspecified, "unspecified": 0, "keyCompromise": 1, "key_compromise": 1, "KEY-COMPROMISE": 1,
		"cACompromise": 2, "affiliationChanged": 3, "superseded": 4, "cessationOfOperation": 5,
		"certificateHold": 6, "privilegeWithdrawn": 9, "aACompromise": 10, "1": 1, "10": 10,
	}
	for in, want := range cases {
		got, err := ParseReason(in)
		if err != nil || got != want {
			t.Errorf("ParseReason(%q) = %d, %v want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"removeFromCRL", "8", "7", "99", "because"} {
		if _, err := ParseReason(in); err == nil {
			t.Errorf("ParseReason(%q) should fail", in)
		}
	}
	if ReasonString(ReasonKeyCompromise) != "keyCompromise" || ReasonString(42) != "reason(42)" {
		t.Error("ReasonString")
	}
	names := ReasonNames()
	if len(names) != 9 || names[0] != "aACompromise" {
		t.Errorf("ReasonNames = %v", names)
	}
}

func TestPEMHelpers(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	chain := EncodeChainPEM(h.device.Certificate(), h.root.Certificate())
	certs, err := ParseCertsPEM(chain)
	if err != nil || len(certs) != 2 || !certs[0].Equal(h.device.Certificate()) {
		t.Fatalf("ParseCertsPEM: %d, %v", len(certs), err)
	}
	one, err := ParseCertPEM(EncodeCertPEM(h.root.Certificate()))
	if err != nil || !one.Equal(h.root.Certificate()) {
		t.Fatal("ParseCertPEM")
	}
	if _, err := ParseCertsPEM([]byte("nothing here")); err == nil {
		t.Error("no blocks accepted")
	}
	if _, err := ParseCertsPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})); err == nil {
		t.Error("garbage cert accepted")
	}
	// Non-certificate blocks are skipped.
	mixed := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), EncodeCertPEM(h.root.Certificate())...)
	if certs, err := ParseCertsPEM(mixed); err != nil || len(certs) != 1 {
		t.Errorf("mixed PEM: %d %v", len(certs), err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(path, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadCertPEM(path); err != nil || !c.Equal(h.device.Certificate()) {
		t.Error("LoadCertPEM")
	}
	if cs, err := LoadCertsPEM(path); err != nil || len(cs) != 2 {
		t.Error("LoadCertsPEM")
	}
	if _, err := LoadCertPEM(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := LoadCertsPEM(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing file accepted")
	}

	// CSR parsing: PEM, DER, wrong block type, bad signature.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: device}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if csr, err := ParseCSRPEM(csrPEM); err != nil || csr.Subject.CommonName != device {
		t.Errorf("ParseCSRPEM(pem): %v", err)
	}
	if csr, err := ParseCSRPEM(der); err != nil || csr.Subject.CommonName != device {
		t.Errorf("ParseCSRPEM(der): %v", err)
	}
	if _, err := ParseCSRPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err == nil {
		t.Error("wrong PEM type accepted")
	}
	if _, err := ParseCSRPEM([]byte{0x30, 0x01}); err == nil {
		t.Error("garbage DER accepted")
	}
	tampered := bytes.Clone(der)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := ParseCSRPEM(tampered); err == nil {
		t.Error("tampered CSR accepted")
	}
}

func TestParseDeviceIdentityRejections(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issue := func(mod func(*x509.Certificate)) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: device, OrganizationalUnit: []string{tenant}, Organization: []string{Organization}},
			NotBefore:    h.now, NotAfter: h.now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs:        []*url.URL{DeviceURN(tenant, device)},
		}
		mod(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, h.device.Certificate(), key.Public(), h.device.Signer())
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	otherTenant := "11111111-2222-4333-8444-555555555555"
	cases := map[string]func(*x509.Certificate){
		"bad CN":                 func(c *x509.Certificate) { c.Subject.CommonName = "gateway-1" },
		"missing O":              func(c *x509.Certificate) { c.Subject.Organization = nil },
		"wrong O":                func(c *x509.Certificate) { c.Subject.Organization = []string{"Acme"} },
		"missing OU":             func(c *x509.Certificate) { c.Subject.OrganizationalUnit = nil },
		"bad tenant OU":          func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"tenant-1"} },
		"bootstrap other tenant": func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{tenant, "bootstrap:" + otherTenant} },
		"two tenants":            func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{tenant, otherTenant} },
		"two bootstrap markers": func(c *x509.Certificate) {
			c.Subject.OrganizationalUnit = []string{tenant, "bootstrap:" + tenant, "bootstrap:" + otherTenant}
		},
		"only marker":         func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"assurance:software"} },
		"unknown OU marker":   func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{tenant, "role:admin"} },
		"no SAN":              func(c *x509.Certificate) { c.URIs = nil },
		"two SANs":            func(c *x509.Certificate) { c.URIs = append(c.URIs, DeviceURN(tenant, device)) },
		"SAN other device":    func(c *x509.Certificate) { c.URIs = []*url.URL{DeviceURN(tenant, "dev-0000000000000000")} },
		"SAN not urn":         func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "https", Host: "x"}} },
		"no clientAuth":       func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"no digitalSignature": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyAgreement },
	}
	for name, mod := range cases {
		if _, err := ParseDeviceIdentity(issue(mod)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ParseDeviceIdentity(issue(func(*x509.Certificate) {})); err != nil {
		t.Errorf("baseline should parse: %v", err)
	}
	if _, err := ParseDeviceIdentity(nil); err == nil {
		t.Error("nil accepted")
	}
	if IssuedBy(nil, nil) || IssuedBy(h.device.Certificate(), h.services.Certificate()) {
		t.Error("IssuedBy false positives")
	}
}
