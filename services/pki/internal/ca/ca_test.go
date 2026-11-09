package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

const (
	tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	device = "dev-8f3a1c2b9d4e5f60"
)

type hierarchy struct {
	root, factory, device, services *CA
	now                             time.Time
}

func newHierarchy(t *testing.T, opts Options) *hierarchy {
	t.Helper()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if opts.Clock == nil {
		opts.Clock = func() time.Time { return now }
	}
	rootKey := mustKey(t, kms.AlgorithmP384)
	rootCert, err := NewRoot(rootKey, now)
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	root, err := New(KindRoot, rootCert, rootKey, nil, opts)
	if err != nil {
		t.Fatalf("New(root): %v", err)
	}
	mk := func(kind Kind) *CA {
		key := mustKey(t, kind.Algorithm())
		cert, err := root.IssueIntermediate(kind, key.Public())
		if err != nil {
			t.Fatalf("IssueIntermediate(%s): %v", kind, err)
		}
		c, err := New(kind, cert, key, []*x509.Certificate{rootCert}, opts)
		if err != nil {
			t.Fatalf("New(%s): %v", kind, err)
		}
		return c
	}
	return &hierarchy{root: root, factory: mk(KindFactory), device: mk(KindDevice), services: mk(KindServices), now: now}
}

func mustKey(t *testing.T, alg kms.Algorithm) kms.Signer {
	t.Helper()
	k, err := kms.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return kms.NewLocal("", k)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestHierarchyProfiles(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	cases := []struct {
		ca       *CA
		kind     Kind
		cn       string
		validity time.Duration
		curve    elliptic.Curve
	}{
		{h.root, KindRoot, "IronMesh Root CA", RootValidity, elliptic.P384()},
		{h.factory, KindFactory, "IronMesh Factory CA", FactoryValidity, elliptic.P384()},
		{h.device, KindDevice, "IronMesh Device CA", DeviceCAValidity, elliptic.P256()},
		{h.services, KindServices, "IronMesh Services CA", ServicesCAValidity, elliptic.P256()},
	}
	for _, c := range cases {
		cert := c.ca.Certificate()
		if c.ca.Kind() != c.kind {
			t.Errorf("%s: kind %s", c.cn, c.ca.Kind())
		}
		if cert.Subject.CommonName != c.cn || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != Organization {
			t.Errorf("%s: subject %v", c.cn, cert.Subject)
		}
		if got := cert.NotAfter.Sub(cert.NotBefore); got != c.validity {
			t.Errorf("%s: validity %s want %s", c.cn, got, c.validity)
		}
		if cert.PublicKey.(*ecdsa.PublicKey).Curve != c.curve {
			t.Errorf("%s: wrong curve", c.cn)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			t.Errorf("%s: not a CA", c.cn)
		}
		if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
			t.Errorf("%s: key usage %v", c.cn, cert.KeyUsage)
		}
		if c.kind != KindRoot {
			if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
				t.Errorf("%s: intermediates must have pathlen 0", c.cn)
			}
			if !IssuedBy(cert, h.root.Certificate()) {
				t.Errorf("%s: not issued by root", c.cn)
			}
			if len(c.ca.Chain()) != 2 || c.ca.Chain()[1] != h.root.Certificate() {
				t.Errorf("%s: chain %d", c.cn, len(c.ca.Chain()))
			}
		} else if !IssuedBy(cert, cert) {
			t.Error("root must be self-signed")
		}
		if cert.SerialNumber.BitLen() > 128 || cert.SerialNumber.Sign() <= 0 {
			t.Errorf("%s: bad serial", c.cn)
		}
	}
	// Signer accessor and default TTL.
	if h.device.Signer() == nil || h.device.OperationalTTL() != DefaultOperationalTTL {
		t.Error("accessors wrong")
	}
	if _, err := ParseKind("Device"); err != nil {
		t.Error(err)
	}
	if _, err := ParseKind("bogus"); err == nil {
		t.Error("expected error for unknown kind")
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	rootCert := h.root.Certificate()
	otherKey := mustKey(t, kms.AlgorithmP384)
	cases := []struct {
		name string
		kind Kind
		cert *x509.Certificate
		key  kms.Signer
		opts Options
	}{
		{"unknown kind", Kind("x"), rootCert, h.root.Signer(), Options{}},
		{"nil cert", KindRoot, nil, h.root.Signer(), Options{}},
		{"key mismatch", KindRoot, rootCert, otherKey, Options{}},
		{"wrong alg for kind", KindDevice, rootCert, h.root.Signer(), Options{}},
		{"ttl too low", KindRoot, rootCert, h.root.Signer(), Options{OperationalTTL: time.Hour}},
		{"ttl too high", KindRoot, rootCert, h.root.Signer(), Options{OperationalTTL: 31 * day}},
	}
	for _, c := range cases {
		if _, err := New(c.kind, c.cert, c.key, nil, c.opts); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
	// A leaf certificate cannot be a CA.
	leaf, err := h.factory.IssueBootstrap(DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: p256(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(KindDevice, leaf, h.device.Signer(), nil, Options{}); err == nil {
		t.Error("leaf certificate accepted as CA")
	}
	// Root key must be P-384.
	if _, err := NewRoot(mustKey(t, kms.AlgorithmP256), h.now); err == nil {
		t.Error("P-256 root accepted")
	}
}

func TestIssueIntermediateRules(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	if _, err := h.device.IssueIntermediate(KindFactory, mustKey(t, kms.AlgorithmP384).Public()); !errors.Is(err, ErrWrongKind) {
		t.Errorf("non-root issuing intermediate: %v", err)
	}
	if _, err := h.root.IssueIntermediate(KindRoot, mustKey(t, kms.AlgorithmP384).Public()); err == nil {
		t.Error("root kind as intermediate accepted")
	}
	if _, err := h.root.IssueIntermediate(KindDevice, mustKey(t, kms.AlgorithmP384).Public()); err == nil {
		t.Error("device CA with P-384 key accepted")
	}
	if _, err := h.root.IssueIntermediate(KindFactory, "not a key"); err == nil {
		t.Error("garbage key accepted")
	}
}

func TestOperationalCertificateProfile(t *testing.T) {
	t.Parallel()
	opts := Options{CRLDistributionPoint: "https://pki.ironmesh.example/crl/device-ca.crl", OCSPServer: "https://pki.ironmesh.example/ocsp"}
	h := newHierarchy(t, opts)
	key := p256(t)
	cases := []struct {
		name      string
		assurance string
		ttl       time.Duration
		wantTTL   time.Duration
		wantOUs   []string
	}{
		{"hardware default ttl", AssuranceHardware, 0, DefaultOperationalTTL, []string{tenant}},
		{"empty assurance", "", 0, DefaultOperationalTTL, []string{tenant}},
		{"software marker", AssuranceSoftware, 0, DefaultOperationalTTL, []string{tenant, "assurance:software"}},
		{"min ttl", AssuranceHardware, MinOperationalTTL, MinOperationalTTL, []string{tenant}},
		{"max ttl", AssuranceHardware, MaxOperationalTTL, MaxOperationalTTL, []string{tenant}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cert, err := h.device.IssueOperational(DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public(), Assurance: c.assurance, TTL: c.ttl})
			if err != nil {
				t.Fatalf("IssueOperational: %v", err)
			}
			if cert.Subject.CommonName != device {
				t.Errorf("CN = %q", cert.Subject.CommonName)
			}
			// Multi-valued RDNs are DER SET OF (sorted), so compare as sets.
			if !sameSet(cert.Subject.OrganizationalUnit, c.wantOUs) {
				t.Fatalf("OU = %v want %v", cert.Subject.OrganizationalUnit, c.wantOUs)
			}
			if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "IronMesh" {
				t.Errorf("O = %v", cert.Subject.Organization)
			}
			if len(cert.URIs) != 1 || cert.URIs[0].String() != "urn:ironmesh:tenant:"+tenant+":device:"+device {
				t.Errorf("SAN URIs = %v", cert.URIs)
			}
			if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses) != 0 {
				t.Error("unexpected extra SANs")
			}
			if cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("KU = %v", cert.KeyUsage)
			}
			if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
				t.Errorf("EKU = %v", cert.ExtKeyUsage)
			}
			if got := cert.NotAfter.Sub(cert.NotBefore); got != c.wantTTL {
				t.Errorf("validity %s want %s", got, c.wantTTL)
			}
			if !cert.NotBefore.Equal(h.now) {
				t.Errorf("NotBefore %s want %s", cert.NotBefore, h.now)
			}
			if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != opts.CRLDistributionPoint {
				t.Errorf("CRL DP = %v", cert.CRLDistributionPoints)
			}
			if len(cert.OCSPServer) != 1 || cert.OCSPServer[0] != opts.OCSPServer {
				t.Errorf("AIA OCSP = %v", cert.OCSPServer)
			}
			if cert.IsCA {
				t.Error("leaf marked as CA")
			}
			if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
				t.Errorf("sig alg %v", cert.SignatureAlgorithm)
			}
			if !IssuedBy(cert, h.device.Certificate()) {
				t.Error("not issued by device CA")
			}
			id, err := ParseDeviceIdentity(cert)
			if err != nil {
				t.Fatalf("ParseDeviceIdentity: %v", err)
			}
			wantAssurance := c.assurance
			if wantAssurance == "" {
				wantAssurance = AssuranceHardware
			}
			if id.DeviceID != device || id.TenantID != tenant || id.Bootstrap || id.Assurance != wantAssurance || id.Serial != FormatSerial(cert.SerialNumber) {
				t.Errorf("identity %+v", id)
			}
			rec := NewRecord(cert, store.KindOperational, wantAssurance, h.now)
			if rec.TenantID != tenant || rec.DeviceID != device || rec.Serial != id.Serial || rec.IssuerCN != "IronMesh Device CA" || rec.SPKISHA256 == "" || len(rec.DER) == 0 {
				t.Errorf("record %+v", rec)
			}
		})
	}
}

func TestOperationalCertificateRejections(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	key := p256(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ok := DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public()}
	cases := []struct {
		name string
		ca   *CA
		req  DeviceRequest
		want error
	}{
		{"ttl below bound", h.device, DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public(), TTL: MinOperationalTTL - time.Second}, ErrTTLOutOfRange},
		{"ttl above bound", h.device, DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public(), TTL: MaxOperationalTTL + time.Second}, ErrTTLOutOfRange},
		{"bad tenant", h.device, DeviceRequest{TenantID: "TENANT", DeviceID: device, PublicKey: key.Public()}, nil},
		{"bad device", h.device, DeviceRequest{TenantID: tenant, DeviceID: "dev-xyz", PublicKey: key.Public()}, nil},
		{"p384 device key", h.device, DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: p384.Public()}, nil},
		{"nil key", h.device, DeviceRequest{TenantID: tenant, DeviceID: device}, nil},
		{"bad assurance", h.device, DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public(), Assurance: "quantum"}, nil},
		{"factory issuing operational", h.factory, ok, ErrWrongKind},
		{"services issuing operational", h.services, ok, ErrWrongKind},
		{"root issuing operational", h.root, ok, ErrWrongKind},
	}
	for _, c := range cases {
		_, err := c.ca.IssueOperational(c.req)
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	if err := ValidateOperationalTTL(DefaultOperationalTTL); err != nil {
		t.Error(err)
	}
}

func TestBootstrapCertificateProfile(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{CRLDistributionPoint: "https://pki/crl/device-ca.crl", OCSPServer: "https://pki/ocsp"})
	key := p256(t)
	cert, err := h.factory.IssueBootstrap(DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public()})
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != BootstrapValidity {
		t.Errorf("validity %s", got)
	}
	if !sameSet(cert.Subject.OrganizationalUnit, []string{tenant, "bootstrap:" + tenant}) {
		t.Errorf("OU = %v", cert.Subject.OrganizationalUnit)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Error("bootstrap KU/EKU wrong")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("sig alg %v", cert.SignatureAlgorithm)
	}
	id, err := ParseDeviceIdentity(cert)
	if err != nil || !id.Bootstrap || id.TenantID != tenant || id.DeviceID != device || id.Assurance != AssuranceHardware {
		t.Errorf("identity %+v, %v", id, err)
	}
	rec := NewRecord(cert, store.KindBootstrap, "", h.now)
	if rec.TenantID != tenant || rec.Kind != store.KindBootstrap {
		t.Errorf("record %+v", rec)
	}
	// Chain verification through the factory CA.
	if _, err := VerifyChain(cert, []*x509.Certificate{h.root.Certificate()}, []*x509.Certificate{h.factory.Certificate()}, h.now.Add(time.Hour), x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
	if _, err := VerifyChain(cert, []*x509.Certificate{h.root.Certificate()}, nil, h.now.Add(time.Hour), x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("chain without intermediate should fail")
	}
	if _, err := VerifyChain(cert, []*x509.Certificate{h.root.Certificate()}, []*x509.Certificate{h.factory.Certificate()}, h.now.Add(time.Hour), x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("serverAuth EKU should fail for device cert")
	}
	if _, err := VerifyChain(nil, nil, nil, h.now, x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("nil leaf should fail")
	}
	// Wrong CA kinds.
	if _, err := h.device.IssueBootstrap(DeviceRequest{TenantID: tenant, DeviceID: device, PublicKey: key.Public()}); !errors.Is(err, ErrWrongKind) {
		t.Errorf("device CA issuing bootstrap: %v", err)
	}
	if _, err := h.factory.IssueBootstrap(DeviceRequest{TenantID: tenant, DeviceID: "bad", PublicKey: key.Public()}); err == nil {
		t.Error("bad device id accepted")
	}
}

func TestServerAndOCSPSignerProfiles(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	key := p256(t)
	cert, err := h.services.IssueServer("pki", []string{"pki.ironmesh.local", " localhost ", "127.0.0.1", "", "::1"}, key.Public())
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if cert.NotAfter.Sub(cert.NotBefore) != ServerCertValidity {
		t.Error("server validity")
	}
	if len(cert.DNSNames) != 2 || cert.DNSNames[1] != "localhost" || len(cert.IPAddresses) != 2 {
		t.Errorf("SANs %v %v", cert.DNSNames, cert.IPAddresses)
	}
	if len(cert.ExtKeyUsage) != 2 || cert.Subject.CommonName != "pki" {
		t.Error("server EKU/CN")
	}
	if o, ou := cert.Subject.Organization, cert.Subject.OrganizationalUnit; len(o) != 1 || o[0] != "IronMesh" || len(ou) != 1 || ou[0] != "services" {
		t.Errorf("server subject O=%v OU=%v, want O=IronMesh OU=services", o, ou)
	}
	if _, err := h.device.IssueServer("x", nil, key.Public()); !errors.Is(err, ErrWrongKind) {
		t.Error("device CA issued server cert")
	}
	if _, err := h.services.IssueServer(" ", nil, key.Public()); err == nil {
		t.Error("empty CN accepted")
	}
	if _, err := h.services.IssueServer("x", nil, "junk"); err == nil {
		t.Error("junk key accepted")
	}

	ocspCert, err := h.device.IssueOCSPSigner(key.Public(), 0)
	if err != nil {
		t.Fatalf("IssueOCSPSigner: %v", err)
	}
	if ocspCert.NotAfter.Sub(ocspCert.NotBefore) != DefaultOCSPSignerTTL {
		t.Error("ocsp default validity")
	}
	if len(ocspCert.ExtKeyUsage) != 1 || ocspCert.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning {
		t.Error("ocsp EKU")
	}
	found := false
	for _, e := range ocspCert.Extensions {
		if e.Id.Equal(oidOCSPNoCheck) {
			found = true
		}
	}
	if !found {
		t.Error("id-pkix-ocsp-nocheck missing")
	}
	if c2, err := h.device.IssueOCSPSigner(key.Public(), time.Hour); err != nil || c2.NotAfter.Sub(c2.NotBefore) != time.Hour {
		t.Error("explicit ocsp validity")
	}
	if _, err := h.services.IssueOCSPSigner(key.Public(), 0); !errors.Is(err, ErrWrongKind) {
		t.Error("services CA issued OCSP signer")
	}
	if _, err := h.device.IssueOCSPSigner(nil, 0); err == nil {
		t.Error("nil key accepted")
	}
}

func TestCreateCRL(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	now := h.now
	entries := []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(0xabc), RevocationTime: now.Add(-time.Hour), ReasonCode: ReasonKeyCompromise},
		{SerialNumber: big.NewInt(0xdef), RevocationTime: now.Add(-time.Minute), ReasonCode: ReasonCessationOfOperation},
	}
	der, err := h.device.CreateCRL(7, now, entries)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(h.device.Certificate()); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
	if crl.Number.Int64() != 7 || !crl.ThisUpdate.Equal(now) || !crl.NextUpdate.Equal(now.Add(24*time.Hour)) {
		t.Errorf("CRL times/number: %v %v %v", crl.Number, crl.ThisUpdate, crl.NextUpdate)
	}
	if len(crl.RevokedCertificateEntries) != 2 || crl.RevokedCertificateEntries[0].ReasonCode != ReasonKeyCompromise || crl.RevokedCertificateEntries[1].SerialNumber.Int64() != 0xdef {
		t.Errorf("entries %+v", crl.RevokedCertificateEntries)
	}
	if _, err := h.device.CreateCRL(0, now, nil); err == nil {
		t.Error("zero CRL number accepted")
	}
	if _, err := h.factory.CreateCRL(1, now, nil); !errors.Is(err, ErrWrongKind) {
		t.Error("factory CRL accepted")
	}
	empty, err := h.device.CreateCRL(8, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := x509.ParseRevocationList(empty); len(c.RevokedCertificateEntries) != 0 {
		t.Error("empty CRL has entries")
	}
}

func TestSPKIHelpers(t *testing.T) {
	t.Parallel()
	h := newHierarchy(t, Options{})
	pin, err := SPKIPin(h.services.Certificate().PublicKey)
	if err != nil || len(pin) != 32 {
		t.Fatalf("SPKIPin: %v", err)
	}
	if SPKISHA256(h.services.Certificate()) == "" {
		t.Error("empty SPKI hash")
	}
	if _, err := SPKIPin("junk"); err == nil {
		t.Error("junk key accepted")
	}
	// NewRecord for a non-device cert falls back to CN and the system tenant.
	rec := NewRecord(h.services.Certificate(), store.KindIntermediate, "", h.now)
	if rec.TenantID != store.SystemTenant || rec.DeviceID != "IronMesh Services CA" {
		t.Errorf("record %+v", rec)
	}
}
