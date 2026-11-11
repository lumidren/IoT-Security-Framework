package ceremony_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ceremony"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/file"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

var fastKDF = file.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}

const tenant = testutil.Tenant

func fileProvider() *file.Provider {
	return &file.Provider{Passphrase: []byte("ceremony-pw"), KDF: fastKDF}
}

// buildDir creates a complete CA directory with the file backend.
func buildDir(t *testing.T) (string, kms.Provider) {
	t.Helper()
	dir := t.TempDir()
	prov := fileProvider()
	ctx := context.Background()
	if _, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: dir, Provider: prov}); err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootSigner, err := prov.Open(ctx, ca.Layout{Dir: dir}.KeyPath(ca.KindRoot))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []ca.Kind{ca.KindFactory, ca.KindDevice, ca.KindServices} {
		if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: kind, RootSigner: rootSigner, Provider: prov}); err != nil {
			t.Fatalf("InitIntermediate(%s): %v", kind, err)
		}
	}
	if _, err := ceremony.InitBundleKey(ctx, dir, []byte("ceremony-pw"), fastKDF); err != nil {
		t.Fatalf("InitBundleKey: %v", err)
	}
	return dir, prov
}

func TestFullOfflineCeremony(t *testing.T) {
	t.Parallel()
	dir, prov := buildDir(t)
	layout := ca.Layout{Dir: dir}
	ctx := context.Background()

	root, err := layout.LoadCert(ca.KindRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IssuedBy(root, root) || root.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P384() || root.NotAfter.Sub(root.NotBefore) != ca.RootValidity {
		t.Fatal("root profile")
	}
	for _, kind := range []ca.Kind{ca.KindFactory, ca.KindDevice, ca.KindServices} {
		c, err := layout.LoadCert(kind)
		if err != nil {
			t.Fatal(err)
		}
		if !ca.IssuedBy(c, root) || c.Subject.CommonName != kind.CommonName() {
			t.Fatalf("%s not issued by root", kind)
		}
		signer, err := prov.Open(ctx, layout.KeyPath(kind))
		if err != nil || !c.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()) {
			t.Fatalf("%s key mismatch: %v", kind, err)
		}
	}
	chain, err := ca.LoadCertsPEM(layout.ChainPath())
	if err != nil || len(chain) != 4 || !chain[3].Equal(root) {
		t.Fatalf("chain.pem: %d %v", len(chain), err)
	}
	pubPEM, err := os.ReadFile(layout.BundlePublicKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("bundle public key pem")
	}

	// Refuse to overwrite existing material.
	if _, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: dir, Provider: prov}); err == nil {
		t.Error("root overwrite accepted")
	}
	rootSigner, _ := prov.Open(ctx, layout.KeyPath(ca.KindRoot))
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: ca.KindDevice, RootSigner: rootSigner, Provider: prov}); err == nil {
		t.Error("intermediate overwrite accepted")
	}
	if _, err := ceremony.InitBundleKey(ctx, dir, []byte("x"), fastKDF); err == nil {
		t.Error("bundle key overwrite accepted")
	}

	// Bootstrap certificates: software key and secure-element CSR.
	factorySigner, _ := prov.Open(ctx, layout.KeyPath(ca.KindFactory))
	device := testutil.NewDeviceID(t)
	soft, err := ceremony.IssueBootstrap(ctx, ceremony.BootstrapOptions{Dir: dir, FactorySigner: factorySigner, TenantID: tenant, DeviceID: device, CRLDistributionPoint: "https://pki/crl/device-ca.crl", OCSPServer: "https://pki/ocsp"})
	if err != nil {
		t.Fatalf("IssueBootstrap(software): %v", err)
	}
	if soft.KeyPath == "" || soft.Record.Kind != store.KindBootstrap || soft.Record.DeviceID != device {
		t.Fatalf("software result %+v", soft)
	}
	id, err := ca.ParseDeviceIdentity(soft.Certificate)
	if err != nil || !id.Bootstrap || id.TenantID != tenant {
		t.Fatalf("bootstrap identity %+v %v", id, err)
	}
	if soft.Certificate.CRLDistributionPoints[0] != "https://pki/crl/device-ca.crl" {
		t.Fatal("CRL DP not embedded")
	}
	keyPEM, _ := os.ReadFile(soft.KeyPath)
	kb, _ := pem.Decode(keyPEM)
	priv, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil || !priv.(*ecdsa.PrivateKey).PublicKey.Equal(soft.Certificate.PublicKey) {
		t.Fatal("software key does not match certificate")
	}
	var rec store.CertificateRecord
	recData, _ := os.ReadFile(soft.RecordPath)
	if err := json.Unmarshal(recData, &rec); err != nil || rec.Serial != soft.Record.Serial {
		t.Fatal("record file")
	}
	certs, err := ca.LoadCertsPEM(soft.CertPath)
	if err != nil || len(certs) != 2 {
		t.Fatalf("bootstrap cert file should contain leaf + factory: %d %v", len(certs), err)
	}

	seKey := testutil.P256Key(t)
	device2 := testutil.NewDeviceID(t)
	csr := testutil.BuildCSRWithSubject(t, seKey, pkix.Name{CommonName: device2}, nil)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	se, err := ceremony.IssueBootstrap(ctx, ceremony.BootstrapOptions{Dir: dir, FactorySigner: factorySigner, TenantID: tenant, DeviceID: device2, CSR: csrPEM, OutDir: filepath.Join(dir, "se")})
	if err != nil {
		t.Fatalf("IssueBootstrap(csr): %v", err)
	}
	if se.KeyPath != "" || !se.Certificate.PublicKey.(*ecdsa.PublicKey).Equal(seKey.Public()) {
		t.Fatalf("secure element result %+v", se)
	}
	if _, err := ceremony.IssueBootstrap(ctx, ceremony.BootstrapOptions{Dir: dir, FactorySigner: factorySigner, TenantID: tenant, DeviceID: "dev-0000000000000001", CSR: csrPEM}); err == nil {
		t.Error("CSR CN mismatch accepted")
	}
	if _, err := ceremony.IssueBootstrap(ctx, ceremony.BootstrapOptions{Dir: dir, FactorySigner: factorySigner, TenantID: tenant, DeviceID: device, CSR: []byte("junk")}); err == nil {
		t.Error("junk CSR accepted")
	}
	bad := []ceremony.BootstrapOptions{
		{Dir: dir, TenantID: tenant, DeviceID: device},
		{Dir: dir, FactorySigner: factorySigner, TenantID: "bad", DeviceID: device},
		{Dir: dir, FactorySigner: factorySigner, TenantID: tenant, DeviceID: "bad"},
		{Dir: t.TempDir(), FactorySigner: factorySigner, TenantID: tenant, DeviceID: device},
	}
	for i, o := range bad {
		if _, err := ceremony.IssueBootstrap(ctx, o); err == nil {
			t.Errorf("bootstrap option set %d accepted", i)
		}
	}

	// Server certificate.
	servicesSigner, _ := prov.Open(ctx, layout.KeyPath(ca.KindServices))
	srv, err := ceremony.IssueServer(ctx, ceremony.ServerOptions{Dir: dir, ServicesSigner: servicesSigner, CN: "svc-registry", SANs: []string{"registry", "10.0.0.5"}})
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if srv.Certificate.Subject.CommonName != "svc-registry" || len(srv.Certificate.DNSNames) != 1 || len(srv.Certificate.IPAddresses) != 1 ||
		len(srv.Certificate.Subject.OrganizationalUnit) != 1 || srv.Certificate.Subject.OrganizationalUnit[0] != ca.ServicesOU {
		t.Fatalf("server cert %+v", srv.Certificate.Subject)
	}
	if _, err := os.Stat(srv.KeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ceremony.IssueServer(ctx, ceremony.ServerOptions{Dir: dir, CN: "x"}); err == nil {
		t.Error("missing signer accepted")
	}
	if _, err := ceremony.IssueServer(ctx, ceremony.ServerOptions{Dir: t.TempDir(), ServicesSigner: servicesSigner, CN: "x"}); err == nil {
		t.Error("missing CA dir accepted")
	}
	if _, err := ceremony.IssueServer(ctx, ceremony.ServerOptions{Dir: dir, ServicesSigner: servicesSigner, CN: ""}); err == nil {
		t.Error("empty CN accepted")
	}
}

func TestQuorumCeremony(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx := context.Background()
	res, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: dir, QuorumShares: 5, QuorumThreshold: 3, FileKDF: fastKDF})
	if err != nil {
		t.Fatalf("InitRoot(quorum): %v", err)
	}
	if len(res.SharePaths) != 5 || res.Certificate == nil || res.KeyRef != (ca.Layout{Dir: dir}).KeyPath(ca.KindRoot) {
		t.Fatalf("result %+v", res)
	}
	for _, p := range res.SharePaths {
		share, err := ceremony.ReadShare(p)
		if err != nil || len(share) != 33 {
			t.Fatalf("ReadShare(%s): %d %v", p, len(share), err)
		}
		content, _ := os.ReadFile(p)
		if !strings.HasPrefix(string(content), "# IronMesh root KEK share") {
			t.Fatal("share header")
		}
	}
	// The key file cannot be opened with a passphrase.
	if _, err := fileProvider().Open(ctx, res.KeyRef); err == nil {
		t.Fatal("quorum-protected key opened with passphrase")
	}
	// Recover with three shares, re-wrap under a passphrase and use it.
	out := filepath.Join(dir, "root-recovered.key.json")
	signer, err := ceremony.RecoverRoot(ctx, res.KeyRef, []string{res.SharePaths[4], res.SharePaths[1], res.SharePaths[2]}, []byte("ceremony-pw"), out, fastKDF)
	if err != nil {
		t.Fatalf("RecoverRoot: %v", err)
	}
	if !res.Certificate.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()) {
		t.Fatal("recovered key does not match the root certificate")
	}
	reopened, err := fileProvider().Open(ctx, out)
	if err != nil || !reopened.Public().(*ecdsa.PublicKey).Equal(signer.Public()) {
		t.Fatalf("re-wrapped key: %v", err)
	}
	// The recovered root signs intermediates.
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: ca.KindDevice, RootSigner: signer, Provider: fileProvider()}); err != nil {
		t.Fatalf("InitIntermediate with recovered root: %v", err)
	}
	// Too few shares reconstruct a wrong KEK, which the AEAD detects.
	if _, err := ceremony.RecoverRoot(ctx, res.KeyRef, res.SharePaths[:2], nil, "", fastKDF); err == nil {
		t.Fatal("two shares must not recover a 3-of-5 secret")
	}
	if _, err := ceremony.RecoverRoot(ctx, res.KeyRef, res.SharePaths[:1], nil, "", fastKDF); err == nil {
		t.Fatal("one share accepted")
	}
	if _, err := ceremony.RecoverRoot(ctx, res.KeyRef, res.SharePaths[:3], nil, out, fastKDF); err == nil {
		t.Fatal("re-wrap without passphrase accepted")
	}
	if _, err := ceremony.RecoverRoot(ctx, res.KeyRef, []string{res.SharePaths[0], filepath.Join(dir, "missing.txt")}, nil, "", fastKDF); err == nil {
		t.Fatal("missing share file accepted")
	}
	badShare := filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(badShare, []byte("no share here\n"), 0o600)
	if _, err := ceremony.ReadShare(badShare); err == nil {
		t.Fatal("share-less file accepted")
	}
	// Invalid quorum parameters and the HSM-only path.
	for _, o := range []ceremony.RootOptions{
		{Dir: t.TempDir(), QuorumShares: 2, QuorumThreshold: 3},
		{Dir: t.TempDir(), QuorumShares: 3, QuorumThreshold: 1},
		{Dir: t.TempDir()},
		{},
	} {
		if _, err := ceremony.InitRoot(ctx, &o); err == nil {
			t.Errorf("options %+v accepted", o)
		}
	}
	// InitIntermediate guards.
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: ca.KindRoot, RootSigner: signer, Provider: fileProvider()}); err == nil {
		t.Error("root as intermediate accepted")
	}
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: ca.KindFactory}); err == nil {
		t.Error("missing signer accepted")
	}
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: t.TempDir(), Kind: ca.KindFactory, RootSigner: signer, Provider: fileProvider()}); err == nil {
		t.Error("missing root cert accepted")
	}
	wrongRoot, _ := kms.GenerateKey(kms.AlgorithmP384)
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: ca.KindFactory, RootSigner: kms.NewLocal("", wrongRoot), Provider: fileProvider()}); err == nil {
		t.Error("mismatched root signer accepted")
	}
}

func TestOnlineClientOperations(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(caFile, ca.EncodeChainPEM(p.CAChain()...), 0o600); err != nil {
		t.Fatal(err)
	}
	svcCert, svcKey := p.NewServiceClient(t, "svc-console")
	certFile, keyFile := filepath.Join(dir, "svc.crt"), filepath.Join(dir, "svc.key")
	_ = os.WriteFile(certFile, ca.EncodeCertPEM(svcCert), 0o600)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(svcKey)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	client, err := ceremony.NewHTTPClient(ceremony.ClientOptions{CAFile: caFile, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dev := p.NewOperationalDevice(t, testutil.Tenant)

	res, err := ceremony.OCSPCheck(ctx, client, s.MTLS.URL+"/ocsp", dev.Cert, p.Device.Certificate())
	if err != nil || res.Status != "good" || !res.NonceEchoed || !res.SignerIsOCSP || res.Responder == "" {
		t.Fatalf("OCSPCheck good: %+v %v", res, err)
	}
	out, err := ceremony.Revoke(ctx, client, s.MTLS.URL, "", ca.FormatSerial(dev.Cert.SerialNumber), "keyCompromise")
	if err != nil || out["published"] != true {
		t.Fatalf("Revoke: %v %v", out, err)
	}
	if _, err := ceremony.Revoke(ctx, client, s.MTLS.URL, "", ca.FormatSerial(dev.Cert.SerialNumber), "keyCompromise"); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := ceremony.Revoke(ctx, client, s.MTLS.URL, "", "zz", "keyCompromise"); err == nil {
		t.Fatal("bad serial accepted")
	}
	res, err = ceremony.OCSPCheck(ctx, client, s.MTLS.URL+"/ocsp", dev.Cert, p.Device.Certificate())
	if err != nil || res.Status != "revoked" || res.Reason != "keyCompromise" || res.RevokedAt.IsZero() {
		t.Fatalf("OCSPCheck revoked: %+v %v", res, err)
	}
	crl, err := ceremony.FetchCRL(ctx, client, s.Plain.URL+"/crl/device-ca.crl")
	if err != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("FetchCRL: %v", err)
	}
	if _, err := ceremony.FetchCRL(ctx, client, s.Plain.URL+"/missing"); err == nil {
		t.Fatal("404 CRL accepted")
	}
	if _, err := ceremony.OCSPCheck(ctx, client, s.Plain.URL+"/ocsp", dev.Cert, p.Device.Certificate()); err == nil {
		t.Fatal("non-OCSP endpoint accepted")
	}
	// Bearer-token client and client option errors.
	if _, err := ceremony.NewHTTPClient(ceremony.ClientOptions{CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("missing CA file accepted")
	}
	if _, err := ceremony.NewHTTPClient(ceremony.ClientOptions{CertFile: certFile}); err == nil {
		t.Fatal("cert without key accepted")
	}
	anon, _ := ceremony.NewHTTPClient(ceremony.ClientOptions{Insecure: true})
	if _, err := ceremony.Revoke(ctx, anon, s.MTLS.URL, "not-a-jwt", ca.FormatSerial(dev.Cert.SerialNumber), "superseded"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("unauthenticated revoke: %v", err)
	}
	if u, err := ceremony.JoinURL("https://pki:8443/", "/ocsp"); err != nil || u != "https://pki:8443/ocsp" {
		t.Fatalf("JoinURL %q %v", u, err)
	}
	if _, err := ceremony.JoinURL("://bad", "x"); err == nil {
		t.Fatal("bad URL accepted")
	}
}
