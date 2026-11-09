package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

func testEnv(extra map[string]string) func(string) string {
	base := map[string]string{"PKI_FILE_KMS_PASSPHRASE": "ctl-pw", "PKI_FILE_KMS_FAST_KDF": "1"}
	for k, v := range extra {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func exec(t *testing.T, getenv func(string) string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, getenv)
	return code, out.String(), errb.String()
}

func TestOfflineCommands(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	env := testEnv(nil)

	code, out, errOut := exec(t, env, "init-root", "--dir", dir, "--quorum-shares", "3", "--quorum-threshold", "2")
	if code != 0 || !strings.Contains(out, "share: ") {
		t.Fatalf("init-root: %d %s %s", code, out, errOut)
	}
	// The quorum-protected root key cannot be used directly; recover it first.
	code, _, errOut = exec(t, env, "init-intermediate", "--dir", dir, "--kind", "factory")
	if code != 1 || !strings.Contains(errOut, "open root key") {
		t.Fatalf("init-intermediate without recovery: %d %s", code, errOut)
	}
	recovered := filepath.Join(dir, "root-recovered.key.json")
	shares := ca.Layout{Dir: dir}.SharePath(1) + "," + ca.Layout{Dir: dir}.SharePath(3)
	code, out, errOut = exec(t, env, "recover-root", "--dir", dir, "--shares", shares, "--out", recovered)
	if code != 0 || !strings.Contains(out, "re-wrapped key written") {
		t.Fatalf("recover-root: %d %s %s", code, out, errOut)
	}
	for _, kind := range []string{"factory", "device", "services"} {
		code, out, errOut = exec(t, env, "init-intermediate", "--dir", dir, "--kind", kind, "--root-key", recovered)
		if code != 0 || !strings.Contains(out, kind+" CA certificate") {
			t.Fatalf("init-intermediate %s: %d %s %s", kind, code, out, errOut)
		}
	}
	code, out, errOut = exec(t, env, "init-bundle-key", "--dir", dir)
	if code != 0 || !strings.Contains(out, "public key (hex") {
		t.Fatalf("init-bundle-key: %d %s %s", code, out, errOut)
	}
	code, out, errOut = exec(t, env, "issue-bootstrap", "--dir", dir, "--tenant", testutil.Tenant, "--device", "dev-8f3a1c2b9d4e5f60")
	if code != 0 || !strings.Contains(out, "private key (software device") {
		t.Fatalf("issue-bootstrap: %d %s %s", code, out, errOut)
	}
	// Secure-element flow with a CSR file.
	key := testutil.P256Key(t)
	csr := testutil.BuildCSR(t, key, "dev-000000000000beef", testutil.Tenant)
	csrPath := filepath.Join(dir, "se.csr")
	_ = os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o600)
	code, out, errOut = exec(t, env, "issue-bootstrap", "--dir", dir, "--tenant", testutil.Tenant, "--device", "dev-000000000000beef", "--csr", csrPath)
	if code != 0 || strings.Contains(out, "private key") {
		t.Fatalf("issue-bootstrap --csr: %d %s %s", code, out, errOut)
	}
	code, _, errOut = exec(t, env, "issue-bootstrap", "--dir", dir, "--tenant", testutil.Tenant, "--device", "dev-000000000000beef", "--csr", filepath.Join(dir, "missing.csr"))
	if code != 1 {
		t.Fatalf("missing csr: %d %s", code, errOut)
	}
	code, out, errOut = exec(t, env, "issue-server", "--dir", dir, "--cn", "svc-registry", "--san", "registry,10.0.0.1")
	if code != 0 || !strings.Contains(out, "server certificate") {
		t.Fatalf("issue-server: %d %s %s", code, out, errOut)
	}
	certs, err := ca.LoadCertsPEM(filepath.Join(dir, "services", "svc-registry.crt"))
	if err != nil || len(certs) != 2 || certs[0].Subject.CommonName != "svc-registry" {
		t.Fatalf("server cert file: %v", err)
	}
	if subj := certs[0].Subject; len(subj.Organization) != 1 || subj.Organization[0] != "IronMesh" || len(subj.OrganizationalUnit) != 1 || subj.OrganizationalUnit[0] != "services" {
		t.Fatalf("issue-server subject %v, want O=IronMesh OU=services", subj)
	}

	// Non-quorum root with a plain passphrase and the HSM-only guard.
	dir2 := t.TempDir()
	if code, _, errOut := exec(t, env, "init-root", "--dir", dir2); code != 0 {
		t.Fatalf("init-root plain: %d %s", code, errOut)
	}
	if code, _, errOut := exec(t, env, "init-intermediate", "--dir", dir2, "--kind", "device"); code != 0 {
		t.Fatalf("init-intermediate plain: %d %s", code, errOut)
	}
	if code, _, errOut := exec(t, env, "init-root", "--dir", t.TempDir(), "--kms", "awskms", "--quorum-shares", "3", "--quorum-threshold", "2"); code != 1 || !strings.Contains(errOut, "file backend only") {
		t.Fatalf("quorum with awskms: %d %s", code, errOut)
	}
	if code, _, errOut := exec(t, env, "init-root", "--dir", t.TempDir(), "--kms", "softhsm"); code != 1 || !strings.Contains(errOut, "pkcs11") {
		t.Fatalf("softhsm without build tag: %d %s", code, errOut)
	}
	if code, _, _ := exec(t, env, "init-root", "--dir", t.TempDir(), "--kms", "vault"); code != 1 {
		t.Fatal("unknown kms accepted")
	}
	if code, _, _ := exec(t, testEnv(map[string]string{"PKI_FILE_KMS_PASSPHRASE": ""}), "init-root", "--dir", t.TempDir()); code != 1 {
		t.Fatal("missing passphrase accepted")
	}
	if code, _, _ := exec(t, testEnv(map[string]string{"PKI_FILE_KMS_PASSPHRASE": ""}), "init-bundle-key", "--dir", t.TempDir()); code != 1 {
		t.Fatal("bundle key without passphrase accepted")
	}
	if code, _, _ := exec(t, env, "init-intermediate", "--dir", dir2, "--kind", "weird"); code != 1 {
		t.Fatal("bad kind accepted")
	}
	if code, _, _ := exec(t, env, "issue-bootstrap", "--dir", dir2, "--tenant", "bad", "--device", "dev-8f3a1c2b9d4e5f60"); code != 1 {
		t.Fatal("bad tenant accepted")
	}
	if code, _, _ := exec(t, env, "issue-server", "--dir", t.TempDir(), "--cn", "x"); code != 1 {
		t.Fatal("missing services key accepted")
	}
	if code, _, _ := exec(t, env, "recover-root", "--dir", dir, "--shares", ca.Layout{Dir: dir}.SharePath(1)); code != 1 {
		t.Fatal("single share accepted")
	}
}

func TestUsageAndErrors(t *testing.T) {
	t.Parallel()
	env := testEnv(nil)
	for _, args := range [][]string{nil, {"-h"}, {"help"}, {"bogus"}} {
		if code, _, errOut := exec(t, env, args...); code != 2 || !strings.Contains(errOut, "usage: pkictl") {
			t.Fatalf("%v: %d %s", args, code, errOut)
		}
	}
	if code, _, _ := exec(t, env, "init-root", "--nope"); code != 2 {
		t.Fatal("bad flag should exit 2")
	}
	if code, _, _ := exec(t, env, "revoke", "--url", "https://localhost:1"); code != 1 {
		t.Fatal("revoke without serial should fail")
	}
	if code, _, _ := exec(t, env, "ocsp-check"); code != 1 {
		t.Fatal("ocsp-check without cert should fail")
	}
	if code, _, _ := exec(t, env, "revoke", "--serial", "01", "--cert", "missing.crt", "--key", "missing.key"); code != 1 {
		t.Fatal("bad client files accepted")
	}
	if code, _, _ := exec(t, env, "crl", "--url", "http://127.0.0.1:1/crl"); code != 1 {
		t.Fatal("unreachable CRL accepted")
	}
	if code, _, _ := exec(t, env, "crl", "--ca", "missing.pem"); code != 1 {
		t.Fatal("missing CA file accepted")
	}
}

func TestOnlineCommands(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "chain.pem")
	_ = os.WriteFile(caFile, ca.EncodeChainPEM(p.CAChain()...), 0o600)
	svcCert, svcKey := p.NewServiceClient(t, "svc-console")
	certFile, keyFile := filepath.Join(dir, "svc.crt"), filepath.Join(dir, "svc.key")
	_ = os.WriteFile(certFile, ca.EncodeCertPEM(svcCert), 0o600)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(svcKey)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	devFile := filepath.Join(dir, "dev.crt")
	_ = os.WriteFile(devFile, ca.EncodeCertPEM(dev.Cert), 0o600)
	issuerFile := filepath.Join(dir, "device-ca.crt")
	_ = os.WriteFile(issuerFile, ca.EncodeCertPEM(p.Device.Certificate()), 0o600)
	env := testEnv(nil)
	clientArgs := []string{"--ca", caFile, "--cert", certFile, "--key", keyFile}

	code, out, errOut := exec(t, env, append([]string{"ocsp-check", "--url", s.MTLS.URL + "/ocsp", "--cert-file", devFile, "--issuer", issuerFile}, clientArgs...)...)
	if code != 0 || !strings.Contains(out, "status: good") || !strings.Contains(out, "nonce echoed: true") {
		t.Fatalf("ocsp-check: %d %s %s", code, out, errOut)
	}
	code, out, errOut = exec(t, env, append([]string{"revoke", "--url", s.MTLS.URL, "--serial", ca.FormatSerial(dev.Cert.SerialNumber), "--reason", "keyCompromise"}, clientArgs...)...)
	if code != 0 || !strings.Contains(out, "published=true") {
		t.Fatalf("revoke: %d %s %s", code, out, errOut)
	}
	code, out, errOut = exec(t, env, append([]string{"ocsp-check", "--url", s.MTLS.URL + "/ocsp", "--cert-file", devFile, "--issuer", issuerFile}, clientArgs...)...)
	if code != 0 || !strings.Contains(out, "status: revoked") || !strings.Contains(out, "reason: keyCompromise") {
		t.Fatalf("ocsp-check revoked: %d %s %s", code, out, errOut)
	}
	code, out, errOut = exec(t, env, "crl", "--url", s.Plain.URL+"/crl/device-ca.crl")
	if code != 0 || !strings.Contains(out, "entries: 1") || !strings.Contains(out, "keyCompromise") {
		t.Fatalf("crl: %d %s %s", code, out, errOut)
	}
	// Default issuer path resolution and missing files.
	if code, _, _ := exec(t, env, append([]string{"ocsp-check", "--url", s.MTLS.URL + "/ocsp", "--cert-file", devFile, "--dir", t.TempDir()}, clientArgs...)...); code != 1 {
		t.Fatal("missing default issuer accepted")
	}
	if code, _, _ := exec(t, env, append([]string{"ocsp-check", "--url", s.MTLS.URL + "/ocsp", "--cert-file", filepath.Join(dir, "missing.crt"), "--issuer", issuerFile}, clientArgs...)...); code != 1 {
		t.Fatal("missing cert accepted")
	}
	if code, _, _ := exec(t, env, "revoke", "--url", s.MTLS.URL, "--serial", "zz", "--ca", caFile); code != 1 {
		t.Fatal("bad serial accepted")
	}
}
