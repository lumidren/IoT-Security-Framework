package hooks

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCertificates(t *testing.T) {
	if certs, err := LoadCertificates(""); err != nil || certs != nil {
		t.Fatal("empty path")
	}
	dir := t.TempDir()
	a, b := newTestCA(t, "Device CA"), newTestCA(t, "Services CA")
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.cert.Raw})...)
	good := filepath.Join(dir, "bundle.pem")
	_ = os.WriteFile(good, bundle, 0o600)
	certs, err := LoadCertificates(good)
	if err != nil || len(certs) != 2 || certs[1].Subject.CommonName != "Services CA" {
		t.Fatalf("bundle: %d %v", len(certs), err)
	}
	if CertPool(certs) == nil || CertPool(nil) != nil {
		t.Fatal("CertPool")
	}
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o600)
	if _, err := LoadCertificates(empty); err == nil {
		t.Fatal("bundle without certificates accepted")
	}
	garbage := filepath.Join(dir, "garbage.pem")
	_ = os.WriteFile(garbage, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}), 0o600)
	if _, err := LoadCertificates(garbage); err == nil {
		t.Fatal("garbage certificate accepted")
	}
	if _, err := LoadCertificates(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing file accepted")
	}
}
