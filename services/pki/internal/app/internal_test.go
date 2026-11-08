package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadJWTKeys(t *testing.T) {
	t.Parallel()
	if keys, err := loadJWTKeys(""); err != nil || keys != nil {
		t.Fatal("empty path should yield nil")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(ec.Public())
	keys, err := loadJWTKeys(writePEM(t, "PUBLIC KEY", der))
	if err != nil || len(keys) != 1 {
		t.Fatalf("valid key: %d %v", len(keys), err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsaDER, _ := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if _, err := loadJWTKeys(writePEM(t, "PUBLIC KEY", rsaDER)); err == nil {
		t.Error("RSA key accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKIXPublicKey(p384.Public())
	if _, err := loadJWTKeys(writePEM(t, "PUBLIC KEY", p384DER)); err == nil {
		t.Error("P-384 key accepted")
	}
	if _, err := loadJWTKeys(writePEM(t, "PUBLIC KEY", []byte{1, 2, 3})); err == nil {
		t.Error("garbage DER accepted")
	}
	if _, err := loadJWTKeys(writePEM(t, "CERTIFICATE", der)); err == nil {
		t.Error("file without PUBLIC KEY blocks accepted")
	}
	if _, err := loadJWTKeys(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file accepted")
	}
	if certs, err := loadOptionalCerts(""); err != nil || certs != nil {
		t.Error("loadOptionalCerts empty")
	}
}

func TestMaintainOnceWithClosedStore(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	_ = st.Close()
	a := &App{Store: st, Metrics: metrics.New(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.maintainOnce(context.Background()) // logs errors, must not panic
	a.Close()
}
