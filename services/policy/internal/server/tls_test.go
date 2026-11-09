package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeKeyPair(t *testing.T, dir string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "policy"}, DNSNames: []string{"policy.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile, cert
}

func TestTLSListener(t *testing.T) {
	certFile, keyFile, cert := writeKeyPair(t, t.TempDir())
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	cfg, err := TLSConfig(certFile, keyFile, pool)
	if err != nil || cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("TLSConfig: %+v %v", cfg, err)
	}
	if plain, err := TLSConfig(certFile, keyFile, nil); err != nil || plain.ClientAuth != tls.NoClientCert {
		t.Fatalf("no client CAs: %v", err)
	}
	if _, err := TLSConfig(filepath.Join(t.TempDir(), "missing"), keyFile, nil); err == nil {
		t.Fatal("missing certificate accepted")
	}
	ln, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var sawTLS atomic.Bool
	go func() {
		done <- Serve(ctx, ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawTLS.Store(r.TLS != nil && r.TLS.Version == tls.VersionTLS13)
			_, _ = io.WriteString(w, "ok")
		}), time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "policy.test", MinVersion: tls.VersionTLS12}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !sawTLS.Load() {
		t.Fatal("request did not arrive over TLS 1.3")
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "policy.test", MaxVersion: tls.VersionTLS12}}}
	if _, err := old.Get("https://" + ln.Addr().String() + "/"); err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("TLS 1.2 client: %v", err)
	}
	client.CloseIdleConnections()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	plainLn, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	plainLn.Close()
	if _, err := Listen("127.0.0.1:99999", nil); err == nil {
		t.Fatal("bad address accepted")
	}
}
