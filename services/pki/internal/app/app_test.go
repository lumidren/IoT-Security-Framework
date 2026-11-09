package app_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/app"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ceremony"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/file"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/server"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

const passphrase = "app-test-pw"

var fastKDF = file.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}

// caDir runs the offline ceremony into a temp dir.
func caDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prov := &file.Provider{Passphrase: []byte(passphrase), KDF: fastKDF}
	ctx := context.Background()
	if _, err := ceremony.InitRoot(ctx, ceremony.RootOptions{Dir: dir, Provider: prov}); err != nil {
		t.Fatal(err)
	}
	root, err := prov.Open(ctx, ca.Layout{Dir: dir}.KeyPath(ca.KindRoot))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []ca.Kind{ca.KindFactory, ca.KindDevice, ca.KindServices} {
		if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: dir, Kind: kind, RootSigner: root, Provider: prov}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ceremony.InitBundleKey(ctx, dir, []byte(passphrase), fastKDF); err != nil {
		t.Fatal(err)
	}
	return dir
}

func load(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func baseEnv(dir string) map[string]string {
	return map[string]string{
		"PKI_CA_DIR": dir, "PKI_FILE_KMS_PASSPHRASE": passphrase,
		"PKI_LISTEN_MTLS": "127.0.0.1:0", "PKI_LISTEN_PLAIN": "127.0.0.1:0",
		"PKI_SERVER_SANS": "localhost,127.0.0.1", "PKI_SHUTDOWN_TIMEOUT": "10s",
	}
}

func TestBuildAndRun(t *testing.T) {
	t.Parallel()
	dir := caDir(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	env := baseEnv(dir)
	env["PKI_REGISTRY_URL"] = "https://registry.invalid"
	env["PKI_POLICY_URL"] = "https://policy.invalid"
	env["PKI_POLICY_TOKEN"] = "tok"
	a, err := app.Build(context.Background(), load(t, env), logger)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer a.Close()
	if a.DeviceCA.Kind() != ca.KindDevice || a.ServicesCA.Kind() != ca.KindServices || a.EST == nil || a.OCSP == nil || a.Mgmt == nil || a.CRL == nil || a.Revoker == nil {
		t.Fatal("components missing")
	}
	if _, _, _, _, ok := a.CRL.Current(); !ok {
		t.Fatal("initial CRL not generated")
	}

	ready := make(chan server.Addrs, 1)
	a.Ready = ready
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()
	var addrs server.Addrs
	select {
	case addrs = <-ready:
	case err := <-errCh:
		t.Fatalf("Run exited: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("not ready")
	}
	plain := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/healthz", "/readyz", "/metrics", "/crl/device-ca.crl"} {
		resp, err := plain.Get("http://" + addrs.Plain + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.Root)
	tlsClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := tlsClient.Get("https://" + addrs.MTLS + "/.well-known/est/cacerts")
	if err != nil {
		t.Fatalf("cacerts: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("cacerts: %d", resp.StatusCode)
	}
	resp, err = tlsClient.Get("https://" + addrs.MTLS + "/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stats without auth: %d", resp.StatusCode)
	}
	plain.CloseIdleConnections()
	tlsClient.CloseIdleConnections()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestBuildWithOptionalFiles(t *testing.T) {
	t.Parallel()
	dir := caDir(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	prov := &file.Provider{Passphrase: []byte(passphrase), KDF: fastKDF}
	servicesSigner, err := prov.Open(context.Background(), ca.Layout{Dir: dir}.KeyPath(ca.KindServices))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ceremony.IssueServer(context.Background(), ceremony.ServerOptions{Dir: dir, ServicesSigner: servicesSigner, CN: "pki", SANs: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	jwtKey := testutil.P256Key(t)
	der, _ := x509.MarshalPKIXPublicKey(jwtKey.Public())
	jwtFile := filepath.Join(dir, "jwt.pem")
	_ = os.WriteFile(jwtFile, append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...), 0o600)
	p := testutil.New(t)
	akFile := filepath.Join(dir, "ak.pem")
	_ = os.WriteFile(akFile, ca.EncodeCertPEM(p.AKCA), 0o600)

	env := baseEnv(dir)
	env["PKI_SERVER_CERT_FILE"] = srv.CertPath
	env["PKI_SERVER_KEY_FILE"] = srv.KeyPath
	env["PKI_MGMT_JWT_PUBLIC_KEY_FILE"] = jwtFile
	env["PKI_TPM_AK_CA_FILE"] = akFile
	env["PKI_TPM_ALLOWED_PCR_DIGESTS"] = strings.Repeat("ab", 32)
	env["PKI_POLICY_URL"] = "http://policy-headless.invalid:8081"
	env["PKI_POLICY_TOKEN"] = "tok"
	env["PKI_POLICY_FANOUT"] = "dns"
	env["PKI_MGMT_JWT_SINGLE_USE"] = "false"
	a, err := app.Build(context.Background(), load(t, env), logger)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	a.Close()
	if a.ServerCert.Leaf == nil || a.ServerCert.Leaf.Subject.CommonName != "pki" {
		t.Fatal("server certificate not loaded from files")
	}

	// Error paths.
	cases := map[string]func(env map[string]string){
		"missing ca dir":   func(e map[string]string) { e["PKI_CA_DIR"] = t.TempDir() },
		"wrong passphrase": func(e map[string]string) { e["PKI_FILE_KMS_PASSPHRASE"] = "nope" },
		"softhsm unavailable": func(e map[string]string) {
			e["PKI_KMS"] = "softhsm"
		},
		"bundle key not ed25519": func(e map[string]string) { e["PKI_BUNDLE_KEY_FILE"] = ca.Layout{Dir: dir}.KeyPath(ca.KindDevice) },
		"missing bundle key":     func(e map[string]string) { e["PKI_BUNDLE_KEY_FILE"] = filepath.Join(dir, "missing.json") },
		"bad server cert files":  func(e map[string]string) { e["PKI_SERVER_CERT_FILE"], e["PKI_SERVER_KEY_FILE"] = jwtFile, jwtFile },
		"bad jwt file":           func(e map[string]string) { e["PKI_MGMT_JWT_PUBLIC_KEY_FILE"] = akFile },
		"missing jwt file":       func(e map[string]string) { e["PKI_MGMT_JWT_PUBLIC_KEY_FILE"] = filepath.Join(dir, "nope.pem") },
		"bad ak file":            func(e map[string]string) { e["PKI_TPM_AK_CA_FILE"] = jwtFile },
		"bad database url":       func(e map[string]string) { e["PKI_DATABASE_URL"] = "::bad" },
	}
	for name, mod := range cases {
		e := baseEnv(dir)
		mod(e)
		if _, err := app.Build(context.Background(), load(t, e), logger); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Missing intermediate certificates.
	partial := t.TempDir()
	_ = os.WriteFile(ca.Layout{Dir: partial}.CertPath(ca.KindRoot), ca.EncodeCertPEM(a.Root), 0o600)
	if _, err := app.Build(context.Background(), load(t, baseEnv(partial)), logger); err == nil {
		t.Error("missing factory cert accepted")
	}
	if _, err := app.Build(context.Background(), nil, logger); err == nil {
		t.Error("nil config accepted")
	}
	// Nil logger falls back to the default.
	if b, err := app.Build(context.Background(), load(t, baseEnv(dir)), nil); err != nil {
		t.Fatal(err)
	} else {
		b.Close()
	}
}
