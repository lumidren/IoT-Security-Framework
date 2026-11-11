package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ceremony"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/file"
)

func TestRunConfigError(t *testing.T) {
	t.Setenv("PKI_FILE_KMS_PASSPHRASE", "")
	t.Setenv("PKI_KMS", "file")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "invalid configuration") {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
}

func TestRequireProductionKMS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		env, kms string
		wantErr  bool
	}{
		{config.EnvProduction, config.KMSFile, true},
		{config.EnvProduction, config.KMSAWS, false},
		{config.EnvProduction, config.KMSSoftHSM, false},
		{config.EnvDevelopment, config.KMSFile, false},
		{"staging", config.KMSFile, false},
	}
	for _, c := range cases {
		err := requireProductionKMS(&config.Config{Env: c.env, KMS: c.kms})
		if (err != nil) != c.wantErr {
			t.Errorf("env=%s kms=%s: err=%v", c.env, c.kms, err)
		}
	}
}

func TestRunRefusesFileKMSInProduction(t *testing.T) {
	t.Setenv("PKI_FILE_KMS_PASSPHRASE", "pw")
	t.Setenv("PKI_ENV", "production")
	t.Setenv("PKI_KMS", "file")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "refusing to start") {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
}

func TestRunStartupFailure(t *testing.T) {
	t.Setenv("PKI_FILE_KMS_PASSPHRASE", "pw")
	t.Setenv("PKI_CA_DIR", t.TempDir())
	var out, errOut bytes.Buffer
	if code := run(context.Background(), &out, &errOut); code != 1 || !strings.Contains(out.String(), "startup failed") {
		t.Fatalf("code %d: %s", code, out.String())
	}
}

func TestRunServesAndStops(t *testing.T) {
	dir := t.TempDir()
	fast := file.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	prov := &file.Provider{Passphrase: []byte("pw"), KDF: fast}
	ctx := context.Background()
	if _, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: dir, Provider: prov}); err != nil {
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
	if _, err := ceremony.InitBundleKey(ctx, dir, []byte("pw"), fast); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKI_FILE_KMS_PASSPHRASE", "pw")
	t.Setenv("PKI_CA_DIR", dir)
	t.Setenv("PKI_LISTEN_MTLS", "127.0.0.1:0")
	t.Setenv("PKI_LISTEN_PLAIN", "127.0.0.1:0")
	t.Setenv("PKI_SHUTDOWN_TIMEOUT", "2s")
	t.Setenv("PKI_LOG_LEVEL", "debug")

	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(runCtx, &out, &errOut) }()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(out.String(), "plain listener started") {
		if time.Now().After(deadline) {
			t.Fatalf("service did not start: %s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(out.String(), "pki service stopped") {
			t.Fatalf("code %d: %s", code, out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("service did not stop")
	}
}

func TestDispatchHealthcheck(t *testing.T) {
	t.Parallel()
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	env := func(k string) (string, bool) {
		if k == "PKI_LISTEN_PLAIN" {
			return listen, true
		}
		return "", false
	}
	var out, errOut bytes.Buffer
	if code := dispatch(context.Background(), []string{"healthcheck"}, env, &out, &errOut); code != 0 {
		t.Fatalf("healthy: %d %s", code, errOut.String())
	}
	status = http.StatusServiceUnavailable
	if code := dispatch(context.Background(), []string{"healthcheck"}, env, &out, &errOut); code != 1 {
		t.Fatalf("unhealthy: %d", code)
	}
	status = http.StatusOK
	if code := dispatch(context.Background(), []string{"healthcheck", "--url", srv.URL + "/healthz"}, func(string) (string, bool) { return "", false }, &out, &errOut); code != 0 {
		t.Fatalf("--url: %d %s", code, errOut.String())
	}
	// Without an override the default plain listener :8444 on loopback is probed.
	if code := dispatch(context.Background(), []string{"healthcheck", "--timeout", "200ms"}, func(string) (string, bool) { return "", false }, &out, &errOut); code != 1 && code != 0 {
		t.Fatalf("default url: %d", code)
	}
}

func TestDispatchRunsService(t *testing.T) {
	t.Setenv("PKI_FILE_KMS_PASSPHRASE", "")
	t.Setenv("PKI_KMS", "file")
	var out, errOut bytes.Buffer
	if code := dispatch(context.Background(), nil, os.LookupEnv, &out, &errOut); code != 2 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
}
