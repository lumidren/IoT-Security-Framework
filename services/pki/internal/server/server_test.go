package server_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/crl"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/server"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

func TestRunLifecycle(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	key := testutil.P256Key(t)
	leaf, err := p.Services.IssueServer("pki", []string{"127.0.0.1", "localhost"}, key.Public())
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{leaf.Raw, p.Services.Certificate().Raw}, PrivateKey: key}
	tlsCfg := server.TLSConfig(tlsCert, server.ClientCAPool(p.Root.Certificate(), nil))
	if tlsCfg.MinVersion != tls.VersionTLS12 || tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatal("tls config")
	}
	m, _ := crl.NewManager(p.Device, p.Store, crl.Options{Metrics: p.Metrics, Logger: p.Logger})
	if err := m.Regenerate(context.Background()); err != nil {
		t.Fatal(err)
	}
	deps := server.Deps{Logger: p.Logger, Metrics: p.Metrics, Store: p.Store, CRL: m}
	ready := make(chan server.Addrs, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run(ctx, server.Options{
			MTLSAddr: "127.0.0.1:0", PlainAddr: "127.0.0.1:0", TLS: tlsCfg,
			MTLSHandler: server.NewMTLSHandler(deps), PlainHandler: server.NewPlainHandler(deps), Logger: p.Logger, Ready: ready,
		})
	}()
	var addrs server.Addrs
	select {
	case addrs = <-ready:
	case err := <-errCh:
		t.Fatalf("Run exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not become ready")
	}

	get := func(t *testing.T, client *http.Client, url string) (*http.Response, string) {
		t.Helper()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}
	plain := "http://" + addrs.Plain
	if resp, body := get(t, http.DefaultClient, plain+"/healthz"); resp.StatusCode != 200 || body != "ok\n" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("healthz: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if resp, body := get(t, http.DefaultClient, plain+"/readyz"); resp.StatusCode != 200 || body != "ready\n" {
		t.Fatalf("readyz: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, http.DefaultClient, plain+"/metrics"); resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
	if resp, _ := get(t, http.DefaultClient, plain+"/crl/device-ca.crl"); resp.StatusCode != 200 || resp.Header.Get("Content-Type") != crl.ContentType {
		t.Fatalf("crl: %d", resp.StatusCode)
	}
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: server.ClientCAPool(p.Root.Certificate()), MinVersion: tls.VersionTLS12}}}
	if resp, _ := get(t, tlsClient, "https://"+addrs.MTLS+"/v1/ca/chain"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("mTLS listener without mgmt handler: %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunErrors(t *testing.T) {
	t.Parallel()
	if err := server.Run(context.Background(), server.Options{}); err == nil {
		t.Fatal("missing TLS config accepted")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if err := server.Run(context.Background(), server.Options{TLS: cfg, MTLSAddr: "127.0.0.1:99999", PlainAddr: "127.0.0.1:0"}); err == nil {
		t.Fatal("bad mTLS address accepted")
	}
	if err := server.Run(context.Background(), server.Options{TLS: cfg, MTLSAddr: "127.0.0.1:0", PlainAddr: "127.0.0.1:99999"}); err == nil {
		t.Fatal("bad plain address accepted")
	}
	// A listener failure (no certificate) terminates Run with an error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := server.Run(ctx, server.Options{TLS: cfg, MTLSAddr: "127.0.0.1:0", PlainAddr: "127.0.0.1:0", MTLSHandler: http.NotFoundHandler(), PlainHandler: http.NotFoundHandler()})
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected ServeTLS failure, got %v", err)
	}
}

func TestReadyzFailures(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	m, _ := crl.NewManager(p.Device, p.Store, crl.Options{Metrics: p.Metrics, Logger: p.Logger})
	h := server.NewPlainHandler(server.Deps{Logger: p.Logger, Store: p.Store, CRL: m})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz without CRL: %d", rec.Code)
	}
	_ = p.Store.Close()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with closed store: %d", rec.Code)
	}
	// Nothing to check -> ready.
	h = server.NewPlainHandler(server.Deps{Logger: p.Logger})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("empty readyz: %d", rec.Code)
	}
	if pool := server.ClientCAPool(nil); pool == nil {
		t.Fatal("pool")
	}
}
