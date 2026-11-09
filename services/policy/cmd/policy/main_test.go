package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/auth"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/config"
)

func TestHealthcheckMain(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	env := map[string]string{"POLICY_LISTEN": strings.TrimPrefix(srv.URL, "http://")}
	var out, errOut bytes.Buffer
	if code := healthcheckMain(nil, config.MapGetenv(env), &out, &errOut); code != 0 {
		t.Fatalf("healthy: %d %s", code, errOut.String())
	}
	status = http.StatusServiceUnavailable
	if code := healthcheckMain(nil, config.MapGetenv(env), &out, &errOut); code != 1 {
		t.Fatalf("unhealthy: %d", code)
	}
	status = http.StatusOK
	if code := healthcheckMain([]string{"--url", srv.URL + "/healthz"}, config.MapGetenv(nil), &out, &errOut); code != 0 {
		t.Fatalf("--url: %d", code)
	}
	if code := healthcheckMain([]string{"--nope"}, config.MapGetenv(nil), &out, &errOut); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
}

func TestBuildGuard(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	signer, err := auth.GenerateSigner("k")
	if err != nil {
		t.Fatal(err)
	}
	pemKey, _ := signer.PublicKeyPEM()
	status := func(g auth.Guard) int {
		h := g(auth.RoleViewer, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policy", nil))
		return rec.Code
	}
	g, err := buildGuard(config.Config{}, "", "", log)
	if err != nil || status(g) != http.StatusServiceUnavailable {
		t.Fatalf("disabled guard: %v", err)
	}
	for name, c := range map[string]struct {
		cfg config.Config
		pem string
	}{
		"service only": {config.Config{}, pemKey},
		"oidc only":    {config.Config{OIDCIssuer: "https://idp.example/realms/x", OIDCAudience: "ironmesh-api", OIDCRoleClaim: "role"}, ""},
		"both":         {config.Config{OIDCIssuer: "https://idp.example/realms/x"}, pemKey},
	} {
		g, err := buildGuard(c.cfg, c.pem, "", log)
		if err != nil || status(g) != http.StatusUnauthorized {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := buildGuard(config.Config{}, "not pem", "", log); err == nil {
		t.Error("bad PEM accepted")
	}
	if _, err := buildGuard(config.Config{OIDCIssuer: "::bad"}, "", "", log); err == nil {
		t.Error("bad issuer accepted")
	}
}
