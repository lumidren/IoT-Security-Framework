package mgmt_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

const releaseDevice = "dev-8f3a1c2b9d4e5f60"

func (e *tenantEnv) releaseURL(device string) string {
	return e.s.MTLS.URL + "/v1/devices/" + device + "/release"
}

// TestReleaseAuthMatrix: only the registry (Services CA CN svc-registry or a
// service JWT with sub registry / svc-registry) may release a device; an
// allow-listed console certificate may not.
func TestReleaseAuthMatrix(t *testing.T) {
	t.Parallel()
	e := newTenantEnv(t, testutil.ServerOptions{})
	body := map[string]any{"tenant_id": testutil.Tenant, "note": "false positive"}
	reused := e.jwt(t, "registry")
	cases := []struct {
		name    string
		client  *http.Client
		headers map[string]string
		status  int
	}{
		{"registry mtls", e.registry, nil, http.StatusAccepted},
		{"registry jwt", e.anonymous, reused, http.StatusAccepted},
		{"registry jwt replayed", e.anonymous, reused, http.StatusUnauthorized},
		{"registry jwt svc-", e.anonymous, e.jwt(t, "svc-registry"), http.StatusAccepted},
		{"registry mtls + matching jwt", e.registry, e.jwt(t, "registry"), http.StatusAccepted},
		{"registry mtls + ota jwt", e.registry, e.jwt(t, "ota"), http.StatusUnauthorized},
		{"ota mtls", e.ota, nil, http.StatusForbidden},
		{"ota jwt", e.anonymous, e.jwt(t, "ota"), http.StatusForbidden},
		{"console (allow-listed, not registry)", e.console, nil, http.StatusForbidden},
		{"console jwt", e.anonymous, e.jwt(t, "svc-console"), http.StatusForbidden},
		{"bridge", e.bridge, nil, http.StatusForbidden},
		{"device cert", e.devCert, nil, http.StatusUnauthorized},
		{"anonymous", e.anonymous, nil, http.StatusUnauthorized},
	}
	for _, c := range cases { // sequential: the replay case depends on the one before it
		resp, raw := do(t, c.client, http.MethodPost, e.releaseURL(releaseDevice), body, c.headers)
		if resp.StatusCode != c.status {
			t.Fatalf("%s: status %d want %d: %s", c.name, resp.StatusCode, c.status, raw)
		}
		if c.status >= 400 && resp.Header.Get("Content-Type") != "application/problem+json" {
			t.Fatalf("%s: error content type %q", c.name, resp.Header.Get("Content-Type"))
		}
	}
	// Four accepted releases, each one event delivered (signed) to the policy service.
	evs := e.s.Policy.Events()
	if len(evs) != 4 {
		t.Fatalf("policy received %d events, want 4", len(evs))
	}
	for _, ev := range evs {
		if !ev.Event.IsRelease() || ev.Event.DeviceID != releaseDevice || ev.Event.TenantID != testutil.Tenant || !ev.SignatureValid || !ev.AuthValid || ev.Event.ReleasedAt.IsZero() {
			t.Fatalf("delivered %+v", ev)
		}
	}
	if n, _ := e.p.Store.CountPendingOutbox(context.Background()); n != 0 {
		t.Fatalf("pending %d", n)
	}
}

// TestReleaseEndToEnd: quarantine (revoke-all) then release through the API;
// the outbox holds both kinds, the policy service receives the deny and then
// the release, and the revoked certificate stays revoked.
func TestReleaseEndToEnd(t *testing.T) {
	t.Parallel()
	e := newTenantEnv(t, testutil.ServerOptions{})
	dev := e.p.NewOperationalDevice(t, testutil.Tenant)
	resp, raw := do(t, e.registry, http.MethodPost, e.s.MTLS.URL+"/v1/devices/"+dev.ID+"/revoke-all", map[string]any{"reason": "cessationOfOperation"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-all %d %s", resp.StatusCode, raw)
	}
	resp, raw = do(t, e.registry, http.MethodPost, e.releaseURL(dev.ID), map[string]any{"tenant_id": testutil.Tenant}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("release %d %s", resp.StatusCode, raw)
	}
	var res revocation.ReleaseResult
	if err := json.Unmarshal(raw, &res); err != nil || !res.Published || res.Event != "device_release" || res.DeviceID != dev.ID || res.EventID == "" {
		t.Fatalf("release result %+v %v (%s)", res, err, raw)
	}
	evs := e.s.Policy.Events()
	if len(evs) != 2 || !evs[0].Event.DeviceDeny || evs[0].Event.IsRelease() || !evs[1].Event.IsRelease() || evs[1].Event.EventID != res.EventID {
		t.Fatalf("policy events %+v", evs)
	}
	if !evs[1].Event.ReleasedAt.After(evs[0].Event.RevokedAt) && !evs[1].Event.ReleasedAt.Equal(evs[0].Event.RevokedAt) {
		t.Fatal("release must not predate the deny it lifts")
	}
	// The quarantined certificate stays revoked.
	resp, raw = do(t, e.console, http.MethodGet, e.s.MTLS.URL+"/v1/devices/"+dev.ID+"/certificates", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"status":"revoked"`) {
		t.Fatalf("certificates after release %d %s", resp.StatusCode, raw)
	}
	// A tenant that does not own the device's certificates is refused.
	resp, raw = do(t, e.registry, http.MethodPost, e.releaseURL(dev.ID), map[string]any{"tenant_id": otherTenant}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("tenant mismatch %d %s", resp.StatusCode, raw)
	}
}

func TestReleaseValidation(t *testing.T) {
	t.Parallel()
	e := newTenantEnv(t, testutil.ServerOptions{})
	cases := []struct {
		name   string
		device string
		body   any
		status int
	}{
		{"bad device id", "not-a-device", map[string]any{"tenant_id": testutil.Tenant}, http.StatusUnprocessableEntity},
		{"missing tenant", releaseDevice, map[string]any{"note": "x"}, http.StatusUnprocessableEntity},
		{"bad tenant", releaseDevice, map[string]any{"tenant_id": "acme"}, http.StatusUnprocessableEntity},
		{"note too long", releaseDevice, map[string]any{"tenant_id": testutil.Tenant, "note": strings.Repeat("n", 1025)}, http.StatusUnprocessableEntity},
		{"unknown field", releaseDevice, map[string]any{"tenant_id": testutil.Tenant, "serial": "01"}, http.StatusBadRequest},
		{"malformed", releaseDevice, "{", http.StatusBadRequest},
		{"empty", releaseDevice, nil, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, raw := do(t, e.registry, http.MethodPost, e.releaseURL(c.device), c.body, nil)
			if resp.StatusCode != c.status || resp.Header.Get("Content-Type") != "application/problem+json" {
				t.Fatalf("status %d want %d: %s", resp.StatusCode, c.status, raw)
			}
		})
	}
	if len(e.s.Policy.Events()) != 0 {
		t.Fatal("invalid releases were published")
	}
}

type failingReleaser struct{ err error }

func (f failingReleaser) Release(context.Context, string, string, string) (*revocation.ReleaseResult, error) {
	return nil, f.err
}

// TestReleaseHandlerWiring: without a releaser the endpoint answers 501; a
// store failure is 503.
func TestReleaseHandlerWiring(t *testing.T) {
	t.Parallel()
	jwtKey := testutil.P256Key(t)
	serve := func(cfg mgmt.Config) *httptest.Server {
		cfg.Auth = mgmt.NewAuthenticator(nil, nil, []*ecdsa.PublicKey{&jwtKey.PublicKey}, nil)
		cfg.Store, cfg.Metrics = store.NewMemory(), metrics.New()
		h, err := mgmt.NewHandler(cfg)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		h.Register(mux)
		srv := httptest.NewServer(logging.Middleware(slog.New(slog.NewTextHandler(io.Discard, nil)), mux))
		t.Cleanup(srv.Close)
		return srv
	}
	post := func(srv *httptest.Server) int {
		now := time.Now().Unix()
		tok, _ := mgmt.SignES256(jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 60, IssuedAt: now, ID: testJTI()})
		resp, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/v1/devices/"+releaseDevice+"/release", map[string]any{"tenant_id": testutil.Tenant}, map[string]string{"Authorization": "Bearer " + tok})
		return resp.StatusCode
	}
	if c := post(serve(mgmt.Config{Revoker: nopRevoker{}})); c != http.StatusNotImplemented {
		t.Fatalf("no releaser: %d", c)
	}
	if c := post(serve(mgmt.Config{Revoker: nopRevoker{}, Releaser: failingReleaser{errors.New("db down")}})); c != http.StatusServiceUnavailable {
		t.Fatalf("store failure: %d", c)
	}
}
