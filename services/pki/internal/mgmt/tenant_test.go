package mgmt_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/logging"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/mgmt"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

const otherTenant = "0b6f3c1e-2d4a-4e8b-9f10-aa55aa55aa55"

type tenantEnv struct {
	p                          *testutil.PKI
	s                          *testutil.Server
	jwtKey                     *ecdsa.PrivateKey
	registry, ota, console     *http.Client
	bridge, anonymous, devCert *http.Client
}

func newTenantEnv(t *testing.T, opts testutil.ServerOptions) *tenantEnv {
	t.Helper()
	p := testutil.New(t)
	e := &tenantEnv{p: p, jwtKey: testutil.P256Key(t)}
	opts.AllowedCNs = []string{"svc-console", "svc-registry"}
	opts.JWTKeys = []crypto.PublicKey{e.jwtKey.Public()}
	e.s = p.StartServer(t, opts)
	client := func(cn string) *http.Client {
		cert, key := p.NewServiceClient(t, cn)
		return e.s.Client(cert, key)
	}
	e.registry, e.ota, e.console, e.bridge = client("svc-registry"), client("svc-ota"), client("svc-console"), client("svc-bridge")
	e.anonymous = e.s.Client(nil, nil)
	e.devCert = e.s.DeviceClient(p.NewOperationalDevice(t, testutil.Tenant))
	return e
}

func (e *tenantEnv) jwt(t *testing.T, sub string) map[string]string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := mgmt.SignES256(e.jwtKey, mgmt.Claims{Subject: sub, Audience: mgmt.Audience{"pki"}, IssuedAt: now, ExpiresAt: now + 300, ID: testJTI()})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"Authorization": "Bearer " + tok}
}

func (e *tenantEnv) url(tenant, suffix string) string {
	return e.s.MTLS.URL + "/v1/tenants/" + tenant + "/" + suffix
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func ed25519Pub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mldsaPub(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, mgmt.MLDSA65PublicKeySize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTenantPolicyAuthMatrix(t *testing.T) {
	t.Parallel()
	e := newTenantEnv(t, testutil.ServerOptions{})
	cmd := map[string]any{"public_key_b64": b64(ed25519Pub(t))}
	fw := map[string]any{"public_keys_b64": []string{b64(ed25519Pub(t))}}
	enr := map[string]any{"allow_software_keys": true}
	cases := []struct {
		name    string
		client  *http.Client
		headers map[string]string
		method  string
		suffix  string
		body    any
		status  int
	}{
		{"command-key registry mtls", e.registry, nil, http.MethodPut, "command-key", cmd, http.StatusNoContent},
		{"command-key registry jwt", e.anonymous, e.jwt(t, "registry"), http.MethodPut, "command-key", cmd, http.StatusNoContent},
		{"command-key registry jwt svc-", e.anonymous, e.jwt(t, "svc-registry"), http.MethodPut, "command-key", cmd, http.StatusNoContent},
		{"command-key ota mtls", e.ota, nil, http.MethodPut, "command-key", cmd, http.StatusForbidden},
		{"command-key ota jwt", e.anonymous, e.jwt(t, "ota"), http.MethodPut, "command-key", cmd, http.StatusForbidden},
		{"command-key console (allow-listed, not owner)", e.console, nil, http.MethodPut, "command-key", cmd, http.StatusForbidden},
		{"command-key bridge", e.bridge, nil, http.MethodPut, "command-key", cmd, http.StatusForbidden},
		{"command-key device cert", e.devCert, nil, http.MethodPut, "command-key", cmd, http.StatusUnauthorized},
		{"command-key anonymous", e.anonymous, nil, http.MethodPut, "command-key", cmd, http.StatusUnauthorized},
		{"firmware-keys ota mtls", e.ota, nil, http.MethodPut, "firmware-keys", fw, http.StatusNoContent},
		{"firmware-keys ota jwt", e.anonymous, e.jwt(t, "svc-ota"), http.MethodPut, "firmware-keys", fw, http.StatusNoContent},
		{"firmware-keys registry", e.registry, nil, http.MethodPut, "firmware-keys", fw, http.StatusForbidden},
		{"firmware-keys registry jwt", e.anonymous, e.jwt(t, "registry"), http.MethodPut, "firmware-keys", fw, http.StatusForbidden},
		{"firmware-keys console", e.console, nil, http.MethodPut, "firmware-keys", fw, http.StatusForbidden},
		{"enrollment registry", e.registry, nil, http.MethodPut, "enrollment", enr, http.StatusNoContent},
		{"enrollment ota", e.ota, nil, http.MethodPut, "enrollment", enr, http.StatusForbidden},
		{"enrollment anonymous", e.anonymous, nil, http.MethodPut, "enrollment", enr, http.StatusUnauthorized},
		{"policy console", e.console, nil, http.MethodGet, "policy", nil, http.StatusOK},
		{"policy registry", e.registry, nil, http.MethodGet, "policy", nil, http.StatusOK},
		{"policy ota (owner, not allow-listed)", e.ota, nil, http.MethodGet, "policy", nil, http.StatusOK},
		{"policy jwt", e.anonymous, e.jwt(t, "svc-console"), http.MethodGet, "policy", nil, http.StatusOK},
		{"policy bridge", e.bridge, nil, http.MethodGet, "policy", nil, http.StatusForbidden},
		{"policy anonymous", e.anonymous, nil, http.MethodGet, "policy", nil, http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := do(t, c.client, c.method, e.url(otherTenant, c.suffix), c.body, c.headers)
			if resp.StatusCode != c.status {
				t.Fatalf("status %d want %d: %s", resp.StatusCode, c.status, body)
			}
			if c.status >= 400 && resp.Header.Get("Content-Type") != "application/problem+json" {
				t.Fatalf("error content type %q", resp.Header.Get("Content-Type"))
			}
		})
	}
}

func TestTenantPolicyValidation(t *testing.T) {
	t.Parallel()
	e := newTenantEnv(t, testutil.ServerOptions{})
	ed := ed25519Pub(t)
	many := make([]string, mgmt.MaxFirmwareKeys+1)
	for i := range many {
		many[i] = b64(ed25519Pub(t))
	}
	cases := []struct {
		name   string
		client *http.Client
		tenant string
		suffix string
		body   any
		status int
	}{
		{"cmd 31 bytes", e.registry, otherTenant, "command-key", map[string]any{"public_key_b64": b64(ed[:31])}, http.StatusUnprocessableEntity},
		{"cmd 33 bytes", e.registry, otherTenant, "command-key", map[string]any{"public_key_b64": b64(append(ed, 0))}, http.StatusUnprocessableEntity},
		{"cmd all zero", e.registry, otherTenant, "command-key", map[string]any{"public_key_b64": b64(make([]byte, 32))}, http.StatusUnprocessableEntity},
		{"cmd not base64", e.registry, otherTenant, "command-key", map[string]any{"public_key_b64": "%%%"}, http.StatusUnprocessableEntity},
		{"cmd missing", e.registry, otherTenant, "command-key", map[string]any{}, http.StatusUnprocessableEntity},
		{"cmd unknown field", e.registry, otherTenant, "command-key", map[string]any{"public_key_b64": b64(ed), "x": 1}, http.StatusBadRequest},
		{"cmd malformed json", e.registry, otherTenant, "command-key", "{", http.StatusBadRequest},
		{"cmd trailing data", e.registry, otherTenant, "command-key", `{"public_key_b64":"` + b64(ed) + `"} {}`, http.StatusBadRequest},
		{"cmd bad tenant", e.registry, "not-a-uuid", "command-key", map[string]any{"public_key_b64": b64(ed)}, http.StatusUnprocessableEntity},
		{"cmd url-safe unpadded", e.registry, otherTenant, "command-key", map[string]any{"public_key_b64": base64.RawURLEncoding.EncodeToString(ed)}, http.StatusNoContent},
		{"fw empty", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": []string{}}, http.StatusUnprocessableEntity},
		{"fw missing", e.ota, otherTenant, "firmware-keys", map[string]any{}, http.StatusUnprocessableEntity},
		{"fw mldsa only", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": []string{b64(mldsaPub(t))}}, http.StatusUnprocessableEntity},
		{"fw wrong size", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": []string{b64(ed), b64(make([]byte, 64))}}, http.StatusUnprocessableEntity},
		{"fw bad base64", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": []string{b64(ed), "!!"}}, http.StatusUnprocessableEntity},
		{"fw duplicate", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": []string{b64(ed), b64(ed)}}, http.StatusUnprocessableEntity},
		{"fw too many", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": many}, http.StatusUnprocessableEntity},
		{"fw malformed", e.ota, otherTenant, "firmware-keys", "[]", http.StatusBadRequest},
		{"fw bad tenant", e.ota, "ABC", "firmware-keys", map[string]any{"public_keys_b64": []string{b64(ed)}}, http.StatusUnprocessableEntity},
		{"fw ed25519 + mldsa", e.ota, otherTenant, "firmware-keys", map[string]any{"public_keys_b64": []string{b64(ed), b64(mldsaPub(t))}}, http.StatusNoContent},
		{"enrollment missing", e.registry, otherTenant, "enrollment", map[string]any{}, http.StatusUnprocessableEntity},
		{"enrollment not bool", e.registry, otherTenant, "enrollment", map[string]any{"allow_software_keys": "yes"}, http.StatusBadRequest},
		{"enrollment bad tenant", e.registry, "x", "enrollment", map[string]any{"allow_software_keys": true}, http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := do(t, c.client, http.MethodPut, e.url(c.tenant, c.suffix), c.body, nil)
			if resp.StatusCode != c.status {
				t.Fatalf("status %d want %d: %s", resp.StatusCode, c.status, body)
			}
			if c.status == http.StatusUnprocessableEntity {
				var prob struct {
					Status int `json:"status"`
					Errors []struct {
						Field string `json:"field"`
					} `json:"errors"`
				}
				if err := json.Unmarshal(body, &prob); err != nil || prob.Status != 422 || len(prob.Errors) == 0 {
					t.Fatalf("problem body %s (%v)", body, err)
				}
			}
		})
	}
	if resp, _ := do(t, e.console, http.MethodGet, e.url("bad", "policy"), nil, nil); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("GET bad tenant: %d", resp.StatusCode)
	}
}

func TestTenantPolicyStoredAndBundled(t *testing.T) {
	t.Parallel()
	e := newTenantEnv(t, testutil.ServerOptions{DefaultAllowSoftwareKeys: true})

	// Unknown tenant: defaults, no updated_at.
	resp, body := do(t, e.console, http.MethodGet, e.url(otherTenant, "policy"), nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"updated_at":null`) || !strings.Contains(string(body), `"firmware_keys_b64":[]`) {
		t.Fatalf("default policy %d %s", resp.StatusCode, body)
	}

	cmdKey, fwKey, pqKey := ed25519Pub(t), ed25519Pub(t), mldsaPub(t)
	if r, b := do(t, e.registry, http.MethodPut, e.url(otherTenant, "command-key"), map[string]any{"public_key_b64": b64(cmdKey)}, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("command-key %d %s", r.StatusCode, b)
	}
	// The first write creates the policy with the service default (software keys allowed).
	pol, err := e.p.Store.GetTenantPolicy(context.Background(), otherTenant)
	if err != nil || !pol.AllowSoftwareKeys || !bytes.Equal(pol.TenantCmdPubKey, cmdKey) || pol.UpdatedAt.IsZero() {
		t.Fatalf("stored policy %+v %v", pol, err)
	}
	if r, b := do(t, e.ota, http.MethodPut, e.url(otherTenant, "firmware-keys"), map[string]any{"public_keys_b64": []string{b64(fwKey), b64(pqKey)}}, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("firmware-keys %d %s", r.StatusCode, b)
	}
	if r, b := do(t, e.registry, http.MethodPut, e.url(otherTenant, "enrollment"), map[string]any{"allow_software_keys": false}, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("enrollment %d %s", r.StatusCode, b)
	}
	// Field owners do not clobber each other.
	pol, _ = e.p.Store.GetTenantPolicy(context.Background(), otherTenant)
	if pol.AllowSoftwareKeys || !bytes.Equal(pol.TenantCmdPubKey, cmdKey) || len(pol.FwSigningPubKeys) != 2 {
		t.Fatalf("merged policy %+v", pol)
	}

	resp, body = do(t, e.ota, http.MethodGet, e.url(otherTenant, "policy"), nil, nil)
	var view struct {
		CommandKey  string     `json:"command_key_b64"`
		Firmware    []string   `json:"firmware_keys_b64"`
		AllowSWKeys bool       `json:"allow_software_keys"`
		UpdatedAt   *time.Time `json:"updated_at"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &view) != nil {
		t.Fatalf("GET %d %s", resp.StatusCode, body)
	}
	if view.CommandKey != b64(cmdKey) || len(view.Firmware) != 2 || view.Firmware[0] != b64(fwKey) || view.Firmware[1] != b64(pqKey) || view.AllowSWKeys || view.UpdatedAt == nil {
		t.Fatalf("view %+v", view)
	}

	// The next enrollment in that tenant carries the new keys in the signed bundle.
	dev := e.p.NewBootstrapDevice(t, otherTenant)
	client := e.s.DeviceClient(dev)
	nonce := testutil.GetNonce(t, client, e.s.MTLS.URL)
	newKey := testutil.P256Key(t)
	csr := testutil.BuildCSR(t, newKey, dev.ID, dev.Tenant)
	att := testutil.BuildAttestation(t, testutil.AttestationOptions{Signer: dev.Key, Nonce: nonce, CSRDER: csr, SeType: "atecc608", KID: dev.Cert.SerialNumber.Bytes()})
	enr := testutil.Enroll(t, client, e.s.MTLS.URL, "simpleenroll", csr, att)
	if enr.Status != http.StatusOK {
		t.Fatalf("enroll %d %s", enr.Status, enr.Body)
	}
	raw, _ := base64.StdEncoding.DecodeString(enr.Bundle)
	bundle, err := est.VerifyBundle(raw, e.p.BundleKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.TenantCmdPubKey, cmdKey) || len(bundle.FwSigningPubKeys) != 2 || !bytes.Equal(bundle.FwSigningPubKeys[0], fwKey) || !bytes.Equal(bundle.FwSigningPubKeys[1], pqKey) {
		t.Fatalf("bundle %+v", bundle)
	}

	// Rotating the command key is picked up by the next renewal.
	rotated := ed25519Pub(t)
	if r, _ := do(t, e.registry, http.MethodPut, e.url(otherTenant, "command-key"), map[string]any{"public_key_b64": b64(rotated)}, nil); r.StatusCode != http.StatusNoContent {
		t.Fatal("rotate")
	}
	op := &testutil.Device{ID: dev.ID, Tenant: dev.Tenant, Key: newKey, Cert: enr.Certs[0]}
	client = e.s.DeviceClient(op)
	nonce = testutil.GetNonce(t, client, e.s.MTLS.URL)
	newKey2 := testutil.P256Key(t)
	csr = testutil.BuildCSR(t, newKey2, dev.ID, dev.Tenant)
	att = testutil.BuildAttestation(t, testutil.AttestationOptions{Signer: newKey, Nonce: nonce, CSRDER: csr, SeType: "atecc608", KID: op.Cert.SerialNumber.Bytes()})
	enr = testutil.Enroll(t, client, e.s.MTLS.URL, "simplereenroll", csr, att)
	raw, _ = base64.StdEncoding.DecodeString(enr.Bundle)
	if bundle, err = est.VerifyBundle(raw, e.p.BundleKey.Public().(ed25519.PublicKey)); err != nil || !bytes.Equal(bundle.TenantCmdPubKey, rotated) {
		t.Fatalf("renewal bundle %+v %v (status %d)", bundle, err, enr.Status)
	}
}

type nopRevoker struct{}

func (nopRevoker) Revoke(context.Context, string, string, string) (*revocation.Result, error) {
	return nil, errors.New("unused")
}

func (nopRevoker) RevokeDevice(context.Context, string, string, string) ([]*revocation.Result, error) {
	return nil, errors.New("unused")
}

// brokenStore fails tenant policy reads or writes.
type brokenStore struct {
	*store.Memory
	failGet, failPut bool
}

func (b *brokenStore) GetTenantPolicy(ctx context.Context, id string) (*store.TenantPolicy, error) {
	if b.failGet {
		return nil, errors.New("db down")
	}
	return b.Memory.GetTenantPolicy(ctx, id)
}

func (b *brokenStore) PutTenantPolicy(ctx context.Context, p *store.TenantPolicy) error {
	if b.failPut {
		return errors.New("db down")
	}
	return b.Memory.PutTenantPolicy(ctx, p)
}

func TestTenantPolicyStoreErrors(t *testing.T) {
	t.Parallel()
	jwtKey := testutil.P256Key(t)
	st := &brokenStore{Memory: store.NewMemory()}
	h, err := mgmt.NewHandler(mgmt.Config{Auth: mgmt.NewAuthenticator(nil, nil, []*ecdsa.PublicKey{&jwtKey.PublicKey}, nil), Revoker: nopRevoker{}, Store: st, Metrics: metrics.New()})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(logging.Middleware(slog.New(slog.NewTextHandler(io.Discard, nil)), mux))
	defer srv.Close()
	now := time.Now().Unix()
	tok, _ := mgmt.SignES256(jwtKey, mgmt.Claims{Subject: "registry", Audience: mgmt.Audience{"pki"}, ExpiresAt: now + 60, IssuedAt: now, ID: testJTI()})
	hdr := map[string]string{"Authorization": "Bearer " + tok}
	put := func() int {
		resp, _ := do(t, srv.Client(), http.MethodPut, srv.URL+"/v1/tenants/"+otherTenant+"/enrollment", map[string]any{"allow_software_keys": true}, hdr)
		return resp.StatusCode
	}
	get := func() int {
		resp, _ := do(t, srv.Client(), http.MethodGet, srv.URL+"/v1/tenants/"+otherTenant+"/policy", nil, hdr)
		return resp.StatusCode
	}
	st.failPut = true
	if c := put(); c != http.StatusServiceUnavailable {
		t.Fatalf("put with failing store: %d", c)
	}
	st.failPut, st.failGet = false, true
	if c := put(); c != http.StatusServiceUnavailable {
		t.Fatalf("put with failing read: %d", c)
	}
	if c := get(); c != http.StatusServiceUnavailable {
		t.Fatalf("get with failing store: %d", c)
	}
	st.failGet = false
	if put() != http.StatusNoContent || get() != http.StatusOK {
		t.Fatal("recovered store")
	}
}

func TestPrincipalService(t *testing.T) {
	t.Parallel()
	cases := map[mgmt.Principal]string{
		{Subject: "svc-registry", Method: "mtls"}: "registry",
		{Subject: "pki", Method: "mtls"}:          "",
		{Subject: "ota", Method: "jwt"}:           "ota",
		{Subject: "svc-ota", Method: "jwt"}:       "ota",
	}
	for p, want := range cases {
		p := p
		if got := p.Service(); got != want {
			t.Errorf("%+v: %q want %q", p, got, want)
		}
	}
	var nilP *mgmt.Principal
	if nilP.Service() != "" {
		t.Error("nil principal")
	}
}
