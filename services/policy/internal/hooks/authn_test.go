package hooks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/engine"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/identity"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/registry"
)

const (
	tenant      = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
	otherTenant = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
	dev         = "dev-8f3a1c2b9d4e5f60"
	otherDev    = "dev-0123456789abcdef"
)

var fixedNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type fakeRegistry struct {
	states map[string]registry.Lifecycle
	err    error
	calls  int
}

func (f *fakeRegistry) Lifecycle(_ context.Context, id string) (registry.Lifecycle, error) {
	f.calls++
	if f.err != nil {
		return registry.Lifecycle{}, f.err
	}
	lc, ok := f.states[id]
	if !ok {
		return registry.Lifecycle{}, registry.ErrNotFound
	}
	return lc, nil
}

type fakeRevoked struct {
	devices map[string]bool
	serials map[string]bool
}

func (f *fakeRevoked) IsRevokedDevice(id string) bool { return f.devices[id] }
func (f *fakeRevoked) IsRevokedSerial(s string) bool  { return f.serials[strings.ToLower(s)] }

type authnEnv struct {
	authn      *Authn
	reg        *fakeRegistry
	revoked    *fakeRevoked
	identities *IdentityCache
	m          *metrics.Metrics
}

func newAuthnEnv(t *testing.T, mutate func(*AuthnConfig)) *authnEnv {
	t.Helper()
	reg := &fakeRegistry{states: map[string]registry.Lifecycle{
		dev: {DeviceID: dev, TenantID: tenant, State: registry.StateActive},
	}}
	revoked := &fakeRevoked{devices: map[string]bool{}, serials: map[string]bool{}}
	ids := NewIdentityCache(time.Hour, 100, nil)
	m := metrics.New(prometheus.NewRegistry())
	cfg := AuthnConfig{
		Registry:   reg,
		Revoked:    revoked,
		Identities: ids,
		Metrics:    m,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:      func() time.Time { return fixedNow },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := NewAuthn(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &authnEnv{authn: a, reg: reg, revoked: revoked, identities: ids, m: m}
}

func deviceReq() AuthnRequest {
	return AuthnRequest{
		ClientID:       dev,
		Username:       dev,
		PeerHost:       "10.0.0.7",
		CertCommonName: dev,
		CertSubject:    "CN=" + dev + ",OU=" + tenant + ",O=IronMesh",
	}
}

func serviceReq(cn string) AuthnRequest {
	return AuthnRequest{ClientID: cn, Username: cn, PeerHost: "10.0.0.9", CertCommonName: cn, CertSubject: "CN=" + cn + ",OU=services,O=IronMesh"}
}

func TestNewAuthnValidation(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	if _, err := NewAuthn(AuthnConfig{Revoked: &fakeRevoked{}, Metrics: m}); err == nil {
		t.Error("missing registry should fail")
	}
	if _, err := NewAuthn(AuthnConfig{Registry: &fakeRegistry{}, Metrics: m}); err == nil {
		t.Error("missing revocation checker should fail")
	}
	if _, err := NewAuthn(AuthnConfig{Registry: &fakeRegistry{}, Revoked: &fakeRevoked{}}); err == nil {
		t.Error("missing metrics should fail")
	}
	a, err := NewAuthn(AuthnConfig{Registry: &fakeRegistry{}, Revoked: &fakeRevoked{}, Metrics: m, FailOpen: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if a.log == nil || a.now == nil || a.maxBody != 64<<10 {
		t.Errorf("defaults not applied: %+v", a)
	}
}

func TestDecideDeviceAllow(t *testing.T) {
	env := newAuthnEnv(t, nil)
	resp, reason := env.authn.Decide(context.Background(), deviceReq())
	if reason != "allow" || resp.Result != "allow" {
		t.Fatalf("resp = %+v reason = %s", resp, reason)
	}
	if resp.IsSuperuser == nil || *resp.IsSuperuser {
		t.Error("is_superuser must be false")
	}
	if resp.ClientAttrs == nil || *resp.ClientAttrs != (engine.Attrs{TenantID: tenant, DeviceID: dev, Kind: "device"}) {
		t.Errorf("client_attrs = %+v", resp.ClientAttrs)
	}
	if resp.ExpireAt != nil {
		t.Error("expire_at must be absent without cert_pem")
	}
	if attrs, ok := env.identities.Get(dev); !ok || attrs.TenantID != tenant {
		t.Error("identity cache should be populated on allow")
	}
	if got := testutil.ToFloat64(env.m.AuthnDecisions.WithLabelValues("allow", "device")); got != 1 {
		t.Errorf("allow decisions = %v", got)
	}

	// Subject with assurance marker and OpenSSL formatting is still a valid device cert.
	req := deviceReq()
	req.CertSubject = "/O=IronMesh/OU=assurance:software/OU=" + tenant + "/CN=" + dev
	if resp, reason := env.authn.Decide(context.Background(), req); reason != "allow" || resp.Result != "allow" {
		t.Errorf("openssl subject: %+v %s", resp, reason)
	}
}

func TestDecideServices(t *testing.T) {
	env := newAuthnEnv(t, nil)
	for _, cn := range []string{"svc-bridge", "svc-registry"} {
		resp, reason := env.authn.Decide(context.Background(), serviceReq(cn))
		if reason != "allow" || resp.ClientAttrs == nil || resp.ClientAttrs.Kind != "service" || resp.ClientAttrs.DeviceID != "" || resp.ClientAttrs.TenantID != "" {
			t.Errorf("%s: resp = %+v reason = %s", cn, resp, reason)
		}
	}
	if env.reg.calls != 0 {
		t.Error("services must not be looked up in the registry")
	}
	if got := testutil.ToFloat64(env.m.AuthnDecisions.WithLabelValues("allow", "service")); got != 2 {
		t.Errorf("service allows = %v", got)
	}
}

func TestCheckServicePrincipalOrigin(t *testing.T) {
	env := newAuthnEnv(t, nil)
	okDN := identity.DN{CN: "svc-bridge", O: []string{"IronMesh"}, OU: []string{"services"}}
	cases := []struct {
		name string
		peer string
		dn   identity.DN
		ok   bool
	}{
		{"rfc1918 10/8", "10.42.0.3", okDN, true},
		{"rfc1918 172.16/12", "172.20.1.1", okDN, true},
		{"rfc1918 192.168/16", "192.168.7.7", okDN, true},
		{"loopback", "127.0.0.1", okDN, true},
		{"host:port form", "10.0.0.5:48122", okDN, true},
		{"bracketed ipv6 loopback is outside v4 CIDRs", "[::1]:1883", okDN, false},
		{"public address", "8.8.8.8", okDN, false},
		{"172.32 is outside 172.16/12", "172.32.0.1", okDN, false},
		{"empty peer", "", okDN, false},
		{"hostname", "bridge.svc.cluster.local", okDN, false},
		{"missing OU", "10.0.0.1", identity.DN{CN: "svc-bridge", O: []string{"IronMesh"}}, false},
		{"wrong O", "10.0.0.1", identity.DN{CN: "svc-bridge", O: []string{"Evil"}, OU: []string{"services"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := env.authn.checkServicePrincipalOrigin(tc.peer, tc.dn)
			if ok != tc.ok {
				t.Fatalf("ok = %v (%s), want %v", ok, detail, tc.ok)
			}
			if !ok && detail == "" {
				t.Error("denials must carry a detail for the logs")
			}
		})
	}

	// Custom CIDRs (incl. IPv6) from configuration.
	nets, err := ParseCIDRs([]string{"fd00::/8", " 100.64.0.0/10 ", ""})
	if err != nil {
		t.Fatal(err)
	}
	custom := newAuthnEnv(t, func(c *AuthnConfig) { c.ServiceCIDRs = nets })
	if ok, _ := custom.authn.checkServicePrincipalOrigin("fd00::1", okDN); !ok {
		t.Error("IPv6 ULA should be allowed by custom CIDRs")
	}
	if ok, _ := custom.authn.checkServicePrincipalOrigin("100.64.1.2", okDN); !ok {
		t.Error("CGNAT range should be allowed by custom CIDRs")
	}
	if ok, _ := custom.authn.checkServicePrincipalOrigin("10.0.0.9", okDN); ok {
		t.Error("default ranges must not apply when custom CIDRs are configured")
	}
	req := serviceReq("svc-bridge")
	req.PeerHost = "fd00::1"
	if _, reason := custom.authn.Decide(context.Background(), req); reason != "allow" {
		t.Errorf("end-to-end allow via custom CIDR = %s", reason)
	}
	if _, err := ParseCIDRs([]string{"10.0.0.0/33"}); err == nil {
		t.Error("invalid CIDR should fail")
	}
	if _, err := ParseCIDRs(nil); err == nil {
		t.Error("empty CIDR list should fail")
	}
}

func TestDecideDenials(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(env *authnEnv, r *AuthnRequest)
		reason string
	}{
		{"no client cert", func(_ *authnEnv, r *AuthnRequest) { r.CertCommonName = "" }, "no_client_cert"},
		{"clientid mismatch", func(_ *authnEnv, r *AuthnRequest) { r.ClientID = otherDev }, "clientid_mismatch"},
		{"empty clientid", func(_ *authnEnv, r *AuthnRequest) { r.ClientID = "" }, "clientid_mismatch"},
		{"username mismatch", func(_ *authnEnv, r *AuthnRequest) { r.Username = "admin" }, "username_mismatch"},
		{"unparseable subject", func(_ *authnEnv, r *AuthnRequest) { r.CertSubject = "CN=" + dev + ",,O=IronMesh" }, "bad_subject"},
		{"subject cn mismatch", func(_ *authnEnv, r *AuthnRequest) {
			r.CertSubject = "CN=" + otherDev + ",OU=" + tenant + ",O=IronMesh"
		}, "bad_subject"},
		{"wrong organization", func(_ *authnEnv, r *AuthnRequest) { r.CertSubject = "CN=" + dev + ",OU=" + tenant + ",O=Evil" }, "bad_subject"},
		{"missing organization", func(_ *authnEnv, r *AuthnRequest) { r.CertSubject = "CN=" + dev + ",OU=" + tenant }, "bad_subject"},
		{"bootstrap cert", func(_ *authnEnv, r *AuthnRequest) {
			r.CertSubject = "CN=" + dev + ",OU=bootstrap:" + tenant + ",O=IronMesh"
		}, "bootstrap_cert"},
		{"no tenant", func(_ *authnEnv, r *AuthnRequest) { r.CertSubject = "CN=" + dev + ",O=IronMesh" }, "no_tenant"},
		{"ambiguous tenant", func(_ *authnEnv, r *AuthnRequest) {
			r.CertSubject = "CN=" + dev + ",OU=" + tenant + ",OU=" + otherTenant + ",O=IronMesh"
		}, "no_tenant"},
		{"revoked device", func(env *authnEnv, _ *AuthnRequest) { env.revoked.devices[dev] = true }, "revoked"},
		{"revoked serial", func(env *authnEnv, r *AuthnRequest) { r.CertSerial = "0A:BC"; env.revoked.serials["abc"] = true }, "revoked_serial"},
		{"unknown to registry", func(env *authnEnv, _ *AuthnRequest) { delete(env.reg.states, dev) }, "registry_unknown"},
		{"registry error fail closed", func(env *authnEnv, _ *AuthnRequest) { env.reg.err = errors.New("timeout") }, "registry_error"},
		{"quarantined", func(env *authnEnv, _ *AuthnRequest) {
			env.reg.states[dev] = registry.Lifecycle{State: registry.StateQuarantined, TenantID: tenant}
		}, "lifecycle_quarantined"},
		{"decommissioned", func(env *authnEnv, _ *AuthnRequest) {
			env.reg.states[dev] = registry.Lifecycle{State: registry.StateDecommissioned}
		}, "lifecycle_decommissioned"},
		{"manufactured", func(env *authnEnv, _ *AuthnRequest) {
			env.reg.states[dev] = registry.Lifecycle{State: registry.StateManufactured}
		}, "lifecycle_manufactured"},
		{"unknown state", func(env *authnEnv, _ *AuthnRequest) { env.reg.states[dev] = registry.Lifecycle{State: "weird"} }, "lifecycle_other"},
		{"tenant mismatch", func(env *authnEnv, _ *AuthnRequest) {
			env.reg.states[dev] = registry.Lifecycle{State: registry.StateActive, TenantID: otherTenant}
		}, "tenant_mismatch"},
		{"service without services OU", func(_ *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-bridge")
			r.CertSubject = "CN=svc-bridge,O=IronMesh"
		}, "service_origin"},
		{"service wrong org", func(_ *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-registry")
			r.CertSubject = "CN=svc-registry,OU=services,O=Other"
		}, "service_origin"},
		{"service from public internet", func(_ *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-bridge")
			r.PeerHost = "203.0.113.7"
		}, "service_origin"},
		{"service without peerhost", func(_ *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-bridge")
			r.PeerHost = ""
		}, "service_origin"},
		{"service with garbage peerhost", func(_ *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-registry")
			r.PeerHost = "emqx.internal"
		}, "service_origin"},
		{"service outside custom CIDRs", func(env *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-registry")
			r.PeerHost = "10.0.0.9"
			nets, _ := ParseCIDRs([]string{"192.168.50.0/24"})
			env.authn.serviceCIDRs = nets
		}, "service_origin"},
		{"service revoked", func(env *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-bridge")
			env.revoked.devices["svc-bridge"] = true
		}, "revoked"},
		{"service revoked serial", func(env *authnEnv, r *AuthnRequest) {
			*r = serviceReq("svc-bridge")
			r.CertSerial = "ff"
			env.revoked.serials["ff"] = true
		}, "revoked_serial"},
		{"unknown identity", func(_ *authnEnv, r *AuthnRequest) {
			*r = AuthnRequest{ClientID: "robot-1", Username: "robot-1", CertCommonName: "robot-1", CertSubject: "CN=robot-1,O=IronMesh,OU=services"}
		}, "unknown_identity"},
		{"uppercase device id", func(_ *authnEnv, r *AuthnRequest) {
			cn := strings.ToUpper(dev)
			*r = AuthnRequest{ClientID: cn, Username: cn, CertCommonName: cn, CertSubject: "CN=" + cn + ",OU=" + tenant + ",O=IronMesh"}
		}, "unknown_identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newAuthnEnv(t, nil)
			req := deviceReq()
			tc.mutate(env, &req)
			resp, reason := env.authn.Decide(context.Background(), req)
			if resp.Result != "deny" || resp.ClientAttrs != nil {
				t.Fatalf("resp = %+v", resp)
			}
			if reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
			if got := testutil.ToFloat64(env.m.AuthFailures.WithLabelValues(tc.reason)); got != 1 {
				t.Errorf("auth failure counter for %s = %v", tc.reason, got)
			}
			if _, ok := env.identities.Get(req.ClientID); ok {
				t.Error("denied clients must not enter the identity cache")
			}
		})
	}
}

func TestDecideFailOpen(t *testing.T) {
	env := newAuthnEnv(t, func(c *AuthnConfig) { c.FailOpen = true })
	env.reg.err = errors.New("registry down")
	resp, reason := env.authn.Decide(context.Background(), deviceReq())
	if reason != "allow" || resp.Result != "allow" {
		t.Fatalf("fail-open should admit: %+v %s", resp, reason)
	}
	// Not-found is still a deny even when failing open: the device simply does not exist.
	env.reg.err = nil
	delete(env.reg.states, dev)
	if _, reason := env.authn.Decide(context.Background(), deviceReq()); reason != "registry_unknown" {
		t.Errorf("unknown device under fail-open: %s", reason)
	}
}

func makeDeviceCert(t *testing.T, cn string, ou []string, notAfter time.Time, serial int64) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"IronMesh"}, OrganizationalUnit: ou},
		NotBefore:    fixedNow.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestDecideWithCertPEM(t *testing.T) {
	env := newAuthnEnv(t, nil)
	notAfter := fixedNow.Add(7 * 24 * time.Hour)
	req := deviceReq()
	req.CertSubject = "" // the parsed certificate is authoritative when cert_pem is present
	req.CertPEM = makeDeviceCert(t, dev, []string{tenant}, notAfter, 0xabc)
	resp, reason := env.authn.Decide(context.Background(), req)
	if reason != "bad_subject" {
		t.Fatalf("empty cert_subject must still be rejected before the PEM is parsed: %s", reason)
	}
	req.CertSubject = "CN=" + dev + ",OU=" + tenant + ",O=IronMesh"
	resp, reason = env.authn.Decide(context.Background(), req)
	if reason != "allow" || resp.ExpireAt == nil || *resp.ExpireAt != notAfter.Unix() {
		t.Fatalf("cert_pem allow: %+v %s", resp, reason)
	}

	env.revoked.serials["abc"] = true
	if _, reason := env.authn.Decide(context.Background(), req); reason != "revoked_serial" {
		t.Errorf("serial from cert_pem should be checked: %s", reason)
	}
	delete(env.revoked.serials, "abc")

	req.CertPEM = makeDeviceCert(t, otherDev, []string{tenant}, notAfter, 1)
	if _, reason := env.authn.Decide(context.Background(), req); reason != "cert_cn_mismatch" {
		t.Errorf("cn mismatch: %s", reason)
	}
	req.CertPEM = makeDeviceCert(t, dev, []string{tenant}, fixedNow.Add(-time.Minute), 2)
	if _, reason := env.authn.Decide(context.Background(), req); reason != "cert_expired" {
		t.Errorf("expired: %s", reason)
	}
	req.CertPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if _, reason := env.authn.Decide(context.Background(), req); reason != "cert_pem_invalid" {
		t.Errorf("garbage pem: %s", reason)
	}
	req.CertPEM = "not pem"
	if _, reason := env.authn.Decide(context.Background(), req); reason != "cert_pem_invalid" {
		t.Errorf("not pem: %s", reason)
	}
	// The PEM subject overrides the textual subject: a bootstrap OU inside the cert is caught.
	req.CertPEM = makeDeviceCert(t, dev, []string{"bootstrap:" + tenant}, notAfter, 3)
	if _, reason := env.authn.Decide(context.Background(), req); reason != "bootstrap_cert" {
		t.Errorf("bootstrap via pem: %s", reason)
	}
}

func TestAuthnServeHTTP(t *testing.T) {
	env := newAuthnEnv(t, nil)
	srv := httptest.NewServer(env.authn)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/emqx/authn")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", resp.StatusCode)
	}

	post := func(body []byte) (int, AuthnResponse) {
		t.Helper()
		resp, err := http.Post(srv.URL+"/emqx/authn", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out AuthnResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if status, out := post([]byte("{nope")); status != http.StatusOK || out.Result != "deny" {
		t.Errorf("bad json: %d %+v", status, out)
	}
	if got := testutil.ToFloat64(env.m.AuthFailures.WithLabelValues("bad_request")); got != 1 {
		t.Errorf("bad_request counter = %v", got)
	}
	raw, _ := json.Marshal(deviceReq())
	status, out := post(raw)
	if status != http.StatusOK || out.Result != "allow" || out.ClientAttrs == nil || out.ClientAttrs.TenantID != tenant {
		t.Errorf("allow: %d %+v", status, out)
	}
	bad := deviceReq()
	bad.ClientID = otherDev
	raw, _ = json.Marshal(bad)
	if status, out := post(raw); status != http.StatusOK || out.Result != "deny" || out.ClientAttrs != nil {
		t.Errorf("deny: %d %+v", status, out)
	}
	huge := append([]byte(`{"clientid":"`), bytes.Repeat([]byte("x"), 70<<10)...)
	if status, out := post(append(huge, []byte(`"}`)...)); status != http.StatusOK || out.Result != "deny" {
		t.Errorf("oversized: %d %+v", status, out)
	}
}
