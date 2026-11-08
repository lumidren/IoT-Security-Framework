package est_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/veraison/go-cose"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

// enrollment bundles everything a test needs to attempt an enrollment.
type enrollment struct {
	s      *testutil.Server
	dev    *testutil.Device
	client *http.Client
	nonce  []byte
	newKey *ecdsa.PrivateKey
	csr    []byte
}

func prepare(t *testing.T, s *testutil.Server, dev *testutil.Device) *enrollment {
	t.Helper()
	e := &enrollment{s: s, dev: dev, client: s.DeviceClient(dev), newKey: testutil.P256Key(t)}
	e.nonce = testutil.GetNonce(t, e.client, s.MTLS.URL)
	e.csr = testutil.BuildCSR(t, e.newKey, dev.ID, dev.Tenant)
	return e
}

func (e *enrollment) attestation(t *testing.T, mod func(*testutil.AttestationOptions)) string {
	t.Helper()
	opts := testutil.AttestationOptions{Signer: e.dev.Key, Nonce: e.nonce, CSRDER: e.csr, SeType: attest.SeTypeATECC608, KID: e.dev.Cert.SerialNumber.Bytes()}
	if mod != nil {
		mod(&opts)
	}
	return testutil.BuildAttestation(t, opts)
}

func (e *enrollment) enroll(t *testing.T, op string, att string) *testutil.EnrollResponse {
	t.Helper()
	return testutil.Enroll(t, e.client, e.s.MTLS.URL, op, e.csr, att)
}

func TestCACertsAndCSRAttrs(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	client := s.Client(nil, nil)

	resp, err := client.Get(s.ESTURL("cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != est.ContentTypePKCS7 || resp.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatalf("cacerts: %d %v", resp.StatusCode, resp.Header)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := est.DecodeCertsOnly(der)
	if err != nil || len(certs) != 4 {
		t.Fatalf("cacerts decode: %d, %v", len(certs), err)
	}
	if !certs[0].Equal(p.Root.Certificate()) || !certs[2].Equal(p.Device.Certificate()) {
		t.Fatal("unexpected cacerts contents")
	}
	// Lines are wrapped at 76 columns per RFC 2045.
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if len(line) > 76 {
			t.Fatalf("line longer than 76: %d", len(line))
		}
	}

	resp, err = client.Get(s.ESTURL("csrattrs"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != est.ContentTypeCSRAttrs {
		t.Fatalf("csrattrs: %d", resp.StatusCode)
	}
	der, _ = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	oids, err := est.DecodeCSRAttrs(der)
	if err != nil || len(oids) != 3 || !oids[1].Equal(est.OIDSecp256r1) {
		t.Fatalf("csrattrs decode: %v %v", oids, err)
	}
}

func TestNonceRequiresClientCertificate(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	resp, err := s.Client(nil, nil).Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nonce without cert: %d", resp.StatusCode)
	}
	// A Services CA certificate is not a device identity.
	svcCert, svcKey := p.NewServiceClient(t, "svc-console")
	resp, err = s.Client(svcCert, svcKey).Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("nonce with service cert: %d", resp.StatusCode)
	}
	// Devices get a 32-byte nonce with an expiry about 120 s out.
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	resp, err = s.DeviceClient(dev).Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Nonce     string    `json:"nonce"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("nonce: %d %s", resp.StatusCode, data)
	}
	if err := jsonUnmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Nonce)
	if err != nil || len(raw) != 32 {
		t.Fatalf("nonce value %q: %v", body.Nonce, err)
	}
	if d := time.Until(body.ExpiresAt); d < 110*time.Second || d > 130*time.Second {
		t.Fatalf("nonce expiry %s away", d)
	}
}

func TestEnrollAndReenrollSuccess(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	e := prepare(t, s, dev)

	resp := e.enroll(t, "simpleenroll", e.attestation(t, nil))
	if resp.Status != http.StatusOK {
		t.Fatalf("simpleenroll: %d %s", resp.Status, resp.Body)
	}
	if resp.Header.Get("Content-Type") != est.ContentTypePKCS7 {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	if len(resp.Certs) != 1 {
		t.Fatalf("expected one certificate, got %d", len(resp.Certs))
	}
	cert := resp.Certs[0]
	if cert.Subject.CommonName != dev.ID || !cert.PublicKey.(*ecdsa.PublicKey).Equal(e.newKey.Public()) {
		t.Fatal("issued certificate does not match the CSR")
	}
	id, err := ca.ParseDeviceIdentity(cert)
	if err != nil || id.Bootstrap || id.Assurance != ca.AssuranceHardware || id.TenantID != testutil.Tenant {
		t.Fatalf("identity %+v %v", id, err)
	}
	if !ca.IssuedBy(cert, p.Device.Certificate()) {
		t.Fatal("not issued by the Device CA")
	}
	if ttl := cert.NotAfter.Sub(cert.NotBefore); ttl != ca.DefaultOperationalTTL {
		t.Fatalf("ttl %s", ttl)
	}
	// Recorded in the store with hardware assurance; registry updated.
	rec, err := p.Store.GetCertificate(context.Background(), ca.FormatSerial(cert.SerialNumber))
	if err != nil || rec.Kind != store.KindOperational || rec.Assurance != ca.AssuranceHardware || rec.DeviceID != dev.ID {
		t.Fatalf("record %+v %v", rec, err)
	}
	regDev, _ := p.Registry.GetDevice(context.Background(), dev.Tenant, dev.ID)
	if regDev.Assurance != ca.AssuranceHardware {
		t.Fatalf("registry assurance %q", regDev.Assurance)
	}
	// Bundle header verifies with the PKI bundle key and carries the tenant data.
	raw, err := base64.StdEncoding.DecodeString(resp.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := est.VerifyBundle(raw, p.BundleKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if bundle.BrokerHost != testutil.BrokerHost || bundle.BrokerPort != testutil.BrokerPort || len(bundle.CAPins) != 2 || len(bundle.TenantCmdPubKey) != 32 || len(bundle.FwSigningPubKeys) != 1 {
		t.Fatalf("bundle %+v", bundle)
	}
	servicesPin, _ := ca.SPKIPin(p.Services.Certificate().PublicKey)
	if string(bundle.CAPins[0]) != string(servicesPin) {
		t.Fatal("first pin must be the Services CA SPKI")
	}
	if v := promtest.ToFloat64(p.Metrics.CertsIssued.WithLabelValues(store.KindOperational)); v != 1 {
		t.Fatalf("certs issued metric %v", v)
	}

	// Renewal with the operational certificate and a fresh key.
	opDev := &testutil.Device{ID: dev.ID, Tenant: dev.Tenant, Key: e.newKey, Cert: cert}
	e2 := prepare(t, s, opDev)
	resp2 := e2.enroll(t, "simplereenroll", e2.attestation(t, nil))
	if resp2.Status != http.StatusOK {
		t.Fatalf("simplereenroll: %d %s", resp2.Status, resp2.Body)
	}
	if resp2.Certs[0].Subject.CommonName != dev.ID || resp2.Certs[0].SerialNumber.Cmp(cert.SerialNumber) == 0 {
		t.Fatal("renewed certificate wrong")
	}
	// The bootstrap certificate can still enroll again (re-bootstrap after expiry).
	e3 := prepare(t, s, dev)
	if r := e3.enroll(t, "simpleenroll", e3.attestation(t, nil)); r.Status != http.StatusOK {
		t.Fatalf("second bootstrap enrollment: %d %s", r.Status, r.Body)
	}
	// Enroll with an operational cert and reenroll with a bootstrap cert are refused.
	e4 := prepare(t, s, opDev)
	if r := e4.enroll(t, "simpleenroll", e4.attestation(t, nil)); r.Status != http.StatusForbidden {
		t.Fatalf("simpleenroll with operational cert: %d", r.Status)
	}
	e5 := prepare(t, s, dev)
	if r := e5.enroll(t, "simplereenroll", e5.attestation(t, nil)); r.Status != http.StatusForbidden {
		t.Fatalf("simplereenroll with bootstrap cert: %d", r.Status)
	}
}

func TestEnrollRejections(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	otherKey := testutil.P256Key(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	cases := []struct {
		name   string
		setup  func(t *testing.T, e *enrollment) (csr []byte, att string)
		status int
		msg    string
	}{
		{"wrong CN", func(t *testing.T, e *enrollment) ([]byte, string) {
			csr := testutil.BuildCSR(t, e.newKey, "dev-0000000000000000", e.dev.Tenant)
			return csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = csr })
		}, http.StatusForbidden, "CN"},
		{"wrong OU", func(t *testing.T, e *enrollment) ([]byte, string) {
			csr := testutil.BuildCSR(t, e.newKey, e.dev.ID, "11111111-2222-4333-8444-555555555555")
			return csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = csr })
		}, http.StatusForbidden, "OU"},
		{"missing OU", func(t *testing.T, e *enrollment) ([]byte, string) {
			csr := testutil.BuildCSRWithSubject(t, e.newKey, pkix.Name{CommonName: e.dev.ID}, nil)
			return csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = csr })
		}, http.StatusForbidden, "OU"},
		{"wrong SAN", func(t *testing.T, e *enrollment) ([]byte, string) {
			csr := testutil.BuildCSRWithSubject(t, e.newKey, pkix.Name{CommonName: e.dev.ID, OrganizationalUnit: []string{e.dev.Tenant}}, []*url.URL{ca.DeviceURN(e.dev.Tenant, "dev-0000000000000000")})
			return csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = csr })
		}, http.StatusForbidden, "SAN"},
		{"same key as identity", func(t *testing.T, e *enrollment) ([]byte, string) {
			csr := testutil.BuildCSR(t, e.dev.Key, e.dev.ID, e.dev.Tenant)
			return csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = csr })
		}, http.StatusBadRequest, "fresh"},
		{"P-384 CSR key", func(t *testing.T, e *enrollment) ([]byte, string) {
			csr := testutil.BuildCSR(t, p384, e.dev.ID, e.dev.Tenant)
			return csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = csr })
		}, http.StatusBadRequest, "P-256"},
		{"attestation by other key", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.Signer = otherKey })
		}, http.StatusUnauthorized, "signature"},
		{"kid mismatch", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.KID = []byte{1, 2, 3} })
		}, http.StatusUnauthorized, "kid"},
		{"csr hash mismatch", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRHash = make([]byte, 32) })
		}, http.StatusBadRequest, "csr hash"},
		{"unknown nonce", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.Nonce = make([]byte, 32) })
		}, http.StatusUnauthorized, "nonce"},
		{"software keys forbidden", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeSoftware })
		}, http.StatusForbidden, "software"},
		{"unknown se_type", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = "enclave" })
		}, http.StatusBadRequest, "se_type"},
		{"bad fw_hash size", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.FwHash = []byte{1} })
		}, http.StatusBadRequest, "fw_hash"},
		{"ES384 attestation", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.Alg = cose.AlgorithmES384; o.Signer = p384 })
		}, http.StatusBadRequest, "ES256"},
		{"tpm2 without evidence", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeTPM2 })
		}, http.StatusBadRequest, "evidence"},
		{"not base64 attestation", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, "!!!not-base64!!!"
		}, http.StatusBadRequest, "base64"},
		{"garbage attestation", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, base64.StdEncoding.EncodeToString([]byte("not cose"))
		}, http.StatusBadRequest, "COSE"},
		{"missing attestation header", func(t *testing.T, e *enrollment) ([]byte, string) {
			return e.csr, ""
		}, http.StatusUnauthorized, est.HeaderAttestation},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dev := p.NewBootstrapDevice(t, testutil.Tenant)
			e := prepare(t, s, dev)
			csr, att := c.setup(t, e)
			resp := testutil.Enroll(t, e.client, s.MTLS.URL, "simpleenroll", csr, att)
			if resp.Status != c.status {
				t.Fatalf("status %d want %d: %s", resp.Status, c.status, resp.Body)
			}
			if !strings.Contains(resp.Body, c.msg) {
				t.Fatalf("body %q does not mention %q", resp.Body, c.msg)
			}
		})
	}
	if v := promtest.ToFloat64(p.Metrics.AuthFailures); v < 5 {
		t.Fatalf("auth failures metric %v", v)
	}
}

func TestNonceLifecycle(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})

	t.Run("reused nonce", func(t *testing.T) {
		dev := p.NewBootstrapDevice(t, testutil.Tenant)
		e := prepare(t, s, dev)
		if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != 200 {
			t.Fatalf("first: %d %s", r.Status, r.Body)
		}
		// Same nonce, fresh CSR: single use.
		e.newKey = testutil.P256Key(t)
		e.csr = testutil.BuildCSR(t, e.newKey, dev.ID, dev.Tenant)
		if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusUnauthorized || !strings.Contains(r.Body, "already been used") {
			t.Fatalf("reuse: %d %s", r.Status, r.Body)
		}
	})
	t.Run("expired nonce", func(t *testing.T) {
		dev := p.NewBootstrapDevice(t, testutil.Tenant)
		e := prepare(t, s, dev)
		p.Advance(est.DefaultNonceTTL + time.Second)
		defer p.Advance(-(est.DefaultNonceTTL + time.Second))
		if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusUnauthorized || !strings.Contains(r.Body, "expired") {
			t.Fatalf("expired: %d %s", r.Status, r.Body)
		}
	})
	t.Run("nonce of another device", func(t *testing.T) {
		a := p.NewBootstrapDevice(t, testutil.Tenant)
		b := p.NewBootstrapDevice(t, testutil.Tenant)
		nonceA := testutil.GetNonce(t, s.DeviceClient(a), s.MTLS.URL)
		e := prepare(t, s, b)
		e.nonce = nonceA
		if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusUnauthorized || !strings.Contains(r.Body, "different device") {
			t.Fatalf("cross-device nonce: %d %s", r.Status, r.Body)
		}
	})
}

func TestLifecycleAndTenantPolicy(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})

	for _, state := range []registry.State{registry.StateQuarantined, registry.StateDecommissioned} {
		dev := p.NewBootstrapDevice(t, testutil.Tenant)
		p.Registry.SetState(dev.Tenant, dev.ID, state)
		e := prepare(t, s, dev)
		if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusForbidden || !strings.Contains(r.Body, string(state)) {
			t.Fatalf("%s: %d %s", state, r.Status, r.Body)
		}
	}
	// Unknown to the registry.
	unknown := p.NewBootstrapDevice(t, testutil.Tenant)
	p.Registry = registry.NewMemory() // forget everything
	s2 := p.StartServer(t, testutil.ServerOptions{})
	e := prepare(t, s2, unknown)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusForbidden || !strings.Contains(r.Body, "not registered") {
		t.Fatalf("unknown device: %d %s", r.Status, r.Body)
	}
	// Registry outage.
	p.Registry.Err = io.ErrUnexpectedEOF
	e = prepare(t, s2, unknown)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("registry outage: %d %s", r.Status, r.Body)
	}
	p.Registry.Err = nil

	// Software keys allowed by tenant policy: certificate carries the marker.
	p.SetTenantPolicy(t, func(tp *store.TenantPolicy) { tp.AllowSoftwareKeys = true })
	soft := p.NewBootstrapDevice(t, testutil.Tenant)
	e = prepare(t, s2, soft)
	r := e.enroll(t, "simpleenroll", e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeSoftware }))
	if r.Status != 200 {
		t.Fatalf("software allowed: %d %s", r.Status, r.Body)
	}
	id, err := ca.ParseDeviceIdentity(r.Certs[0])
	if err != nil || id.Assurance != ca.AssuranceSoftware {
		t.Fatalf("software identity %+v %v", id, err)
	}
	regDev, _ := p.Registry.GetDevice(context.Background(), soft.Tenant, soft.ID)
	if regDev.Assurance != ca.AssuranceSoftware {
		t.Fatalf("registry assurance %q", regDev.Assurance)
	}
	// optee is hardware without evidence.
	optee := p.NewBootstrapDevice(t, testutil.Tenant)
	e = prepare(t, s2, optee)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeOPTEE })); r.Status != 200 {
		t.Fatalf("optee: %d %s", r.Status, r.Body)
	}
	// A tenant without a stored policy uses the server default (software off).
	otherTenant := "11111111-2222-4333-8444-555555555555"
	dev := p.NewBootstrapDevice(t, otherTenant)
	e = prepare(t, s2, dev)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeSoftware })); r.Status != http.StatusForbidden {
		t.Fatalf("default policy software: %d %s", r.Status, r.Body)
	}
	s3 := p.StartServer(t, testutil.ServerOptions{DefaultAllowSoftwareKeys: true})
	e = prepare(t, s3, dev)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeSoftware })); r.Status != 200 {
		t.Fatalf("default policy software allowed: %d %s", r.Status, r.Body)
	}
	// An invalid stored AK CA bundle is a server-side error, never a bypass.
	p.SetTenantPolicy(t, func(tp *store.TenantPolicy) { tp.AKCAPEM = "garbage" })
	bad := p.NewBootstrapDevice(t, testutil.Tenant)
	e = prepare(t, s2, bad)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusInternalServerError {
		t.Fatalf("invalid AK CA policy: %d %s", r.Status, r.Body)
	}
}

func TestTPMAttestation(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	golden := testutil.GoldenPCRDigest()
	p.SetTenantPolicy(t, func(tp *store.TenantPolicy) { tp.AllowedPCRDigests = []string{hex.EncodeToString(golden)} })
	s := p.StartServer(t, testutil.ServerOptions{})
	akKey, akCert := p.NewAK(t)

	// A foreign AK CA that the tenant does not trust.
	foreign := testutil.New(t)
	foreignKey, foreignCert := foreign.NewAK(t)

	cases := []struct {
		name     string
		evidence func(t *testing.T, e *enrollment) any
		status   int
		msg      string
	}{
		{"valid quote", func(t *testing.T, e *enrollment) any {
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: golden})
		}, http.StatusOK, ""},
		{"wrong nonce", func(t *testing.T, e *enrollment) any {
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: make([]byte, 32), PCRDigest: golden})
		}, http.StatusUnauthorized, "nonce"},
		{"disallowed PCR digest", func(t *testing.T, e *enrollment) any {
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: make([]byte, 32)})
		}, http.StatusForbidden, "PCR digest"},
		{"wrong PCR selection", func(t *testing.T, e *enrollment) any {
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: golden, PCRs: []int{0, 1, 2, 3}})
		}, http.StatusForbidden, "selection"},
		{"bad signature", func(t *testing.T, e *enrollment) any {
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: golden, BadSignature: true})
		}, http.StatusUnauthorized, "signature"},
		{"untrusted AK", func(t *testing.T, e *enrollment) any {
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: foreignKey, AKCert: foreignCert, Nonce: e.nonce, PCRDigest: golden})
		}, http.StatusForbidden, "attestation CA"},
		{"AK cert mismatch", func(t *testing.T, e *enrollment) any {
			// Signed by the foreign key but presenting the trusted AK certificate.
			return testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: foreignKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: golden})
		}, http.StatusUnauthorized, "signature"},
		{"malformed evidence", func(t *testing.T, e *enrollment) any {
			return map[int]any{1: []byte{1, 2, 3}, 2: []byte{4}, 3: akCert.Raw}
		}, http.StatusBadRequest, "TPMS_ATTEST"},
		{"missing evidence fields", func(t *testing.T, e *enrollment) any {
			return map[int]any{1: []byte{1}}
		}, http.StatusBadRequest, "requires"},
		{"evidence not a map", func(t *testing.T, e *enrollment) any {
			return "nope"
		}, http.StatusBadRequest, "invalid tpm2 evidence"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dev := p.NewBootstrapDevice(t, testutil.Tenant)
			e := prepare(t, s, dev)
			att := e.attestation(t, func(o *testutil.AttestationOptions) {
				o.SeType = attest.SeTypeTPM2
				o.Evidence = c.evidence(t, e)
			})
			r := e.enroll(t, "simpleenroll", att)
			if r.Status != c.status {
				t.Fatalf("status %d want %d: %s", r.Status, c.status, r.Body)
			}
			if c.msg != "" && !strings.Contains(r.Body, c.msg) {
				t.Fatalf("body %q does not mention %q", r.Body, c.msg)
			}
		})
	}
	// Without any AK CA configured the tenant cannot use TPM attestation.
	p.SetTenantPolicy(t, func(tp *store.TenantPolicy) { tp.AKCAPEM = "" })
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	e := prepare(t, s, dev)
	att := e.attestation(t, func(o *testutil.AttestationOptions) {
		o.SeType = attest.SeTypeTPM2
		o.Evidence = testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: golden})
	})
	if r := e.enroll(t, "simpleenroll", att); r.Status != http.StatusForbidden || !strings.Contains(r.Body, "no TPM attestation CA") {
		t.Fatalf("no AK CA: %d %s", r.Status, r.Body)
	}
	// Server-wide PCR allow list and AK roots apply when the tenant has none.
	p.SetTenantPolicy(t, func(tp *store.TenantPolicy) {
		tp.AllowedPCRDigests = nil
		tp.AKCAPEM = string(ca.EncodeCertPEM(p.AKCA))
	})
	s2 := p.StartServer(t, testutil.ServerOptions{DefaultPCRDigests: []string{strings.ToUpper(hex.EncodeToString(golden))}})
	dev = p.NewBootstrapDevice(t, testutil.Tenant)
	e = prepare(t, s2, dev)
	att = e.attestation(t, func(o *testutil.AttestationOptions) {
		o.SeType = attest.SeTypeTPM2
		o.Evidence = testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: e.nonce, PCRDigest: golden})
	})
	if r := e.enroll(t, "simpleenroll", att); r.Status != 200 {
		t.Fatalf("default PCR list: %d %s", r.Status, r.Body)
	}
}

func TestRequestFormatErrors(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	e := prepare(t, s, dev)
	att := e.attestation(t, nil)
	std := func(csr []byte) string { return base64.StdEncoding.EncodeToString(csr) }

	cases := []struct {
		name        string
		contentType string
		body        func(csr []byte) string
		status      int
	}{
		{"wrong content type", "application/json", std, http.StatusUnsupportedMediaType},
		{"missing content type", "", std, http.StatusUnsupportedMediaType},
		{"bad base64", est.ContentTypePKCS10, func([]byte) string { return "@@@" }, http.StatusBadRequest},
		{"empty body", est.ContentTypePKCS10, func([]byte) string { return "" }, http.StatusBadRequest},
		{"garbage CSR", est.ContentTypePKCS10, func([]byte) string { return std([]byte("hello")) }, http.StatusBadRequest},
		{"raw DER accepted", est.ContentTypePKCS10, func(csr []byte) string { return string(csr) }, http.StatusOK},
		{"wrapped base64 accepted", est.ContentTypePKCS10, func(csr []byte) string { b := std(csr); return b[:40] + "\r\n" + b[40:] }, http.StatusOK},
		{"content type with params", est.ContentTypePKCS10 + "; charset=utf-8", std, http.StatusOK},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Each success consumes the nonce and certifies the key, so use a
			// fresh nonce, key and CSR for the cases expected to succeed.
			a, csr := att, e.csr
			if c.status == http.StatusOK {
				e.nonce = testutil.GetNonce(t, e.client, s.MTLS.URL)
				e.newKey = testutil.P256Key(t)
				e.csr = testutil.BuildCSR(t, e.newKey, dev.ID, dev.Tenant)
				csr = e.csr
				a = e.attestation(t, nil)
			}
			r := testutil.EnrollRaw(t, e.client, s.MTLS.URL, "simpleenroll", c.contentType, c.body(csr), a)
			if r.Status != c.status {
				t.Fatalf("status %d want %d: %s", r.Status, c.status, r.Body)
			}
		})
	}
	// Tampered CSR signature.
	tampered := append([]byte(nil), e.csr...)
	tampered[len(tampered)-1] ^= 0xff
	e.nonce = testutil.GetNonce(t, e.client, s.MTLS.URL)
	if r := testutil.Enroll(t, e.client, s.MTLS.URL, "simpleenroll", tampered, e.attestation(t, func(o *testutil.AttestationOptions) { o.CSRDER = tampered })); r.Status != http.StatusBadRequest {
		t.Fatalf("tampered CSR: %d %s", r.Status, r.Body)
	}
}

func TestRevokedClientCertificateRejected(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	if err := p.Store.AddRevocation(context.Background(), &store.Revocation{Serial: ca.FormatSerial(dev.Cert.SerialNumber), DeviceID: dev.ID, TenantID: dev.Tenant, IssuerCN: dev.Cert.Issuer.CommonName, NotAfter: dev.Cert.NotAfter, Reason: ca.ReasonKeyCompromise, RevokedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.DeviceClient(dev).Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "revoked") {
		t.Fatalf("revoked client: %d %s", resp.StatusCode, body)
	}
	// Store outage during the revocation lookup is a 503.
	_ = p.Store.Close()
	resp, err = s.DeviceClient(dev).Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("store closed: %d", resp.StatusCode)
	}
}

func TestNewHandlerValidation(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	good := est.Config{DeviceCA: p.Device, FactoryCA: p.Factory.Certificate(), Store: p.Store, Registry: p.Registry, Bundler: p.Bundler, Metrics: p.Metrics}
	if h, err := est.NewHandler(good); err != nil || h == nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	mods := map[string]func(*est.Config){
		"no device ca":  func(c *est.Config) { c.DeviceCA = nil },
		"wrong ca kind": func(c *est.Config) { c.DeviceCA = p.Factory },
		"no factory":    func(c *est.Config) { c.FactoryCA = nil },
		"no store":      func(c *est.Config) { c.Store = nil },
		"no registry":   func(c *est.Config) { c.Registry = nil },
		"no bundler":    func(c *est.Config) { c.Bundler = nil },
		"no metrics":    func(c *est.Config) { c.Metrics = nil },
	}
	for name, mod := range mods {
		c := good
		mod(&c)
		if _, err := est.NewHandler(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
