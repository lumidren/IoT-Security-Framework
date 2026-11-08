package est_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

func TestSupersedePreviousOnReenroll(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{SupersedeGrace: 50 * time.Millisecond})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	oldSerial := ca.FormatSerial(dev.Cert.SerialNumber)
	e := prepare(t, s, dev)
	resp := e.enroll(t, "simplereenroll", e.attestation(t, nil))
	if resp.Status != http.StatusOK {
		t.Fatalf("reenroll: %d %s", resp.Status, resp.Body)
	}
	due, err := time.Parse(time.RFC3339, resp.Header.Get(est.HeaderSupersedes))
	if err != nil || due.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("supersede header %q: %v", resp.Header.Get(est.HeaderSupersedes), err)
	}
	// The scheduled revocation publishes to the policy service after writing
	// the store, so wait for the event and then inspect the store.
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Policy.Events()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("previous certificate was not revoked within the grace period")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if evs := s.Policy.Events(); len(evs) != 1 || evs[0].Event.Serial != oldSerial || evs[0].Event.Reason != "superseded" {
		t.Fatalf("policy events %+v", evs)
	}
	rev, err := p.Store.GetRevocation(context.Background(), oldSerial)
	if err != nil || rev.Reason != ca.ReasonSuperseded || !strings.HasPrefix(rev.RevokedBy, "pki:supersede:") {
		t.Fatalf("revocation %+v %v", rev, err)
	}
	if _, err := p.Store.GetRevocation(context.Background(), ca.FormatSerial(resp.Certs[0].SerialNumber)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("new certificate must not be revoked")
	}
	// First enrollment never sets the header (bootstrap certs are not superseded).
	boot := p.NewBootstrapDevice(t, testutil.Tenant)
	e2 := prepare(t, s, boot)
	if r := e2.enroll(t, "simpleenroll", e2.attestation(t, nil)); r.Status != 200 || r.Header.Get(est.HeaderSupersedes) != "" {
		t.Fatalf("simpleenroll: %d header %q", r.Status, r.Header.Get(est.HeaderSupersedes))
	}
}

func TestManufactureRecordChecks(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})

	// se_type recorded as tpm2: an atecc608 attestation is refused, a matching one accepted.
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	p.Registry.Put(registry.Device{DeviceID: dev.ID, TenantID: dev.Tenant, State: registry.StateManufactured, SeType: attest.SeTypeOPTEE, BootstrapSerial: ca.FormatSerial(dev.Cert.SerialNumber)})
	e := prepare(t, s, dev)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusForbidden || !strings.Contains(r.Body, "manufacture record") {
		t.Fatalf("se_type mismatch: %d %s", r.Status, r.Body)
	}
	e = prepare(t, s, dev)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, func(o *testutil.AttestationOptions) { o.SeType = attest.SeTypeOPTEE })); r.Status != 200 {
		t.Fatalf("se_type match: %d %s", r.Status, r.Body)
	}

	// Bootstrap serial recorded differently: first enrollment refused.
	other := p.NewBootstrapDevice(t, testutil.Tenant)
	p.Registry.Put(registry.Device{DeviceID: other.ID, TenantID: other.Tenant, State: registry.StateManufactured, BootstrapSerial: "00000000000000000000000000000001"})
	e = prepare(t, s, other)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusForbidden || !strings.Contains(r.Body, "bootstrap certificate serial") {
		t.Fatalf("bootstrap serial mismatch: %d %s", r.Status, r.Body)
	}
	// Renewal of an operational device is not subject to the bootstrap check.
	op := p.NewOperationalDevice(t, testutil.Tenant)
	p.Registry.Put(registry.Device{DeviceID: op.ID, TenantID: op.Tenant, State: registry.StateActive, BootstrapSerial: "00000000000000000000000000000001"})
	e = prepare(t, s, op)
	if r := e.enroll(t, "simplereenroll", e.attestation(t, nil)); r.Status != 200 {
		t.Fatalf("reenroll with recorded bootstrap serial: %d %s", r.Status, r.Body)
	}
}

func TestReusedKeyRejected(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	e := prepare(t, s, dev)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != 200 {
		t.Fatalf("first enrollment: %d %s", r.Status, r.Body)
	}
	// Re-bootstrap with the key that was just certified.
	e2 := prepare(t, s, dev)
	e2.newKey = e.newKey
	e2.csr = testutil.BuildCSR(t, e2.newKey, dev.ID, dev.Tenant)
	r := e2.enroll(t, "simpleenroll", e2.attestation(t, nil))
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "already certified") {
		t.Fatalf("reused key: %d %s", r.Status, r.Body)
	}
	// Reusing the bootstrap key of another device of the same tenant is allowed
	// by this check (keys are scoped per device); the identity-key check covers
	// the device's own bootstrap key.
	e3 := prepare(t, s, dev)
	if r := e3.enroll(t, "simpleenroll", e3.attestation(t, nil)); r.Status != 200 {
		t.Fatalf("fresh key after rejection: %d %s", r.Status, r.Body)
	}
}

func TestRateLimiting(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{RateLimit: &est.RateLimitConfig{DeviceBurst: 3, DevicePerMinute: 6, IPBurst: 1000, IPPerMinute: 60000}})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	client := s.DeviceClient(dev)
	for i := 0; i < 3; i++ {
		resp, err := client.Get(s.ESTURL("ironmesh/nonce"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("nonce %d: %d", i, resp.StatusCode)
		}
	}
	resp, err := client.Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("4th nonce: %d retry-after %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Enrollment shares the per-device bucket.
	r := testutil.Enroll(t, client, s.MTLS.URL, "simpleenroll", []byte{0x30}, "")
	if r.Status != http.StatusTooManyRequests {
		t.Fatalf("enroll while limited: %d", r.Status)
	}
	// Other devices are unaffected; cacerts is never limited.
	other := p.NewBootstrapDevice(t, testutil.Tenant)
	resp, err = s.DeviceClient(other).Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("other device: %d", resp.StatusCode)
	}
	for i := 0; i < 5; i++ {
		resp, err = client.Get(s.ESTURL("cacerts"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("cacerts: %d", resp.StatusCode)
		}
	}
	// Tokens come back after the refill interval (6/min = one per 10 s).
	p.Advance(11 * time.Second)
	resp, err = client.Get(s.ESTURL("ironmesh/nonce"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("after refill: %d", resp.StatusCode)
	}

	p.Advance(-11 * time.Second)

	// Per-IP limit applies before authentication.
	s2 := p.StartServer(t, testutil.ServerOptions{RateLimit: &est.RateLimitConfig{DeviceBurst: 100, DevicePerMinute: 600, IPBurst: 2, IPPerMinute: 60}})
	anon := s2.Client(nil, nil)
	codes := []int{}
	for i := 0; i < 3; i++ {
		resp, err := anon.Get(s2.ESTURL("ironmesh/nonce"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != http.StatusUnauthorized || codes[1] != http.StatusUnauthorized || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("ip limit codes %v", codes)
	}
}
