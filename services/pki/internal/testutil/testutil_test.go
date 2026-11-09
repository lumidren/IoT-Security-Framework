package testutil

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
)

// TestHarness exercises the helpers themselves so regressions in the test
// support code are caught directly rather than through confusing failures
// elsewhere.
func TestHarness(t *testing.T) {
	t.Parallel()
	p := New(t)
	if len(p.CAChain()) != 4 || p.Device.Kind() != ca.KindDevice {
		t.Fatal("chain")
	}
	before := p.Clock()
	p.Advance(time.Hour)
	if p.Clock().Sub(before) < time.Hour {
		t.Fatal("Advance")
	}
	p.Advance(-time.Hour)
	p.SetTenantPolicy(t, func(tp *storeTenantPolicy) { tp.BrokerPort = 1 })
	p.SetTenantPolicy(t, func(tp *storeTenantPolicy) { tp.BrokerPort = 0 })

	s := p.StartServer(t, ServerOptions{PolicyFailures: 1, NonceTTL: time.Minute})
	dev := p.NewBootstrapDevice(t, Tenant)
	op := p.NewOperationalDevice(t, Tenant)
	if id, err := ca.ParseDeviceIdentity(dev.Cert); err != nil || !id.Bootstrap {
		t.Fatal("bootstrap device")
	}
	if id, err := ca.ParseDeviceIdentity(op.Cert); err != nil || id.Bootstrap {
		t.Fatal("operational device")
	}
	if _, err := p.Registry.GetDevice(context.Background(), Tenant, dev.ID); err != nil {
		t.Fatal(err)
	}
	client := s.DeviceClient(dev)
	nonce := GetNonce(t, client, s.MTLS.URL)
	newKey := P256Key(t)
	csr := BuildCSR(t, newKey, dev.ID, dev.Tenant)
	akKey, akCert := p.NewAK(t)
	ev := TPMEvidence(t, TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: nonce, PCRDigest: GoldenPCRDigest()})
	if len(ev) != 3 {
		t.Fatal("evidence")
	}
	att := BuildAttestation(t, AttestationOptions{Signer: dev.Key, Nonce: nonce, CSRDER: csr, SeType: attest.SeTypeATECC608})
	resp := Enroll(t, client, s.MTLS.URL, "simpleenroll", csr, att)
	if resp.Status != http.StatusOK || len(resp.Certs) != 1 || resp.Bundle == "" {
		t.Fatalf("enroll via harness: %d %s", resp.Status, resp.Body)
	}
	if !bytes.Equal(MustCBOR(t, 1), []byte{0x01}) {
		t.Fatal("MustCBOR")
	}
	svcCert, svcKey := p.NewServiceClient(t, "svc-x")
	if svcCert.Subject.CommonName != "svc-x" || svcKey == nil {
		t.Fatal("service client")
	}
	// Fake policy: first request fails, then events are recorded with valid auth.
	pub, err := revocation.NewHTTPPublisher(s.Policy.URL, s.Policy.Token, s.Policy.HMACKey, s.Policy.Client())
	if err != nil {
		t.Fatal(err)
	}
	pub.Sleep = func(time.Duration) {}
	pub.Retries = 1
	if err := pub.Publish(context.Background(), revocation.Event{EventID: "e", Serial: "01"}); err != nil {
		t.Fatal(err)
	}
	if s.Policy.Requests() != 2 || len(s.Policy.Events()) != 1 || !s.Policy.Events()[0].SignatureValid {
		t.Fatalf("policy requests=%d events=%d", s.Policy.Requests(), len(s.Policy.Events()))
	}
	r, err := http.Get(s.Policy.URL + "/other")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatal("unexpected policy path")
	}
	r, err = http.Post(s.Policy.URL+revocation.PublishPath, "application/json", bytes.NewReader([]byte("{")))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatal("bad json accepted by fake policy")
	}
	if WaitContext(t).Err() != nil {
		t.Fatal("WaitContext")
	}
	if NewDeviceID(t) == NewDeviceID(t) {
		t.Fatal("device ids must differ")
	}
}
