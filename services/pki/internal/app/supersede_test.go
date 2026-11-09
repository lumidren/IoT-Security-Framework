package app_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/app"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/server"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

// policyRecorder stands in for the Policy service and applies the same
// deny-list semantics to the events it receives: device_deny events deny the
// device id, all others deny only their serial.
type policyRecorder struct {
	mu            sync.Mutex
	events        []revocation.Event
	deniedDevices map[string]bool
	deniedSerials map[string]bool
}

func (p *policyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ev revocation.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
	if ev.DeviceDeny {
		p.deniedDevices[ev.DeviceID] = true
	}
	p.deniedSerials[ev.Serial] = true
	w.WriteHeader(http.StatusAccepted)
}

// mayConnect mirrors the Policy authn decision for a device certificate.
func (p *policyRecorder) mayConnect(deviceID, serial string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.deniedDevices[deviceID] && !p.deniedSerials[serial]
}

func (p *policyRecorder) snapshot() []revocation.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]revocation.Event(nil), p.events...)
}

// TestRenewalSupersedesOnlyTheOldSerial runs the wired application: a device
// renews (simplereenroll), the previous certificate is revoked after
// PKI_SUPERSEDE_GRACE with a serial-scoped event, and afterwards the renewed
// certificate is still admitted while the old serial is not.
func TestRenewalSupersedesOnlyTheOldSerial(t *testing.T) {
	t.Parallel()
	policy := &policyRecorder{deniedDevices: map[string]bool{}, deniedSerials: map[string]bool{}}
	policySrv := httptest.NewServer(policy)
	defer policySrv.Close()

	dir := caDir(t)
	env := baseEnv(dir)
	env["PKI_POLICY_URL"] = policySrv.URL
	env["PKI_POLICY_TOKEN"] = "tok"
	env["PKI_SUPERSEDE_GRACE"] = "500ms"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := app.Build(context.Background(), load(t, env), logger)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer a.Close()
	ready := make(chan server.Addrs, 1)
	a.Ready = ready
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(15 * time.Second):
			t.Error("Run did not stop")
		}
	}()
	var addrs server.Addrs
	select {
	case addrs = <-ready:
	case err := <-errCh:
		t.Fatalf("Run exited: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("not ready")
	}
	base := "https://" + addrs.MTLS

	// An operational device of the running PKI.
	deviceID := testutil.NewDeviceID(t)
	key := testutil.P256Key(t)
	oldCert, err := a.DeviceCA.IssueOperational(ca.DeviceRequest{TenantID: testutil.Tenant, DeviceID: deviceID, PublicKey: key.Public(), Assurance: ca.AssuranceHardware})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.PutCertificate(ctx, ca.NewRecord(oldCert, store.KindOperational, ca.AssuranceHardware, time.Now())); err != nil {
		t.Fatal(err)
	}
	oldSerial := ca.FormatSerial(oldCert.SerialNumber)
	roots := x509.NewCertPool()
	roots.AddCert(a.Root)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{oldCert.Raw}, PrivateKey: key, Leaf: oldCert}},
	}}}
	defer client.CloseIdleConnections()

	// Renewal.
	newKey := testutil.P256Key(t)
	csr := testutil.BuildCSR(t, newKey, deviceID, testutil.Tenant)
	nonce := testutil.GetNonce(t, client, base)
	att := testutil.BuildAttestation(t, testutil.AttestationOptions{Signer: key, Nonce: nonce, CSRDER: csr, SeType: attest.SeTypeATECC608, KID: oldCert.SerialNumber.Bytes()})
	resp := testutil.Enroll(t, client, base, "simplereenroll", csr, att)
	if resp.Status != http.StatusOK || len(resp.Certs) != 1 || resp.Header.Get(est.HeaderSupersedes) == "" {
		t.Fatalf("simplereenroll: %d %q %s", resp.Status, resp.Header.Get(est.HeaderSupersedes), resp.Body)
	}
	newSerial := ca.FormatSerial(resp.Certs[0].SerialNumber)

	// During the grace period (nothing pushed yet) both certificates work.
	if len(policy.snapshot()) == 0 && (!policy.mayConnect(deviceID, oldSerial) || !policy.mayConnect(deviceID, newSerial)) {
		t.Fatal("certificates denied before the grace period ended")
	}

	// After the grace period the superseded serial is revoked and pushed.
	deadline := time.Now().Add(10 * time.Second)
	for len(policy.snapshot()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("superseded certificate was not revoked after the grace period")
		}
		time.Sleep(10 * time.Millisecond)
	}
	evs := policy.snapshot()
	if len(evs) != 1 || evs[0].Serial != oldSerial || evs[0].Reason != "superseded" || evs[0].DeviceDeny || evs[0].DeviceID != deviceID {
		t.Fatalf("policy events %+v", evs)
	}
	if policy.mayConnect(deviceID, oldSerial) {
		t.Fatal("old serial still admitted after supersede")
	}
	if !policy.mayConnect(deviceID, newSerial) {
		t.Fatal("renewed device locked out by the supersede of its previous certificate")
	}
	if rev, err := a.Store.GetRevocation(ctx, oldSerial); err != nil || rev.Reason != ca.ReasonSuperseded {
		t.Fatalf("old revocation %+v %v", rev, err)
	}
	if _, err := a.Store.GetRevocation(ctx, newSerial); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new certificate revoked: %v", err)
	}
	if n, _ := a.Store.CountPendingOutbox(ctx); n != 0 {
		t.Fatalf("outbox still pending: %d", n)
	}
}
