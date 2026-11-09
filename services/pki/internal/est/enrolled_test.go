package est_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

// operationalSerials returns the serials of the operational certificates the
// PKI recorded for a device (issued, whether or not they were delivered).
func operationalSerials(t *testing.T, p *testutil.PKI, deviceID string) []string {
	t.Helper()
	recs, err := p.Store.ListCertificatesByDevice(context.Background(), deviceID)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		if r.Kind == store.KindOperational {
			out = append(out, r.Serial)
		}
	}
	return out
}

func TestEnrolledCallbackRecordsEnrollment(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	fwHash := make([]byte, 32)
	for i := range fwHash {
		fwHash[i] = byte(i)
	}
	e := prepare(t, s, dev)
	resp := e.enroll(t, "simpleenroll", e.attestation(t, func(o *testutil.AttestationOptions) {
		o.FwVersion = "2.4.1"
		o.FwHash = fwHash
	}))
	if resp.Status != http.StatusOK {
		t.Fatalf("enroll: %d %s", resp.Status, resp.Body)
	}
	cert := resp.Certs[0]
	got := p.Registry.Enrollments(dev.Tenant, dev.ID)
	if len(got) != 1 {
		t.Fatalf("enrollments %+v", got)
	}
	want := registry.Enrollment{
		SerialHex: ca.FormatSerial(cert.SerialNumber), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
		SeType: "atecc608", AssuranceLevel: ca.AssuranceHardware, FwVersion: "2.4.1", FwHashHex: hex.EncodeToString(fwHash),
	}
	if !got[0].NotBefore.Equal(want.NotBefore) || !got[0].NotAfter.Equal(want.NotAfter) {
		t.Fatalf("validity %v..%v, want %v..%v", got[0].NotBefore, got[0].NotAfter, want.NotBefore, want.NotAfter)
	}
	got[0].NotBefore, got[0].NotAfter = want.NotBefore, want.NotAfter
	if got[0] != want {
		t.Fatalf("enrollment %+v, want %+v", got[0], want)
	}
	d, err := p.Registry.GetDevice(context.Background(), dev.Tenant, dev.ID)
	if err != nil || d.State != registry.StateActive {
		t.Fatalf("device %+v %v", d, err)
	}
}

func TestEnrolledCallbackRetriesTransientFailures(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{RegistryRetries: 3})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	p.Registry.SetEnrollFailure(errors.New("registry: HTTP 503"), 2)
	e := prepare(t, s, dev)
	resp := e.enroll(t, "simpleenroll", e.attestation(t, nil))
	if resp.Status != http.StatusOK {
		t.Fatalf("enroll: %d %s", resp.Status, resp.Body)
	}
	if calls := p.Registry.EnrollCalls(); calls != 3 {
		t.Fatalf("callback calls %d, want 3", calls)
	}
	if n := len(p.Registry.Enrollments(dev.Tenant, dev.ID)); n != 1 {
		t.Fatalf("recorded enrollments %d", n)
	}
}

func TestEnrolledCallbackFailureRevokesUndeliveredCertificate(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{RegistryRetries: 2})
	dev := p.NewBootstrapDevice(t, testutil.Tenant)
	p.Registry.SetEnrollFailure(errors.New("registry: HTTP 502"), 0)
	e := prepare(t, s, dev)
	resp := e.enroll(t, "simpleenroll", e.attestation(t, nil))
	if resp.Status != http.StatusServiceUnavailable {
		t.Fatalf("enroll: %d %s", resp.Status, resp.Body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	if len(resp.Certs) != 0 {
		t.Fatal("a certificate was delivered although the registry did not record it")
	}
	if calls := p.Registry.EnrollCalls(); calls != 3 {
		t.Fatalf("callback calls %d, want 1 + 2 retries", calls)
	}
	serials := operationalSerials(t, p, dev.ID)
	if len(serials) != 1 {
		t.Fatalf("issued serials %v", serials)
	}
	rev, err := p.Store.GetRevocation(context.Background(), serials[0])
	if err != nil || rev.Reason != ca.ReasonCessationOfOperation || rev.RevokedBy != est.RollbackRevokedBy {
		t.Fatalf("revocation %+v %v", rev, err)
	}
	// The certificate never left the PKI, so the policy service is not told:
	// a push would deny-list the whole device.
	if evs := s.Policy.Events(); len(evs) != 0 {
		t.Fatalf("policy events %+v", evs)
	}
	d, err := p.Registry.GetDevice(context.Background(), dev.Tenant, dev.ID)
	if err != nil || d.State != registry.StateManufactured {
		t.Fatalf("device %+v %v", d, err)
	}

	// Once the registry recovers, the device enrolls normally.
	p.Registry.SetEnrollFailure(nil, 0)
	e = prepare(t, s, dev)
	if r := e.enroll(t, "simpleenroll", e.attestation(t, nil)); r.Status != http.StatusOK {
		t.Fatalf("retry after recovery: %d %s", r.Status, r.Body)
	}
}

func TestEnrolledCallbackRejectionIsNotRetried(t *testing.T) {
	t.Parallel()
	for _, failure := range []error{registry.ErrRejected, registry.ErrNotFound} {
		t.Run(failure.Error(), func(t *testing.T) {
			t.Parallel()
			p := testutil.New(t)
			s := p.StartServer(t, testutil.ServerOptions{RegistryRetries: 3})
			dev := p.NewBootstrapDevice(t, testutil.Tenant)
			p.Registry.SetEnrollFailure(failure, 0)
			e := prepare(t, s, dev)
			resp := e.enroll(t, "simpleenroll", e.attestation(t, nil))
			if resp.Status != http.StatusServiceUnavailable {
				t.Fatalf("enroll: %d %s", resp.Status, resp.Body)
			}
			if calls := p.Registry.EnrollCalls(); calls != 1 {
				t.Fatalf("callback calls %d, want 1 (no retry)", calls)
			}
		})
	}
}

func TestReenrollCallbackFailureKeepsPreviousCertificate(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{SupersedeGrace: 20 * time.Millisecond, RegistryRetries: 1})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	oldSerial := ca.FormatSerial(dev.Cert.SerialNumber)
	p.Registry.SetEnrollFailure(errors.New("registry: connection refused"), 0)
	e := prepare(t, s, dev)
	resp := e.enroll(t, "simplereenroll", e.attestation(t, nil))
	if resp.Status != http.StatusServiceUnavailable {
		t.Fatalf("reenroll: %d %s", resp.Status, resp.Body)
	}
	if h := resp.Header.Get(est.HeaderSupersedes); h != "" {
		t.Fatalf("supersede scheduled for a failed renewal: %q", h)
	}
	// Wait well past the supersede grace: the device's current certificate
	// must stay valid because the renewal never completed.
	time.Sleep(200 * time.Millisecond)
	if _, err := p.Store.GetRevocation(context.Background(), oldSerial); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("previous certificate revoked after a failed renewal: %v", err)
	}
	if !strings.Contains(resp.Body, "registry") {
		t.Fatalf("problem detail does not name the cause: %s", resp.Body)
	}
}
