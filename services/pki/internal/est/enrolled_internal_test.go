package est

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/revocation"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

type failingRollback struct{ err error }

func (f failingRollback) RevokeUndelivered(context.Context, string, string, string) (*revocation.Result, error) {
	return nil, f.err
}

func TestRegistryDefaults(t *testing.T) {
	t.Parallel()
	c := Config{}.withRegistryDefaults()
	if c.RegistryRetries != DefaultRegistryRetries || c.RegistryBackoff != DefaultRegistryBackoff || c.EnrollRetryAfter != DefaultEnrollRetryAfter {
		t.Fatalf("defaults %+v", c)
	}
	c = Config{RegistryRetries: -5, RegistryBackoff: time.Second, EnrollRetryAfter: time.Minute}.withRegistryDefaults()
	if c.RegistryRetries != 0 || c.RegistryBackoff != time.Second || c.EnrollRetryAfter != time.Minute {
		t.Fatalf("overrides %+v", c)
	}
}

func TestRecordEnrollmentStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	reg := registry.NewMemory()
	reg.SetEnrollFailure(errors.New("down"), 0)
	h := newTestHandler(t, Config{Registry: reg, RegistryRetries: 3, RegistryBackoff: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	err := h.recordEnrollment(ctx, testTenant, testDevice, registry.Enrollment{SerialHex: "01"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if reg.EnrollCalls() != 1 {
		t.Fatalf("calls %d", reg.EnrollCalls())
	}
}

func TestRollbackWithoutRevoker(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	h := newTestHandler(t, Config{Store: st})
	rec := &store.CertificateRecord{Serial: "0a", DeviceID: testDevice, TenantID: testTenant, IssuerCN: "IronMesh Device CA", NotAfter: time.Now().Add(time.Hour)}
	h.rollback(context.Background(), rec, nil)
	rev, err := st.GetRevocation(context.Background(), "0a")
	if err != nil || rev.Reason != ca.ReasonCessationOfOperation || rev.RevokedBy != RollbackRevokedBy || rev.DeviceID != testDevice {
		t.Fatalf("revocation %+v %v", rev, err)
	}
	// Idempotent: a second rollback of the same serial is not an error.
	h.rollback(context.Background(), rec, nil)
	// A failing revoker is logged, not fatal.
	h2 := newTestHandler(t, Config{Store: st, Rollback: failingRollback{err: errors.New("store down")}})
	h2.rollback(context.Background(), &store.CertificateRecord{Serial: "0b"}, []any{"device_id", testDevice})
}
