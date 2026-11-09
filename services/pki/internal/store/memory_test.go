package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store/storetest"
)

func TestMemoryConformance(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T) store.Store {
		m := store.NewMemory()
		t.Cleanup(func() { _ = m.Close() })
		return m
	})
}

func TestMemoryClosed(t *testing.T) {
	t.Parallel()
	m := store.NewMemory()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	checks := []struct {
		name string
		err  error
	}{
		{"PutCertificate", m.PutCertificate(ctx, &store.CertificateRecord{Serial: "01"})},
		{"GetCertificate", second(m.GetCertificate(ctx, "01"))},
		{"ListCertificatesByDevice", second(m.ListCertificatesByDevice(ctx, "dev"))},
		{"CountExpiring", second(m.CountExpiring(ctx, now, now))},
		{"Stats", second(m.Stats(ctx, now))},
		{"AddRevocation", m.AddRevocation(ctx, &store.Revocation{Serial: "01"})},
		{"GetRevocation", second(m.GetRevocation(ctx, "01"))},
		{"ListRevocations", second(m.ListRevocations(ctx))},
		{"AddRevocationWithEvent", m.AddRevocationWithEvent(ctx, &store.Revocation{Serial: "01"}, &store.OutboxEvent{EventID: "e"})},
		{"ClaimOutbox", second(m.ClaimOutbox(ctx, now, time.Second, 1))},
		{"RecordOutboxAttempt", m.RecordOutboxAttempt(ctx, "e", 1, now, "")},
		{"AckOutbox", m.AckOutbox(ctx, "e", now)},
		{"CountPendingOutbox", second(m.CountPendingOutbox(ctx))},
		{"PutNonce", m.PutNonce(ctx, &store.Nonce{Value: "n"})},
		{"ConsumeNonce", second(m.ConsumeNonce(ctx, "n", now))},
		{"DeleteExpiredNonces", second(m.DeleteExpiredNonces(ctx, now))},
		{"NextCRLNumber", second(m.NextCRLNumber(ctx))},
		{"GetTenantPolicy", second(m.GetTenantPolicy(ctx, "t"))},
		{"PutTenantPolicy", m.PutTenantPolicy(ctx, &store.TenantPolicy{TenantID: "t"})},
		{"Ping", m.Ping(ctx)},
	}
	for _, c := range checks {
		if c.err == nil {
			t.Errorf("%s on closed store should fail", c.name)
		}
	}
}

func second[T any](_ T, err error) error { return err }
