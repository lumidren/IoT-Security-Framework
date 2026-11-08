// Package storetest is a conformance suite that every store.Store
// implementation must pass. It is run against the in-memory store always and
// against Postgres when PKI_TEST_DATABASE_URL is set.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Factory returns a fresh, empty store for one test.
type Factory func(t *testing.T) store.Store

const tenantA = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"

// Run executes the conformance suite.
func Run(t *testing.T, newStore Factory) {
	t.Run("Certificates", func(t *testing.T) { testCertificates(t, newStore(t)) })
	t.Run("Revocations", func(t *testing.T) { testRevocations(t, newStore(t)) })
	t.Run("Nonces", func(t *testing.T) { testNonces(t, newStore(t)) })
	t.Run("CRLNumber", func(t *testing.T) { testCRLNumber(t, newStore(t)) })
	t.Run("TenantPolicy", func(t *testing.T) { testTenantPolicy(t, newStore(t)) })
	t.Run("Ping", func(t *testing.T) {
		s := newStore(t)
		if err := s.Ping(context.Background()); err != nil {
			t.Fatalf("Ping: %v", err)
		}
	})
}

func cert(serial, device string, notAfter time.Time, issued time.Time) *store.CertificateRecord {
	return &store.CertificateRecord{
		Serial:     serial,
		DeviceID:   device,
		TenantID:   tenantA,
		Kind:       store.KindOperational,
		IssuerCN:   "IronMesh Device CA",
		NotBefore:  notAfter.Add(-14 * 24 * time.Hour),
		NotAfter:   notAfter,
		SPKISHA256: "ab" + serial,
		Assurance:  "hardware",
		DER:        []byte("der-" + serial),
		IssuedAt:   issued,
	}
}

func testCertificates(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	c1 := cert("00000000000000000000000000000001", "dev-8f3a1c2b9d4e5f60", now.Add(12*time.Hour), now.Add(-2*time.Hour))
	c2 := cert("00000000000000000000000000000002", "dev-8f3a1c2b9d4e5f60", now.Add(48*time.Hour), now.Add(-1*time.Hour))
	c3 := cert("00000000000000000000000000000003", "dev-000000000000beef", now.Add(10*24*time.Hour), now)
	expired := cert("00000000000000000000000000000004", "dev-000000000000beef", now.Add(-time.Hour), now.Add(-30*24*time.Hour))
	for _, c := range []*store.CertificateRecord{c1, c2, c3, expired} {
		if err := s.PutCertificate(ctx, c); err != nil {
			t.Fatalf("PutCertificate(%s): %v", c.Serial, err)
		}
	}
	if err := s.PutCertificate(ctx, c1); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate PutCertificate: got %v want ErrAlreadyExists", err)
	}
	if err := s.PutCertificate(ctx, &store.CertificateRecord{}); err == nil {
		t.Fatal("empty serial must be rejected")
	}

	got, err := s.GetCertificate(ctx, c1.Serial)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got.DeviceID != c1.DeviceID || got.TenantID != tenantA || got.Kind != store.KindOperational ||
		!got.NotAfter.Equal(c1.NotAfter) || !bytes.Equal(got.DER, c1.DER) || got.Assurance != "hardware" ||
		got.SPKISHA256 != c1.SPKISHA256 || got.IssuerCN != c1.IssuerCN || !got.IssuedAt.Equal(c1.IssuedAt) {
		t.Fatalf("record mismatch: %+v vs %+v", got, c1)
	}
	// Mutating the returned record must not affect the store.
	got.DER[0] = 'X'
	again, _ := s.GetCertificate(ctx, c1.Serial)
	if !bytes.Equal(again.DER, c1.DER) {
		t.Fatal("store aliased returned DER")
	}
	if _, err := s.GetCertificate(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing cert: got %v want ErrNotFound", err)
	}

	list, err := s.ListCertificatesByDevice(ctx, "dev-8f3a1c2b9d4e5f60")
	if err != nil {
		t.Fatalf("ListCertificatesByDevice: %v", err)
	}
	if len(list) != 2 || list[0].Serial != c2.Serial || list[1].Serial != c1.Serial {
		t.Fatalf("unexpected list order/contents: %+v", serials(list))
	}
	none, err := s.ListCertificatesByDevice(ctx, "dev-0000000000000000")
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown device list = %v, %v", none, err)
	}

	cases := []struct {
		name   string
		window time.Duration
		want   int
	}{
		{"24h", 24 * time.Hour, 1},
		{"72h", 72 * time.Hour, 2},
		{"7d", 7 * 24 * time.Hour, 2},
		{"30d", 30 * 24 * time.Hour, 3},
	}
	for _, c := range cases {
		n, err := s.CountExpiring(ctx, now, now.Add(c.window))
		if err != nil {
			t.Fatalf("CountExpiring(%s): %v", c.name, err)
		}
		if n != c.want {
			t.Errorf("CountExpiring(%s) = %d want %d", c.name, n, c.want)
		}
	}
	// Revoked certificates are excluded from expiring counts.
	if err := s.AddRevocation(ctx, &store.Revocation{Serial: c1.Serial, DeviceID: c1.DeviceID, TenantID: tenantA, IssuerCN: c1.IssuerCN, NotAfter: c1.NotAfter, Reason: 1, RevokedAt: now}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountExpiring(ctx, now, now.Add(24*time.Hour)); n != 0 {
		t.Fatalf("revoked cert still counted as expiring: %d", n)
	}
	st, err := s.Stats(ctx, now)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Total != 4 || st.Revoked != 1 || st.Expired != 1 {
		t.Fatalf("Stats = %+v", st)
	}
}

func serials(list []*store.CertificateRecord) []string {
	out := make([]string, len(list))
	for i, c := range list {
		out[i] = c.Serial
	}
	return out
}

func testRevocations(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rev := &store.Revocation{
		Serial: "0000000000000000000000000000000a", DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: tenantA,
		IssuerCN: "IronMesh Device CA", NotAfter: now.Add(time.Hour), Reason: 1, RevokedAt: now, RevokedBy: "svc-console",
	}
	if err := s.AddRevocation(ctx, rev); err != nil {
		t.Fatalf("AddRevocation: %v", err)
	}
	if err := s.AddRevocation(ctx, rev); !errors.Is(err, store.ErrAlreadyRevoked) {
		t.Fatalf("duplicate: got %v want ErrAlreadyRevoked", err)
	}
	if err := s.AddRevocation(ctx, &store.Revocation{}); err == nil {
		t.Fatal("empty serial must be rejected")
	}
	got, err := s.GetRevocation(ctx, rev.Serial)
	if err != nil {
		t.Fatalf("GetRevocation: %v", err)
	}
	if got.Reason != 1 || !got.RevokedAt.Equal(now) || got.RevokedBy != "svc-console" || got.DeviceID != rev.DeviceID || !got.NotAfter.Equal(rev.NotAfter) {
		t.Fatalf("revocation mismatch: %+v", got)
	}
	if _, err := s.GetRevocation(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: got %v want ErrNotFound", err)
	}
	rev2 := *rev
	rev2.Serial = "0000000000000000000000000000000b"
	if err := s.AddRevocation(ctx, &rev2); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListRevocations(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListRevocations = %d, %v", len(list), err)
	}
}

func testNonces(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	n := &store.Nonce{Value: "abc123", DeviceID: "dev-8f3a1c2b9d4e5f60", TenantID: tenantA, IssuedAt: now, ExpiresAt: now.Add(120 * time.Second)}
	if err := s.PutNonce(ctx, n); err != nil {
		t.Fatalf("PutNonce: %v", err)
	}
	if err := s.PutNonce(ctx, n); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate nonce: got %v", err)
	}
	if err := s.PutNonce(ctx, &store.Nonce{}); err == nil {
		t.Fatal("empty nonce must be rejected")
	}
	got, err := s.ConsumeNonce(ctx, "abc123", now.Add(time.Second))
	if err != nil {
		t.Fatalf("ConsumeNonce: %v", err)
	}
	if got.DeviceID != n.DeviceID || !got.ExpiresAt.Equal(n.ExpiresAt) {
		t.Fatalf("nonce mismatch: %+v", got)
	}
	// Single use.
	if _, err := s.ConsumeNonce(ctx, "abc123", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second consume: got %v want ErrNotFound", err)
	}
	// Expired nonce: reported and deleted.
	if err := s.PutNonce(ctx, &store.Nonce{Value: "old", DeviceID: n.DeviceID, TenantID: tenantA, IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeNonce(ctx, "old", now.Add(10*time.Second)); !errors.Is(err, store.ErrNonceExpired) {
		t.Fatalf("expired consume: got %v want ErrNonceExpired", err)
	}
	if _, err := s.ConsumeNonce(ctx, "old", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired nonce must be deleted: got %v", err)
	}
	// Purge.
	for i := 0; i < 3; i++ {
		exp := now.Add(time.Duration(i-1) * time.Minute) // -1m, 0, +1m
		if err := s.PutNonce(ctx, &store.Nonce{Value: fmt.Sprintf("p%d", i), DeviceID: n.DeviceID, TenantID: tenantA, IssuedAt: now, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := s.DeleteExpiredNonces(ctx, now)
	if err != nil || deleted != 2 {
		t.Fatalf("DeleteExpiredNonces = %d, %v want 2", deleted, err)
	}
	if _, err := s.ConsumeNonce(ctx, "p2", now); err != nil {
		t.Fatalf("live nonce was purged: %v", err)
	}
}

func testCRLNumber(t *testing.T, s store.Store) {
	ctx := context.Background()
	first, err := s.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	second, err := s.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	if second != first+1 || first < 1 {
		t.Fatalf("CRL numbers not monotonic: %d, %d", first, second)
	}
}

func testTenantPolicy(t *testing.T, s store.Store) {
	ctx := context.Background()
	if _, err := s.GetTenantPolicy(ctx, tenantA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing policy: got %v want ErrNotFound", err)
	}
	if err := s.PutTenantPolicy(ctx, &store.TenantPolicy{}); err == nil {
		t.Fatal("empty tenant id must be rejected")
	}
	p := &store.TenantPolicy{
		TenantID:          tenantA,
		AllowSoftwareKeys: true,
		AllowedPCRDigests: []string{"aa", "bb"},
		AKCAPEM:           "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		TenantCmdPubKey:   bytes.Repeat([]byte{7}, 32),
		FwSigningPubKeys:  [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)},
		BrokerHost:        "mqtt.tenant.example",
		BrokerPort:        8883,
	}
	if err := s.PutTenantPolicy(ctx, p); err != nil {
		t.Fatalf("PutTenantPolicy: %v", err)
	}
	got, err := s.GetTenantPolicy(ctx, tenantA)
	if err != nil {
		t.Fatalf("GetTenantPolicy: %v", err)
	}
	if !got.AllowSoftwareKeys || len(got.AllowedPCRDigests) != 2 || got.AllowedPCRDigests[1] != "bb" || got.AKCAPEM != p.AKCAPEM ||
		!bytes.Equal(got.TenantCmdPubKey, p.TenantCmdPubKey) || len(got.FwSigningPubKeys) != 2 || !bytes.Equal(got.FwSigningPubKeys[1], p.FwSigningPubKeys[1]) ||
		got.BrokerHost != p.BrokerHost || got.BrokerPort != 8883 {
		t.Fatalf("policy mismatch: %+v", got)
	}
	// Returned slices must not alias stored state.
	got.AllowedPCRDigests[0] = "zz"
	got.TenantCmdPubKey[0] = 9
	again, _ := s.GetTenantPolicy(ctx, tenantA)
	if again.AllowedPCRDigests[0] != "aa" || again.TenantCmdPubKey[0] != 7 {
		t.Fatal("store aliased policy slices")
	}
	// Upsert replaces.
	p.AllowSoftwareKeys = false
	p.AllowedPCRDigests = nil
	if err := s.PutTenantPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	again, _ = s.GetTenantPolicy(ctx, tenantA)
	if again.AllowSoftwareKeys || len(again.AllowedPCRDigests) != 0 {
		t.Fatalf("upsert did not replace: %+v", again)
	}
}
