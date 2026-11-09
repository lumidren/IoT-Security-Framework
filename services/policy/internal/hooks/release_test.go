package hooks

import (
	"context"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/revocation"
)

// TestReleasedDeviceAdmittedWithNewCertificate is the policy half of the quarantine -> release
// flow: the PKI revoke-all (device_deny) refuses every certificate of the device at CONNECT; the
// device_release event lifts the device-level deny, the quarantined (revoked) serial stays
// refused, and the certificate enrolled after the release is admitted. A later quarantine denies
// the device again.
func TestReleasedDeviceAdmittedWithNewCertificate(t *testing.T) {
	cache := revocation.NewCache("", func() time.Time { return fixedNow })
	env := newAuthnEnv(t, func(c *AuthnConfig) { c.Revoked = cache })
	quarantined, reenrolled := deviceReq(), deviceReq()
	quarantined.CertSerial, reenrolled.CertSerial = "01aa", "03cc"
	decide := func(req AuthnRequest) string {
		t.Helper()
		_, reason := env.authn.Decide(context.Background(), req)
		return reason
	}

	if _, err := cache.Upsert(revocation.Entry{EventID: "q", Serial: "01aa", DeviceID: dev, TenantID: tenant, Reason: "cessationOfOperation", DeviceDeny: true, RevokedAt: fixedNow.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := decide(quarantined); got != "revoked" {
		t.Fatalf("quarantined certificate: %s", got)
	}
	if got := decide(reenrolled); got != "revoked" {
		t.Fatalf("device deny must refuse every certificate: %s", got)
	}

	added, lifted, err := cache.Release(revocation.Release{EventID: "rel", DeviceID: dev, TenantID: tenant, ReleasedAt: fixedNow.Add(-time.Minute)})
	if err != nil || !added || !lifted {
		t.Fatalf("release added=%v lifted=%v err=%v", added, lifted, err)
	}
	if cache.IsRevokedDevice(dev) {
		t.Fatal("device-level deny must be gone")
	}
	if got := decide(quarantined); got != "revoked_serial" {
		t.Fatalf("the quarantined certificate must stay refused: %s", got)
	}
	if got := decide(reenrolled); got != "allow" {
		t.Fatalf("the re-enrolled certificate must be admitted: %s", got)
	}

	if _, err := cache.Upsert(revocation.Entry{EventID: "q2", Serial: "03cc", DeviceID: dev, TenantID: tenant, Reason: "cessationOfOperation", DeviceDeny: true, RevokedAt: fixedNow}); err != nil {
		t.Fatal(err)
	}
	renewed := deviceReq()
	renewed.CertSerial = "04dd"
	if got := decide(renewed); got != "revoked" {
		t.Fatalf("re-quarantine: %s", got)
	}
}
