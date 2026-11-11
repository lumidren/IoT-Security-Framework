package ceremony_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ceremony"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

// TestFilesystemFailures covers the error branches that depend on the
// filesystem refusing writes.
func TestFilesystemFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file where a directory is expected.
	if _, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: filepath.Join(blocker, "sub"), Provider: fileProvider()}); err == nil {
		t.Error("InitRoot under a file accepted")
	}
	if _, err := ceremony.InitBundleKey(ctx, filepath.Join(blocker, "sub"), []byte("pw"), fastKDF); err == nil {
		t.Error("InitBundleKey under a file accepted")
	}
	dir, prov := buildDir(t)
	factorySigner, _ := prov.Open(ctx, ca.Layout{Dir: dir}.KeyPath(ca.KindFactory))
	if _, err := ceremony.IssueBootstrap(ctx, ceremony.BootstrapOptions{Dir: dir, FactorySigner: factorySigner, TenantID: tenant, DeviceID: testutil.NewDeviceID(t), OutDir: filepath.Join(blocker, "out")}); err == nil {
		t.Error("IssueBootstrap into a file accepted")
	}
	servicesSigner, _ := prov.Open(ctx, ca.Layout{Dir: dir}.KeyPath(ca.KindServices))
	if _, err := ceremony.IssueServer(ctx, ceremony.ServerOptions{Dir: dir, ServicesSigner: servicesSigner, CN: "x", OutDir: filepath.Join(blocker, "out")}); err == nil {
		t.Error("IssueServer into a file accepted")
	}
	// Explicit key reference for an intermediate and an invalid share encoding.
	extra := t.TempDir()
	if _, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: extra, Provider: fileProvider(), KeyRef: filepath.Join(extra, "custom-root.json")}); err != nil {
		t.Fatal(err)
	}
	rootSigner, err := fileProvider().Open(ctx, filepath.Join(extra, "custom-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ceremony.InitIntermediate(ctx, ceremony.IntermediateOptions{Dir: extra, Kind: ca.KindServices, RootSigner: rootSigner, Provider: fileProvider(), KeyRef: filepath.Join(extra, "svc.json")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(extra, "svc.json")); err != nil {
		t.Error("custom key ref not honoured")
	}
	badShare := filepath.Join(extra, "share.txt")
	_ = os.WriteFile(badShare, []byte("ironmesh-root-share-v1:!!!\n"), 0o600)
	if _, err := ceremony.ReadShare(badShare); err == nil {
		t.Error("invalid share encoding accepted")
	}
	if _, err := ceremony.ReadShare(filepath.Join(extra, "missing.txt")); err == nil {
		t.Error("missing share accepted")
	}
	// Quorum root key under a custom reference.
	q := t.TempDir()
	res, err := ceremony.InitRoot(ctx, &ceremony.RootOptions{Dir: q, QuorumShares: 2, QuorumThreshold: 2, KeyRef: filepath.Join(q, "r.json"), FileKDF: fastKDF})
	if err != nil || res.KeyRef != filepath.Join(q, "r.json") {
		t.Fatalf("quorum custom ref: %+v %v", res, err)
	}
}

func TestClientErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := testutil.New(t)
	s := p.StartServer(t, testutil.ServerOptions{})
	client, _ := ceremony.NewHTTPClient(ceremony.ClientOptions{Insecure: true})
	dev := p.NewOperationalDevice(t, testutil.Tenant)
	// Unknown certificate -> status unknown (not an error).
	key := testutil.P256Key(t)
	unknown, _ := p.Device.IssueOperational(ca.DeviceRequest{TenantID: testutil.Tenant, DeviceID: "dev-00000000000000ff", PublicKey: key.Public()})
	res, err := ceremony.OCSPCheck(ctx, client, s.MTLS.URL+"/ocsp", unknown, p.Device.Certificate())
	if err != nil || res.Status != "unknown" {
		t.Fatalf("unknown: %+v %v", res, err)
	}
	// Bad URLs and unreachable endpoints.
	if _, err := ceremony.OCSPCheck(ctx, client, "::bad", dev.Cert, p.Device.Certificate()); err == nil {
		t.Error("bad OCSP URL accepted")
	}
	if _, err := ceremony.OCSPCheck(ctx, client, "https://127.0.0.1:1/ocsp", dev.Cert, p.Device.Certificate()); err == nil {
		t.Error("unreachable OCSP accepted")
	}
	if _, err := ceremony.Revoke(ctx, client, "::bad", "", ca.FormatSerial(dev.Cert.SerialNumber), "superseded"); err == nil {
		t.Error("bad revoke URL accepted")
	}
	if _, err := ceremony.Revoke(ctx, client, "https://127.0.0.1:1", "", ca.FormatSerial(dev.Cert.SerialNumber), "superseded"); err == nil {
		t.Error("unreachable revoke accepted")
	}
	if _, err := ceremony.FetchCRL(ctx, client, "::bad"); err == nil {
		t.Error("bad CRL URL accepted")
	}
	if _, err := ceremony.FetchCRL(ctx, client, s.Plain.URL+"/healthz"); err == nil {
		t.Error("non-CRL body accepted")
	}
	garbage := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(garbage, []byte("not pem"), 0o600)
	if _, err := ceremony.NewHTTPClient(ceremony.ClientOptions{CAFile: garbage}); err == nil {
		t.Error("garbage CA file accepted")
	}
	// A non-OCSP body from an OCSP URL is rejected.
	if _, err := ceremony.OCSPCheck(ctx, client, s.MTLS.URL+"/.well-known/est/cacerts", dev.Cert, p.Device.Certificate()); err == nil {
		t.Error("non-OCSP response accepted")
	}
}
