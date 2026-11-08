// Package testutil builds a complete in-memory IronMesh PKI (root, factory,
// device and services CAs, bundle key, test TPM attestation CA, stores,
// registry) and starts the real HTTP handlers behind httptest mTLS servers so
// packages can run end-to-end tests without external dependencies.
package testutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Tenant is the default test tenant.
const Tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"

// Defaults used by the test PKI.
const (
	BrokerHost    = "mqtt.test.ironmesh"
	BrokerPort    = 8883
	PublicBaseURL = "https://pki.test.ironmesh"
)

// PKI is a full in-memory PKI.
type PKI struct {
	Root, Factory, Device, Services *ca.CA
	Store                           *store.Memory
	Registry                        *registry.Memory
	Metrics                         *metrics.Metrics
	Logger                          *slog.Logger
	BundleKey                       ed25519.PrivateKey
	Bundler                         *est.Bundler
	// AKCA is the test TPM endorsement/attestation CA.
	AKCA    *x509.Certificate
	AKCAKey *ecdsa.PrivateKey

	mu     sync.Mutex
	base   time.Time
	offset time.Duration
}

// New builds the PKI. The clock starts at the real time and can be advanced
// with Advance (TLS validity checks use the real clock, so the base is real).
func New(t testing.TB) *PKI {
	t.Helper()
	p := &PKI{
		Store:    store.NewMemory(),
		Registry: registry.NewMemory(),
		Metrics:  metrics.New(),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		base:     time.Now().UTC(),
	}
	opts := ca.Options{CRLDistributionPoint: PublicBaseURL + "/crl/device-ca.crl", OCSPServer: PublicBaseURL + "/ocsp", Clock: p.Clock}

	rootKey := mustSigner(t, kms.AlgorithmP384)
	rootCert, err := ca.NewRoot(rootKey, p.Clock())
	if err != nil {
		t.Fatalf("testutil: NewRoot: %v", err)
	}
	if p.Root, err = ca.New(ca.KindRoot, rootCert, rootKey, nil, opts); err != nil {
		t.Fatalf("testutil: root CA: %v", err)
	}
	mk := func(kind ca.Kind) *ca.CA {
		key := mustSigner(t, kind.Algorithm())
		cert, err := p.Root.IssueIntermediate(kind, key.Public())
		if err != nil {
			t.Fatalf("testutil: issue %s CA: %v", kind, err)
		}
		c, err := ca.New(kind, cert, key, []*x509.Certificate{rootCert}, opts)
		if err != nil {
			t.Fatalf("testutil: %s CA: %v", kind, err)
		}
		return c
	}
	p.Factory, p.Device, p.Services = mk(ca.KindFactory), mk(ca.KindDevice), mk(ca.KindServices)

	_, p.BundleKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pins [][]byte
	for _, c := range []*x509.Certificate{p.Services.Certificate(), rootCert} {
		pin, err := ca.SPKIPin(c.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, pin)
	}
	if p.Bundler, err = est.NewBundler(p.BundleKey, BrokerHost, BrokerPort, pins); err != nil {
		t.Fatalf("testutil: bundler: %v", err)
	}

	p.AKCAKey, p.AKCA = newSelfSignedCA(t, "IronMesh Test TPM AK CA")

	// Default tenant policy: hardware only, with a command key and firmware keys.
	cmdPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fwPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := p.Store.PutTenantPolicy(t.Context(), &store.TenantPolicy{
		TenantID: Tenant, AllowSoftwareKeys: false, TenantCmdPubKey: cmdPub, FwSigningPubKeys: [][]byte{fwPub},
		AKCAPEM: string(ca.EncodeCertPEM(p.AKCA)),
	}); err != nil {
		t.Fatal(err)
	}
	return p
}

// Clock returns the (advanceable) test time.
func (p *PKI) Clock() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.base.Add(p.offset).Add(time.Since(p.base))
}

// Advance moves the test clock forward.
func (p *PKI) Advance(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.offset += d
}

// SetTenantPolicy replaces the policy of a tenant.
func (p *PKI) SetTenantPolicy(t testing.TB, mod func(*store.TenantPolicy)) {
	t.Helper()
	pol, err := p.Store.GetTenantPolicy(t.Context(), Tenant)
	if err != nil {
		pol = &store.TenantPolicy{TenantID: Tenant}
	}
	mod(pol)
	if err := p.Store.PutTenantPolicy(t.Context(), pol); err != nil {
		t.Fatal(err)
	}
}

// CAChain returns root, factory, device and services certificates.
func (p *PKI) CAChain() []*x509.Certificate {
	return []*x509.Certificate{p.Root.Certificate(), p.Factory.Certificate(), p.Device.Certificate(), p.Services.Certificate()}
}

// Device is a test device with its current identity key and certificate.
type Device struct {
	ID     string
	Tenant string
	Key    *ecdsa.PrivateKey
	Cert   *x509.Certificate
}

// NewDeviceID mints a random device id.
func NewDeviceID(t testing.TB) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "dev-" + hex.EncodeToString(b)
}

// NewBootstrapDevice issues a bootstrap certificate (Factory CA), records it
// and registers the device as manufactured.
func (p *PKI) NewBootstrapDevice(t testing.TB, tenant string) *Device {
	t.Helper()
	d := &Device{ID: NewDeviceID(t), Tenant: tenant, Key: P256Key(t)}
	cert, err := p.Factory.IssueBootstrap(ca.DeviceRequest{TenantID: tenant, DeviceID: d.ID, PublicKey: d.Key.Public()})
	if err != nil {
		t.Fatalf("testutil: bootstrap: %v", err)
	}
	d.Cert = cert
	if err := p.Store.PutCertificate(t.Context(), ca.NewRecord(cert, store.KindBootstrap, "", p.Clock())); err != nil {
		t.Fatal(err)
	}
	p.Registry.Put(registry.Device{DeviceID: d.ID, TenantID: tenant, State: registry.StateManufactured, BootstrapSerial: ca.FormatSerial(cert.SerialNumber)})
	return d
}

// NewOperationalDevice issues an operational certificate directly (as if the
// device had enrolled) and registers the device as active.
func (p *PKI) NewOperationalDevice(t testing.TB, tenant string) *Device {
	t.Helper()
	d := &Device{ID: NewDeviceID(t), Tenant: tenant, Key: P256Key(t)}
	cert, err := p.Device.IssueOperational(ca.DeviceRequest{TenantID: tenant, DeviceID: d.ID, PublicKey: d.Key.Public(), Assurance: ca.AssuranceHardware})
	if err != nil {
		t.Fatalf("testutil: operational: %v", err)
	}
	d.Cert = cert
	if err := p.Store.PutCertificate(t.Context(), ca.NewRecord(cert, store.KindOperational, ca.AssuranceHardware, p.Clock())); err != nil {
		t.Fatal(err)
	}
	p.Registry.Put(registry.Device{DeviceID: d.ID, TenantID: tenant, State: registry.StateActive, Assurance: ca.AssuranceHardware})
	return d
}

// NewServiceClient issues a Services CA certificate for an internal service.
func (p *PKI) NewServiceClient(t testing.TB, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := P256Key(t)
	cert, err := p.Services.IssueServer(cn, []string{cn}, key.Public())
	if err != nil {
		t.Fatalf("testutil: service cert: %v", err)
	}
	return cert, key
}

// NewAK issues a TPM attestation key certificate from the test AK CA.
func (p *PKI) NewAK(t testing.TB) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := P256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "tpm-ak", Organization: []string{"Test TPM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.AKCA, key.Public(), p.AKCAKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// P256Key generates an ECDSA P-256 key.
func P256Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustSigner(t testing.TB, alg kms.Algorithm) kms.Signer {
	t.Helper()
	k, err := kms.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return kms.NewLocal("", k)
}

func newSelfSignedCA(t testing.TB, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := P256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}
