// Package ceremony implements the offline key ceremonies and factory
// operations exposed by pkictl: root creation (optionally protected by a
// Shamir quorum), root recovery, intermediate CA creation, bootstrap and
// server certificate issuance, and the bundle key.
package ceremony

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms/file"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/shamir"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// sharePrefix tags share files so they are not confused with other secrets.
const sharePrefix = "ironmesh-root-share-v1:"

// RootOptions configures InitRoot.
type RootOptions struct {
	Dir string
	// Provider holds the root key. Required unless a quorum is requested, in
	// which case the file backend is used with a random KEK.
	Provider kms.Provider
	// KeyRef is the backend reference for the root key (file path, KMS alias,
	// PKCS#11 label). Defaults to <Dir>/root-ca.key.json for the file backend.
	KeyRef string
	// QuorumShares/QuorumThreshold enable Shamir protection of the root KEK.
	QuorumShares    int
	QuorumThreshold int
	// FileKDF tunes the file backend (tests use fast parameters).
	FileKDF file.KDFParams
	Now     time.Time
}

// RootResult describes the created root.
type RootResult struct {
	Certificate *x509.Certificate
	CertPath    string
	KeyID       string
	KeyRef      string
	SharePaths  []string
}

// InitRoot generates the root key, writes the self-signed certificate and,
// when a quorum is configured, the KEK shares.
func InitRoot(ctx context.Context, opts RootOptions) (*RootResult, error) {
	if opts.Dir == "" {
		return nil, errors.New("ceremony: directory is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	layout := ca.Layout{Dir: opts.Dir}
	if _, err := os.Stat(layout.CertPath(ca.KindRoot)); err == nil {
		return nil, fmt.Errorf("ceremony: %s already exists; refusing to overwrite the root", layout.CertPath(ca.KindRoot))
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	res := &RootResult{CertPath: layout.CertPath(ca.KindRoot)}
	var signer kms.Signer
	switch {
	case opts.QuorumShares > 0 || opts.QuorumThreshold > 0:
		if opts.QuorumThreshold < 2 || opts.QuorumShares < opts.QuorumThreshold || opts.QuorumShares > shamir.MaxShares {
			return nil, fmt.Errorf("ceremony: quorum must satisfy 2 <= threshold <= shares <= %d", shamir.MaxShares)
		}
		kek, err := file.NewKEK()
		if err != nil {
			return nil, err
		}
		prov := &file.Provider{KEK: kek, KDF: opts.FileKDF}
		res.KeyRef = layout.KeyPath(ca.KindRoot)
		if opts.KeyRef != "" {
			res.KeyRef = opts.KeyRef
		}
		signer, err = prov.Generate(ctx, res.KeyRef, kms.AlgorithmP384)
		if err != nil {
			return nil, err
		}
		shares, err := shamir.Split(kek, opts.QuorumShares, opts.QuorumThreshold, nil)
		if err != nil {
			return nil, err
		}
		for i, sh := range shares {
			p := layout.SharePath(i + 1)
			content := fmt.Sprintf("# IronMesh root KEK share %d of %d (threshold %d). Store offline, separately from the others.\n%s%s\n",
				i+1, opts.QuorumShares, opts.QuorumThreshold, sharePrefix, base64.StdEncoding.EncodeToString(sh))
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				return nil, err
			}
			res.SharePaths = append(res.SharePaths, p)
		}
	case opts.Provider != nil:
		res.KeyRef = opts.KeyRef
		if res.KeyRef == "" {
			res.KeyRef = layout.KeyPath(ca.KindRoot)
		}
		var err error
		signer, err = opts.Provider.Generate(ctx, res.KeyRef, kms.AlgorithmP384)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("ceremony: a KMS provider or a quorum configuration is required")
	}
	cert, err := ca.NewRoot(signer, now)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(res.CertPath, ca.EncodeCertPEM(cert), 0o644); err != nil {
		return nil, err
	}
	res.Certificate, res.KeyID = cert, signer.KeyID()
	return res, writeChain(layout)
}

// ReadShare parses a share file written by InitRoot.
func ReadShare(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, sharePrefix) {
			return base64.StdEncoding.DecodeString(strings.TrimPrefix(line, sharePrefix))
		}
	}
	return nil, fmt.Errorf("ceremony: %s does not contain a share", path)
}

// RecoverRoot reconstructs the root KEK from share files and re-wraps the
// root key under passphrase at outPath (so it can be used with the file
// backend without the quorum). It returns the root signer.
func RecoverRoot(ctx context.Context, keyPath string, sharePaths []string, passphrase []byte, outPath string, kdf file.KDFParams) (kms.Signer, error) {
	if len(sharePaths) < 2 {
		return nil, errors.New("ceremony: at least two shares are required")
	}
	var shares [][]byte
	for _, p := range sharePaths {
		s, err := ReadShare(p)
		if err != nil {
			return nil, err
		}
		shares = append(shares, s)
	}
	kek, err := shamir.Combine(shares)
	if err != nil {
		return nil, err
	}
	prov := &file.Provider{KEK: kek}
	key, err := prov.Load(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ceremony: recovered KEK does not open the root key (wrong or insufficient shares?): %w", err)
	}
	if outPath != "" {
		if len(passphrase) == 0 {
			return nil, errors.New("ceremony: a passphrase is required to write the recovered key")
		}
		out := &file.Provider{Passphrase: passphrase, KDF: kdf}
		if err := out.Save(outPath, key); err != nil {
			return nil, err
		}
	}
	return kms.NewLocal("", key), nil
}

// IntermediateOptions configures InitIntermediate.
type IntermediateOptions struct {
	Dir        string
	Kind       ca.Kind
	RootSigner kms.Signer
	Provider   kms.Provider
	KeyRef     string
	Now        time.Time
}

// InitIntermediate creates an intermediate CA key in the provider and signs
// its certificate with the root.
func InitIntermediate(ctx context.Context, opts IntermediateOptions) (*x509.Certificate, error) {
	if opts.Kind == ca.KindRoot {
		return nil, errors.New("ceremony: use InitRoot for the root")
	}
	if opts.RootSigner == nil || opts.Provider == nil {
		return nil, errors.New("ceremony: root signer and KMS provider are required")
	}
	layout := ca.Layout{Dir: opts.Dir}
	rootCert, err := layout.LoadCert(ca.KindRoot)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	root, err := ca.New(ca.KindRoot, rootCert, opts.RootSigner, nil, ca.Options{Clock: func() time.Time { return now }})
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(layout.CertPath(opts.Kind)); err == nil {
		return nil, fmt.Errorf("ceremony: %s already exists; refusing to overwrite", layout.CertPath(opts.Kind))
	}
	keyRef := opts.KeyRef
	if keyRef == "" {
		keyRef = layout.KeyPath(opts.Kind)
	}
	signer, err := opts.Provider.Generate(ctx, keyRef, opts.Kind.Algorithm())
	if err != nil {
		return nil, err
	}
	cert, err := root.IssueIntermediate(opts.Kind, signer.Public())
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(layout.CertPath(opts.Kind), ca.EncodeCertPEM(cert), 0o644); err != nil {
		return nil, err
	}
	return cert, writeChain(layout)
}

// writeChain rewrites chain.pem with every CA certificate present.
func writeChain(layout ca.Layout) error {
	var certs []*x509.Certificate
	for _, kind := range []ca.Kind{ca.KindDevice, ca.KindServices, ca.KindFactory, ca.KindRoot} {
		c, err := layout.LoadCert(kind)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil
	}
	return os.WriteFile(layout.ChainPath(), ca.EncodeChainPEM(certs...), 0o644)
}

// InitBundleKey creates the Ed25519 bundle signing key (file backend) and
// writes its public key as PEM for the firmware build.
func InitBundleKey(ctx context.Context, dir string, passphrase []byte, kdf file.KDFParams) (ed25519.PublicKey, error) {
	layout := ca.Layout{Dir: dir}
	if _, err := os.Stat(layout.BundleKeyPath()); err == nil {
		return nil, fmt.Errorf("ceremony: %s already exists", layout.BundleKeyPath())
	}
	prov := &file.Provider{Passphrase: passphrase, KDF: kdf}
	signer, err := prov.Generate(ctx, layout.BundleKeyPath(), kms.AlgorithmEd25519)
	if err != nil {
		return nil, err
	}
	pub := signer.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(layout.BundlePublicKeyPath(), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return pub, nil
}

// BootstrapOptions configures IssueBootstrap.
type BootstrapOptions struct {
	Dir           string
	FactorySigner kms.Signer
	TenantID      string
	DeviceID      string
	// CSR, when set (PEM or DER), is signed instead of generating a software
	// key: this is the secure-element flow (ATECC608 / TPM generates the key).
	CSR    []byte
	OutDir string
	// CRLDistributionPoint and OCSPServer are embedded in the certificate.
	CRLDistributionPoint string
	OCSPServer           string
	Now                  time.Time
}

// BootstrapResult describes an issued bootstrap certificate.
type BootstrapResult struct {
	Certificate *x509.Certificate
	CertPath    string
	// KeyPath is set only for software devices (PEM PKCS#8 key).
	KeyPath    string
	RecordPath string
	Record     *store.CertificateRecord
}

// IssueBootstrap issues a 10-year bootstrap certificate from the Factory CA.
func IssueBootstrap(_ context.Context, opts BootstrapOptions) (*BootstrapResult, error) {
	if opts.FactorySigner == nil {
		return nil, errors.New("ceremony: factory signer is required")
	}
	if err := ca.ValidateTenantID(opts.TenantID); err != nil {
		return nil, err
	}
	if err := ca.ValidateDeviceID(opts.DeviceID); err != nil {
		return nil, err
	}
	layout := ca.Layout{Dir: opts.Dir}
	factoryCert, err := layout.LoadCert(ca.KindFactory)
	if err != nil {
		return nil, err
	}
	rootCert, err := layout.LoadCert(ca.KindRoot)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	factory, err := ca.New(ca.KindFactory, factoryCert, opts.FactorySigner, []*x509.Certificate{rootCert}, ca.Options{
		CRLDistributionPoint: opts.CRLDistributionPoint, OCSPServer: opts.OCSPServer, Clock: func() time.Time { return now },
	})
	if err != nil {
		return nil, err
	}
	outDir := opts.OutDir
	if outDir == "" {
		outDir = filepath.Join(opts.Dir, "devices")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	res := &BootstrapResult{}
	var pub crypto.PublicKey
	if len(opts.CSR) > 0 {
		csr, err := ca.ParseCSRPEM(opts.CSR)
		if err != nil {
			return nil, err
		}
		if csr.Subject.CommonName != "" && csr.Subject.CommonName != opts.DeviceID {
			return nil, fmt.Errorf("ceremony: CSR CN %q does not match device id %s", csr.Subject.CommonName, opts.DeviceID)
		}
		pub = csr.PublicKey
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = key.Public()
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		res.KeyPath = filepath.Join(outDir, opts.DeviceID+".key.pem")
		if err := os.WriteFile(res.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
	}
	cert, err := factory.IssueBootstrap(ca.DeviceRequest{TenantID: opts.TenantID, DeviceID: opts.DeviceID, PublicKey: pub})
	if err != nil {
		return nil, err
	}
	res.Certificate = cert
	res.CertPath = filepath.Join(outDir, opts.DeviceID+".crt")
	if err := os.WriteFile(res.CertPath, ca.EncodeChainPEM(cert, factoryCert), 0o644); err != nil {
		return nil, err
	}
	res.Record = ca.NewRecord(cert, store.KindBootstrap, "", now)
	res.RecordPath = filepath.Join(outDir, opts.DeviceID+".record.json")
	data, err := json.MarshalIndent(res.Record, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(res.RecordPath, data, 0o644); err != nil {
		return nil, err
	}
	return res, nil
}

// ServerOptions configures IssueServer.
type ServerOptions struct {
	Dir            string
	ServicesSigner kms.Signer
	CN             string
	SANs           []string
	OutDir         string
	Now            time.Time
}

// ServerResult describes an issued server certificate.
type ServerResult struct {
	Certificate *x509.Certificate
	CertPath    string
	KeyPath     string
}

// IssueServer issues a 90-day server certificate from the Services CA with a
// fresh P-256 key.
func IssueServer(_ context.Context, opts ServerOptions) (*ServerResult, error) {
	if opts.ServicesSigner == nil {
		return nil, errors.New("ceremony: services signer is required")
	}
	layout := ca.Layout{Dir: opts.Dir}
	servicesCert, err := layout.LoadCert(ca.KindServices)
	if err != nil {
		return nil, err
	}
	rootCert, err := layout.LoadCert(ca.KindRoot)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	services, err := ca.New(ca.KindServices, servicesCert, opts.ServicesSigner, []*x509.Certificate{rootCert}, ca.Options{Clock: func() time.Time { return now }})
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert, err := services.IssueServer(opts.CN, opts.SANs, key.Public())
	if err != nil {
		return nil, err
	}
	outDir := opts.OutDir
	if outDir == "" {
		outDir = filepath.Join(opts.Dir, "services")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	res := &ServerResult{Certificate: cert, CertPath: filepath.Join(outDir, opts.CN+".crt"), KeyPath: filepath.Join(outDir, opts.CN+".key.pem")}
	if err := os.WriteFile(res.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(res.CertPath, ca.EncodeChainPEM(cert, servicesCert), 0o644); err != nil {
		return nil, err
	}
	return res, nil
}
