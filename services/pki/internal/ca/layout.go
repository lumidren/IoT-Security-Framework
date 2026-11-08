package ca

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
)

// Layout describes the on-disk CA directory (PKI_CA_DIR) produced by pkictl:
//
//	root-ca.crt / root-ca.key.json        (key file only with the file KMS)
//	root-share-<n>.txt                    Shamir shares of the root KEK (quorum ceremony)
//	factory-ca.crt / factory-ca.key.json
//	device-ca.crt / device-ca.key.json
//	services-ca.crt / services-ca.key.json
//	bundle.key.json / bundle.pub.pem      Ed25519 bundle signing key
//	chain.pem                             every CA certificate, leaf-most first
type Layout struct {
	Dir string
}

// CertPath returns the certificate path for a CA kind.
func (l Layout) CertPath(kind Kind) string {
	return filepath.Join(l.Dir, string(kind)+"-ca.crt")
}

// KeyPath returns the file-KMS key path for a CA kind.
func (l Layout) KeyPath(kind Kind) string {
	return filepath.Join(l.Dir, string(kind)+"-ca.key.json")
}

// SharePath returns the path of the n-th (1-based) root KEK share.
func (l Layout) SharePath(n int) string {
	return filepath.Join(l.Dir, fmt.Sprintf("root-share-%d.txt", n))
}

// BundleKeyPath returns the bundle signing key path.
func (l Layout) BundleKeyPath() string { return filepath.Join(l.Dir, "bundle.key.json") }

// BundlePublicKeyPath returns the PEM public bundle key path (for firmware).
func (l Layout) BundlePublicKeyPath() string { return filepath.Join(l.Dir, "bundle.pub.pem") }

// ChainPath returns the combined PEM chain path.
func (l Layout) ChainPath() string { return filepath.Join(l.Dir, "chain.pem") }

// LoadCert loads the certificate of a CA kind.
func (l Layout) LoadCert(kind Kind) (*x509.Certificate, error) {
	cert, err := LoadCertPEM(l.CertPath(kind))
	if err != nil {
		return nil, fmt.Errorf("load %s CA certificate: %w", kind, err)
	}
	return cert, nil
}
