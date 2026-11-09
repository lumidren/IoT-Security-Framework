package hooks

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadCertificates reads every CERTIFICATE block of a PEM bundle (POLICY_DEVICE_CA_FILE,
// POLICY_SERVICES_CA_FILE). An empty path yields no certificates.
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trust bundle: %w", err)
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust bundle %s: %w", path, err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("trust bundle " + path + ": no CERTIFICATE blocks")
	}
	return out, nil
}

// CertPool returns a pool of certs, or nil when there are none.
func CertPool(certs []*x509.Certificate) *x509.CertPool {
	if len(certs) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}
