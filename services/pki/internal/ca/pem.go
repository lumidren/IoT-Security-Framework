package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// EncodeCertPEM returns the PEM encoding of one certificate.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// EncodeChainPEM concatenates the PEM encodings of certs.
func EncodeChainPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, EncodeCertPEM(c)...)
	}
	return out
}

// ParseCertsPEM parses every CERTIFICATE block in data.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return out, nil
}

// ParseCertPEM parses exactly one certificate.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertsPEM(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// LoadCertPEM reads and parses the first certificate in a PEM file.
func LoadCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertPEM(data)
}

// LoadCertsPEM reads and parses all certificates in a PEM file.
func LoadCertsPEM(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertsPEM(data)
}

// ParseCSRPEM parses a PEM or DER encoded PKCS#10 request and verifies its
// signature.
func ParseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	return csr, nil
}
