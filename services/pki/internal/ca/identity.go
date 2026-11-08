package ca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeviceIdentity is the identity carried by a verified device certificate.
// Per the contract, authorization decisions use only these fields, never
// strings in payloads.
type DeviceIdentity struct {
	DeviceID  string
	TenantID  string
	Serial    string // canonical serial
	Bootstrap bool   // issued by the Factory CA (OU bootstrap:<tenant>)
	Assurance string // hardware | software
}

// ParseDeviceIdentity validates the subject and SAN of a device certificate
// against the profile and extracts the identity.
func ParseDeviceIdentity(cert *x509.Certificate) (*DeviceIdentity, error) {
	if cert == nil {
		return nil, errors.New("nil certificate")
	}
	id := &DeviceIdentity{DeviceID: cert.Subject.CommonName, Serial: FormatSerial(cert.SerialNumber), Assurance: AssuranceHardware}
	if err := ValidateDeviceID(id.DeviceID); err != nil {
		return nil, err
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != Organization {
		return nil, fmt.Errorf("subject O must be %q", Organization)
	}
	// DER encodes multi-valued RDNs as a SET OF, which sorts the values, so the
	// OU order is not significant: classify every value instead.
	var bootstrapTenant string
	for _, ou := range cert.Subject.OrganizationalUnit {
		switch {
		case tenantIDRe.MatchString(ou):
			if id.TenantID != "" {
				return nil, errors.New("subject carries more than one tenant OU")
			}
			id.TenantID = ou
		case strings.HasPrefix(ou, ouBootstrapPrefix):
			if bootstrapTenant != "" {
				return nil, errors.New("subject carries more than one bootstrap OU")
			}
			bootstrapTenant = strings.TrimPrefix(ou, ouBootstrapPrefix)
			id.Bootstrap = true
		case ou == ouAssurancePrefix+AssuranceSoftware:
			id.Assurance = AssuranceSoftware
		default:
			return nil, fmt.Errorf("unexpected subject OU %q", ou)
		}
	}
	if id.TenantID == "" {
		return nil, errors.New("subject OU (tenant id) missing or malformed")
	}
	if id.Bootstrap && bootstrapTenant != id.TenantID {
		return nil, fmt.Errorf("bootstrap marker tenant %q does not match tenant OU %s", bootstrapTenant, id.TenantID)
	}
	if len(cert.URIs) != 1 {
		return nil, fmt.Errorf("device certificate must carry exactly one URI SAN, found %d", len(cert.URIs))
	}
	t, d, err := ParseDeviceURN(cert.URIs[0])
	if err != nil {
		return nil, fmt.Errorf("SAN URI: %w", err)
	}
	if t != id.TenantID || d != id.DeviceID {
		return nil, errors.New("SAN URI does not match subject CN/OU")
	}
	if !hasEKU(cert, x509.ExtKeyUsageClientAuth) {
		return nil, errors.New("device certificate lacks EKU clientAuth")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("device certificate lacks KU digitalSignature")
	}
	return id, nil
}

func hasEKU(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, e := range cert.ExtKeyUsage {
		if e == want {
			return true
		}
	}
	return false
}

// VerifyChain verifies that leaf chains to one of roots (optionally through
// intermediates) at time now for the given extended key usage. It returns the
// verified chains.
func VerifyChain(leaf *x509.Certificate, roots, intermediates []*x509.Certificate, now time.Time, eku x509.ExtKeyUsage) ([][]*x509.Certificate, error) {
	if leaf == nil {
		return nil, errors.New("nil leaf certificate")
	}
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	var interPool *x509.CertPool
	if len(intermediates) > 0 {
		interPool = x509.NewCertPool()
		for _, i := range intermediates {
			interPool.AddCert(i)
		}
	}
	return leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{eku},
	})
}

// IssuedBy reports whether leaf was directly signed by issuer.
func IssuedBy(leaf, issuer *x509.Certificate) bool {
	if leaf == nil || issuer == nil {
		return false
	}
	if string(leaf.RawIssuer) != string(issuer.RawSubject) {
		return false
	}
	return leaf.CheckSignatureFrom(issuer) == nil
}
