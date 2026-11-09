// Package ca implements the IronMesh certificate authorities and the exact
// certificate profiles of DESIGN_CONTRACT §2:
//
//	IronMesh Root CA (offline, 20 y, P-384)
//	├── IronMesh Factory CA   (10 y, P-384) -> bootstrap certs (10 y)
//	├── IronMesh Device CA    (5 y, P-256)  -> operational certs (14 d, bounded 7-30 d)
//	└── IronMesh Services CA  (5 y, P-256)  -> server certs (90 d)
//
// A CA is bound to a Kind at construction and refuses to issue profiles that
// do not belong to it (a Device CA cannot mint bootstrap certificates, a
// Services CA cannot sign device certificates, only the Root issues
// intermediates).
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// Kind identifies a CA in the hierarchy.
type Kind string

// CA kinds.
const (
	KindRoot     Kind = "root"
	KindFactory  Kind = "factory"
	KindDevice   Kind = "device"
	KindServices Kind = "services"
)

// Profile constants from the design contract.
const (
	Organization = "IronMesh"
	// ServicesOU is the OU of every Services CA service identity (svc-*):
	// the policy authn hook only accepts service principals whose subject is
	// O=IronMesh, OU=services.
	ServicesOU = "services"

	year = 365 * 24 * time.Hour
	day  = 24 * time.Hour

	RootValidity          = 20 * year
	FactoryValidity       = 10 * year
	DeviceCAValidity      = 5 * year
	ServicesCAValidity    = 5 * year
	BootstrapValidity     = 10 * year
	ServerCertValidity    = 90 * day
	DefaultOperationalTTL = 14 * day
	MinOperationalTTL     = 7 * day
	MaxOperationalTTL     = 30 * day
	DefaultOCSPSignerTTL  = 7 * day
	CRLValidity           = 24 * time.Hour

	// Assurance levels (§10).
	AssuranceHardware = "hardware"
	AssuranceSoftware = "software"

	ouBootstrapPrefix = "bootstrap:"
	ouAssurancePrefix = "assurance:"
	ocspResponderCN   = "IronMesh OCSP Responder"
)

var (
	// ErrTTLOutOfRange is returned when an operational TTL is outside 7-30 days.
	ErrTTLOutOfRange = fmt.Errorf("operational certificate TTL must be between %s and %s", MinOperationalTTL, MaxOperationalTTL)
	// ErrWrongKind is returned when a CA is asked to issue a profile of another CA.
	ErrWrongKind = errors.New("certificate profile not permitted for this CA kind")

	oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
)

type kindProfile struct {
	name     string
	validity time.Duration
	alg      kms.Algorithm
}

var profiles = map[Kind]kindProfile{
	KindRoot:     {"IronMesh Root CA", RootValidity, kms.AlgorithmP384},
	KindFactory:  {"IronMesh Factory CA", FactoryValidity, kms.AlgorithmP384},
	KindDevice:   {"IronMesh Device CA", DeviceCAValidity, kms.AlgorithmP256},
	KindServices: {"IronMesh Services CA", ServicesCAValidity, kms.AlgorithmP256},
}

// ParseKind parses a CA kind name.
func ParseKind(s string) (Kind, error) {
	k := Kind(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := profiles[k]; !ok {
		return "", fmt.Errorf("unknown CA kind %q (want root, factory, device or services)", s)
	}
	return k, nil
}

// CommonName returns the subject CN used for a CA kind.
func (k Kind) CommonName() string { return profiles[k].name }

// Algorithm returns the key algorithm mandated for a CA kind.
func (k Kind) Algorithm() kms.Algorithm { return profiles[k].alg }

// Options configures issuance.
type Options struct {
	// CRLDistributionPoint and OCSPServer URLs are embedded in device certs.
	CRLDistributionPoint string
	OCSPServer           string
	// OperationalTTL is the default operational cert lifetime (14 d). It
	// must lie within [MinOperationalTTL, MaxOperationalTTL].
	OperationalTTL time.Duration
	// Clock supplies the current time (tests); defaults to time.Now.
	Clock func() time.Time
}

// CA is a certificate authority bound to a signing key.
type CA struct {
	kind   Kind
	cert   *x509.Certificate
	signer kms.Signer
	chain  []*x509.Certificate
	opts   Options
}

// New binds a CA certificate to its signer. chain lists the issuers of cert up
// to and including the root (empty for the root itself).
func New(kind Kind, cert *x509.Certificate, signer kms.Signer, chain []*x509.Certificate, opts Options) (*CA, error) {
	if _, ok := profiles[kind]; !ok {
		return nil, fmt.Errorf("ca: unknown kind %q", kind)
	}
	if cert == nil || signer == nil {
		return nil, errors.New("ca: certificate and signer are required")
	}
	if !cert.IsCA {
		return nil, errors.New("ca: certificate is not a CA certificate")
	}
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return nil, errors.New("ca: signer public key does not match the CA certificate")
	}
	alg, err := kms.AlgorithmOf(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if alg != profiles[kind].alg {
		return nil, fmt.Errorf("ca: %s CA must use %s, certificate uses %s", kind, profiles[kind].alg, alg)
	}
	if opts.OperationalTTL == 0 {
		opts.OperationalTTL = DefaultOperationalTTL
	}
	if err := ValidateOperationalTTL(opts.OperationalTTL); err != nil {
		return nil, err
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &CA{kind: kind, cert: cert, signer: signer, chain: append([]*x509.Certificate(nil), chain...), opts: opts}, nil
}

// ValidateOperationalTTL checks the 7-30 day bound.
func ValidateOperationalTTL(ttl time.Duration) error {
	if ttl < MinOperationalTTL || ttl > MaxOperationalTTL {
		return fmt.Errorf("%w (got %s)", ErrTTLOutOfRange, ttl)
	}
	return nil
}

// Kind returns the CA kind.
func (c *CA) Kind() Kind { return c.kind }

// Certificate returns the CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// Signer returns the CA signing key.
func (c *CA) Signer() kms.Signer { return c.signer }

// Chain returns the CA certificate followed by its issuers up to the root.
func (c *CA) Chain() []*x509.Certificate {
	return append([]*x509.Certificate{c.cert}, c.chain...)
}

// OperationalTTL returns the configured default operational lifetime.
func (c *CA) OperationalTTL() time.Duration { return c.opts.OperationalTTL }

func (c *CA) now() time.Time { return c.opts.Clock().UTC().Truncate(time.Second) }

func (c *CA) requireKind(kinds ...Kind) error {
	for _, k := range kinds {
		if c.kind == k {
			return nil
		}
	}
	return fmt.Errorf("%w: %s CA cannot issue this profile", ErrWrongKind, c.kind)
}

func caName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{Organization}}
}

// NewRoot creates the self-signed root certificate for signer (P-384).
func NewRoot(signer kms.Signer, now time.Time) (*x509.Certificate, error) {
	if alg, err := kms.AlgorithmOf(signer.Public()); err != nil || alg != kms.AlgorithmP384 {
		return nil, fmt.Errorf("ca: root key must be ECDSA P-384 (got %s, %v)", alg, err)
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now = now.UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               caName(profiles[KindRoot].name),
		NotBefore:             now,
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("ca: create root certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// IssueIntermediate signs an intermediate CA certificate of the given kind.
// Only the root may call it; the key algorithm must match the kind's profile.
func (c *CA) IssueIntermediate(kind Kind, pub crypto.PublicKey) (*x509.Certificate, error) {
	if err := c.requireKind(KindRoot); err != nil {
		return nil, err
	}
	p, ok := profiles[kind]
	if !ok || kind == KindRoot {
		return nil, fmt.Errorf("ca: cannot issue intermediate of kind %q", kind)
	}
	alg, err := kms.AlgorithmOf(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if alg != p.alg {
		return nil, fmt.Errorf("ca: %s CA key must be %s, got %s", kind, p.alg, alg)
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               caName(p.name),
		NotBefore:             now,
		NotAfter:              now.Add(p.validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	return c.sign(tmpl, pub)
}

// DeviceRequest describes a device certificate to issue.
type DeviceRequest struct {
	TenantID  string
	DeviceID  string
	PublicKey crypto.PublicKey // must be ECDSA P-256
	// Assurance is "hardware" or "software" (operational certs only). Software
	// keys get the OU marker "assurance:software".
	Assurance string
	// TTL overrides the default operational lifetime; must respect the bounds.
	TTL time.Duration
}

func (r *DeviceRequest) validate() error {
	if err := ValidateTenantID(r.TenantID); err != nil {
		return err
	}
	if err := ValidateDeviceID(r.DeviceID); err != nil {
		return err
	}
	pk, ok := r.PublicKey.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return errors.New("device key must be ECDSA P-256")
	}
	return nil
}

func (c *CA) deviceTemplate(req DeviceRequest, ous []string, validity time.Duration) (*x509.Certificate, error) {
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         req.DeviceID,
			OrganizationalUnit: ous,
			Organization:       []string{Organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{DeviceURN(req.TenantID, req.DeviceID)},
		CRLDistributionPoints: nonEmpty(c.opts.CRLDistributionPoint),
		OCSPServer:            nonEmpty(c.opts.OCSPServer),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}, nil
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// IssueBootstrap issues a 10-year bootstrap certificate (Factory CA only).
// OU carries the tenant id plus the marker "bootstrap:<tenant>".
func (c *CA) IssueBootstrap(req DeviceRequest) (*x509.Certificate, error) {
	if err := c.requireKind(KindFactory); err != nil {
		return nil, err
	}
	if err := req.validate(); err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	tmpl, err := c.deviceTemplate(req, []string{req.TenantID, ouBootstrapPrefix + req.TenantID}, BootstrapValidity)
	if err != nil {
		return nil, err
	}
	return c.sign(tmpl, req.PublicKey)
}

// IssueOperational issues an operational device certificate (Device CA only).
func (c *CA) IssueOperational(req DeviceRequest) (*x509.Certificate, error) {
	if err := c.requireKind(KindDevice); err != nil {
		return nil, err
	}
	if err := req.validate(); err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = c.opts.OperationalTTL
	}
	if err := ValidateOperationalTTL(ttl); err != nil {
		return nil, err
	}
	ous := []string{req.TenantID}
	switch req.Assurance {
	case AssuranceHardware, "":
	case AssuranceSoftware:
		ous = append(ous, ouAssurancePrefix+AssuranceSoftware)
	default:
		return nil, fmt.Errorf("ca: unknown assurance level %q", req.Assurance)
	}
	tmpl, err := c.deviceTemplate(req, ous, ttl)
	if err != nil {
		return nil, err
	}
	return c.sign(tmpl, req.PublicKey)
}

// IssueServer issues a 90-day TLS certificate for a service (Services CA
// only). SANs may be DNS names or IP addresses; the certificate carries both
// serverAuth and clientAuth so services can use it for mTLS in either role.
// The subject is CN=<cn>, O=IronMesh, OU=services.
func (c *CA) IssueServer(cn string, sans []string, pub crypto.PublicKey) (*x509.Certificate, error) {
	if err := c.requireKind(KindServices); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cn) == "" {
		return nil, errors.New("ca: server certificate CN is required")
	}
	if _, err := kms.AlgorithmOf(pub); err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{Organization}, OrganizationalUnit: []string{ServicesOU}},
		NotBefore:             now,
		NotAfter:              now.Add(ServerCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, san)
		}
	}
	return c.sign(tmpl, pub)
}

// IssueOCSPSigner issues a delegated OCSP responder certificate (Device CA
// only) with EKU OCSPSigning and the id-pkix-ocsp-nocheck extension.
func (c *CA) IssueOCSPSigner(pub crypto.PublicKey, validity time.Duration) (*x509.Certificate, error) {
	if err := c.requireKind(KindDevice); err != nil {
		return nil, err
	}
	if validity <= 0 {
		validity = DefaultOCSPSignerTTL
	}
	if _, err := kms.AlgorithmOf(pub); err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ocspResponderCN, Organization: []string{Organization}},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidOCSPNoCheck, Value: asn1.NullBytes}},
	}
	return c.sign(tmpl, pub)
}

func (c *CA) sign(tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca: sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse issued certificate: %w", err)
	}
	return cert, nil
}

// CreateCRL signs a CRL with the given number and entries (Device CA only).
// thisUpdate is now and nextUpdate is now + 24 h.
func (c *CA) CreateCRL(number int64, now time.Time, entries []x509.RevocationListEntry) ([]byte, error) {
	if err := c.requireKind(KindDevice); err != nil {
		return nil, err
	}
	if number <= 0 {
		return nil, errors.New("ca: CRL number must be positive")
	}
	now = now.UTC().Truncate(time.Second)
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(CRLValidity),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca: create CRL: %w", err)
	}
	return der, nil
}

// SPKISHA256 returns the hex SHA-256 of the certificate's SubjectPublicKeyInfo.
func SPKISHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// SPKIPin returns the raw SHA-256 of a public key's SubjectPublicKeyInfo as
// used for bundle ca_pins.
func SPKIPin(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

// NewRecord builds the store record for an issued certificate.
func NewRecord(cert *x509.Certificate, kind, assurance string, issuedAt time.Time) *store.CertificateRecord {
	rec := &store.CertificateRecord{
		Serial:     FormatSerial(cert.SerialNumber),
		DeviceID:   cert.Subject.CommonName,
		TenantID:   store.SystemTenant,
		Kind:       kind,
		IssuerCN:   cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		SPKISHA256: SPKISHA256(cert),
		Assurance:  assurance,
		DER:        cert.Raw,
		IssuedAt:   issuedAt.UTC(),
	}
	if id, err := ParseDeviceIdentity(cert); err == nil {
		rec.TenantID = id.TenantID
		rec.DeviceID = id.DeviceID
	}
	return rec
}
