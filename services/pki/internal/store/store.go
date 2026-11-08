// Package store defines the persistence interface of the PKI service and an
// in-memory implementation. The Postgres implementation lives in the postgres
// sub-package so that its (integration-only) coverage is reported separately.
package store

import (
	"context"
	"errors"
	"time"
)

// SystemTenant is the tenant id recorded for certificates that do not belong
// to a tenant (server certificates, OCSP signers).
const SystemTenant = "00000000-0000-0000-0000-000000000000"

var (
	// ErrNotFound is returned when a record does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrAlreadyExists is returned when inserting a duplicate primary key.
	ErrAlreadyExists = errors.New("store: already exists")
	// ErrAlreadyRevoked is returned when revoking an already revoked serial.
	ErrAlreadyRevoked = errors.New("store: certificate already revoked")
	// ErrNonceExpired is returned by ConsumeNonce for a nonce past its TTL.
	// The nonce is deleted regardless.
	ErrNonceExpired = errors.New("store: nonce expired")
)

// Certificate kinds.
const (
	KindBootstrap    = "bootstrap"
	KindOperational  = "operational"
	KindServer       = "server"
	KindOCSPSigner   = "ocsp-signer"
	KindIntermediate = "intermediate"
)

// CertificateRecord is an issued certificate.
type CertificateRecord struct {
	Serial     string // canonical lower-case hex, see ca.FormatSerial
	DeviceID   string // device id for device certs, CN otherwise
	TenantID   string
	Kind       string
	IssuerCN   string
	NotBefore  time.Time
	NotAfter   time.Time
	SPKISHA256 string // hex SHA-256 of the SubjectPublicKeyInfo
	Assurance  string // "hardware" | "software" | ""
	DER        []byte
	IssuedAt   time.Time
}

// Revocation marks a serial as revoked.
type Revocation struct {
	Serial    string
	DeviceID  string
	TenantID  string
	IssuerCN  string
	NotAfter  time.Time // copied from the certificate so CRLs can drop expired entries
	Reason    int       // RFC 5280 CRLReason
	RevokedAt time.Time
	RevokedBy string
}

// Nonce is a single-use attestation nonce bound to the device that fetched it.
type Nonce struct {
	Value     string // base64url (unpadded) of the 32 random bytes
	DeviceID  string
	TenantID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TenantPolicy holds per-tenant enrollment policy and bundle contents.
type TenantPolicy struct {
	TenantID string
	// AllowSoftwareKeys permits se_type "software" (assurance level software).
	AllowSoftwareKeys bool
	// AllowedPCRDigests lists accepted TPM2 quote pcrDigest values (hex SHA-256).
	AllowedPCRDigests []string
	// AKCAPEM is a PEM bundle of EK/AK CA certificates the tenant's TPM
	// attestation keys must chain to.
	AKCAPEM string
	// TenantCmdPubKey is the tenant's 32-byte Ed25519 command signing key.
	TenantCmdPubKey []byte
	// FwSigningPubKeys are the firmware manifest signing keys.
	FwSigningPubKeys [][]byte
	// BrokerHost / BrokerPort override the service defaults in the bundle.
	BrokerHost string
	BrokerPort int
	UpdatedAt  time.Time
}

// Stats are aggregate certificate counts.
type Stats struct {
	Total   int
	Revoked int
	Expired int
}

// Store is the persistence interface. Implementations must be safe for
// concurrent use.
type Store interface {
	// PutCertificate inserts a certificate; ErrAlreadyExists on duplicate serial.
	PutCertificate(ctx context.Context, rec *CertificateRecord) error
	// GetCertificate returns the certificate with the canonical serial.
	GetCertificate(ctx context.Context, serial string) (*CertificateRecord, error)
	// ListCertificatesByDevice returns all certificates of a device, newest first.
	ListCertificatesByDevice(ctx context.Context, deviceID string) ([]*CertificateRecord, error)
	// CountExpiring counts non-revoked certificates with from < NotAfter <= until.
	CountExpiring(ctx context.Context, from, until time.Time) (int, error)
	// Stats returns aggregate counts as of now.
	Stats(ctx context.Context, now time.Time) (*Stats, error)

	// AddRevocation records a revocation; ErrAlreadyRevoked on duplicate serial.
	AddRevocation(ctx context.Context, rev *Revocation) error
	// GetRevocation returns the revocation for serial or ErrNotFound.
	GetRevocation(ctx context.Context, serial string) (*Revocation, error)
	// ListRevocations returns all revocations.
	ListRevocations(ctx context.Context) ([]*Revocation, error)

	// PutNonce stores a nonce; ErrAlreadyExists on duplicate value.
	PutNonce(ctx context.Context, n *Nonce) error
	// ConsumeNonce atomically deletes and returns the nonce. It returns
	// ErrNotFound for unknown nonces and ErrNonceExpired (after deleting) for
	// nonces whose ExpiresAt is not after now.
	ConsumeNonce(ctx context.Context, value string, now time.Time) (*Nonce, error)
	// DeleteExpiredNonces removes nonces with ExpiresAt <= now.
	DeleteExpiredNonces(ctx context.Context, now time.Time) (int, error)

	// NextCRLNumber atomically increments and returns the CRL number.
	NextCRLNumber(ctx context.Context) (int64, error)

	// GetTenantPolicy returns the tenant policy or ErrNotFound.
	GetTenantPolicy(ctx context.Context, tenantID string) (*TenantPolicy, error)
	// PutTenantPolicy inserts or replaces a tenant policy.
	PutTenantPolicy(ctx context.Context, p *TenantPolicy) error

	// Ping checks connectivity.
	Ping(ctx context.Context) error
	// Close releases resources.
	Close() error
}
