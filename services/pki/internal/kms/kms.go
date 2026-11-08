// Package kms defines the signing-key abstraction used by every CA in the PKI
// service. Private keys never leave their backend: the CA code only sees a
// crypto.Signer plus a stable key identifier.
//
// Backends live in sub-packages: file (development only), awskms (AWS KMS
// asymmetric keys) and pkcs11 (SoftHSM2 / real HSMs, behind the pkcs11 build
// tag).
package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// Signer is a signing key held by a KMS, HSM or encrypted file.
type Signer interface {
	crypto.Signer
	// KeyID returns a stable, backend-specific identifier for the key, such as
	// an AWS KMS ARN, a PKCS#11 label or an SPKI fingerprint for file keys.
	KeyID() string
}

// Algorithm names the asymmetric key algorithms the PKI uses.
type Algorithm string

const (
	// AlgorithmP256 is ECDSA over NIST P-256 (Device CA, Services CA, leaf certs).
	AlgorithmP256 Algorithm = "ecdsa-p256"
	// AlgorithmP384 is ECDSA over NIST P-384 (Root CA, Factory CA).
	AlgorithmP384 Algorithm = "ecdsa-p384"
	// AlgorithmEd25519 is Ed25519 (bundle signing key).
	AlgorithmEd25519 Algorithm = "ed25519"
)

// ErrUnavailable is returned by backends compiled out of the binary.
var ErrUnavailable = errors.New("kms: backend not available in this build")

// Provider creates and opens signers held by one backend. ref is backend
// specific: a file path, an AWS KMS key id/ARN/alias or a PKCS#11 label.
type Provider interface {
	Generate(ctx context.Context, ref string, alg Algorithm) (Signer, error)
	Open(ctx context.Context, ref string) (Signer, error)
}

// ParseAlgorithm parses a user supplied algorithm name.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch Algorithm(s) {
	case AlgorithmP256, AlgorithmP384, AlgorithmEd25519:
		return Algorithm(s), nil
	}
	switch s {
	case "p256", "P-256", "P256":
		return AlgorithmP256, nil
	case "p384", "P-384", "P384":
		return AlgorithmP384, nil
	case "Ed25519", "ED25519":
		return AlgorithmEd25519, nil
	}
	return "", fmt.Errorf("kms: unknown algorithm %q", s)
}

// GenerateKey creates a fresh in-memory private key for alg.
func GenerateKey(alg Algorithm) (crypto.Signer, error) {
	switch alg {
	case AlgorithmP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgorithmP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("kms: unsupported algorithm %q", alg)
}

// AlgorithmOf reports the Algorithm of a public key.
func AlgorithmOf(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgorithmP256, nil
		case elliptic.P384():
			return AlgorithmP384, nil
		}
		return "", fmt.Errorf("kms: unsupported ECDSA curve %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return AlgorithmEd25519, nil
	}
	return "", fmt.Errorf("kms: unsupported public key type %T", pub)
}

// Hash returns the digest algorithm paired with the key algorithm.
func (a Algorithm) Hash() crypto.Hash {
	switch a {
	case AlgorithmP384:
		return crypto.SHA384
	case AlgorithmEd25519:
		return 0 // PureEdDSA signs the message directly
	default:
		return crypto.SHA256
	}
}

// Fingerprint returns "spki-sha256:<hex>" of the DER SubjectPublicKeyInfo.
func Fingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("kms: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "spki-sha256:" + hex.EncodeToString(sum[:]), nil
}

// Local wraps an in-memory crypto.Signer. It is used by tests and for
// ephemeral keys (the delegated OCSP signer) that never need to persist.
type Local struct {
	crypto.Signer
	id string
}

// NewLocal wraps s. If id is empty the SPKI fingerprint is used.
func NewLocal(id string, s crypto.Signer) *Local {
	if id == "" {
		if fp, err := Fingerprint(s.Public()); err == nil {
			id = fp
		}
	}
	return &Local{Signer: s, id: id}
}

// KeyID implements Signer.
func (l *Local) KeyID() string { return l.id }
