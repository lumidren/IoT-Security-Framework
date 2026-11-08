package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// Signer issues ES256 JWTs. Production tokens come from the IdP / Services CA keys; this type backs
// tests and local tooling (e.g. minting an operator token for the console in compose).
type Signer struct {
	key *ecdsa.PrivateKey
	kid string
}

// NewSigner wraps a P-256 private key.
func NewSigner(key *ecdsa.PrivateKey, kid string) (*Signer, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("jwt signer: a P-256 private key is required")
	}
	return &Signer{key: key, kid: kid}, nil
}

// GenerateSigner creates a fresh P-256 key pair.
func GenerateSigner(kid string) (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewSigner(key, kid)
}

// PublicKeyPEM renders the verification key as a PEM PUBLIC KEY block (POLICY_JWT_PUBLIC_KEY_PEM).
func (s *Signer) PublicKeyPEM() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// Sign produces a compact JWT over claims.
func (s *Signer) Sign(claims map[string]any) (string, error) {
	h := map[string]string{"alg": "ES256", "typ": "JWT"}
	if s.kid != "" {
		h["kid"] = s.kid
	}
	headRaw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	payloadRaw, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt signer: encode claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headRaw) + "." + base64.RawURLEncoding.EncodeToString(payloadRaw)
	digest := sha256.Sum256([]byte(signingInput))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
