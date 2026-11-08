package mgmt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Minimal JWS/JWT support for ES256 service tokens (DESIGN_CONTRACT §7:
// internal calls carry an ES256 JWT with aud=<service>, 5 min lifetime).
// Only ES256 is accepted; "alg" confusion is impossible because the header
// algorithm is checked before any key is consulted.

// Claims are the registered claims the PKI evaluates.
type Claims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
}

// Audience accepts both the string and array forms of "aud".
type Audience []string

// UnmarshalJSON implements json.Unmarshaler.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = list
	return nil
}

// MarshalJSON implements json.Marshaler.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains reports whether aud is listed.
func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

var (
	// ErrInvalidToken is returned for malformed or unverifiable tokens.
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired is returned for expired or not-yet-valid tokens.
	ErrTokenExpired = errors.New("token expired or not yet valid")
	// ErrAudience is returned when aud does not include the expected value.
	ErrAudience = errors.New("token audience mismatch")
)

// MaxTokenLifetime bounds exp - iat (when iat is present) to catch
// misconfigured issuers; the contract specifies 5 minute tokens.
const MaxTokenLifetime = time.Hour

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// VerifyES256 parses token, verifies its ES256 signature with any of keys and
// validates aud/exp/nbf at time now.
func VerifyES256(token string, keys []*ecdsa.PublicKey, audience string, now time.Time) (*Claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected three segments", ErrInvalidToken)
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrInvalidToken)
	}
	var hdr header
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrInvalidToken)
	}
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("%w: alg %q not accepted", ErrInvalidToken, hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("%w: signature encoding", ErrInvalidToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	verified := false
	for _, k := range keys {
		if k != nil && k.Curve == elliptic.P256() && ecdsa.Verify(k, digest[:], r, s) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: claims encoding", ErrInvalidToken)
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims json", ErrInvalidToken)
	}
	unix := now.Unix()
	if claims.ExpiresAt == 0 || claims.ExpiresAt <= unix {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore != 0 && claims.NotBefore > unix+30 {
		return nil, ErrTokenExpired
	}
	if claims.IssuedAt != 0 && time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > MaxTokenLifetime {
		return nil, fmt.Errorf("%w: lifetime exceeds %s", ErrInvalidToken, MaxTokenLifetime)
	}
	if !claims.Audience.Contains(audience) {
		return nil, ErrAudience
	}
	return &claims, nil
}

// SignES256 creates a compact JWT for claims (used by tests and pkictl).
func SignES256(key *ecdsa.PrivateKey, claims Claims) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", errors.New("ES256 requires a P-256 key")
	}
	hdr, err := json.Marshal(header{Alg: "ES256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
