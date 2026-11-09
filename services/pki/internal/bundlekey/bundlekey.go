// Package bundlekey loads the PKI's Ed25519 trust-bundle signing key from
// AWS Secrets Manager (PKI_BUNDLE_KEY_SECRET_ARN). AWS KMS has no Ed25519,
// so the 32-byte seed is stored as a base64 secret string; Secrets Manager
// encrypts it server-side with a customer-managed symmetric KMS key whose
// policy only lets the PKI role decrypt (DESIGN_CONTRACT §3).
//
// The decoded seed is zeroized as soon as the private key has been derived.
// The SecretString itself is an immutable Go string owned by the SDK and
// cannot be wiped; the reference is dropped immediately so it becomes
// garbage. Prefer storing the seed as SecretBinary (raw 32 bytes or base64
// text), which is wiped in place.
package bundlekey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretsClient is the subset of *secretsmanager.Client the loader uses.
type SecretsClient interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// LoadConfig loads the default AWS configuration; a variable for tests.
var LoadConfig = func(ctx context.Context) (aws.Config, error) { return awsconfig.LoadDefaultConfig(ctx) }

// NewSecretsClient returns a Secrets Manager client from the default AWS
// credential chain (environment, IRSA / web identity, ECS, EC2 role).
func NewSecretsClient(ctx context.Context) (SecretsClient, error) {
	cfg, err := LoadConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundlekey: load AWS configuration: %w", err)
	}
	return secretsmanager.NewFromConfig(cfg), nil
}

// Load fetches the secret and returns the Ed25519 private key it holds.
func Load(ctx context.Context, client SecretsClient, secretARN string) (ed25519.PrivateKey, error) {
	if client == nil || secretARN == "" {
		return nil, errors.New("bundlekey: a Secrets Manager client and a secret ARN are required")
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretARN)})
	if err != nil {
		return nil, fmt.Errorf("bundlekey: GetSecretValue %s: %w", secretARN, err)
	}
	if out == nil {
		return nil, errors.New("bundlekey: empty GetSecretValue response")
	}
	switch {
	case out.SecretBinary != nil:
		defer clear(out.SecretBinary)
		if len(out.SecretBinary) == ed25519.SeedSize {
			return FromSeed(out.SecretBinary)
		}
		return ParseSeed(out.SecretBinary)
	case out.SecretString != nil:
		buf := []byte(*out.SecretString)
		out.SecretString = nil
		defer clear(buf)
		return ParseSeed(buf)
	}
	return nil, fmt.Errorf("bundlekey: secret %s has neither a SecretString nor a SecretBinary", secretARN)
}

// ParseSeed decodes a base64 (standard or URL alphabet, padded or not,
// surrounding whitespace ignored) 32-byte Ed25519 seed. The decoded buffer
// is zeroized before returning; the caller owns text.
func ParseSeed(text []byte) (ed25519.PrivateKey, error) {
	text = bytes.TrimSpace(text)
	seed := make([]byte, len(text)) // large enough for every alphabet, padded or not
	defer clear(seed)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		n, err := enc.Decode(seed, text)
		if err != nil {
			continue
		}
		if n != ed25519.SeedSize {
			return nil, fmt.Errorf("bundlekey: seed is %d bytes, want %d", n, ed25519.SeedSize)
		}
		return FromSeed(seed[:n])
	}
	return nil, errors.New("bundlekey: secret is not a base64 Ed25519 seed")
}

// FromSeed derives the private key from a 32-byte seed. It does not modify
// seed; callers zeroize it.
func FromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("bundlekey: seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
