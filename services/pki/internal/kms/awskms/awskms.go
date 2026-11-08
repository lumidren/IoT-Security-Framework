// Package awskms implements the kms.Provider and kms.Signer interfaces on top
// of AWS KMS asymmetric signing keys (ECC_NIST_P256 / ECC_NIST_P384).
//
// Signing sends the pre-computed digest (MessageType DIGEST) with
// ECDSA_SHA_256 or ECDSA_SHA_384 and returns the DER encoded ECDSA signature
// KMS produces, which is exactly what crypto/x509 expects from a crypto.Signer.
// Ed25519 keys are not offered by AWS KMS, so the bundle signing key must use
// a different backend.
package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

// Client is the subset of the AWS KMS API used by this package. It is
// satisfied by *kms.Client and by fakes in tests.
type Client interface {
	Sign(ctx context.Context, params *awskms.SignInput, optFns ...func(*awskms.Options)) (*awskms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *awskms.GetPublicKeyInput, optFns ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
	CreateKey(ctx context.Context, params *awskms.CreateKeyInput, optFns ...func(*awskms.Options)) (*awskms.CreateKeyOutput, error)
}

// Provider opens and creates AWS KMS signing keys.
type Provider struct {
	Client Client
}

// NewProvider loads the default AWS configuration (environment, shared
// config, IAM role / web identity) and returns a Provider.
func NewProvider(ctx context.Context) (*Provider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("awskms: load AWS config: %w", err)
	}
	return &Provider{Client: awskms.NewFromConfig(cfg)}, nil
}

// Open fetches the public key for keyID (key id, ARN or alias) and returns a
// Signer bound to it.
func (p *Provider) Open(ctx context.Context, keyID string) (kms.Signer, error) {
	if keyID == "" {
		return nil, errors.New("awskms: key id is required")
	}
	out, err := p.Client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("awskms: GetPublicKey %s: %w", keyID, err)
	}
	if out.KeyUsage != "" && out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("awskms: key %s has usage %s, want SIGN_VERIFY", keyID, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("awskms: key %s is %T, only ECDSA P-256/P-384 keys are supported", keyID, pub)
	}
	alg, err := kms.AlgorithmOf(ecPub)
	if err != nil {
		return nil, err
	}
	id := keyID
	if out.KeyId != nil && *out.KeyId != "" {
		id = *out.KeyId // the ARN
	}
	return &Signer{client: p.Client, keyID: id, pub: ecPub, alg: alg}, nil
}

// Generate creates a new asymmetric SIGN_VERIFY key. ref is used as the key
// description; the returned signer's KeyID is the new key's ARN.
func (p *Provider) Generate(ctx context.Context, ref string, alg kms.Algorithm) (kms.Signer, error) {
	var spec types.KeySpec
	switch alg {
	case kms.AlgorithmP256:
		spec = types.KeySpecEccNistP256
	case kms.AlgorithmP384:
		spec = types.KeySpecEccNistP384
	default:
		return nil, fmt.Errorf("awskms: algorithm %s is not supported by AWS KMS", alg)
	}
	in := &awskms.CreateKeyInput{
		KeySpec:  spec,
		KeyUsage: types.KeyUsageTypeSignVerify,
		Tags:     []types.Tag{{TagKey: aws.String("ironmesh:component"), TagValue: aws.String("pki")}},
	}
	if ref != "" {
		in.Description = aws.String(ref)
	}
	out, err := p.Client.CreateKey(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("awskms: CreateKey: %w", err)
	}
	if out.KeyMetadata == nil || out.KeyMetadata.Arn == nil {
		return nil, errors.New("awskms: CreateKey returned no key metadata")
	}
	return p.Open(ctx, *out.KeyMetadata.Arn)
}

// Signer signs digests with an AWS KMS ECDSA key.
type Signer struct {
	client Client
	keyID  string
	pub    *ecdsa.PublicKey
	alg    kms.Algorithm
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// KeyID implements kms.Signer.
func (s *Signer) KeyID() string { return s.keyID }

// Sign implements crypto.Signer. digest must be the SHA-256 (P-256) or
// SHA-384 (P-384) hash of the message; opts must name that hash.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	want := s.alg.Hash()
	if opts == nil || opts.HashFunc() != want {
		return nil, fmt.Errorf("awskms: key %s requires %s digests", s.keyID, want)
	}
	if len(digest) != want.Size() {
		return nil, fmt.Errorf("awskms: digest length %d does not match %s", len(digest), want)
	}
	var sa types.SigningAlgorithmSpec
	if s.alg == kms.AlgorithmP384 {
		sa = types.SigningAlgorithmSpecEcdsaSha384
	} else {
		sa = types.SigningAlgorithmSpecEcdsaSha256
	}
	out, err := s.client.Sign(context.Background(), &awskms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: sa,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: Sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return nil, errors.New("awskms: Sign returned an empty signature")
	}
	// Defence in depth: never return a signature that does not verify.
	if !ecdsa.VerifyASN1(s.pub, digest, out.Signature) {
		return nil, errors.New("awskms: signature returned by KMS does not verify against the cached public key")
	}
	return out.Signature, nil
}
