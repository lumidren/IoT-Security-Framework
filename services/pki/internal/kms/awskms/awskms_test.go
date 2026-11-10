package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

// fakeKMS emulates the subset of AWS KMS the provider uses with local keys.
type fakeKMS struct {
	keys       map[string]crypto.Signer
	usage      map[string]types.KeyUsageType
	signErr    error
	badSig     bool
	emptySig   bool
	createErr  error
	noMetadata bool
	lastSign   *awskms.SignInput
}

func newFake() *fakeKMS {
	return &fakeKMS{keys: map[string]crypto.Signer{}, usage: map[string]types.KeyUsageType{}}
}

func (f *fakeKMS) add(id string, k crypto.Signer) {
	f.keys[id] = k
	f.usage[id] = types.KeyUsageTypeSignVerify
}

const fakeARNPrefix = "arn:aws:kms:eu-west-1:123456789012:key/"

func (f *fakeKMS) Sign(_ context.Context, in *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	f.lastSign = in
	if f.signErr != nil {
		return nil, f.signErr
	}
	k, ok := f.keys[strings.TrimPrefix(*in.KeyId, fakeARNPrefix)]
	if !ok {
		return nil, errors.New("NotFoundException")
	}
	if in.MessageType != types.MessageTypeDigest {
		return nil, errors.New("fake only supports DIGEST")
	}
	if f.emptySig {
		return &awskms.SignOutput{}, nil
	}
	ek := k.(*ecdsa.PrivateKey)
	if f.badSig {
		other, _ := ecdsa.GenerateKey(ek.Curve, rand.Reader)
		ek = other
	}
	sig, err := ecdsa.SignASN1(rand.Reader, ek, in.Message)
	if err != nil {
		return nil, err
	}
	return &awskms.SignOutput{KeyId: in.KeyId, Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	id := strings.TrimPrefix(*in.KeyId, fakeARNPrefix)
	k, ok := f.keys[id]
	if !ok {
		return nil, errors.New("NotFoundException")
	}
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return nil, err
	}
	return &awskms.GetPublicKeyOutput{KeyId: aws.String(fakeARNPrefix + id), PublicKey: der, KeyUsage: f.usage[id]}, nil
}

func (f *fakeKMS) CreateKey(_ context.Context, in *awskms.CreateKeyInput, _ ...func(*awskms.Options)) (*awskms.CreateKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.noMetadata {
		return &awskms.CreateKeyOutput{}, nil
	}
	var curve elliptic.Curve
	switch in.KeySpec {
	case types.KeySpecEccNistP256:
		curve = elliptic.P256()
	case types.KeySpecEccNistP384:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported spec %s", in.KeySpec)
	}
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	id := fmt.Sprintf("key-%d", len(f.keys)+1)
	f.add(id, k)
	return &awskms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: aws.String(id), Arn: aws.String(fakeARNPrefix + id), KeySpec: in.KeySpec}}, nil
}

func TestOpenAndSign(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
		alg   kms.Algorithm
		spec  types.SigningAlgorithmSpec
	}{
		{"p256", elliptic.P256(), crypto.SHA256, kms.AlgorithmP256, types.SigningAlgorithmSpecEcdsaSha256},
		{"p384", elliptic.P384(), crypto.SHA384, kms.AlgorithmP384, types.SigningAlgorithmSpecEcdsaSha384},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := newFake()
			k, _ := ecdsa.GenerateKey(c.curve, rand.Reader)
			f.add("k1", k)
			p := &Provider{Client: f}
			s, err := p.Open(context.Background(), "k1")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if s.KeyID() != fakeARNPrefix+"k1" {
				t.Fatalf("KeyID = %q", s.KeyID())
			}
			if !k.PublicKey.Equal(s.Public()) {
				t.Fatal("public key mismatch")
			}
			var digest []byte
			if c.hash == crypto.SHA256 {
				d := sha256.Sum256([]byte("msg"))
				digest = d[:]
			} else {
				d := sha512.Sum384([]byte("msg"))
				digest = d[:]
			}
			sig, err := s.Sign(rand.Reader, digest, c.hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ecdsa.VerifyASN1(&k.PublicKey, digest, sig) {
				t.Fatal("signature invalid")
			}
			if f.lastSign.SigningAlgorithm != c.spec || f.lastSign.MessageType != types.MessageTypeDigest {
				t.Fatalf("unexpected sign input %+v", f.lastSign)
			}
			// Wrong hash / digest length / nil opts rejected.
			if _, err := s.Sign(rand.Reader, digest, crypto.SHA1); err == nil {
				t.Error("expected error for wrong hash")
			}
			if _, err := s.Sign(rand.Reader, digest[:5], c.hash); err == nil {
				t.Error("expected error for short digest")
			}
			if _, err := s.Sign(rand.Reader, digest, nil); err == nil {
				t.Error("expected error for nil opts")
			}
		})
	}
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := &Provider{Client: f}
	if _, err := p.Open(context.Background(), ""); err == nil {
		t.Error("empty key id should fail")
	}
	if _, err := p.Open(context.Background(), "missing"); err == nil {
		t.Error("missing key should fail")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.add("rsa", rsaKey)
	if _, err := p.Open(context.Background(), "rsa"); err == nil {
		t.Error("RSA key should be rejected")
	}
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	f.add("p521", p521)
	if _, err := p.Open(context.Background(), "p521"); err == nil {
		t.Error("P-521 should be rejected")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.add("enc", k)
	f.usage["enc"] = types.KeyUsageTypeEncryptDecrypt
	if _, err := p.Open(context.Background(), "enc"); err == nil {
		t.Error("ENCRYPT_DECRYPT key should be rejected")
	}
}

func TestSignErrors(t *testing.T) {
	t.Parallel()
	f := newFake()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.add("k", k)
	p := &Provider{Client: f}
	s, err := p.Open(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("x"))
	f.signErr = errors.New("throttled")
	if _, err := s.Sign(rand.Reader, d[:], crypto.SHA256); err == nil {
		t.Error("expected KMS error to propagate")
	}
	f.signErr = nil
	f.emptySig = true
	if _, err := s.Sign(rand.Reader, d[:], crypto.SHA256); err == nil {
		t.Error("expected error for empty signature")
	}
	f.emptySig = false
	f.badSig = true
	if _, err := s.Sign(rand.Reader, d[:], crypto.SHA256); err == nil {
		t.Error("expected error for non-verifying signature")
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()
	f := newFake()
	p := &Provider{Client: f}
	s, err := p.Generate(context.Background(), "ironmesh device ca", kms.AlgorithmP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
		t.Fatal("expected ECDSA public key")
	}
	if _, err := p.Generate(context.Background(), "", kms.AlgorithmP384); err != nil {
		t.Fatalf("Generate P-384: %v", err)
	}
	if _, err := p.Generate(context.Background(), "x", kms.AlgorithmEd25519); err == nil {
		t.Error("Ed25519 must be rejected")
	}
	f.createErr = errors.New("denied")
	if _, err := p.Generate(context.Background(), "x", kms.AlgorithmP256); err == nil {
		t.Error("expected CreateKey error")
	}
	f.createErr = nil
	f.noMetadata = true
	if _, err := p.Generate(context.Background(), "x", kms.AlgorithmP256); err == nil {
		t.Error("expected error for missing metadata")
	}
}
