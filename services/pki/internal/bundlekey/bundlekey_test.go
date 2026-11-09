package bundlekey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSecrets struct {
	out     *secretsmanager.GetSecretValueOutput
	err     error
	gotID   string
	callCnt int
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.callCnt++
	f.gotID = aws.ToString(in.SecretId)
	return f.out, f.err
}

const testARN = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:ironmesh/pki/bundle-AbCdEf"

func seed() []byte { return bytes.Repeat([]byte{0x42}, ed25519.SeedSize) }

func TestLoadSecretString(t *testing.T) {
	t.Parallel()
	want := ed25519.NewKeyFromSeed(seed())
	for name, s := range map[string]string{
		"std":        base64.StdEncoding.EncodeToString(seed()),
		"raw url":    base64.RawURLEncoding.EncodeToString(seed()),
		"whitespace": "  " + base64.StdEncoding.EncodeToString(seed()) + "\n",
	} {
		f := &fakeSecrets{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(s)}}
		key, err := Load(context.Background(), f, testARN)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !key.Equal(want) || f.gotID != testARN || f.callCnt != 1 {
			t.Fatalf("%s: wrong key or request (%s)", name, f.gotID)
		}
		if f.out.SecretString != nil {
			t.Fatalf("%s: secret string reference kept", name)
		}
	}
}

func TestLoadSecretBinaryZeroized(t *testing.T) {
	t.Parallel()
	want := ed25519.NewKeyFromSeed(seed())
	raw := seed()
	f := &fakeSecrets{out: &secretsmanager.GetSecretValueOutput{SecretBinary: raw}}
	key, err := Load(context.Background(), f, testARN)
	if err != nil || !key.Equal(want) {
		t.Fatalf("raw binary: %v", err)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("SecretBinary not zeroized")
	}
	text := []byte(base64.StdEncoding.EncodeToString(seed()))
	f = &fakeSecrets{out: &secretsmanager.GetSecretValueOutput{SecretBinary: text}}
	if key, err := Load(context.Background(), f, testARN); err != nil || !key.Equal(want) {
		t.Fatalf("base64 binary: %v", err)
	}
	if !bytes.Equal(text, make([]byte, len(text))) {
		t.Fatal("base64 SecretBinary not zeroized")
	}
	// The derived key must survive the zeroization of its source.
	if !key.Equal(want) {
		t.Fatal("key aliased the zeroized buffer")
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := Load(ctx, nil, testARN); err == nil {
		t.Error("nil client accepted")
	}
	if _, err := Load(ctx, &fakeSecrets{}, ""); err == nil {
		t.Error("empty ARN accepted")
	}
	if _, err := Load(ctx, &fakeSecrets{err: errors.New("AccessDeniedException")}, testARN); err == nil {
		t.Error("API error ignored")
	}
	if _, err := Load(ctx, &fakeSecrets{}, testARN); err == nil {
		t.Error("nil output accepted")
	}
	if _, err := Load(ctx, &fakeSecrets{out: &secretsmanager.GetSecretValueOutput{}}, testARN); err == nil {
		t.Error("empty secret accepted")
	}
	for name, s := range map[string]string{
		"not base64": "!!!not-base64!!!",
		"short seed": base64.StdEncoding.EncodeToString(seed()[:16]),
		"long seed":  base64.StdEncoding.EncodeToString(append(seed(), 1)),
		"empty":      "",
	} {
		if _, err := Load(ctx, &fakeSecrets{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(s)}}, testARN); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := FromSeed([]byte{1, 2}); err == nil {
		t.Error("short seed accepted by FromSeed")
	}
}

func TestNewSecretsClient(t *testing.T) {
	orig := LoadConfig
	t.Cleanup(func() { LoadConfig = orig })
	LoadConfig = func(context.Context) (aws.Config, error) { return aws.Config{Region: "eu-west-1"}, nil }
	if c, err := NewSecretsClient(context.Background()); err != nil || c == nil {
		t.Fatalf("NewSecretsClient: %v", err)
	}
	LoadConfig = func(context.Context) (aws.Config, error) { return aws.Config{}, errors.New("no config") }
	if _, err := NewSecretsClient(context.Background()); err == nil {
		t.Fatal("config error ignored")
	}
}
