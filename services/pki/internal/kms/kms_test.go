package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	t.Parallel()
	cases := map[string]Algorithm{
		"ecdsa-p256": AlgorithmP256, "p256": AlgorithmP256, "P-256": AlgorithmP256, "P256": AlgorithmP256,
		"ecdsa-p384": AlgorithmP384, "p384": AlgorithmP384, "P-384": AlgorithmP384, "P384": AlgorithmP384,
		"ed25519": AlgorithmEd25519, "Ed25519": AlgorithmEd25519, "ED25519": AlgorithmEd25519,
	}
	for in, want := range cases {
		got, err := ParseAlgorithm(in)
		if err != nil || got != want {
			t.Errorf("ParseAlgorithm(%q) = %q, %v want %q", in, got, err, want)
		}
	}
	if _, err := ParseAlgorithm("rsa"); err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestGenerateKeyAndAlgorithmOf(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmP256, AlgorithmP384, AlgorithmEd25519} {
		key, err := GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		got, err := AlgorithmOf(key.Public())
		if err != nil || got != alg {
			t.Fatalf("AlgorithmOf = %s, %v want %s", got, err, alg)
		}
	}
	if _, err := GenerateKey(Algorithm("rsa")); err == nil {
		t.Error("expected error for unsupported algorithm")
	}
	if _, err := AlgorithmOf("not a key"); err == nil {
		t.Error("expected error for unsupported key type")
	}
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if _, err := AlgorithmOf(p521.Public()); err == nil {
		t.Error("expected error for P-521")
	}
}

func TestHash(t *testing.T) {
	t.Parallel()
	if AlgorithmP256.Hash() != crypto.SHA256 || AlgorithmP384.Hash() != crypto.SHA384 || AlgorithmEd25519.Hash() != 0 {
		t.Fatal("unexpected hash pairing")
	}
}

func TestLocalSignerAndFingerprint(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	l := NewLocal("", key)
	if !strings.HasPrefix(l.KeyID(), "spki-sha256:") {
		t.Fatalf("unexpected key id %q", l.KeyID())
	}
	digest := sha256.Sum256([]byte("hello"))
	sig, err := l.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	if NewLocal("custom", key).KeyID() != "custom" {
		t.Fatal("explicit id not honoured")
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Fingerprint(edPriv.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := Fingerprint("bogus"); err == nil {
		t.Fatal("expected error for bogus key")
	}
}
