package file

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

var testKDF = KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}

func TestGenerateOpenRoundTrip(t *testing.T) {
	t.Parallel()
	for _, alg := range []kms.Algorithm{kms.AlgorithmP256, kms.AlgorithmP384, kms.AlgorithmEd25519} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()
			var logBuf bytes.Buffer
			p := &Provider{Passphrase: []byte("correct horse"), KDF: testKDF, Logger: slog.New(slog.NewTextHandler(&logBuf, nil))}
			path := filepath.Join(t.TempDir(), "sub", "key.json")
			s, err := p.Generate(context.Background(), path, alg)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if !strings.Contains(logBuf.String(), "NOT FOR PRODUCTION") {
				t.Fatal("expected production warning to be logged")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() == 0 {
				t.Fatal("empty key file")
			}
			reopened, err := p.Open(context.Background(), path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if reopened.KeyID() != s.KeyID() || !strings.HasPrefix(s.KeyID(), "spki-sha256:") {
				t.Fatalf("key ids differ: %q vs %q", reopened.KeyID(), s.KeyID())
			}
			if reopened.(*Signer).Algorithm() != alg {
				t.Fatalf("algorithm = %s", reopened.(*Signer).Algorithm())
			}
			// The reopened key signs for the original public key.
			msg := []byte("payload")
			var sig []byte
			if alg == kms.AlgorithmEd25519 {
				sig, err = reopened.Sign(rand.Reader, msg, crypto.Hash(0))
			} else {
				d := sha256.Sum256(msg)
				sig, err = reopened.Sign(rand.Reader, d[:], crypto.SHA256)
			}
			if err != nil {
				t.Fatal(err)
			}
			if pub, ok := s.Public().(*ecdsa.PublicKey); ok {
				d := sha256.Sum256(msg)
				if !ecdsa.VerifyASN1(pub, d[:], sig) {
					t.Fatal("signature does not verify")
				}
			}
		})
	}
}

func TestWrongPassphraseAndKEK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := &Provider{Passphrase: []byte("right"), KDF: testKDF}
	path := filepath.Join(dir, "k.json")
	if _, err := p.Generate(context.Background(), path, kms.AlgorithmP256); err != nil {
		t.Fatal(err)
	}
	bad := &Provider{Passphrase: []byte("wrong"), KDF: testKDF}
	if _, err := bad.Open(context.Background(), path); err == nil {
		t.Fatal("expected decryption failure with wrong passphrase")
	}
	none := &Provider{}
	if _, err := none.Open(context.Background(), path); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("expected ErrNoSecret, got %v", err)
	}
	if err := none.Save(filepath.Join(dir, "x.json"), mustKey(t)); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("expected ErrNoSecret, got %v", err)
	}

	// KEK mode: file records kdf none; opening with passphrase-only provider fails.
	kek, err := NewKEK()
	if err != nil {
		t.Fatal(err)
	}
	kp := &Provider{KEK: kek}
	kpath := filepath.Join(dir, "kek.json")
	if _, err := kp.Generate(context.Background(), kpath, kms.AlgorithmP384); err != nil {
		t.Fatal(err)
	}
	var env envelope
	raw, _ := os.ReadFile(kpath)
	if err := json.Unmarshal(raw, &env); err != nil || env.KDF != kdfNone || env.Salt != "" {
		t.Fatalf("unexpected envelope %+v (%v)", env, err)
	}
	if _, err := p.Open(context.Background(), kpath); err == nil {
		t.Fatal("passphrase provider must not open a KEK file")
	}
	otherKEK, _ := NewKEK()
	if _, err := (&Provider{KEK: otherKEK}).Open(context.Background(), kpath); err == nil {
		t.Fatal("wrong KEK must fail")
	}
	if _, err := (&Provider{KEK: kek}).Open(context.Background(), kpath); err != nil {
		t.Fatalf("right KEK: %v", err)
	}
	if err := (&Provider{KEK: []byte("short")}).Save(filepath.Join(dir, "s.json"), mustKey(t)); err == nil {
		t.Fatal("short KEK must be rejected")
	}
}

func TestCorruptedFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := &Provider{Passphrase: []byte("pw"), KDF: testKDF}
	path := filepath.Join(dir, "k.json")
	if _, err := p.Generate(context.Background(), path, kms.AlgorithmP256); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var good envelope
	if err := json.Unmarshal(raw, &good); err != nil {
		t.Fatal(err)
	}
	mutate := func(name string, f func(e *envelope)) {
		e := good
		f(&e)
		data, _ := json.Marshal(e)
		mp := filepath.Join(dir, name+".json")
		if err := os.WriteFile(mp, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Open(context.Background(), mp); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	mutate("version", func(e *envelope) { e.Version = 9 })
	mutate("kdf", func(e *envelope) { e.KDF = "scrypt" })
	mutate("salt", func(e *envelope) { e.Salt = "!!" })
	mutate("time", func(e *envelope) { e.Time = 0 })
	mutate("nonce", func(e *envelope) { e.Nonce = "AAAA" })
	mutate("nonce-enc", func(e *envelope) { e.Nonce = "!!" })
	mutate("ct-enc", func(e *envelope) { e.Ciphertext = "!!" })
	mutate("ct", func(e *envelope) {
		e.Ciphertext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	})
	mutate("alg-swap", func(e *envelope) { e.Algorithm = "ecdsa-p384" }) // AAD mismatch

	if err := os.WriteFile(filepath.Join(dir, "notjson.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Open(context.Background(), filepath.Join(dir, "notjson.json")); err == nil {
		t.Error("expected parse error")
	}
	if _, err := p.Open(context.Background(), filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected read error")
	}
}

func TestDefaultKDFParams(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	if p.kdfParams() != DefaultKDFParams {
		t.Fatal("zero KDF should fall back to defaults")
	}
	p.KDF = testKDF
	if p.kdfParams() != testKDF {
		t.Fatal("explicit KDF not honoured")
	}
}

func mustKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := kms.GenerateKey(kms.AlgorithmP256)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestGenerateAndSaveErrors(t *testing.T) {
	t.Parallel()
	p := &Provider{Passphrase: []byte("pw"), KDF: testKDF}
	if _, err := p.Generate(context.Background(), filepath.Join(t.TempDir(), "k.json"), kms.Algorithm("rsa")); err == nil {
		t.Error("unsupported algorithm accepted")
	}
	// Parent "directory" is a regular file: MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Save(filepath.Join(blocker, "k.json"), mustKey(t)); err == nil {
		t.Error("save under a file accepted")
	}
	// A KEK file with a wrong-size KEK configured cannot be opened.
	kek, _ := NewKEK()
	path := filepath.Join(t.TempDir(), "kek.json")
	if _, err := (&Provider{KEK: kek}).Generate(context.Background(), path, kms.AlgorithmP256); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Provider{KEK: []byte("short")}).Open(context.Background(), path); err == nil {
		t.Error("short KEK accepted on open")
	}
}
