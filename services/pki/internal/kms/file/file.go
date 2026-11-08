// Package file implements a development-only KMS backend that stores private
// keys in AES-256-GCM encrypted JSON files.
//
// The file key is derived from a passphrase with Argon2id, or supplied
// directly as a 32-byte key encryption key (KEK) - the latter is what the root
// ceremony uses so the KEK can be split into Shamir shares. Keys are decrypted
// into process memory on Open; this backend is NOT suitable for production and
// logs a warning whenever it is used.
package file

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

const (
	formatVersion = 1
	kdfArgon2id   = "argon2id"
	kdfNone       = "none"
	kekSize       = 32
)

// KDFParams tunes Argon2id. The defaults follow the RFC 9106 second
// recommended option (t=3, m=64 MiB, p=4); tests use smaller values.
type KDFParams struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultKDFParams are used when Provider.KDF is zero.
var DefaultKDFParams = KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// Provider opens and generates encrypted key files.
type Provider struct {
	// Passphrase protects key files when KEK is nil.
	Passphrase []byte
	// KEK is a raw 32-byte key encryption key; when set it takes precedence
	// over Passphrase and the file records kdf "none".
	KEK []byte
	// KDF parameters for passphrase derivation.
	KDF KDFParams
	// Logger receives the "not for production" warning. Defaults to slog.Default().
	Logger *slog.Logger

	warned bool
}

// ErrNoSecret is returned when neither a passphrase nor a KEK is configured.
var ErrNoSecret = errors.New("file kms: a passphrase (PKI_FILE_KMS_PASSPHRASE) or KEK is required")

type envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt,omitempty"`
	Time       uint32 `json:"time,omitempty"`
	Memory     uint32 `json:"memory_kib,omitempty"`
	Threads    uint8  `json:"threads,omitempty"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Signer is a file-backed signing key.
type Signer struct {
	crypto.Signer
	id  string
	alg kms.Algorithm
}

// KeyID implements kms.Signer.
func (s *Signer) KeyID() string { return s.id }

// Algorithm reports the key algorithm.
func (s *Signer) Algorithm() kms.Algorithm { return s.alg }

func (p *Provider) warn() {
	if p.warned {
		return
	}
	p.warned = true
	l := p.Logger
	if l == nil {
		l = slog.Default()
	}
	l.Warn("file KMS backend in use: private keys are decrypted into process memory; NOT FOR PRODUCTION")
}

func (p *Provider) kdfParams() KDFParams {
	if p.KDF == (KDFParams{}) {
		return DefaultKDFParams
	}
	return p.KDF
}

// Generate creates a new key of the given algorithm, writes it encrypted to
// path (mode 0600) and returns the signer.
func (p *Provider) Generate(_ context.Context, path string, alg kms.Algorithm) (kms.Signer, error) {
	p.warn()
	key, err := kms.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	if err := p.Save(path, key); err != nil {
		return nil, err
	}
	return newSigner(key)
}

// Save encrypts an existing private key to path.
func (p *Provider) Save(path string, key crypto.Signer) error {
	if len(p.KEK) == 0 && len(p.Passphrase) == 0 {
		return ErrNoSecret
	}
	alg, err := kms.AlgorithmOf(key.Public())
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("file kms: marshal key: %w", err)
	}
	id, err := kms.Fingerprint(key.Public())
	if err != nil {
		return err
	}
	env := envelope{Version: formatVersion, Algorithm: string(alg), KeyID: id}
	var fileKey []byte
	if len(p.KEK) > 0 {
		if len(p.KEK) != kekSize {
			return fmt.Errorf("file kms: KEK must be %d bytes", kekSize)
		}
		env.KDF = kdfNone
		fileKey = p.KEK
	} else {
		salt := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return err
		}
		kp := p.kdfParams()
		env.KDF, env.Salt, env.Time, env.Memory, env.Threads = kdfArgon2id, b64(salt), kp.Time, kp.Memory, kp.Threads
		fileKey = argon2.IDKey(p.Passphrase, salt, kp.Time, kp.Memory, kp.Threads, kekSize)
	}
	aead, err := newAEAD(fileKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	// The algorithm and key id are authenticated as additional data so they
	// cannot be swapped without detection.
	ct := aead.Seal(nil, nonce, pkcs8, []byte(env.Algorithm+"|"+env.KeyID))
	env.Nonce, env.Ciphertext = b64(nonce), b64(ct)

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("file kms: create directory: %w", err)
		}
	}
	return os.WriteFile(path, data, 0o600)
}

// Open decrypts the key file at path.
func (p *Provider) Open(_ context.Context, path string) (kms.Signer, error) {
	p.warn()
	key, err := p.Load(path)
	if err != nil {
		return nil, err
	}
	return newSigner(key)
}

// Load decrypts and returns the private key stored at path.
func (p *Provider) Load(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file kms: read key file: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("file kms: parse key file: %w", err)
	}
	if env.Version != formatVersion {
		return nil, fmt.Errorf("file kms: unsupported key file version %d", env.Version)
	}
	var fileKey []byte
	switch env.KDF {
	case kdfNone:
		if len(p.KEK) != kekSize {
			return nil, errors.New("file kms: key file requires a 32-byte KEK")
		}
		fileKey = p.KEK
	case kdfArgon2id:
		if len(p.Passphrase) == 0 {
			return nil, ErrNoSecret
		}
		salt, err := ub64(env.Salt)
		if err != nil || len(salt) < 8 || env.Time == 0 || env.Memory == 0 || env.Threads == 0 {
			return nil, errors.New("file kms: invalid KDF parameters")
		}
		fileKey = argon2.IDKey(p.Passphrase, salt, env.Time, env.Memory, env.Threads, kekSize)
	default:
		return nil, fmt.Errorf("file kms: unsupported kdf %q", env.KDF)
	}
	aead, err := newAEAD(fileKey)
	if err != nil {
		return nil, err
	}
	nonce, err := ub64(env.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("file kms: invalid nonce")
	}
	ct, err := ub64(env.Ciphertext)
	if err != nil {
		return nil, errors.New("file kms: invalid ciphertext encoding")
	}
	pkcs8, err := aead.Open(nil, nonce, ct, []byte(env.Algorithm+"|"+env.KeyID))
	if err != nil {
		return nil, errors.New("file kms: decryption failed (wrong passphrase/KEK or corrupted file)")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("file kms: parse private key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("file kms: key type %T cannot sign", parsed)
	}
	alg, err := kms.AlgorithmOf(signer.Public())
	if err != nil {
		return nil, err
	}
	if string(alg) != env.Algorithm {
		return nil, errors.New("file kms: key algorithm does not match file header")
	}
	return signer, nil
}

// NewKEK returns a fresh random 32-byte key encryption key.
func NewKEK() ([]byte, error) {
	k := make([]byte, kekSize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

func newSigner(key crypto.Signer) (*Signer, error) {
	alg, err := kms.AlgorithmOf(key.Public())
	if err != nil {
		return nil, err
	}
	id, err := kms.Fingerprint(key.Public())
	if err != nil {
		return nil, err
	}
	return &Signer{Signer: key, id: id, alg: alg}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func b64(b []byte) string           { return base64.StdEncoding.EncodeToString(b) }
func ub64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
