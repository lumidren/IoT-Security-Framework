//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

// TestSoftHSM exercises the backend against a real SoftHSM2 token. It is
// skipped unless SOFTHSM2_CONF is set; PKI_PKCS11_MODULE, PKI_PKCS11_TOKEN and
// PKI_PKCS11_PIN select the module, token label and PIN.
func TestSoftHSM(t *testing.T) {
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set; skipping PKCS#11 integration test")
	}
	module := os.Getenv("PKI_PKCS11_MODULE")
	if module == "" {
		module = "/usr/lib/softhsm/libsofthsm2.so"
	}
	pin := os.Getenv("PKI_PKCS11_PIN")
	if pin == "" {
		pin = "1234"
	}
	prov, err := New(Config{ModulePath: module, TokenLabel: os.Getenv("PKI_PKCS11_TOKEN"), PIN: pin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer prov.(*Provider).Close()

	label := fmt.Sprintf("ironmesh-test-%d", time.Now().UnixNano())
	s, err := prov.Generate(context.Background(), label, kms.AlgorithmP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	digest := sha256.Sum256([]byte("hello"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	reopened, err := prov.Open(context.Background(), label)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !reopened.Public().(*ecdsa.PublicKey).Equal(s.Public()) {
		t.Fatal("reopened key differs")
	}
}
