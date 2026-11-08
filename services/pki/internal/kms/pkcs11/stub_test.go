//go:build !pkcs11

package pkcs11

import (
	"errors"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

func TestStubReturnsUnavailable(t *testing.T) {
	t.Parallel()
	p, err := New(Config{ModulePath: "/usr/lib/softhsm/libsofthsm2.so", TokenLabel: "ironmesh", PIN: "1234"})
	if p != nil {
		t.Fatal("stub must not return a provider")
	}
	if !errors.Is(err, kms.ErrUnavailable) {
		t.Fatalf("expected kms.ErrUnavailable, got %v", err)
	}
}
