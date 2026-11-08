//go:build !pkcs11

// Package pkcs11 implements the kms.Provider and kms.Signer interfaces on top
// of a PKCS#11 token such as SoftHSM2. This build does not include the cgo
// backend: build with `-tags pkcs11` to enable it. In this configuration New
// always returns kms.ErrUnavailable so callers fail fast with a clear message.
package pkcs11

import (
	"fmt"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

// Config locates the PKCS#11 module and token.
type Config struct {
	// ModulePath is the path to the PKCS#11 shared library (e.g. libsofthsm2.so).
	ModulePath string
	// TokenLabel selects the token; the first token is used when empty.
	TokenLabel string
	// PIN is the user PIN.
	PIN string
}

// New reports that the PKCS#11 backend was compiled out of this binary.
func New(cfg Config) (kms.Provider, error) {
	return nil, fmt.Errorf("pkcs11 backend (module %q): %w; rebuild with -tags pkcs11", cfg.ModulePath, kms.ErrUnavailable)
}
