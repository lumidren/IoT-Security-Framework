package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
)

// curveBits returns the field size of an ECDSA public key.
func curveBits(pub crypto.PublicKey) (int, error) {
	ek, ok := pub.(*ecdsa.PublicKey)
	if !ok || ek.Curve == nil {
		return 0, fmt.Errorf("ocsp: responder key must be ECDSA, got %T", pub)
	}
	return ek.Curve.Params().BitSize, nil
}
