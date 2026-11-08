package ca

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// SerialBytes is the size of a certificate serial number (128 bits).
const SerialBytes = 16

// NewSerial returns a random 128-bit, positive serial number.
func NewSerial() (*big.Int, error) {
	return newSerial(rand.Reader)
}

func newSerial(rnd io.Reader) (*big.Int, error) {
	buf := make([]byte, SerialBytes)
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := io.ReadFull(rnd, buf); err != nil {
			return nil, fmt.Errorf("ca: generating serial: %w", err)
		}
		n := new(big.Int).SetBytes(buf)
		// RFC 5280 requires a positive INTEGER; a zero serial is meaningless.
		if n.Sign() > 0 {
			return n, nil
		}
	}
	return nil, errors.New("ca: random source produced only zero serials")
}

// FormatSerial returns the canonical representation of a serial used as the
// store key: lower-case hex, left-padded with zeros to at least 32 digits.
func FormatSerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	s := n.Text(16)
	if len(s) < 2*SerialBytes {
		s = strings.Repeat("0", 2*SerialBytes-len(s)) + s
	}
	return s
}

// ParseSerial accepts hex serials in any common presentation (upper/lower
// case, optional 0x prefix, optional colon separators) and returns the number
// and its canonical form.
func ParseSerial(s string) (*big.Int, string, error) {
	clean := strings.ToLower(strings.TrimSpace(s))
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.ReplaceAll(clean, ":", "")
	if clean == "" || len(clean) > 40 {
		return nil, "", fmt.Errorf("invalid serial %q", s)
	}
	n, ok := new(big.Int).SetString(clean, 16)
	if !ok || n.Sign() <= 0 {
		return nil, "", fmt.Errorf("invalid serial %q", s)
	}
	return n, FormatSerial(n), nil
}
