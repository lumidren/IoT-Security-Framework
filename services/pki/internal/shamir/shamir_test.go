package shamir

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestFieldArithmetic(t *testing.T) {
	t.Parallel()
	// Known AES field products.
	cases := []struct{ a, b, want byte }{
		{0x00, 0x53, 0x00},
		{0x01, 0x53, 0x53},
		{0x53, 0xca, 0x01}, // 0x53 and 0xca are inverses (FIPS-197 example)
		{0x57, 0x83, 0xc1},
		{0x57, 0x13, 0xfe},
	}
	for _, c := range cases {
		if got := mul(c.a, c.b); got != c.want {
			t.Errorf("mul(%#x,%#x)=%#x want %#x", c.a, c.b, got, c.want)
		}
	}
	for a := 1; a < 256; a++ {
		inv := inverse(byte(a))
		if got := mul(byte(a), inv); got != 1 {
			t.Fatalf("inverse(%#x)=%#x but product is %#x", a, inv, got)
		}
	}
	if inverse(0) != 0 {
		t.Fatalf("inverse(0) should be 0 by convention")
	}
}

func TestSplitCombineRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		secretLen        int
		parts, threshold int
	}{
		{"3of5-32B", 32, 5, 3},
		{"2of2-1B", 1, 2, 2},
		{"2of3-48B", 48, 3, 2},
		{"5of5-16B", 16, 5, 5},
		{"7of10-64B", 64, 10, 7},
		{"254of255", 8, 255, 254},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			secret := make([]byte, c.secretLen)
			if _, err := rand.Read(secret); err != nil {
				t.Fatal(err)
			}
			shares, err := Split(secret, c.parts, c.threshold, nil)
			if err != nil {
				t.Fatalf("Split: %v", err)
			}
			if len(shares) != c.parts {
				t.Fatalf("got %d shares want %d", len(shares), c.parts)
			}
			seenX := map[byte]bool{}
			for _, s := range shares {
				if len(s) != c.secretLen+1 {
					t.Fatalf("share length %d want %d", len(s), c.secretLen+1)
				}
				x := s[len(s)-1]
				if x == 0 || seenX[x] {
					t.Fatalf("bad or duplicate x coordinate %d", x)
				}
				seenX[x] = true
			}
			// Exactly threshold shares (the last ones) reconstruct.
			got, err := Combine(shares[len(shares)-c.threshold:])
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("reconstructed secret mismatch")
			}
			// All shares reconstruct too.
			got, err = Combine(shares)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("Combine(all) = %x, %v", got, err)
			}
			// Fewer than threshold shares do not reconstruct (except the
			// degenerate 2-of-2 case where 1 share is rejected outright).
			if c.threshold > 2 {
				wrong, err := Combine(shares[:c.threshold-1])
				if err != nil {
					t.Fatalf("Combine(threshold-1): %v", err)
				}
				if bytes.Equal(wrong, secret) {
					t.Fatalf("threshold-1 shares must not reconstruct the secret")
				}
			}
		})
	}
}

func TestSplitValidation(t *testing.T) {
	t.Parallel()
	secret := []byte("s3cret")
	cases := []struct {
		name             string
		secret           []byte
		parts, threshold int
	}{
		{"empty secret", nil, 3, 2},
		{"threshold 1", secret, 3, 1},
		{"parts < threshold", secret, 2, 3},
		{"too many parts", secret, 256, 2},
	}
	for _, c := range cases {
		if _, err := Split(c.secret, c.parts, c.threshold, nil); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestCombineValidation(t *testing.T) {
	t.Parallel()
	if _, err := Combine([][]byte{{1, 2}}); !errors.Is(err, ErrTooFewShares) {
		t.Errorf("one share: got %v want ErrTooFewShares", err)
	}
	if _, err := Combine([][]byte{{1}, {2}}); !errors.Is(err, ErrShareLength) {
		t.Errorf("short shares: got %v want ErrShareLength", err)
	}
	if _, err := Combine([][]byte{{1, 2, 3}, {1, 2}}); !errors.Is(err, ErrShareLength) {
		t.Errorf("mismatched lengths: got %v want ErrShareLength", err)
	}
	if _, err := Combine([][]byte{{1, 7}, {2, 7}}); !errors.Is(err, ErrDuplicateShare) {
		t.Errorf("duplicate x: got %v want ErrDuplicateShare", err)
	}
	if _, err := Combine([][]byte{{1, 0}, {2, 7}}); err == nil {
		t.Errorf("x=0 share: expected error")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

func TestSplitRandomnessFailure(t *testing.T) {
	t.Parallel()
	if _, err := Split([]byte{1}, 3, 2, failingReader{}); err == nil {
		t.Fatal("expected error from failing random source")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) || ConstantTimeEqual([]byte("abc"), []byte("abd")) {
		t.Fatal("ConstantTimeEqual misbehaves")
	}
}
