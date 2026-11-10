package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// TPM 2.0 constants (TPM 2.0 Library Specification, Part 2: Structures).
const (
	// TPMGeneratedValue is TPM_GENERATED_VALUE, the TPMS_ATTEST magic.
	TPMGeneratedValue uint32 = 0xff544347
	// TPMSTAttestQuote is TPM_ST_ATTEST_QUOTE.
	TPMSTAttestQuote uint16 = 0x8018

	TPMAlgRSA    uint16 = 0x0001
	TPMAlgSHA256 uint16 = 0x000b
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgECDSA  uint16 = 0x0018
	TPMAlgECC    uint16 = 0x0023

	maxTPMField = 1024
	// maxPCRBanks bounds TPML_PCR_SELECTION.count when parsing and marshalling.
	maxPCRBanks = 16
	// pcrSelectSize is the sizeofSelect written for 24 PCRs.
	pcrSelectSize = 3
)

// ClockInfo is TPMS_CLOCK_INFO.
type ClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

// PCRSelection is one TPMS_PCR_SELECTION with the bitmap decoded to indexes.
type PCRSelection struct {
	Hash uint16
	PCRs []int
}

// Quote is a parsed TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE.
type Quote struct {
	QualifiedSigner []byte
	ExtraData       []byte
	ClockInfo       ClockInfo
	FirmwareVersion uint64
	PCRSelections   []PCRSelection
	PCRDigest       []byte
}

type reader struct {
	buf []byte
	off int
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.off+n > len(r.buf) {
		r.err = fmt.Errorf("tpm2: truncated structure at offset %d (need %d bytes)", r.off, n)
		return false
	}
	return true
}

func (r *reader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.buf[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v
}

// sized reads a TPM2B_* (UINT16 size + bytes).
func (r *reader) sized() []byte {
	n := int(r.u16())
	if r.err != nil {
		return nil
	}
	if n > maxTPMField {
		r.err = fmt.Errorf("tpm2: field of %d bytes exceeds limit", n)
		return nil
	}
	if !r.need(n) {
		return nil
	}
	v := append([]byte(nil), r.buf[r.off:r.off+n]...)
	r.off += n
	return v
}

// ParseQuote parses a TPMS_ATTEST and checks that it is a quote.
func ParseQuote(b []byte) (*Quote, error) {
	r := &reader{buf: b}
	magic := r.u32()
	typ := r.u16()
	if r.err != nil {
		return nil, r.err
	}
	if magic != TPMGeneratedValue {
		return nil, fmt.Errorf("tpm2: bad TPMS_ATTEST magic %#x", magic)
	}
	if typ != TPMSTAttestQuote {
		return nil, fmt.Errorf("tpm2: attestation type %#x is not TPM_ST_ATTEST_QUOTE", typ)
	}
	q := &Quote{}
	q.QualifiedSigner = r.sized()
	q.ExtraData = r.sized()
	q.ClockInfo = ClockInfo{Clock: r.u64(), ResetCount: r.u32(), RestartCount: r.u32(), Safe: r.u8() != 0}
	q.FirmwareVersion = r.u64()
	count := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if count == 0 || count > maxPCRBanks {
		return nil, fmt.Errorf("tpm2: invalid PCR selection count %d", count)
	}
	for i := uint32(0); i < count; i++ {
		sel := PCRSelection{Hash: r.u16()}
		size := int(r.u8())
		if r.err != nil {
			return nil, r.err
		}
		if size == 0 || size > 32 || !r.need(size) {
			return nil, fmt.Errorf("tpm2: invalid pcrSelect size %d", size)
		}
		for byteIdx := 0; byteIdx < size; byteIdx++ {
			bits := r.buf[r.off+byteIdx]
			for bit := 0; bit < 8; bit++ {
				if bits&(1<<bit) != 0 {
					sel.PCRs = append(sel.PCRs, byteIdx*8+bit)
				}
			}
		}
		r.off += size
		q.PCRSelections = append(q.PCRSelections, sel)
	}
	q.PCRDigest = r.sized()
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(b) {
		return nil, errors.New("tpm2: trailing bytes after TPMS_ATTEST")
	}
	if len(q.PCRDigest) == 0 {
		return nil, errors.New("tpm2: empty pcrDigest")
	}
	return q, nil
}

// Marshal encodes the quote as TPMS_ATTEST bytes. It is the inverse of
// ParseQuote and is used by tests and tooling to build synthetic quotes.
func (q *Quote) Marshal() ([]byte, error) {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, TPMGeneratedValue)
	out = binary.BigEndian.AppendUint16(out, TPMSTAttestQuote)
	var err error
	if out, err = appendSized(out, q.QualifiedSigner); err != nil {
		return nil, err
	}
	if out, err = appendSized(out, q.ExtraData); err != nil {
		return nil, err
	}
	out = binary.BigEndian.AppendUint64(out, q.ClockInfo.Clock)
	out = binary.BigEndian.AppendUint32(out, q.ClockInfo.ResetCount)
	out = binary.BigEndian.AppendUint32(out, q.ClockInfo.RestartCount)
	if q.ClockInfo.Safe {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = binary.BigEndian.AppendUint64(out, q.FirmwareVersion)
	if len(q.PCRSelections) > maxPCRBanks {
		return nil, fmt.Errorf("tpm2: %d PCR banks exceed limit", len(q.PCRSelections))
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(q.PCRSelections))) // #nosec G115 -- <= maxPCRBanks, checked above
	for _, sel := range q.PCRSelections {
		out = binary.BigEndian.AppendUint16(out, sel.Hash)
		bitmap := make([]byte, pcrSelectSize)
		for _, pcr := range sel.PCRs {
			if pcr < 0 || pcr >= 24 {
				return nil, fmt.Errorf("tpm2: PCR index %d out of range", pcr)
			}
			bitmap[pcr/8] |= 1 << (pcr % 8)
		}
		out = append(out, pcrSelectSize)
		out = append(out, bitmap...)
	}
	return appendSized(out, q.PCRDigest)
}

func appendSized(out, field []byte) ([]byte, error) {
	if len(field) > maxTPMField {
		return nil, fmt.Errorf("tpm2: field of %d bytes exceeds limit", len(field))
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(field))) // #nosec G115 -- <= maxTPMField (1024), checked above
	return append(out, field...), nil
}

// CheckPCRSelection verifies that the quote covers exactly the required PCRs
// in the given hash bank and nothing else.
func (q *Quote) CheckPCRSelection(hash uint16, required []int) error {
	if len(q.PCRSelections) != 1 {
		return fmt.Errorf("tpm2: expected exactly one PCR bank, got %d", len(q.PCRSelections))
	}
	sel := q.PCRSelections[0]
	if sel.Hash != hash {
		return fmt.Errorf("tpm2: PCR bank %#x, want %#x", sel.Hash, hash)
	}
	want := append([]int(nil), required...)
	sort.Ints(want)
	got := append([]int(nil), sel.PCRs...)
	sort.Ints(got)
	if len(got) != len(want) {
		return fmt.Errorf("tpm2: quote covers PCRs %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("tpm2: quote covers PCRs %v, want %v", got, want)
		}
	}
	return nil
}

// Signature is a parsed TPMT_SIGNATURE (ECDSA or RSASSA, SHA-256 only).
type Signature struct {
	SigAlg  uint16
	HashAlg uint16
	// R and S are set for ECDSA.
	R, S []byte
	// RSA holds the PKCS#1 v1.5 signature for RSASSA.
	RSA []byte
}

// ParseSignature parses a TPMT_SIGNATURE.
func ParseSignature(b []byte) (*Signature, error) {
	r := &reader{buf: b}
	s := &Signature{SigAlg: r.u16(), HashAlg: r.u16()}
	if r.err != nil {
		return nil, r.err
	}
	if s.HashAlg != TPMAlgSHA256 {
		return nil, fmt.Errorf("tpm2: unsupported signature hash %#x (SHA-256 required)", s.HashAlg)
	}
	switch s.SigAlg {
	case TPMAlgECDSA:
		s.R = r.sized()
		s.S = r.sized()
	case TPMAlgRSASSA:
		s.RSA = r.sized()
	default:
		return nil, fmt.Errorf("tpm2: unsupported signature scheme %#x", s.SigAlg)
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(b) {
		return nil, errors.New("tpm2: trailing bytes after TPMT_SIGNATURE")
	}
	return s, nil
}

// Marshal encodes the signature as TPMT_SIGNATURE bytes.
func (s *Signature) Marshal() ([]byte, error) {
	var out []byte
	out = binary.BigEndian.AppendUint16(out, s.SigAlg)
	out = binary.BigEndian.AppendUint16(out, s.HashAlg)
	var err error
	switch s.SigAlg {
	case TPMAlgECDSA:
		if out, err = appendSized(out, s.R); err != nil {
			return nil, err
		}
		return appendSized(out, s.S)
	case TPMAlgRSASSA:
		return appendSized(out, s.RSA)
	}
	return nil, fmt.Errorf("tpm2: unsupported signature scheme %#x", s.SigAlg)
}

// VerifyQuoteSignature checks sig over sha256(attest) with the AK public key.
func VerifyQuoteSignature(attest []byte, sig *Signature, pub crypto.PublicKey) error {
	digest := sha256.Sum256(attest)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if sig.SigAlg != TPMAlgECDSA {
			return errors.New("tpm2: ECDSA key but signature scheme is not ECDSA")
		}
		if len(sig.R) == 0 || len(sig.S) == 0 {
			return errors.New("tpm2: empty ECDSA signature component")
		}
		if !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S)) {
			return errors.New("tpm2: ECDSA quote signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if sig.SigAlg != TPMAlgRSASSA {
			return errors.New("tpm2: RSA key but signature scheme is not RSASSA")
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig.RSA); err != nil {
			return fmt.Errorf("tpm2: RSASSA quote signature does not verify: %w", err)
		}
		return nil
	}
	return fmt.Errorf("tpm2: unsupported AK public key type %T", pub)
}

func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
