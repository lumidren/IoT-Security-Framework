package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// Secure element types (contract §3).
const (
	SeTypeATECC608 = "atecc608"
	SeTypeTPM2     = "tpm2"
	SeTypeOPTEE    = "optee"
	SeTypeSoftware = "software"

	// Assurance levels (§10).
	AssuranceHardware = "hardware"
	AssuranceSoftware = "software"

	// NonceSize is the attestation nonce length in bytes.
	NonceSize = 32
	// MaxFwVersionLen bounds the fw_version string.
	MaxFwVersionLen = 64
	// MaxAttestationSize bounds the encoded COSE message accepted from devices.
	MaxAttestationSize = 64 * 1024
)

// payload is the CBOR map signed by the device.
type payload struct {
	Nonce     []byte          `cbor:"1,keyasint"`
	CSRHash   []byte          `cbor:"2,keyasint"`
	FwHash    []byte          `cbor:"3,keyasint"`
	FwVersion string          `cbor:"4,keyasint"`
	SeType    string          `cbor:"5,keyasint"`
	Evidence  cbor.RawMessage `cbor:"6,keyasint,omitempty"`
}

var (
	// Strict decoding: definite lengths only, no duplicate keys, no unknown
	// fields, so devices cannot smuggle ambiguous encodings past the verifier.
	decMode cbor.DecMode
	// Core deterministic encoding for everything the server signs.
	encMode cbor.EncMode
)

func init() {
	var err error
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxArrayElements:  64,
		MaxMapPairs:       64,
		MaxNestedLevels:   8,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
}

// DecMode returns the strict CBOR decoder shared by the PKI.
func DecMode() cbor.DecMode { return decMode }

// EncMode returns the deterministic CBOR encoder shared by the PKI.
func EncMode() cbor.EncMode { return encMode }

// Statement is a decoded, not yet verified attestation.
type Statement struct {
	msg *cose.Sign1Message
	// KeyID is the protected-header kid (the device cert serial as bstr), if any.
	KeyID []byte
	// Nonce is the 32-byte nonce the device obtained from the server.
	Nonce []byte
	// CSRHash is sha256(csr_der).
	CSRHash []byte
	// FwHash and FwVersion describe the running firmware.
	FwHash    []byte
	FwVersion string
	// SeType is the secure element type.
	SeType string
	// Evidence is the raw CBOR evidence item (nil when absent or null).
	Evidence []byte
}

// Parse decodes a COSE_Sign1 attestation and validates the payload schema.
// It performs no cryptographic checks.
func Parse(raw []byte) (*Statement, error) {
	if len(raw) == 0 {
		return nil, malformed("empty attestation", nil)
	}
	if len(raw) > MaxAttestationSize {
		return nil, malformed("attestation too large", nil)
	}
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(raw); err != nil {
		return nil, malformed("invalid COSE_Sign1", err)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, malformed("missing protected alg header", err)
	}
	if alg != cose.AlgorithmES256 {
		return nil, malformed(fmt.Sprintf("unsupported COSE algorithm %s (ES256 required)", alg), nil)
	}
	if len(msg.Payload) == 0 {
		return nil, malformed("detached payload not supported", nil)
	}
	var p payload
	if err := decMode.Unmarshal(msg.Payload, &p); err != nil {
		return nil, malformed("invalid attestation payload", err)
	}
	st := &Statement{msg: msg, Nonce: p.Nonce, CSRHash: p.CSRHash, FwHash: p.FwHash, FwVersion: p.FwVersion, SeType: p.SeType}
	if len(p.Evidence) > 0 && !bytes.Equal(p.Evidence, []byte{0xf6}) { // 0xf6 = CBOR null
		st.Evidence = []byte(p.Evidence)
	}
	// go-cose has already enforced that kid, when present, is a byte string.
	if kid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID].([]byte); ok {
		st.KeyID = kid
	}
	if err := st.validateSchema(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Statement) validateSchema() error {
	if len(s.Nonce) != NonceSize {
		return malformed(fmt.Sprintf("nonce must be %d bytes", NonceSize), nil)
	}
	if len(s.CSRHash) != sha256.Size {
		return malformed("csr hash must be 32 bytes", nil)
	}
	if len(s.FwHash) != sha256.Size {
		return malformed("fw_hash must be 32 bytes", nil)
	}
	if len(s.FwVersion) > MaxFwVersionLen {
		return malformed("fw_version too long", nil)
	}
	switch s.SeType {
	case SeTypeATECC608, SeTypeOPTEE, SeTypeSoftware:
		if s.Evidence != nil {
			return malformed("evidence must be null for se_type "+s.SeType, nil)
		}
	case SeTypeTPM2:
		if s.Evidence == nil {
			return malformed("tpm2 attestation requires evidence", nil)
		}
	default:
		return malformed(fmt.Sprintf("unknown se_type %q", s.SeType), nil)
	}
	return nil
}

// VerifySignature checks the ES256 signature with the device's current
// identity key (the TLS client certificate public key).
func (s *Statement) VerifySignature(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve != elliptic.P256() {
		return unauthorized("identity key must be ECDSA P-256", nil)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, pub)
	if err != nil {
		return unauthorized("cannot build verifier", err)
	}
	if err := s.msg.Verify(nil, verifier); err != nil {
		return unauthorized("attestation signature invalid", err)
	}
	return nil
}

// VerifyKeyID checks that the kid header, when present, equals the device
// certificate serial (big-endian bytes).
func (s *Statement) VerifyKeyID(serial []byte) error {
	if s.KeyID == nil {
		return nil
	}
	if !bytes.Equal(bytes.TrimLeft(s.KeyID, "\x00"), bytes.TrimLeft(serial, "\x00")) {
		return unauthorized("kid does not match the client certificate serial", nil)
	}
	return nil
}

// VerifyBinding checks that the statement binds the given CSR.
func (s *Statement) VerifyBinding(csrDER []byte) error {
	sum := sha256.Sum256(csrDER)
	if subtle.ConstantTimeCompare(sum[:], s.CSRHash) != 1 {
		return malformed("csr hash does not match the submitted CSR", nil)
	}
	return nil
}

// ErrNoEvidence is returned by TPM verification when evidence is absent.
var ErrNoEvidence = errors.New("no evidence")
