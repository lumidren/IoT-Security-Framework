package attest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Policy is the resolved per-tenant attestation policy.
type Policy struct {
	// AllowSoftwareKeys permits se_type "software".
	AllowSoftwareKeys bool
	// AllowedPCRDigests lists acceptable TPM2 pcrDigest values (hex, any case).
	AllowedPCRDigests []string
	// AKRoots are the EK/AK CA certificates TPM attestation keys must chain to.
	AKRoots *x509.CertPool
	// RequiredPCRs lists the PCR indexes a quote must cover; defaults to 0,2,4,7.
	RequiredPCRs []int
}

// DefaultRequiredPCRs are the PCRs the contract requires in TPM quotes.
var DefaultRequiredPCRs = []int{0, 2, 4, 7}

// Result is the outcome of a successful verification.
type Result struct {
	SeType    string
	Assurance string
	FwHash    []byte
	FwVersion string
	// TPM is set for se_type tpm2.
	TPM *TPMResult
}

// TPMResult carries the verified quote details.
type TPMResult struct {
	PCRDigest       []byte
	AKCert          *x509.Certificate
	FirmwareVersion uint64
	ResetCount      uint32
}

// AssuranceFor maps a secure element type to its assurance level.
func AssuranceFor(seType string) string {
	if seType == SeTypeSoftware {
		return AssuranceSoftware
	}
	return AssuranceHardware
}

// VerifyEvidence enforces the se_type policy and, for tpm2, verifies the quote.
// Call it after VerifySignature and VerifyBinding.
func (s *Statement) VerifyEvidence(p Policy, now time.Time) (*Result, error) {
	res := &Result{SeType: s.SeType, Assurance: AssuranceFor(s.SeType), FwHash: s.FwHash, FwVersion: s.FwVersion}
	switch s.SeType {
	case SeTypeSoftware:
		if !p.AllowSoftwareKeys {
			return nil, forbidden("tenant policy does not allow software keys", nil)
		}
	case SeTypeATECC608, SeTypeOPTEE:
		// Hardware assurance is established by the secure element's bootstrap
		// key; no additional evidence is defined by the contract.
	case SeTypeTPM2:
		tpm, err := s.verifyTPM(p, now)
		if err != nil {
			return nil, err
		}
		res.TPM = tpm
	default:
		return nil, malformed(fmt.Sprintf("unknown se_type %q", s.SeType), nil)
	}
	return res, nil
}

// tpmEvidence is the CBOR evidence map for se_type tpm2.
type tpmEvidence struct {
	Quote     []byte `cbor:"1,keyasint"`
	Signature []byte `cbor:"2,keyasint"`
	AKCertDER []byte `cbor:"3,keyasint"`
}

func (s *Statement) verifyTPM(p Policy, now time.Time) (*TPMResult, error) {
	if s.Evidence == nil {
		return nil, malformed("tpm2 evidence missing", ErrNoEvidence)
	}
	var ev tpmEvidence
	if err := decMode.Unmarshal(s.Evidence, &ev); err != nil {
		return nil, malformed("invalid tpm2 evidence", err)
	}
	if len(ev.Quote) == 0 || len(ev.Signature) == 0 || len(ev.AKCertDER) == 0 {
		return nil, malformed("tpm2 evidence requires quote, signature and ak_cert_der", nil)
	}

	// 1. The attestation key must be certified by a configured EK/AK CA.
	akCert, err := x509.ParseCertificate(ev.AKCertDER)
	if err != nil {
		return nil, malformed("invalid ak_cert_der", err)
	}
	if p.AKRoots == nil {
		return nil, forbidden("no TPM attestation CA configured for this tenant", nil)
	}
	if _, err := akCert.Verify(x509.VerifyOptions{Roots: p.AKRoots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, forbidden("AK certificate does not chain to a trusted attestation CA", err)
	}

	// 2. Parse the quote and bind it to the nonce.
	quote, err := ParseQuote(ev.Quote)
	if err != nil {
		return nil, malformed("invalid TPMS_ATTEST", err)
	}
	if !constantTimeEqual(quote.ExtraData, s.Nonce) {
		return nil, unauthorized("quote qualifying data does not match the nonce", nil)
	}

	// 3. Verify the quote signature with the AK public key.
	sig, err := ParseSignature(ev.Signature)
	if err != nil {
		return nil, malformed("invalid TPMT_SIGNATURE", err)
	}
	if err := VerifyQuoteSignature(ev.Quote, sig, akCert.PublicKey); err != nil {
		return nil, unauthorized("quote signature invalid", err)
	}

	// 4. The quote must cover exactly the required PCRs in the SHA-256 bank.
	required := p.RequiredPCRs
	if len(required) == 0 {
		required = DefaultRequiredPCRs
	}
	if err := quote.CheckPCRSelection(TPMAlgSHA256, required); err != nil {
		return nil, forbidden("quote PCR selection not acceptable", err)
	}

	// 5. The PCR digest must be on the tenant's allow list.
	digest := hex.EncodeToString(quote.PCRDigest)
	allowed := false
	for _, d := range p.AllowedPCRDigests {
		if strings.EqualFold(strings.TrimSpace(d), digest) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, forbidden("PCR digest is not on the allowed policy list", nil)
	}
	return &TPMResult{PCRDigest: quote.PCRDigest, AKCert: akCert, FirmwareVersion: quote.FirmwareVersion, ResetCount: quote.ClockInfo.ResetCount}, nil
}

// PCRDigest computes the TPM2 pcrDigest for the given PCR values (in
// selection order): SHA-256 over their concatenation. Exposed for tooling
// that derives allow-list entries from golden PCR values.
func PCRDigest(values ...[]byte) []byte {
	h := sha256.New()
	for _, v := range values {
		h.Write(v)
	}
	return h.Sum(nil)
}
