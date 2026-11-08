package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
)

type ecdsaPublicKey = ecdsa.PublicKey

// BuildCSR creates a DER PKCS#10 request with CN=device, OU=tenant.
func BuildCSR(t testing.TB, key *ecdsa.PrivateKey, deviceID, tenantID string) []byte {
	t.Helper()
	return BuildCSRWithSubject(t, key, pkix.Name{CommonName: deviceID, OrganizationalUnit: []string{tenantID}, Organization: []string{ca.Organization}}, nil)
}

// BuildCSRWithSubject creates a DER PKCS#10 request with an explicit subject
// and optional URI SANs.
func BuildCSRWithSubject(t testing.TB, key *ecdsa.PrivateKey, subject pkix.Name, uris []*url.URL) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, URIs: uris}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// GetNonce fetches an attestation nonce for the device.
func GetNonce(t testing.TB, client *http.Client, baseURL string) []byte {
	t.Helper()
	resp, err := client.Get(baseURL + est.BasePath + "/ironmesh/nonce")
	if err != nil {
		t.Fatalf("nonce request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nonce: HTTP %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("nonce json: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(out.Nonce)
	if err != nil {
		t.Fatalf("nonce encoding: %v", err)
	}
	return raw
}

// AttestationOptions describe the COSE_Sign1 attestation to build.
type AttestationOptions struct {
	// Signer is the device's current identity key.
	Signer *ecdsa.PrivateKey
	Nonce  []byte
	// CSRDER is hashed into the statement unless CSRHash is set.
	CSRDER  []byte
	CSRHash []byte
	SeType  string
	// Evidence is CBOR-encoded as-is (nil -> CBOR null).
	Evidence  any
	FwHash    []byte
	FwVersion string
	// KID is the protected kid header (defaults to the cert serial when
	// Serial is set).
	KID []byte
	// Alg overrides the COSE algorithm (default ES256).
	Alg cose.Algorithm
	// Extra adds unknown payload keys (schema violation tests).
	Extra map[int]any
}

// BuildAttestation returns the base64 header value for the attestation.
func BuildAttestation(t testing.TB, opts AttestationOptions) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(BuildAttestationRaw(t, opts))
}

// BuildAttestationRaw returns the tagged COSE_Sign1 bytes.
func BuildAttestationRaw(t testing.TB, opts AttestationOptions) []byte {
	t.Helper()
	csrHash := opts.CSRHash
	if csrHash == nil {
		sum := sha256.Sum256(opts.CSRDER)
		csrHash = sum[:]
	}
	fwHash := opts.FwHash
	if fwHash == nil {
		fwHash = bytes.Repeat([]byte{0xab}, 32)
	}
	fwVersion := opts.FwVersion
	if fwVersion == "" {
		fwVersion = "2.4.1"
	}
	seType := opts.SeType
	if seType == "" {
		seType = attest.SeTypeATECC608
	}
	payload := map[int]any{1: opts.Nonce, 2: csrHash, 3: fwHash, 4: fwVersion, 5: seType, 6: opts.Evidence}
	for k, v := range opts.Extra {
		payload[k] = v
	}
	encoded, err := attest.EncMode().Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	alg := opts.Alg
	if alg == 0 {
		alg = cose.AlgorithmES256
	}
	signer, err := cose.NewSigner(alg, opts.Signer)
	if err != nil {
		t.Fatal(err)
	}
	protected := cose.ProtectedHeader{cose.HeaderLabelAlgorithm: alg}
	if opts.KID != nil {
		protected[cose.HeaderLabelKeyID] = opts.KID
	}
	msg, err := cose.Sign1(rand.Reader, signer, cose.Headers{Protected: protected}, encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TPMQuoteOptions describe a synthetic TPM2 quote.
type TPMQuoteOptions struct {
	AKKey     *ecdsa.PrivateKey
	AKCert    *x509.Certificate
	Nonce     []byte // qualifying data
	PCRDigest []byte
	PCRs      []int // default 0,2,4,7
	// BadSignature corrupts the signature.
	BadSignature bool
}

// TPMEvidence builds the evidence map {1: quote, 2: signature, 3: ak_cert_der}.
func TPMEvidence(t testing.TB, opts TPMQuoteOptions) map[int]any {
	t.Helper()
	pcrs := opts.PCRs
	if pcrs == nil {
		pcrs = []int{0, 2, 4, 7}
	}
	q := &attest.Quote{
		QualifiedSigner: bytes.Repeat([]byte{0x11}, 34),
		ExtraData:       opts.Nonce,
		ClockInfo:       attest.ClockInfo{Clock: 123456, ResetCount: 3, RestartCount: 1, Safe: true},
		FirmwareVersion: 0x20240101,
		PCRSelections:   []attest.PCRSelection{{Hash: attest.TPMAlgSHA256, PCRs: pcrs}},
		PCRDigest:       opts.PCRDigest,
	}
	quoteBytes, err := q.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(quoteBytes)
	r, s, err := ecdsa.Sign(rand.Reader, opts.AKKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := &attest.Signature{SigAlg: attest.TPMAlgECDSA, HashAlg: attest.TPMAlgSHA256, R: r.Bytes(), S: s.Bytes()}
	if opts.BadSignature {
		sig.S[0] ^= 0xff
	}
	sigBytes, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return map[int]any{1: quoteBytes, 2: sigBytes, 3: opts.AKCert.Raw}
}

// GoldenPCRDigest returns a deterministic PCR digest for tests.
func GoldenPCRDigest() []byte {
	return attest.PCRDigest(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{7}, 32))
}

// EnrollResponse is the parsed outcome of simpleenroll/simplereenroll.
type EnrollResponse struct {
	Status int
	Body   string
	Certs  []*x509.Certificate
	Bundle string
	Header http.Header
}

// Enroll POSTs a CSR with the attestation header. op is "simpleenroll" or
// "simplereenroll".
func Enroll(t testing.TB, client *http.Client, baseURL, op string, csrDER []byte, attestation string) *EnrollResponse {
	t.Helper()
	return EnrollRaw(t, client, baseURL, op, est.ContentTypePKCS10, base64.StdEncoding.EncodeToString(csrDER), attestation)
}

// EnrollRaw gives full control over content type and body.
func EnrollRaw(t testing.TB, client *http.Client, baseURL, op, contentType, body, attestation string) *EnrollResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+est.BasePath+"/"+op, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if attestation != "" {
		req.Header.Set(est.HeaderAttestation, attestation)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := &EnrollResponse{Status: resp.StatusCode, Body: string(data), Bundle: resp.Header.Get(est.HeaderBundle), Header: resp.Header}
	if resp.StatusCode == http.StatusOK {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(data)), ""))
		if err != nil {
			t.Fatalf("%s: response base64: %v", op, err)
		}
		if out.Certs, err = est.DecodeCertsOnly(der); err != nil {
			t.Fatalf("%s: response PKCS#7: %v", op, err)
		}
	}
	return out
}

// MustCBOR encodes v with the deterministic encoder.
func MustCBOR(t testing.TB, v any) []byte {
	t.Helper()
	b, err := attest.EncMode().Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RawCBOR wraps pre-encoded CBOR so it can be embedded in a map value.
type RawCBOR = cbor.RawMessage
