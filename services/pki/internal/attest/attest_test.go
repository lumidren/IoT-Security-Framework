package attest_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/testutil"
)

func nonce() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func baseOpts(key *ecdsa.PrivateKey, csr []byte) testutil.AttestationOptions {
	return testutil.AttestationOptions{Signer: key, Nonce: nonce(), CSRDER: csr, SeType: attest.SeTypeATECC608}
}

func TestParseAndVerify(t *testing.T) {
	t.Parallel()
	key := testutil.P256Key(t)
	csr := testutil.BuildCSR(t, testutil.P256Key(t), "dev-8f3a1c2b9d4e5f60", testutil.Tenant)
	opts := baseOpts(key, csr)
	opts.KID = []byte{0, 0, 0xab, 0xcd}
	raw := testutil.BuildAttestationRaw(t, opts)

	st, err := attest.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(st.Nonce, nonce()) || st.SeType != attest.SeTypeATECC608 || st.FwVersion != "2.4.1" || st.Evidence != nil || !bytes.Equal(st.KeyID, opts.KID) {
		t.Fatalf("statement %+v", st)
	}
	if err := st.VerifySignature(&key.PublicKey); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if err := st.VerifyKeyID([]byte{0xab, 0xcd}); err != nil {
		t.Fatalf("VerifyKeyID (leading zeros ignored): %v", err)
	}
	if err := st.VerifyKeyID([]byte{0xab, 0xce}); attest.CodeOf(err) != attest.CodeUnauthorized {
		t.Fatalf("VerifyKeyID mismatch: %v", err)
	}
	if err := st.VerifyBinding(csr); err != nil {
		t.Fatalf("VerifyBinding: %v", err)
	}
	if err := st.VerifyBinding([]byte("other")); attest.CodeOf(err) != attest.CodeMalformed {
		t.Fatalf("VerifyBinding mismatch: %v", err)
	}
	res, err := st.VerifyEvidence(attest.Policy{}, time.Now())
	if err != nil || res.Assurance != attest.AssuranceHardware || res.SeType != attest.SeTypeATECC608 {
		t.Fatalf("VerifyEvidence: %+v %v", res, err)
	}

	other := testutil.P256Key(t)
	if err := st.VerifySignature(&other.PublicKey); attest.CodeOf(err) != attest.CodeUnauthorized {
		t.Fatalf("wrong key: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := st.VerifySignature(&p384.PublicKey); err == nil {
		t.Fatal("P-384 identity key accepted")
	}
	if err := st.VerifySignature(nil); err == nil {
		t.Fatal("nil key accepted")
	}
	// Statement without kid passes VerifyKeyID.
	raw2 := testutil.BuildAttestationRaw(t, baseOpts(key, csr))
	st2, _ := attest.Parse(raw2)
	if st2.KeyID != nil || st2.VerifyKeyID([]byte{1}) != nil {
		t.Fatal("absent kid must be accepted")
	}
}

func TestParseSchemaErrors(t *testing.T) {
	t.Parallel()
	key := testutil.P256Key(t)
	csr := []byte("csr")
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := []struct {
		name string
		raw  func(t *testing.T) []byte
		msg  string
	}{
		{"empty", func(*testing.T) []byte { return nil }, "empty"},
		{"too large", func(*testing.T) []byte { return make([]byte, attest.MaxAttestationSize+1) }, "too large"},
		{"not cose", func(*testing.T) []byte { return []byte{0x01, 0x02} }, "COSE"},
		{"wrong alg", func(t *testing.T) []byte {
			o := baseOpts(p384, csr)
			o.Alg = cose.AlgorithmES384
			return testutil.BuildAttestationRaw(t, o)
		}, "ES256"},
		{"short nonce", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.Nonce = []byte{1, 2}
			return testutil.BuildAttestationRaw(t, o)
		}, "nonce"},
		{"short csr hash", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.CSRHash = []byte{1}
			return testutil.BuildAttestationRaw(t, o)
		}, "csr hash"},
		{"short fw hash", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.FwHash = []byte{1}
			return testutil.BuildAttestationRaw(t, o)
		}, "fw_hash"},
		{"long fw version", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.FwVersion = strings.Repeat("9", attest.MaxFwVersionLen+1)
			return testutil.BuildAttestationRaw(t, o)
		}, "fw_version"},
		{"unknown se_type", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.SeType = "hsm"
			return testutil.BuildAttestationRaw(t, o)
		}, "se_type"},
		{"evidence on atecc608", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.Evidence = map[int]any{1: []byte{1}}
			return testutil.BuildAttestationRaw(t, o)
		}, "evidence must be null"},
		{"tpm2 without evidence", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.SeType = attest.SeTypeTPM2
			return testutil.BuildAttestationRaw(t, o)
		}, "requires evidence"},
		{"unknown payload key", func(t *testing.T) []byte {
			o := baseOpts(key, csr)
			o.Extra = map[int]any{9: "x"}
			return testutil.BuildAttestationRaw(t, o)
		}, "payload"},
		{"kid wrong type", func(t *testing.T) []byte {
			// go-cose refuses to encode a non-bstr kid, so hand-encode the
			// COSE_Sign1 array: protected {1: -7, 4: 42}, unprotected {}, payload, sig.
			protected := testutil.MustCBOR(t, map[int]any{1: -7, 4: 42})
			payload := testutil.MustCBOR(t, map[int]any{1: nonce(), 2: make([]byte, 32), 3: make([]byte, 32), 4: "1", 5: attest.SeTypeATECC608, 6: nil})
			return testutil.MustCBOR(t, cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, payload, make([]byte, 64)}})
		}, "COSE"},
		{"payload not a map", func(t *testing.T) []byte {
			signer, _ := cose.NewSigner(cose.AlgorithmES256, key)
			msg, _ := cose.Sign1(rand.Reader, signer, cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}}, testutil.MustCBOR(t, []int{1, 2}), nil)
			return msg
		}, "payload"},
		{"no alg header", func(t *testing.T) []byte {
			// Hand-build a Sign1 with an empty protected header.
			msg := cose.NewSign1Message()
			msg.Headers.Protected = cose.ProtectedHeader{}
			msg.Payload = testutil.MustCBOR(t, map[int]any{})
			msg.Signature = []byte{1}
			raw, err := msg.MarshalCBOR()
			if err != nil {
				t.Skip("library refuses to encode message without alg")
			}
			return raw
		}, "alg"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := attest.Parse(c.raw(t))
			if err == nil {
				t.Fatal("expected error")
			}
			if attest.CodeOf(err) != attest.CodeMalformed {
				t.Fatalf("code %v", attest.CodeOf(err))
			}
			if !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("error %q does not mention %q", err, c.msg)
			}
		})
	}
}

func TestSoftwarePolicy(t *testing.T) {
	t.Parallel()
	key := testutil.P256Key(t)
	o := baseOpts(key, []byte("csr"))
	o.SeType = attest.SeTypeSoftware
	st, err := attest.Parse(testutil.BuildAttestationRaw(t, o))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyEvidence(attest.Policy{}, time.Now()); attest.CodeOf(err) != attest.CodeForbidden {
		t.Fatalf("software forbidden: %v", err)
	}
	res, err := st.VerifyEvidence(attest.Policy{AllowSoftwareKeys: true}, time.Now())
	if err != nil || res.Assurance != attest.AssuranceSoftware {
		t.Fatalf("software allowed: %+v %v", res, err)
	}
	if attest.AssuranceFor(attest.SeTypeOPTEE) != attest.AssuranceHardware {
		t.Fatal("optee assurance")
	}
}

func TestTPMEvidenceVerification(t *testing.T) {
	t.Parallel()
	p := testutil.New(t)
	akKey, akCert := p.NewAK(t)
	roots := x509.NewCertPool()
	roots.AddCert(p.AKCA)
	golden := testutil.GoldenPCRDigest()
	policy := attest.Policy{AllowedPCRDigests: []string{hex.EncodeToString(golden)}, AKRoots: roots}
	key := testutil.P256Key(t)

	build := func(t *testing.T, ev any) *attest.Statement {
		o := baseOpts(key, []byte("csr"))
		o.SeType = attest.SeTypeTPM2
		o.Evidence = ev
		st, err := attest.Parse(testutil.BuildAttestationRaw(t, o))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	good := testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: nonce(), PCRDigest: golden})
	res, err := build(t, good).VerifyEvidence(policy, time.Now())
	if err != nil {
		t.Fatalf("valid quote: %v", err)
	}
	if res.TPM == nil || !bytes.Equal(res.TPM.PCRDigest, golden) || res.TPM.AKCert == nil || res.TPM.ResetCount != 3 || res.TPM.FirmwareVersion != 0x20240101 {
		t.Fatalf("tpm result %+v", res.TPM)
	}
	// Custom required PCRs.
	custom := testutil.TPMEvidence(t, testutil.TPMQuoteOptions{AKKey: akKey, AKCert: akCert, Nonce: nonce(), PCRDigest: golden, PCRs: []int{0, 7}})
	pol2 := policy
	pol2.RequiredPCRs = []int{7, 0}
	if _, err := build(t, custom).VerifyEvidence(pol2, time.Now()); err != nil {
		t.Fatalf("custom PCRs: %v", err)
	}

	cases := []struct {
		name   string
		ev     any
		policy attest.Policy
		code   attest.Code
	}{
		{"no AK roots", good, attest.Policy{AllowedPCRDigests: policy.AllowedPCRDigests}, attest.CodeForbidden},
		{"bad ak cert der", map[int]any{1: good[1], 2: good[2], 3: []byte{1, 2, 3}}, policy, attest.CodeMalformed},
		{"bad quote", map[int]any{1: []byte{1}, 2: good[2], 3: good[3]}, policy, attest.CodeMalformed},
		{"bad signature encoding", map[int]any{1: good[1], 2: []byte{1}, 3: good[3]}, policy, attest.CodeMalformed},
		{"expired AK", good, attest.Policy{AllowedPCRDigests: policy.AllowedPCRDigests, AKRoots: roots}, attest.CodeForbidden},
		{"digest not allowed", good, attest.Policy{AKRoots: roots}, attest.CodeForbidden},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			now := time.Now()
			if c.name == "expired AK" {
				now = now.Add(48 * time.Hour)
			}
			_, err := build(t, c.ev).VerifyEvidence(c.policy, now)
			if attest.CodeOf(err) != c.code || err == nil {
				t.Fatalf("got %v (code %v) want code %v", err, attest.CodeOf(err), c.code)
			}
		})
	}
}

func TestTPMStructures(t *testing.T) {
	t.Parallel()
	q := &attest.Quote{
		QualifiedSigner: []byte{1, 2, 3}, ExtraData: nonce(),
		ClockInfo:       attest.ClockInfo{Clock: 1, ResetCount: 2, RestartCount: 3, Safe: false},
		FirmwareVersion: 99,
		PCRSelections:   []attest.PCRSelection{{Hash: attest.TPMAlgSHA256, PCRs: []int{0, 2, 4, 7}}},
		PCRDigest:       make([]byte, 32),
	}
	b, err := q.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := attest.ParseQuote(b)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}
	if !bytes.Equal(parsed.ExtraData, nonce()) || parsed.ClockInfo.ResetCount != 2 || parsed.ClockInfo.Safe || parsed.FirmwareVersion != 99 ||
		len(parsed.PCRSelections) != 1 || len(parsed.PCRSelections[0].PCRs) != 4 || parsed.PCRSelections[0].PCRs[3] != 7 {
		t.Fatalf("parsed %+v", parsed)
	}
	if err := parsed.CheckPCRSelection(attest.TPMAlgSHA256, []int{7, 4, 2, 0}); err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckPCRSelection(0x0004, []int{0, 2, 4, 7}); err == nil {
		t.Error("wrong bank accepted")
	}
	if err := parsed.CheckPCRSelection(attest.TPMAlgSHA256, []int{0, 2, 4}); err == nil {
		t.Error("fewer PCRs accepted")
	}
	if err := parsed.CheckPCRSelection(attest.TPMAlgSHA256, []int{0, 2, 4, 8}); err == nil {
		t.Error("different PCRs accepted")
	}
	two := *parsed
	two.PCRSelections = append(two.PCRSelections, attest.PCRSelection{Hash: 0x0004, PCRs: []int{1}})
	if err := two.CheckPCRSelection(attest.TPMAlgSHA256, []int{0, 2, 4, 7}); err == nil {
		t.Error("two banks accepted")
	}

	// Marshal errors.
	bad := *q
	bad.PCRSelections = []attest.PCRSelection{{Hash: attest.TPMAlgSHA256, PCRs: []int{24}}}
	if _, err := bad.Marshal(); err == nil {
		t.Error("PCR 24 accepted")
	}
	bad = *q
	bad.ExtraData = make([]byte, 2000)
	if _, err := bad.Marshal(); err == nil {
		t.Error("oversized field accepted")
	}

	// Parse errors.
	mutations := map[string]func([]byte) []byte{
		"short":         func(b []byte) []byte { return b[:5] },
		"bad magic":     func(b []byte) []byte { c := bytes.Clone(b); c[0] = 0; return c },
		"bad type":      func(b []byte) []byte { c := bytes.Clone(b); c[5] = 0x19; return c },
		"trailing":      func(b []byte) []byte { return append(bytes.Clone(b), 0) },
		"truncated mid": func(b []byte) []byte { return b[:len(b)-10] },
		"zero count": func(b []byte) []byte {
			c := bytes.Clone(b)
			// count is after magic(4)+type(2)+signer(2+3)+extra(2+32)+clock(17)+fw(8)
			off := 4 + 2 + 5 + 34 + 17 + 8
			copy(c[off:off+4], []byte{0, 0, 0, 0})
			return c
		},
		"huge field": func(b []byte) []byte {
			c := bytes.Clone(b)
			c[6], c[7] = 0xff, 0xff // qualifiedSigner size
			return c
		},
	}
	for name, mut := range mutations {
		if _, err := attest.ParseQuote(mut(b)); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}

	// Signatures: ECDSA and RSA paths.
	ecKey := testutil.P256Key(t)
	digest := sha256.Sum256(b)
	r, s, _ := ecdsa.Sign(rand.Reader, ecKey, digest[:])
	ecSig := &attest.Signature{SigAlg: attest.TPMAlgECDSA, HashAlg: attest.TPMAlgSHA256, R: r.Bytes(), S: s.Bytes()}
	ecBytes, err := ecSig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSig, err := attest.ParseSignature(ecBytes)
	if err != nil || parsedSig.SigAlg != attest.TPMAlgECDSA {
		t.Fatalf("ParseSignature: %v", err)
	}
	if err := attest.VerifyQuoteSignature(b, parsedSig, ecKey.Public()); err != nil {
		t.Fatalf("ECDSA verify: %v", err)
	}
	if err := attest.VerifyQuoteSignature(append(bytes.Clone(b), 1), parsedSig, ecKey.Public()); err == nil {
		t.Error("ECDSA verify of modified quote succeeded")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaSigBytes, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	rsaSig := &attest.Signature{SigAlg: attest.TPMAlgRSASSA, HashAlg: attest.TPMAlgSHA256, RSA: rsaSigBytes}
	rsaBytes, err := rsaSig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedRSA, err := attest.ParseSignature(rsaBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.VerifyQuoteSignature(b, parsedRSA, rsaKey.Public()); err != nil {
		t.Fatalf("RSA verify: %v", err)
	}
	if err := attest.VerifyQuoteSignature(b, parsedRSA, ecKey.Public()); err == nil {
		t.Error("RSA sig with EC key accepted")
	}
	if err := attest.VerifyQuoteSignature(b, parsedSig, rsaKey.Public()); err == nil {
		t.Error("EC sig with RSA key accepted")
	}
	if err := attest.VerifyQuoteSignature(b, &attest.Signature{SigAlg: attest.TPMAlgECDSA, HashAlg: attest.TPMAlgSHA256}, ecKey.Public()); err == nil {
		t.Error("empty ECDSA components accepted")
	}
	if err := attest.VerifyQuoteSignature(b, parsedSig, "junk"); err == nil {
		t.Error("junk key accepted")
	}
	tamperedRSA := bytes.Clone(rsaSigBytes)
	tamperedRSA[0] ^= 1
	if err := attest.VerifyQuoteSignature(b, &attest.Signature{SigAlg: attest.TPMAlgRSASSA, HashAlg: attest.TPMAlgSHA256, RSA: tamperedRSA}, rsaKey.Public()); err == nil {
		t.Error("tampered RSA accepted")
	}
	if _, err := (&attest.Signature{SigAlg: 0x0099}).Marshal(); err == nil {
		t.Error("unknown scheme marshalled")
	}
	sigErrs := map[string][]byte{
		"short":           {0x00},
		"wrong hash":      {0x00, 0x18, 0x00, 0x04, 0x00, 0x01, 0xaa, 0x00, 0x01, 0xbb},
		"unknown scheme":  {0x00, 0x99, 0x00, 0x0b},
		"trailing":        append(bytes.Clone(ecBytes), 0),
		"truncated ecdsa": ecBytes[:len(ecBytes)-3],
	}
	for name, in := range sigErrs {
		if _, err := attest.ParseSignature(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if !bytes.Equal(attest.PCRDigest([]byte("a"), []byte("b")), func() []byte { h := sha256.Sum256([]byte("ab")); return h[:] }()) {
		t.Error("PCRDigest")
	}
}

func TestErrorType(t *testing.T) {
	t.Parallel()
	inner := errors.New("boom")
	e := &attest.Error{Code: attest.CodeForbidden, Reason: "policy", Err: inner}
	if !strings.Contains(e.Error(), "forbidden") || !strings.Contains(e.Error(), "boom") || !errors.Is(e, inner) {
		t.Fatalf("error %q", e)
	}
	if (&attest.Error{Code: attest.CodeUnauthorized, Reason: "sig"}).Error() != "attestation unauthorized: sig" {
		t.Fatal("error without cause")
	}
	if attest.CodeOf(inner) != attest.CodeMalformed || attest.Code(42).String() != "code(42)" || attest.CodeMalformed.String() != "malformed" {
		t.Fatal("code helpers")
	}
	if attest.DecMode() == nil || attest.EncMode() == nil {
		t.Fatal("modes")
	}
}
