package attest_test

// Cross-implementation check against the normative wire-format vector produced by the Python
// reference (libs/python/ironmesh-wire): device/common/vectors/attestation_software.json
// (WIRE_FORMAT.md §4 and Appendix B.3).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
)

// vectorPath is relative to this package directory (services/pki/internal/attest).
var vectorPath = filepath.Join("..", "..", "..", "..", "device", "common", "vectors", "attestation_software.json")

type attestationVector struct {
	DeviceKey struct {
		PublicPEM string `json:"public_pem"`
	} `json:"device_key"`
	KidHex     string `json:"kid_hex"`
	Now        int64  `json:"now"`
	NonceHex   string `json:"nonce_hex"`
	CSRDERHex  string `json:"csr_der_hex"`
	CSRHashHex string `json:"csr_hash_hex"`
	Message    struct {
		Seq  uint64 `json:"seq"`
		Ts   uint64 `json:"ts"`
		Type int    `json:"type"`
		Body struct {
			NonceHex  string `json:"nonce_hex"`
			FwHashHex string `json:"fw_hash_hex"`
			FwVersion string `json:"fw_version"`
			SeType    string `json:"se_type"`
		} `json:"body"`
		WireHex string `json:"wire_hex"`
	} `json:"message"`
	Negative []struct {
		Name             string   `json:"name"`
		ExpectedNonceHex string   `json:"expected_nonce_hex"`
		CSRDERHex        string   `json:"csr_der_hex"`
		AllowedSeTypes   []string `json:"allowed_se_types"`
		Error            string   `json:"error"`
	} `json:"negative"`
}

func loadVector(t *testing.T) *attestationVector {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("vector %s not present in this checkout", vectorPath)
	}
	if err != nil {
		t.Fatal(err)
	}
	var v attestationVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return &v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func vectorKey(t *testing.T, v *attestationVector) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(v.DeviceKey.PublicPEM))
	if block == nil {
		t.Fatal("vector public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub.(*ecdsa.PublicKey)
}

func TestAttestationSoftwareVector(t *testing.T) {
	t.Parallel()
	v := loadVector(t)
	wire := mustHex(t, v.Message.WireHex)
	now := time.Unix(v.Now, 0)

	st, err := attest.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if st.Seq != v.Message.Seq || st.Ts != v.Message.Ts || v.Message.Type != attest.MessageTypeAttestation {
		t.Fatalf("envelope seq=%d ts=%d", st.Seq, st.Ts)
	}
	if err := st.VerifySignature(vectorKey(t, v)); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if err := st.VerifyTimestamp(now); err != nil {
		t.Fatalf("VerifyTimestamp: %v", err)
	}
	if err := st.VerifyKeyID(mustHex(t, v.KidHex)); err != nil {
		t.Fatalf("VerifyKeyID: %v", err)
	}
	if !bytes.Equal(st.Nonce, mustHex(t, v.NonceHex)) || !bytes.Equal(st.Nonce, mustHex(t, v.Message.Body.NonceHex)) {
		t.Fatal("nonce differs from the vector")
	}
	if !bytes.Equal(st.CSRHash, mustHex(t, v.CSRHashHex)) {
		t.Fatal("csr hash differs from the vector")
	}
	if err := st.VerifyBinding(mustHex(t, v.CSRDERHex)); err != nil {
		t.Fatalf("VerifyBinding: %v", err)
	}
	if !bytes.Equal(st.FwHash, mustHex(t, v.Message.Body.FwHashHex)) || st.FwVersion != v.Message.Body.FwVersion || st.SeType != v.Message.Body.SeType || st.Evidence != nil {
		t.Fatalf("body %+v", st)
	}
	res, err := st.VerifyEvidence(attest.Policy{AllowSoftwareKeys: true}, now)
	if err != nil || res.Assurance != attest.AssuranceSoftware || res.SeType != attest.SeTypeSoftware {
		t.Fatalf("VerifyEvidence: %+v %v", res, err)
	}

	// Tampering with any signed byte breaks the signature.
	bad := append([]byte(nil), wire...)
	bad[len(bad)-70] ^= 0x01
	if st2, err := attest.Parse(bad); err == nil {
		if err := st2.VerifySignature(vectorKey(t, v)); err == nil {
			t.Fatal("tampered vector verified")
		}
	}
	// The vector is stale relative to the real clock and to a clock 301 s later.
	if err := st.VerifyTimestamp(now.Add(301 * time.Second)); err == nil {
		t.Fatal("stale vector accepted")
	}
	// A different kid (another certificate) is rejected.
	if err := st.VerifyKeyID([]byte{0x01}); err == nil {
		t.Fatal("wrong kid accepted")
	}

	for _, n := range v.Negative {
		switch n.Error {
		case "ATT_NONCE":
			if bytes.Equal(st.Nonce, mustHex(t, n.ExpectedNonceHex)) {
				t.Errorf("%s: nonce unexpectedly matches", n.Name)
			}
		case "ATT_CSR_HASH":
			if err := st.VerifyBinding(mustHex(t, n.CSRDERHex)); err == nil {
				t.Errorf("%s: binding accepted", n.Name)
			}
		case "ATT_SE_TYPE":
			allowed := false
			for _, s := range n.AllowedSeTypes {
				allowed = allowed || s == st.SeType
			}
			if allowed {
				t.Fatalf("%s: vector expectation inconsistent", n.Name)
			}
			if _, err := st.VerifyEvidence(attest.Policy{AllowSoftwareKeys: false}, now); attest.CodeOf(err) != attest.CodeForbidden {
				t.Errorf("%s: software key accepted by a hardware-only policy: %v", n.Name, err)
			}
		default:
			t.Errorf("unhandled negative case %s (%s)", n.Name, n.Error)
		}
	}
}
