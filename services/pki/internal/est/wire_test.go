package est

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertsOnlyRoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 2, 4} {
		var certs []*x509.Certificate
		for i := 0; i < n; i++ {
			certs = append(certs, selfSigned(t, "ca-"+string(rune('a'+i))))
		}
		der, err := EncodeCertsOnly(certs)
		if err != nil {
			t.Fatalf("Encode(%d): %v", n, err)
		}
		got, err := DecodeCertsOnly(der)
		if err != nil {
			t.Fatalf("Decode(%d): %v", n, err)
		}
		if len(got) != n {
			t.Fatalf("got %d certs want %d", len(got), n)
		}
		for i := range certs {
			if !got[i].Equal(certs[i]) {
				t.Fatalf("cert %d differs", i)
			}
		}
		// Structural check: ContentInfo { id-signedData, [0] EXPLICIT SignedData }
		// with version 1 and empty digestAlgorithms / signerInfos.
		var ci contentInfo
		if _, err := asn1.Unmarshal(der, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
			t.Fatalf("ContentInfo: %v %v", ci.ContentType, err)
		}
		if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 || !ci.Content.IsCompound {
			t.Fatalf("content not [0] EXPLICIT: %+v", ci.Content)
		}
		var sd signedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
			t.Fatal(err)
		}
		if sd.Version != 1 || len(sd.DigestAlgorithms) != 0 || len(sd.SignerInfos) != 0 || !sd.EncapContentInfo.EContentType.Equal(oidData) {
			t.Fatalf("SignedData structure wrong: %+v", sd)
		}
		if sd.Certificates.Class != asn1.ClassContextSpecific || sd.Certificates.Tag != 0 || !sd.Certificates.IsCompound {
			t.Fatalf("certificates tag wrong: %+v", sd.Certificates)
		}
	}
}

// wrapCI builds a ContentInfo around an already encoded inner element.
func wrapCI(t *testing.T, contentType asn1.ObjectIdentifier, inner asn1.RawValue) []byte {
	t.Helper()
	b, err := asn1.Marshal(contentInfo{ContentType: contentType, Content: inner})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func explicit0(sdDER []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}
}

func TestCertsOnlyErrors(t *testing.T) {
	t.Parallel()
	if _, err := EncodeCertsOnly(nil); err == nil {
		t.Error("empty encode accepted")
	}
	if _, err := EncodeCertsOnly([]*x509.Certificate{{}}); err == nil {
		t.Error("cert without raw accepted")
	}
	cert := selfSigned(t, "x")
	good, _ := EncodeCertsOnly([]*x509.Certificate{cert})

	sdWith := func(certs []byte, signers []asn1.RawValue, econtent asn1.ObjectIdentifier) []byte {
		sd := signedData{Version: 1, DigestAlgorithms: []asn1.RawValue{}, EncapContentInfo: encapContentInfo{EContentType: econtent}, SignerInfos: signers}
		if certs != nil {
			sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs}
		}
		if signers == nil {
			sd.SignerInfos = []asn1.RawValue{}
		}
		return mustMarshal(t, sd)
	}
	signer := []asn1.RawValue{{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{}}}

	cases := map[string][]byte{
		"garbage":            {0x01, 0x02},
		"trailing data":      append(append([]byte{}, good...), 0x00),
		"wrong content type": wrapCI(t, oidData, explicit0(sdWith(cert.Raw, nil, oidData))),
		"content not [0]":    wrapCI(t, oidSignedData, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: sdWith(cert.Raw, nil, oidData)}),
		"content not seq":    wrapCI(t, oidSignedData, explicit0(mustMarshal(t, 5))),
		"bad econtent":       wrapCI(t, oidSignedData, explicit0(sdWith(cert.Raw, nil, oidSignedData))),
		"with signer":        wrapCI(t, oidSignedData, explicit0(sdWith(cert.Raw, signer, oidData))),
		"no certs":           wrapCI(t, oidSignedData, explicit0(sdWith(nil, nil, oidData))),
		"other cert choice":  wrapCI(t, oidSignedData, explicit0(sdWith([]byte{0xa3, 0x02, 0x05, 0x00}, nil, oidData))),
		"garbage cert":       wrapCI(t, oidSignedData, explicit0(sdWith([]byte{0x30, 0x02, 0x05, 0x00}, nil, oidData))),
		"truncated cert":     wrapCI(t, oidSignedData, explicit0(sdWith([]byte{0x30, 0x10, 0x01}, nil, oidData))),
		"sd trailing":        wrapCI(t, oidSignedData, explicit0(append(sdWith(cert.Raw, nil, oidData), 0x00))),
	}
	for name, in := range cases {
		if _, err := DecodeCertsOnly(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCSRAttrsRoundTrip(t *testing.T) {
	t.Parallel()
	der, err := EncodeCSRAttrs(CSRAttrsOIDs())
	if err != nil {
		t.Fatal(err)
	}
	oids, err := DecodeCSRAttrs(der)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := CSRAttrsOIDs()
	if len(oids) != len(want) {
		t.Fatalf("got %d oids", len(oids))
	}
	for i := range want {
		if !oids[i].Equal(want[i]) {
			t.Errorf("oid %d = %v want %v", i, oids[i], want[i])
		}
	}
	if !oids[0].Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) || !oids[1].Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) || !oids[2].Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}) {
		t.Error("unexpected OID values")
	}

	if _, err := EncodeCSRAttrs(nil); err == nil {
		t.Error("empty encode accepted")
	}
	bad := map[string][]byte{
		"garbage":   {0xff},
		"not seq":   mustMarshal(t, 5),
		"attribute": mustMarshal(t, []struct{ A int }{{1}}),
		"trailing":  append(append([]byte{}, der...), 0x00),
		"bad el":    {0x30, 0x02, 0x06, 0x05},
	}
	for name, in := range bad {
		if _, err := DecodeCSRAttrs(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
