package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHashHelpers(t *testing.T) {
	t.Parallel()
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		oid, err := oidFromHash(h)
		if err != nil {
			t.Fatal(err)
		}
		back, err := hashFromOID(oid)
		if err != nil || back != h {
			t.Fatalf("round trip %v: %v %v", h, back, err)
		}
		if newHash(h).Size() != h.Size() {
			t.Fatalf("newHash(%v) size", h)
		}
	}
	if _, err := oidFromHash(crypto.MD5); err == nil {
		t.Error("MD5 oid accepted")
	}
	if _, err := hashFromOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}); err == nil {
		t.Error("MD5 hash accepted")
	}
	if _, err := publicKeyBytes(&x509.Certificate{RawSubjectPublicKeyInfo: []byte{1, 2}}); err == nil {
		t.Error("bad SPKI accepted")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := curveBits(rsaKey.Public()); err == nil {
		t.Error("RSA key accepted as responder key")
	}
	if _, _, err := signatureAlgorithmFor(rsaKey.Public()); err == nil {
		t.Error("RSA signature algorithm")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	oid, h, err := signatureAlgorithmFor(p384.Public())
	if err != nil || !oid.Equal(oidECDSAWithSHA384) || h != crypto.SHA384 {
		t.Fatalf("P-384 algorithm: %v %v %v", oid, h, err)
	}
	if string(unwrapNonce([]byte{0xff, 0x01})) != string([]byte{0xff, 0x01}) {
		t.Error("legacy bare nonce not passed through")
	}
}

func TestParseRequestErrors(t *testing.T) {
	t.Parallel()
	cid := certID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, NameHash: []byte{1}, IssuerKeyHash: []byte{2}, SerialNumber: big.NewInt(7)}
	two, _ := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: cid}, {Cert: cid}}}})
	if _, err := ParseRequest(two); err == nil {
		t.Error("two requests accepted")
	}
	zero := cid
	zero.SerialNumber = big.NewInt(0)
	z, _ := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: zero}}}})
	if _, err := ParseRequest(z); err == nil {
		t.Error("zero serial accepted")
	}
	md5 := cid
	md5.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	m, _ := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: md5}}}})
	if _, err := ParseRequest(m); err == nil {
		t.Error("MD5 request accepted")
	}
	// Nonce extension in the request is decoded.
	wrapped, _ := asn1.Marshal([]byte("n0nce"))
	withNonce, _ := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: cid}}, ExtensionList: []pkix.Extension{{Id: oidNonce, Value: wrapped}}}})
	pr, err := ParseRequest(withNonce)
	if err != nil || string(pr.Nonce) != "n0nce" || pr.SerialNumber.Int64() != 7 {
		t.Fatalf("nonce request: %+v %v", pr, err)
	}
	// Response nonce lookup on a response without extensions returns nil.
	noExt, _ := asn1.Marshal(responseASN1{Status: statusSuccessful, Response: responseBytes{ResponseType: oidBasicResponse, Response: mustBasic(t)}})
	if n, err := ParseResponseNonce(noExt); err != nil || n != nil {
		t.Fatalf("no nonce: %x %v", n, err)
	}
	bad, _ := asn1.Marshal(responseASN1{Status: statusSuccessful, Response: responseBytes{ResponseType: oidBasicResponse, Response: []byte{1}}})
	if _, err := ParseResponseNonce(bad); err == nil {
		t.Error("bad basic response accepted")
	}
}

func mustBasic(t *testing.T) []byte {
	t.Helper()
	rd := responseData{RawResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: []byte{0x04, 0x01, 0x00}}, Responses: []singleResponse{}}
	tbs, err := asn1.Marshal(rd)
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshalBasic(basicResponse{SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}, Signature: asn1.BitString{Bytes: []byte{1}, BitLength: 8}}, tbs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGETWithoutRequest(t *testing.T) {
	t.Parallel()
	r := &Responder{}
	req := httptest.NewRequest(http.MethodGet, "/ocsp/", nil)
	req.SetPathValue("request", "")
	rec := httptest.NewRecorder()
	r.handleGET(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty GET request: %d", rec.Code)
	}
}
