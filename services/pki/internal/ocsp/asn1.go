package ocsp

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // RFC 6960 mandates SHA-1 for the byKey ResponderID
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"
)

// RFC 6960 structures. The layouts mirror golang.org/x/crypto/ocsp so that
// responses produced here parse with its ParseResponse; the difference is that
// our ResponseData carries responseExtensions (where the nonce belongs).

var (
	oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidNonce         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

// Response status values (OCSPResponseStatus).
const (
	statusSuccessful       = 0
	statusMalformedRequest = 1
	statusInternalError    = 2
	statusUnauthorized     = 6
)

// Certificate status values.
const (
	// Good means the certificate is known and not revoked.
	Good = 0
	// Revoked means the certificate is revoked.
	Revoked = 1
	// Unknown means the responder has no record of the serial.
	Unknown = 2
)

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type ocspRequest struct {
	TBSRequest        tbsRequest
	OptionalSignature asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type tbsRequest struct {
	Version       int           `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName asn1.RawValue `asn1:"explicit,tag:1,optional"`
	RequestList   []request
	ExtensionList []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type request struct {
	Cert                    certID
	SingleRequestExtensions []pkix.Extension `asn1:"explicit,tag:0,optional"`
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID     asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []singleResponse
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// Pre-encoded error responses (RFC 6960 §4.2.1).
var (
	malformedRequestResponse = []byte{0x30, 0x03, 0x0a, 0x01, statusMalformedRequest}
	internalErrorResponse    = []byte{0x30, 0x03, 0x0a, 0x01, statusInternalError}
	unauthorizedResponse     = []byte{0x30, 0x03, 0x0a, 0x01, statusUnauthorized}
)

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("ocsp: unsupported hash algorithm %v", oid)
}

func oidFromHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA1:
		return oidSHA1, nil
	case crypto.SHA256:
		return oidSHA256, nil
	case crypto.SHA384:
		return oidSHA384, nil
	case crypto.SHA512:
		return oidSHA512, nil
	}
	return nil, fmt.Errorf("ocsp: unsupported hash %v", h)
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New() //nolint:gosec // request-selected certID hash, not used for integrity
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// publicKeyBytes returns the issuer's SubjectPublicKey BIT STRING contents,
// which RFC 6960 hashes for issuerKeyHash and the byKey ResponderID.
func publicKeyBytes(cert *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("ocsp: parse SPKI: %w", err)
	}
	return spki.PublicKey.RightAlign(), nil
}

// ParsedRequest is the single certificate query of an OCSP request.
type ParsedRequest struct {
	Hash           crypto.Hash
	HashOID        asn1.ObjectIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
	Nonce          []byte
}

// ParseRequest decodes an OCSPRequest with exactly one Request and extracts
// the nonce extension if present.
func ParseRequest(der []byte) (*ParsedRequest, error) {
	var req ocspRequest
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return nil, fmt.Errorf("ocsp: malformed request: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("ocsp: trailing data after request")
	}
	if len(req.TBSRequest.RequestList) != 1 {
		return nil, fmt.Errorf("ocsp: %d requests in message, exactly one is supported", len(req.TBSRequest.RequestList))
	}
	cid := req.TBSRequest.RequestList[0].Cert
	h, err := hashFromOID(cid.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if cid.SerialNumber == nil || cid.SerialNumber.Sign() <= 0 {
		return nil, errors.New("ocsp: invalid serial number")
	}
	pr := &ParsedRequest{Hash: h, HashOID: cid.HashAlgorithm.Algorithm, IssuerNameHash: cid.NameHash, IssuerKeyHash: cid.IssuerKeyHash, SerialNumber: cid.SerialNumber}
	for _, ext := range req.TBSRequest.ExtensionList {
		if ext.Id.Equal(oidNonce) {
			pr.Nonce = unwrapNonce(ext.Value)
		}
	}
	return pr, nil
}

// unwrapNonce handles both RFC 8954 (OCTET STRING wrapped) and legacy bare
// nonce encodings.
func unwrapNonce(v []byte) []byte {
	var inner []byte
	if rest, err := asn1.Unmarshal(v, &inner); err == nil && len(rest) == 0 {
		return inner
	}
	return v
}

// CreateRequest builds a DER OCSPRequest for cert issued by issuer, hashing
// the issuer with h and attaching nonce when non-empty.
func CreateRequest(cert, issuer *x509.Certificate, h crypto.Hash, nonce []byte) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, errors.New("ocsp: certificate and issuer are required")
	}
	oid, err := oidFromHash(h)
	if err != nil {
		return nil, err
	}
	pk, err := publicKeyBytes(issuer)
	if err != nil {
		return nil, err
	}
	nameHasher := newHash(h)
	nameHasher.Write(issuer.RawSubject)
	keyHasher := newHash(h)
	keyHasher.Write(pk)
	req := ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: certID{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue},
		NameHash:      nameHasher.Sum(nil),
		IssuerKeyHash: keyHasher.Sum(nil),
		SerialNumber:  cert.SerialNumber,
	}}}}}
	if len(nonce) > 0 {
		wrapped, err := asn1.Marshal(nonce)
		if err != nil {
			return nil, err
		}
		req.TBSRequest.ExtensionList = []pkix.Extension{{Id: oidNonce, Value: wrapped}}
	}
	return asn1.Marshal(req)
}

// ParseResponseNonce returns the nonce from a response's responseExtensions,
// or nil when absent. It does not verify the signature.
func ParseResponseNonce(der []byte) ([]byte, error) {
	var resp responseASN1
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, fmt.Errorf("ocsp: malformed response: %w", err)
	}
	if resp.Status != statusSuccessful {
		return nil, fmt.Errorf("ocsp: response status %d", resp.Status)
	}
	var basic basicResponse
	if _, err := asn1.Unmarshal(resp.Response.Response, &basic); err != nil {
		return nil, fmt.Errorf("ocsp: malformed basic response: %w", err)
	}
	for _, ext := range basic.TBSResponseData.ResponseExtensions {
		if ext.Id.Equal(oidNonce) {
			return unwrapNonce(ext.Value), nil
		}
	}
	return nil, nil
}

// signedResponse builds and signs a BasicOCSPResponse wrapped in OCSPResponse.
func signedResponse(single singleResponse, nonce []byte, producedAt time.Time, signerCert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	pk, err := publicKeyBytes(signerCert)
	if err != nil {
		return nil, err
	}
	keyHash := sha1.Sum(pk) //nolint:gosec // RFC 6960 §4.2.1 KeyHash is SHA-1 by definition
	keyHashDER, err := asn1.Marshal(keyHash[:])
	if err != nil {
		return nil, err
	}
	rd := responseData{
		RawResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: keyHashDER},
		ProducedAt:     producedAt.UTC().Truncate(time.Second),
		Responses:      []singleResponse{single},
	}
	if len(nonce) > 0 {
		wrapped, err := asn1.Marshal(nonce)
		if err != nil {
			return nil, err
		}
		rd.ResponseExtensions = []pkix.Extension{{Id: oidNonce, Value: wrapped}}
	}
	tbs, err := asn1.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("ocsp: marshal ResponseData: %w", err)
	}
	sigAlg, h, err := signatureAlgorithmFor(signer.Public())
	if err != nil {
		return nil, err
	}
	hasher := newHash(h)
	hasher.Write(tbs)
	sig, err := signer.Sign(nil, hasher.Sum(nil), h)
	if err != nil {
		return nil, fmt.Errorf("ocsp: sign response: %w", err)
	}
	basic := basicResponse{
		TBSResponseData:    responseData{Raw: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigAlg},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
		Certificates:       []asn1.RawValue{{FullBytes: signerCert.Raw}},
	}
	// Marshal with the pre-encoded TBS: asn1 uses RawContent when set.
	basicDER, err := marshalBasic(basic, tbs)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(responseASN1{Status: statusSuccessful, Response: responseBytes{ResponseType: oidBasicResponse, Response: basicDER}})
}

// marshalBasic encodes a BasicOCSPResponse reusing the already signed TBS
// bytes verbatim (Go's asn1 does not honour RawContent when marshalling).
func marshalBasic(b basicResponse, tbs []byte) ([]byte, error) {
	type basicOut struct {
		TBSResponseData    asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
		Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}
	return asn1.Marshal(basicOut{
		TBSResponseData:    asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: b.SignatureAlgorithm,
		Signature:          b.Signature,
		Certificates:       b.Certificates,
	})
}

func signatureAlgorithmFor(pub crypto.PublicKey) (asn1.ObjectIdentifier, crypto.Hash, error) {
	// The delegated responder key is always ECDSA; pick the hash by curve size.
	bits, err := curveBits(pub)
	if err != nil {
		return nil, 0, err
	}
	if bits > 256 {
		return oidECDSAWithSHA384, crypto.SHA384, nil
	}
	return oidECDSAWithSHA256, crypto.SHA256, nil
}
