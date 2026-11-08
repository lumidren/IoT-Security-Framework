package est

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// PKCS#7 / CMS "certs-only" messages (RFC 5652 §5, RFC 7030 §4.1.3): a
// degenerate SignedData with no signers, no digest algorithms and no content,
// used solely as a container for certificates.
//
//	ContentInfo ::= SEQUENCE {
//	  contentType  id-signedData,
//	  content      [0] EXPLICIT SignedData }
//	SignedData ::= SEQUENCE {
//	  version          INTEGER (1),
//	  digestAlgorithms SET OF AlgorithmIdentifier   -- empty
//	  encapContentInfo SEQUENCE { eContentType id-data } -- no eContent
//	  certificates     [0] IMPLICIT SET OF Certificate,
//	  signerInfos      SET OF SignerInfo }          -- empty
//
// The standard library has no CMS support, so this file implements the
// encoder and decoder directly with encoding/asn1.

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// contentInfo's Content is the [0] EXPLICIT wrapper itself: encoding/asn1
// ignores explicit-tag parameters when marshalling a RawValue, so the wrapper
// is built and unwrapped by hand (see EncodeCertsOnly / DecodeCertsOnly).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

type signedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// EncodeCertsOnly builds a DER certs-only CMS message holding certs.
func EncodeCertsOnly(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("pkcs7: at least one certificate is required")
	}
	var certBytes []byte
	for _, c := range certs {
		if c == nil || len(c.Raw) == 0 {
			return nil, errors.New("pkcs7: certificate without raw DER")
		}
		certBytes = append(certBytes, c.Raw...)
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{},
		EncapContentInfo: encapContentInfo{EContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		},
		SignerInfos: []asn1.RawValue{},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: marshal SignedData: %w", err)
	}
	ci := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	out, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: marshal ContentInfo: %w", err)
	}
	return out, nil
}

// DecodeCertsOnly parses a DER certs-only CMS message and returns its
// certificates in order.
func DecodeCertsOnly(der []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: parse ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs7: trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkcs7: unexpected content type %v", ci.ContentType)
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return nil, errors.New("pkcs7: content is not [0] EXPLICIT SignedData")
	}
	var sd signedData
	if rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("pkcs7: parse SignedData: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs7: trailing data after SignedData")
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidData) {
		return nil, fmt.Errorf("pkcs7: unexpected encapsulated content type %v", sd.EncapContentInfo.EContentType)
	}
	if len(sd.SignerInfos) != 0 {
		return nil, errors.New("pkcs7: certs-only message must not carry signers")
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, errors.New("pkcs7: no certificates present")
	}
	var certs []*x509.Certificate
	data := sd.Certificates.Bytes
	for len(data) > 0 {
		var raw asn1.RawValue
		data, err = asn1.Unmarshal(data, &raw)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: parse certificate element: %w", err)
		}
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			return nil, errors.New("pkcs7: unsupported certificate choice (only X.509 Certificate is accepted)")
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}
