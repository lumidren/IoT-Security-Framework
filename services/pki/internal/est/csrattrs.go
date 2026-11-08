package est

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// CSR attributes (RFC 7030 §4.5.2): the server tells clients which key type,
// curve and signature algorithm it expects.
//
//	CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
//	AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
//
// IronMesh advertises three plain OIDs: id-ecPublicKey, secp256r1 (P-256) and
// ecdsa-with-SHA256, matching the mandatory device key algorithm (§2).
var (
	OIDECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OIDSecp256r1       = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// CSRAttrsOIDs are the attributes IronMesh advertises, in order.
func CSRAttrsOIDs() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{OIDECPublicKey, OIDSecp256r1, OIDECDSAWithSHA256}
}

// EncodeCSRAttrs returns the DER CsrAttrs sequence for the given OIDs.
func EncodeCSRAttrs(oids []asn1.ObjectIdentifier) ([]byte, error) {
	if len(oids) == 0 {
		return nil, errors.New("csrattrs: at least one OID is required")
	}
	der, err := asn1.Marshal(oids)
	if err != nil {
		return nil, fmt.Errorf("csrattrs: marshal: %w", err)
	}
	return der, nil
}

// DecodeCSRAttrs parses a DER CsrAttrs sequence. Only the plain-OID choice is
// supported; Attribute elements are rejected.
func DecodeCSRAttrs(der []byte) ([]asn1.ObjectIdentifier, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("csrattrs: parse: %w", err)
	}
	if len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, errors.New("csrattrs: not a SEQUENCE")
	}
	var oids []asn1.ObjectIdentifier
	data := seq.Bytes
	for len(data) > 0 {
		var el asn1.RawValue
		data, err = asn1.Unmarshal(data, &el)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: parse element: %w", err)
		}
		if el.Tag != asn1.TagOID || el.Class != asn1.ClassUniversal {
			return nil, errors.New("csrattrs: unsupported AttrOrOID choice (only OID is supported)")
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(el.FullBytes, &oid); err != nil {
			return nil, fmt.Errorf("csrattrs: parse OID: %w", err)
		}
		oids = append(oids, oid)
	}
	return oids, nil
}
