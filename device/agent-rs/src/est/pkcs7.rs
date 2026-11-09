//! Minimal decoder (and encoder, for test servers) for the RFC 7030 / RFC 5652 "certs-only"
//! degenerate SignedData, built on the `der` crate.
//!
//! ```text
//! ContentInfo ::= SEQUENCE { contentType id-signedData, content [0] EXPLICIT SignedData }
//! SignedData  ::= SEQUENCE { version CMSVersion, digestAlgorithms SET OF (empty),
//!                            encapContentInfo SEQUENCE { id-data }, certificates [0] IMPLICIT
//!                            SET OF Certificate, crls [1] IMPLICIT OPTIONAL, signerInfos SET (empty) }
//! ```
//! Bounded: at most [`MAX_INPUT`] bytes and [`MAX_CERTS`] certificates; every certificate is
//! fully parsed as X.509.

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};

/// Maximum input size.
pub const MAX_INPUT: usize = 64 * 1024;
/// Maximum number of certificates.
pub const MAX_CERTS: usize = 16;

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// PKCS#7 decoding error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PKCS#7 certs-only: {0}")]
pub struct Pkcs7Error(pub String);

fn e(m: impl Into<String>) -> Pkcs7Error {
    Pkcs7Error(m.into())
}

fn ctx(number: TagNumber, constructed: bool) -> Tag {
    Tag::ContextSpecific { constructed, number }
}

fn children(value: &[u8]) -> Result<Vec<AnyRef<'_>>, Pkcs7Error> {
    let mut r = SliceReader::new(value).map_err(|x| e(x.to_string()))?;
    let mut out = Vec::new();
    while !r.is_finished() {
        out.push(r.decode::<AnyRef<'_>>().map_err(|x| e(x.to_string()))?);
        if out.len() > MAX_CERTS + 8 {
            return Err(e("too many elements"));
        }
    }
    Ok(out)
}

/// Decode a certs-only SignedData (DER) into the contained certificate DERs (in order).
///
/// # Errors
/// [`Pkcs7Error`] on any structural problem.
pub fn decode_certs_only(data: &[u8]) -> Result<Vec<Vec<u8>>, Pkcs7Error> {
    if data.len() > MAX_INPUT {
        return Err(e("input too large"));
    }
    let content_info = AnyRef::from_der(data).map_err(|x| e(x.to_string()))?;
    if content_info.tag() != Tag::Sequence {
        return Err(e("ContentInfo is not a SEQUENCE"));
    }
    let ci = children(content_info.value())?;
    let [content_type, explicit] = ci.as_slice() else {
        return Err(e("ContentInfo must have 2 elements"));
    };
    let oid = content_type.decode_as::<ObjectIdentifier>().map_err(|x| e(x.to_string()))?;
    if oid != OID_SIGNED_DATA {
        return Err(e("contentType is not signedData"));
    }
    if explicit.tag() != ctx(TagNumber::N0, true) {
        return Err(e("content must be [0] EXPLICIT"));
    }
    let inner = children(explicit.value())?;
    let [signed_data] = inner.as_slice() else {
        return Err(e("[0] must hold exactly one SignedData"));
    };
    if signed_data.tag() != Tag::Sequence {
        return Err(e("SignedData is not a SEQUENCE"));
    }
    let sd = children(signed_data.value())?;
    let mut it = sd.iter();
    let version = it.next().ok_or_else(|| e("missing version"))?;
    if version.tag() != Tag::Integer {
        return Err(e("version is not an INTEGER"));
    }
    let digest_algs = it.next().ok_or_else(|| e("missing digestAlgorithms"))?;
    if digest_algs.tag() != Tag::Set {
        return Err(e("digestAlgorithms is not a SET"));
    }
    let encap = it.next().ok_or_else(|| e("missing encapContentInfo"))?;
    if encap.tag() != Tag::Sequence {
        return Err(e("encapContentInfo is not a SEQUENCE"));
    }
    let encap_children = children(encap.value())?;
    let encap_oid =
        encap_children.first().ok_or_else(|| e("empty encapContentInfo"))?.decode_as::<ObjectIdentifier>().map_err(|x| e(x.to_string()))?;
    if encap_oid != OID_DATA || encap_children.len() != 1 {
        return Err(e("certs-only encapContentInfo must be id-data without content"));
    }
    let mut certs = Vec::new();
    let mut signer_infos_seen = false;
    for item in it {
        if item.tag() == ctx(TagNumber::N0, true) {
            for cert in children(item.value())? {
                if cert.tag() != Tag::Sequence {
                    return Err(e("certificate is not a SEQUENCE"));
                }
                let der = cert.to_der().map_err(|x| e(x.to_string()))?;
                x509_cert::Certificate::from_der(&der).map_err(|x| e(format!("invalid certificate: {x}")))?;
                certs.push(der);
                if certs.len() > MAX_CERTS {
                    return Err(e("too many certificates"));
                }
            }
        } else if item.tag() == ctx(TagNumber::N1, true) {
            // CRLs are ignored.
        } else if item.tag() == Tag::Set && !signer_infos_seen {
            signer_infos_seen = true;
            if !item.value().is_empty() {
                return Err(e("certs-only SignedData must not carry signerInfos"));
            }
        } else {
            return Err(e("unexpected element in SignedData"));
        }
    }
    if !signer_infos_seen {
        return Err(e("missing signerInfos"));
    }
    if certs.is_empty() {
        return Err(e("no certificates"));
    }
    Ok(certs)
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(value);
    out
}

/// Encode certificates as a certs-only SignedData (used by test EST servers and tooling).
#[must_use]
pub fn encode_certs_only(certs: &[Vec<u8>]) -> Vec<u8> {
    let oid = |o: &ObjectIdentifier| o.to_der().unwrap_or_default();
    let mut sd = Vec::new();
    sd.extend(tlv(0x02, &[1]));
    sd.extend(tlv(0x31, &[]));
    sd.extend(tlv(0x30, &oid(&OID_DATA)));
    sd.extend(tlv(0xA0, &certs.concat()));
    sd.extend(tlv(0x31, &[]));
    let signed = tlv(0x30, &sd);
    let mut ci = oid(&OID_SIGNED_DATA);
    ci.extend(tlv(0xA0, &signed));
    tlv(0x30, &ci)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> Vec<u8> {
        let kp = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(vec!["x".into()]).unwrap().self_signed(&kp).unwrap().der().to_vec()
    }

    #[test]
    fn round_trip() {
        let a = cert();
        let b = cert();
        let p7 = encode_certs_only(&[a.clone(), b.clone()]);
        assert_eq!(decode_certs_only(&p7).unwrap(), vec![a.clone(), b]);
        assert!(decode_certs_only(&encode_certs_only(&[])).is_err());
        assert!(decode_certs_only(&[0x30, 0x00]).is_err());
        assert!(decode_certs_only(&[0x31, 0x00]).is_err());
        assert!(decode_certs_only(&vec![0u8; MAX_INPUT + 1]).is_err());
        let mut bad = p7.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(decode_certs_only(&bad).is_err());
        let not_cert = encode_certs_only(&[tlv(0x30, &[0x02, 0x01, 0x01])]);
        assert!(decode_certs_only(&not_cert).is_err());
        let too_many: Vec<Vec<u8>> = (0..17).map(|_| a.clone()).collect();
        assert!(decode_certs_only(&encode_certs_only(&too_many)).is_err());
        let long = tlv(0x04, &[0u8; 300]);
        assert_eq!(long[1], 0x82);
    }
}
