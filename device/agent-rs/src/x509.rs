//! Minimal X.509 helpers: certificate inspection (serial, validity, subject, SPKI pin) and PKCS#10
//! CSR construction with an external (secure-element) signer.

use std::str::FromStr;

use der::asn1::{BitString, Ia5String, OctetString};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;

/// X.509 handling error.
#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    /// DER decode/encode failure.
    #[error("DER: {0}")]
    Der(String),
    /// Semantic problem.
    #[error("certificate: {0}")]
    Invalid(String),
}

impl From<der::Error> for X509Error {
    fn from(e: der::Error) -> Self {
        X509Error::Der(e.to_string())
    }
}

const OID_CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_OU: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_ECDSA_SHA256: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_SAN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

/// The facts the agent needs from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// Full DER.
    pub der: Vec<u8>,
    /// Device kid: minimal big-endian serial.
    pub kid: Vec<u8>,
    /// Not-before (unix s).
    pub not_before: u64,
    /// Not-after (unix s).
    pub not_after: u64,
    /// Subject CN.
    pub subject_cn: Option<String>,
    /// Subject OUs.
    pub subject_ou: Vec<String>,
    /// Issuer name DER.
    pub issuer_der: Vec<u8>,
    /// Subject name DER.
    pub subject_der: Vec<u8>,
    /// SubjectPublicKeyInfo DER.
    pub spki_der: Vec<u8>,
    /// SHA-256 of the SPKI DER (the pin format of the bundle's `ca_pins`).
    pub spki_sha256: [u8; 32],
    /// The subject public key if it is P-256.
    pub p256: Option<p256::PublicKey>,
}

impl CertInfo {
    /// Hex serial (DUT `cert_serial_hex`).
    #[must_use]
    pub fn serial_hex(&self) -> String {
        hex::encode(&self.kid)
    }

    /// Lifetime in seconds.
    #[must_use]
    pub fn lifetime(&self) -> u64 {
        self.not_after.saturating_sub(self.not_before)
    }
}

fn name_values(name: &Name, oid: der::asn1::ObjectIdentifier) -> Vec<String> {
    name.0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|atv| atv.oid == oid)
        .filter_map(|atv| std::str::from_utf8(atv.value.value()).ok().map(str::to_owned))
        .collect()
}

/// Parse a DER certificate.
///
/// # Errors
/// On malformed input.
pub fn parse_cert(der_bytes: &[u8]) -> Result<CertInfo, X509Error> {
    let cert = Certificate::from_der(der_bytes)?;
    let tbs = &cert.tbs_certificate;
    let kid = crate::wire::ids::kid_from_serial(tbs.serial_number.as_bytes()).map_err(|e| X509Error::Invalid(e.to_string()))?;
    let spki_der = tbs.subject_public_key_info.to_der()?;
    let p256 = p256::PublicKey::from_sec1_bytes(tbs.subject_public_key_info.subject_public_key.raw_bytes()).ok();
    Ok(CertInfo {
        der: der_bytes.to_vec(),
        kid,
        not_before: tbs.validity.not_before.to_unix_duration().as_secs(),
        not_after: tbs.validity.not_after.to_unix_duration().as_secs(),
        subject_cn: name_values(&tbs.subject, OID_CN).into_iter().next(),
        subject_ou: name_values(&tbs.subject, OID_OU),
        issuer_der: tbs.issuer.to_der()?,
        subject_der: tbs.subject.to_der()?,
        spki_sha256: Sha256::digest(&spki_der).into(),
        spki_der,
        p256,
    })
}

/// All certificates in a PEM bundle, or the single DER certificate.
///
/// # Errors
/// On malformed PEM.
pub fn pem_or_der_all(data: &[u8]) -> Result<Vec<Vec<u8>>, X509Error> {
    if data.first() == Some(&0x30) {
        return Ok(vec![data.to_vec()]);
    }
    let mut reader = std::io::BufReader::new(data);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| X509Error::Der(e.to_string()))?;
    if certs.is_empty() {
        return Err(X509Error::Invalid("no certificate found".into()));
    }
    Ok(certs.into_iter().map(|c| c.to_vec()).collect())
}

/// First certificate of a PEM bundle or DER blob.
///
/// # Errors
/// On malformed input.
pub fn pem_or_der_first(data: &[u8]) -> Result<Vec<u8>, X509Error> {
    pem_or_der_all(data)?.into_iter().next().ok_or_else(|| X509Error::Invalid("no certificate found".into()))
}

/// PEM-encode DER bytes.
#[must_use]
pub fn to_pem(label: &str, der_bytes: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der_bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Signs a SHA-256 digest, returning `r || s`.
pub type DigestSigner<'a> = dyn Fn(&[u8; 32]) -> Result<[u8; 64], String> + 'a;

/// Device SAN URI (`urn:ironmesh:tenant:<t>:device:<d>`).
#[must_use]
pub fn device_urn(tenant_id: &str, device_id: &str) -> String {
    format!("urn:ironmesh:tenant:{tenant_id}:device:{device_id}")
}

/// Build a DER PKCS#10 CSR (CN = device id, OU = tenant id, O = IronMesh, SAN URI) for `public_key`,
/// signed with `sign(sha256(CertificationRequestInfo)) -> r || s`.
///
/// # Errors
/// On encoding or signer failure.
pub fn build_csr(device_id: &str, tenant_id: &str, public_key: &p256::PublicKey, sign: &DigestSigner<'_>) -> Result<Vec<u8>, X509Error> {
    use p256::pkcs8::EncodePublicKey;
    let subject = Name::from_str(&format!("CN={device_id},OU={tenant_id},O=IronMesh"))?;
    let spki_der = public_key.to_public_key_der().map_err(|e| X509Error::Der(e.to_string()))?;
    let public_key_info = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
    let uri = Ia5String::new(&device_urn(tenant_id, device_id))?;
    let san = SubjectAltName(vec![GeneralName::UniformResourceIdentifier(uri)]);
    let ext = Extension { extn_id: OID_SAN, critical: false, extn_value: OctetString::new(san.to_der()?)? };
    let mut attributes = x509_cert::attr::Attributes::new();
    attributes.insert(x509_cert::attr::Attribute::try_from(ExtensionReq(vec![ext]))?)?;
    let info = CertReqInfo { version: Version::V1, subject, public_key: public_key_info, attributes };
    let tbs = info.to_der()?;
    let digest: [u8; 32] = Sha256::digest(&tbs).into();
    let raw = sign(&digest).map_err(X509Error::Invalid)?;
    let sig_der = crate::wire::keys::ecdsa_raw_to_der(&raw).map_err(|e| X509Error::Invalid(e.to_string()))?;
    let req = CertReq {
        info,
        algorithm: AlgorithmIdentifierOwned { oid: OID_ECDSA_SHA256, parameters: None },
        signature: BitString::from_bytes(&sig_der)?,
    };
    Ok(req.to_der()?)
}

/// Parse a CSR and return `(subject CN, public key)` (used by tests and `--factory` self-check).
///
/// # Errors
/// On malformed input.
pub fn inspect_csr(der_bytes: &[u8]) -> Result<(Option<String>, Vec<String>, p256::PublicKey), X509Error> {
    let req = CertReq::from_der(der_bytes)?;
    let pk = p256::PublicKey::from_sec1_bytes(req.info.public_key.subject_public_key.raw_bytes())
        .map_err(|e| X509Error::Invalid(e.to_string()))?;
    // Verify the self-signature.
    use p256::ecdsa::signature::Verifier;
    let tbs = req.info.to_der()?;
    let sig = p256::ecdsa::Signature::from_der(req.signature.raw_bytes()).map_err(|e| X509Error::Invalid(e.to_string()))?;
    p256::ecdsa::VerifyingKey::from(pk).verify(&tbs, &sig).map_err(|e| X509Error::Invalid(format!("CSR signature: {e}")))?;
    Ok((name_values(&req.info.subject, OID_CN).into_iter().next(), name_values(&req.info.subject, OID_OU), pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_round_trip() {
        let sk = p256::SecretKey::from_slice(&[5u8; 32]).unwrap();
        let signing = p256::ecdsa::SigningKey::from(&sk);
        let sign = |d: &[u8; 32]| -> Result<[u8; 64], String> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let s: p256::ecdsa::Signature = signing.sign_prehash(d).map_err(|e| e.to_string())?;
            Ok(s.to_bytes().into())
        };
        let csr = build_csr("dev-0123456789abcdef", "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", &sk.public_key(), &sign).unwrap();
        let (cn, ou, pk) = inspect_csr(&csr).unwrap();
        assert_eq!(cn.as_deref(), Some("dev-0123456789abcdef"));
        assert_eq!(ou, vec!["7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11".to_string()]);
        assert_eq!(pk, sk.public_key());
        let bad = |_: &[u8; 32]| -> Result<[u8; 64], String> { Err("no".into()) };
        assert!(build_csr("dev-0123456789abcdef", "t", &sk.public_key(), &bad).is_err());
        assert!(inspect_csr(b"\x30\x00").is_err());
    }

    #[test]
    fn pem_helpers() {
        let pem = to_pem("CERTIFICATE", &[0x30, 0x03, 0x02, 0x01, 0x01]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert_eq!(pem_or_der_first(pem.as_bytes()).unwrap(), vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        assert_eq!(pem_or_der_all(&[0x30, 0x00]).unwrap().len(), 1);
        assert!(pem_or_der_all(b"garbage").is_err());
        assert!(parse_cert(&[0x30, 0x00]).is_err());
        assert_eq!(device_urn("t", "d"), "urn:ironmesh:tenant:t:device:d");
    }
}
