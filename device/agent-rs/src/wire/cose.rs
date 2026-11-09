//! COSE profiles (`WIRE_FORMAT.md` §2): COSE_Sign1 (tag 18), COSE_Sign (tag 98) and
//! COSE_Encrypt0 (tag 16), with the exact structural checks and error codes of
//! `ironmesh_wire/cose.py`.

use super::cbor::{self, DecodeLimits, Value, TAG_ENCRYPT0, TAG_SIGN, TAG_SIGN1};
use super::error::{err, ErrorCode as C, WireResult};
use super::keys::{self, CoseSigner, PublicKey, ALG_A256GCM, ALG_EDDSA, ALG_ES256, ALG_ML_DSA_65};

/// Header label `alg`.
pub const HDR_ALG: i128 = 1;
/// Header label `kid`.
pub const HDR_KID: i128 = 4;
/// Header label `IV`.
pub const HDR_IV: i128 = 5;
/// IronMesh HPKE wrap header label.
pub const HDR_IRONMESH_HPKE: i128 = -70000;
/// AES-GCM IV size.
pub const A256GCM_IV_SIZE: usize = 12;
/// AES-GCM tag size.
pub const A256GCM_TAG_SIZE: usize = 16;
/// HPKE `enc` size (uncompressed P-256 point).
pub const HPKE_ENC_SIZE: usize = 65;
/// HPKE wrapped CEK size.
pub const HPKE_WRAPPED_KEY_SIZE: usize = 48;
/// Firmware key id size.
pub const KEY_ID_SIZE: usize = 8;
/// Maximum kid size in a protected header.
pub const MAX_KID_SIZE: usize = 255;

/// Encrypt0 protected header bytes `a1 01 03`.
pub const ENCRYPT0_PROTECTED: [u8; 3] = [0xa1, 0x01, 0x03];

/// A key identifier: a bstr (devices, firmware keys) or a tstr (tenant command key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kid {
    /// Byte-string kid.
    Bytes(Vec<u8>),
    /// Text-string kid.
    Text(String),
}

impl Kid {
    fn to_value(&self) -> Value {
        match self {
            Kid::Bytes(b) => Value::Bytes(b.clone()),
            Kid::Text(t) => Value::Text(t.clone()),
        }
    }

    /// Stable printable form (`hex` for bstr, the text for tstr).
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Kid::Bytes(b) => hex::encode(b),
            Kid::Text(t) => t.clone(),
        }
    }
}

fn check_kid(kid: &Value) -> WireResult<Kid> {
    match kid {
        Value::Bytes(b) if (1..=MAX_KID_SIZE).contains(&b.len()) => Ok(Kid::Bytes(b.clone())),
        Value::Text(t) if (1..=MAX_KID_SIZE).contains(&t.len()) => Ok(Kid::Text(t.clone())),
        Value::Bytes(_) | Value::Text(_) => Err(err(C::CoseKid, "kid must be 1..255 bytes")),
        _ => Err(err(C::CoseKid, "kid must be a bstr or a tstr")),
    }
}

/// Serialize the protected header `{1: alg, 4: kid}`.
///
/// # Errors
/// `COSE_KID` for an out-of-range kid.
pub fn encode_protected(alg: i64, kid: &Kid) -> WireResult<Vec<u8>> {
    check_kid(&kid.to_value())?;
    cbor::encode(&cbor::int_map(vec![(HDR_ALG, Value::int(alg)), (HDR_KID, kid.to_value())]))
}

/// `Sig_structure` for COSE_Sign1 with empty external AAD.
///
/// # Errors
/// Never in practice (encoding of byte strings cannot fail).
pub fn sig_structure1(protected: &[u8], payload: &[u8]) -> WireResult<Vec<u8>> {
    cbor::encode(&Value::Array(vec![Value::text("Signature1"), Value::bytes(protected), Value::bytes(Vec::new()), Value::bytes(payload)]))
}

/// `Sig_structure` for COSE_Sign with empty body protected header and external AAD.
///
/// # Errors
/// Never in practice.
pub fn sig_structure(sign_protected: &[u8], payload: &[u8]) -> WireResult<Vec<u8>> {
    cbor::encode(&Value::Array(vec![
        Value::text("Signature"),
        Value::bytes(Vec::new()),
        Value::bytes(sign_protected),
        Value::bytes(Vec::new()),
        Value::bytes(payload),
    ]))
}

/// `Enc_structure` for COSE_Encrypt0: `["Encrypt0", protected, h'']`.
///
/// # Errors
/// Never in practice.
pub fn enc_structure0(protected: &[u8]) -> WireResult<Vec<u8>> {
    cbor::encode(&Value::Array(vec![Value::text("Encrypt0"), Value::bytes(protected), Value::bytes(Vec::new())]))
}

/// Strictly parse a protected header that must be exactly `{1: alg, 4: kid}`.
///
/// # Errors
/// `COSE_HEADER`, `COSE_ALG`, `COSE_KID` or any `CBOR_*` code.
pub fn parse_protected(protected: &[u8], allowed_algs: &[i64], limits: DecodeLimits) -> WireResult<(i64, Kid)> {
    if protected.is_empty() {
        return Err(err(C::CoseHeader, "protected header must not be empty"));
    }
    let header = cbor::decode_with(protected, limits)?;
    let Value::Map(entries) = &header else {
        return Err(err(C::CoseHeader, "protected header must be exactly {1: alg, 4: kid}"));
    };
    let keys_ok = entries.len() == 2
        && entries.iter().any(|(k, _)| *k == Value::Int(HDR_ALG))
        && entries.iter().any(|(k, _)| *k == Value::Int(HDR_KID));
    if !keys_ok {
        return Err(err(C::CoseHeader, "protected header must be exactly {1: alg, 4: kid}"));
    }
    let alg = match header.get_int_key(HDR_ALG) {
        Some(Value::Int(a)) => i64::try_from(*a).ok().filter(|a| allowed_algs.contains(a)),
        _ => None,
    }
    .ok_or_else(|| err(C::CoseAlg, "algorithm not allowed here"))?;
    let kid = check_kid(header.get_int_key(HDR_KID).unwrap_or(&Value::Null))?;
    Ok((alg, kid))
}

fn as_tagged_array(data: &[u8], tag: u64, length: usize, limits: DecodeLimits) -> WireResult<Vec<Value>> {
    let value = cbor::decode_with(data, limits)?;
    let Value::Tag(t, inner) = value else {
        return Err(err(C::CoseTag, "expected a CBOR tag"));
    };
    if t != tag {
        return Err(err(C::CoseTag, "unexpected CBOR tag"));
    }
    match *inner {
        Value::Array(items) if items.len() == length => Ok(items),
        _ => Err(err(C::CoseStructure, "unexpected COSE array shape")),
    }
}

fn require_empty_map(value: &Value) -> WireResult<()> {
    match value {
        Value::Map(m) if m.is_empty() => Ok(()),
        _ => Err(err(C::CoseHeader, "unprotected header must be an empty map")),
    }
}

fn require_bstr(value: Value) -> WireResult<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(err(C::CoseStructure, "expected a byte string")),
    }
}

// ---------------------------------------------------------------------------------------------
// COSE_Sign1
// ---------------------------------------------------------------------------------------------

/// A structurally valid COSE_Sign1 (not yet verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign1Message {
    /// Serialized protected header (used verbatim in `Sig_structure`).
    pub protected: Vec<u8>,
    /// Algorithm.
    pub alg: i64,
    /// Key identifier.
    pub kid: Kid,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

impl Sign1Message {
    /// The to-be-signed `Sig_structure` bytes.
    ///
    /// # Errors
    /// Never in practice.
    pub fn to_be_signed(&self) -> WireResult<Vec<u8>> {
        sig_structure1(&self.protected, &self.payload)
    }
}

/// Build a COSE_Sign1 over `payload` with protected header `{1: alg, 4: kid}`.
///
/// # Errors
/// `COSE_KID` for a bad kid or a signer failure.
pub fn sign1_encode(payload: &[u8], signer: &dyn CoseSigner, kid: &Kid) -> WireResult<Vec<u8>> {
    let protected = encode_protected(signer.alg(), kid)?;
    let signature = signer.sign(&sig_structure1(&protected, payload)?)?;
    cbor::encode(&Value::Tag(
        TAG_SIGN1,
        Box::new(Value::Array(vec![Value::Bytes(protected), Value::Map(Vec::new()), Value::bytes(payload), Value::Bytes(signature)])),
    ))
}

/// Parse and structurally validate a COSE_Sign1 with ES256 or EdDSA.
///
/// # Errors
/// `CBOR_*`, `COSE_TAG`, `COSE_STRUCTURE`, `COSE_HEADER`, `COSE_ALG`, `COSE_KID`, `COSE_SIGNATURE`.
pub fn sign1_decode(data: &[u8], limits: DecodeLimits) -> WireResult<Sign1Message> {
    let mut items = as_tagged_array(data, TAG_SIGN1, 4, limits)?.into_iter();
    let (Some(protected), Some(unprotected), Some(payload), Some(signature)) = (items.next(), items.next(), items.next(), items.next())
    else {
        return Err(err(C::CoseStructure, "expected 4 elements"));
    };
    let protected = require_bstr(protected)?;
    require_empty_map(&unprotected)?;
    if payload == Value::Null {
        return Err(err(C::CoseStructure, "detached payloads are not allowed"));
    }
    let payload = require_bstr(payload)?;
    let signature = require_bstr(signature)?;
    let (alg, kid) = parse_protected(&protected, &[ALG_ES256, ALG_EDDSA], limits)?;
    if Some(signature.len()) != keys::signature_size(alg) {
        return Err(err(C::CoseSignature, "signature has the wrong length"));
    }
    Ok(Sign1Message { protected, alg, kid, payload, signature })
}

/// Verify the signature of a parsed COSE_Sign1.
///
/// # Errors
/// `COSE_ALG` (key type mismatch) or `COSE_SIGNATURE`.
pub fn sign1_verify(message: &Sign1Message, key: &PublicKey) -> WireResult<()> {
    keys::raw_verify(key, message.alg, &message.to_be_signed()?, &message.signature)
}

// ---------------------------------------------------------------------------------------------
// COSE_Sign (firmware manifest)
// ---------------------------------------------------------------------------------------------

/// One `COSE_Signature` of a COSE_Sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSignature {
    /// Serialized signature protected header.
    pub protected: Vec<u8>,
    /// Algorithm (`-8` or `-49`).
    pub alg: i64,
    /// 8-byte key id.
    pub kid: [u8; KEY_ID_SIZE],
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// A structurally valid COSE_Sign (not yet verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessage {
    /// Payload (the canonical manifest).
    pub payload: Vec<u8>,
    /// Signatures in wire order.
    pub signatures: Vec<CoseSignature>,
}

impl SignMessage {
    /// The signature for an algorithm, if present.
    #[must_use]
    pub fn signature_for(&self, alg: i64) -> Option<&CoseSignature> {
        self.signatures.iter().find(|s| s.alg == alg)
    }

    /// `Sig_structure` bytes for one signature.
    ///
    /// # Errors
    /// Never in practice.
    pub fn to_be_signed(&self, signature: &CoseSignature) -> WireResult<Vec<u8>> {
        sig_structure(&signature.protected, &self.payload)
    }
}

/// A COSE_Sign signer: algorithm, 8-byte kid and a signing function.
pub struct SignSigner<'a> {
    /// Algorithm (`-8` or `-49`).
    pub alg: i64,
    /// Key id (`SHA-256(raw key)[0:8]`).
    pub kid: [u8; KEY_ID_SIZE],
    /// Signing function over the `Sig_structure`.
    pub sign: &'a dyn Fn(&[u8]) -> WireResult<Vec<u8>>,
}

/// Build a COSE_Sign (tag 98) with an empty body header and one signature per signer.
///
/// # Errors
/// `COSE_STRUCTURE` (no signers), `COSE_ALG`, `COSE_DUPLICATE_ALG`, `COSE_SIGNATURE`.
pub fn sign_encode(payload: &[u8], signers: &[SignSigner<'_>]) -> WireResult<Vec<u8>> {
    if signers.is_empty() {
        return Err(err(C::CoseStructure, "at least one signer is required"));
    }
    let mut seen = Vec::new();
    let mut signatures = Vec::new();
    for signer in signers {
        if signer.alg != ALG_EDDSA && signer.alg != ALG_ML_DSA_65 {
            return Err(err(C::CoseAlg, "algorithm not allowed in COSE_Sign"));
        }
        if seen.contains(&signer.alg) {
            return Err(err(C::CoseDuplicateAlg, "one signature per algorithm"));
        }
        seen.push(signer.alg);
        let protected = encode_protected(signer.alg, &Kid::Bytes(signer.kid.to_vec()))?;
        let signature = (signer.sign)(&sig_structure(&protected, payload)?)?;
        if Some(signature.len()) != keys::signature_size(signer.alg) {
            return Err(err(C::CoseSignature, "signer produced a signature of wrong size"));
        }
        signatures.push(Value::Array(vec![Value::Bytes(protected), Value::Map(Vec::new()), Value::Bytes(signature)]));
    }
    cbor::encode(&Value::Tag(
        TAG_SIGN,
        Box::new(Value::Array(vec![Value::bytes(Vec::new()), Value::Map(Vec::new()), Value::bytes(payload), Value::Array(signatures)])),
    ))
}

/// Parse and structurally validate a COSE_Sign.
///
/// # Errors
/// `CBOR_*`, `COSE_TAG`, `COSE_STRUCTURE`, `COSE_HEADER`, `COSE_ALG`, `COSE_KID`,
/// `COSE_DUPLICATE_ALG`, `COSE_SIGNATURE`.
pub fn sign_decode(data: &[u8], limits: DecodeLimits) -> WireResult<SignMessage> {
    let mut items = as_tagged_array(data, TAG_SIGN, 4, limits)?.into_iter();
    let (Some(body_protected), Some(unprotected), Some(payload), Some(signatures)) =
        (items.next(), items.next(), items.next(), items.next())
    else {
        return Err(err(C::CoseStructure, "expected 4 elements"));
    };
    if !require_bstr(body_protected)?.is_empty() {
        return Err(err(C::CoseHeader, "body protected header must be the empty bstr"));
    }
    require_empty_map(&unprotected)?;
    let payload = require_bstr(payload)?;
    let Value::Array(entries) = signatures else {
        return Err(err(C::CoseStructure, "signatures must be a non-empty array"));
    };
    if entries.is_empty() {
        return Err(err(C::CoseStructure, "signatures must be a non-empty array"));
    }
    let mut parsed: Vec<CoseSignature> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Array(parts) = entry else {
            return Err(err(C::CoseStructure, "COSE_Signature must be a 3-element array"));
        };
        let mut parts = parts.into_iter();
        let (Some(protected), Some(unprot), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(err(C::CoseStructure, "COSE_Signature must be a 3-element array"));
        };
        let protected = require_bstr(protected)?;
        require_empty_map(&unprot)?;
        let signature = require_bstr(signature)?;
        let (alg, kid) = parse_protected(&protected, &[ALG_EDDSA, ALG_ML_DSA_65], limits)?;
        let kid: [u8; KEY_ID_SIZE] = match kid {
            Kid::Bytes(b) => b.try_into().map_err(|_| err(C::CoseKid, "COSE_Sign kid must be an 8-byte bstr"))?,
            Kid::Text(_) => return Err(err(C::CoseKid, "COSE_Sign kid must be an 8-byte bstr")),
        };
        if parsed.iter().any(|s| s.alg == alg) {
            return Err(err(C::CoseDuplicateAlg, "more than one signature with the same alg"));
        }
        if Some(signature.len()) != keys::signature_size(alg) {
            return Err(err(C::CoseSignature, "signature has the wrong length"));
        }
        parsed.push(CoseSignature { protected, alg, kid, signature });
    }
    Ok(SignMessage { payload, signatures: parsed })
}

// ---------------------------------------------------------------------------------------------
// COSE_Encrypt0 (Config)
// ---------------------------------------------------------------------------------------------

/// A structurally valid IronMesh COSE_Encrypt0 (not yet decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypt0Message {
    /// Protected header bytes (`a1 01 03`).
    pub protected: Vec<u8>,
    /// AES-GCM IV.
    pub iv: [u8; A256GCM_IV_SIZE],
    /// HPKE `enc`.
    pub enc: Vec<u8>,
    /// HPKE-sealed CEK.
    pub wrapped_key: Vec<u8>,
    /// AES-256-GCM ciphertext with tag.
    pub ciphertext: Vec<u8>,
}

impl Encrypt0Message {
    /// `Enc_structure` bytes.
    ///
    /// # Errors
    /// Never in practice.
    pub fn enc_structure(&self) -> WireResult<Vec<u8>> {
        enc_structure0(&self.protected)
    }
}

/// Serialize the IronMesh Encrypt0 layout.
///
/// # Errors
/// `COSE_HEADER` for wrong field sizes.
pub fn encrypt0_encode(iv: &[u8], enc: &[u8], wrapped_key: &[u8], ciphertext: &[u8]) -> WireResult<Vec<u8>> {
    if iv.len() != A256GCM_IV_SIZE {
        return Err(err(C::CoseHeader, "IV must be 12 bytes"));
    }
    if enc.len() != HPKE_ENC_SIZE {
        return Err(err(C::CoseHeader, "HPKE enc must be 65 bytes"));
    }
    if wrapped_key.len() != HPKE_WRAPPED_KEY_SIZE {
        return Err(err(C::CoseHeader, "wrapped key must be 48 bytes"));
    }
    let unprotected = cbor::int_map(vec![
        (HDR_IV, Value::bytes(iv)),
        (HDR_IRONMESH_HPKE, cbor::int_map(vec![(1, Value::bytes(enc)), (2, Value::bytes(wrapped_key))])),
    ]);
    cbor::encode(&Value::Tag(
        TAG_ENCRYPT0,
        Box::new(Value::Array(vec![Value::bytes(ENCRYPT0_PROTECTED.to_vec()), unprotected, Value::bytes(ciphertext)])),
    ))
}

fn exact_int_keys(entries: &[(Value, Value)], keys: &[i128]) -> bool {
    entries.len() == keys.len() && keys.iter().all(|k| entries.iter().any(|(ek, _)| *ek == Value::Int(*k)))
}

/// Parse and structurally validate an IronMesh COSE_Encrypt0.
///
/// # Errors
/// `CBOR_*`, `COSE_TAG`, `COSE_STRUCTURE`, `COSE_HEADER`, `COSE_ALG`.
pub fn encrypt0_decode(data: &[u8], limits: DecodeLimits) -> WireResult<Encrypt0Message> {
    let mut items = as_tagged_array(data, TAG_ENCRYPT0, 3, limits)?.into_iter();
    let (Some(protected), Some(unprotected), Some(ciphertext)) = (items.next(), items.next(), items.next()) else {
        return Err(err(C::CoseStructure, "expected 3 elements"));
    };
    let protected = require_bstr(protected)?;
    if protected.is_empty() {
        return Err(err(C::CoseHeader, "protected header must not be empty"));
    }
    let header = cbor::decode_with(&protected, limits)?;
    match header.as_map() {
        Some(m) if exact_int_keys(m, &[HDR_ALG]) => {}
        _ => return Err(err(C::CoseHeader, "protected header must be exactly {1: alg}")),
    }
    if header.get_int_key(HDR_ALG) != Some(&Value::Int(i128::from(ALG_A256GCM))) {
        return Err(err(C::CoseAlg, "content encryption algorithm must be A256GCM (3)"));
    }
    let Some(unprot) = unprotected.as_map().filter(|m| exact_int_keys(m, &[HDR_IV, HDR_IRONMESH_HPKE])) else {
        return Err(err(C::CoseHeader, "unprotected header must be exactly {5, -70000}"));
    };
    let _ = unprot;
    let iv: [u8; A256GCM_IV_SIZE] = unprotected
        .get_int_key(HDR_IV)
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err(C::CoseHeader, "IV must be a 12-byte bstr"))?;
    let hpke = unprotected.get_int_key(HDR_IRONMESH_HPKE).unwrap_or(&Value::Null);
    if !hpke.as_map().is_some_and(|m| exact_int_keys(m, &[1, 2])) {
        return Err(err(C::CoseHeader, "-70000 must be exactly {1: enc, 2: wrapped_key}"));
    }
    let enc = hpke
        .get_int_key(1)
        .and_then(Value::as_bytes)
        .filter(|b| b.len() == HPKE_ENC_SIZE)
        .ok_or_else(|| err(C::CoseHeader, "enc must be a 65-byte bstr"))?
        .to_vec();
    let wrapped_key = hpke
        .get_int_key(2)
        .and_then(Value::as_bytes)
        .filter(|b| b.len() == HPKE_WRAPPED_KEY_SIZE)
        .ok_or_else(|| err(C::CoseHeader, "wrapped_key must be a 48-byte bstr"))?
        .to_vec();
    let ciphertext = require_bstr(ciphertext)?;
    if ciphertext.len() < A256GCM_TAG_SIZE {
        return Err(err(C::CoseStructure, "ciphertext shorter than the AEAD tag"));
    }
    Ok(Encrypt0Message { protected, iv, enc, wrapped_key, ciphertext })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> DecodeLimits {
        DecodeLimits::default()
    }

    #[test]
    fn sign1_round_trip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let kid = Kid::Text("tenant-cmd-x".into());
        let msg = sign1_encode(b"payload", &sk, &kid).unwrap();
        let parsed = sign1_decode(&msg, lim()).unwrap();
        assert_eq!(parsed.kid, kid);
        assert_eq!(parsed.payload, b"payload");
        sign1_verify(&parsed, &PublicKey::Ed25519(sk.verifying_key())).unwrap();
        assert_eq!(kid.display(), "tenant-cmd-x");
        assert_eq!(Kid::Bytes(vec![0xab]).display(), "ab");
    }

    #[test]
    fn sign1_structural_errors() {
        let enc = |v: Value| cbor::encode(&v).unwrap();
        let prot = encode_protected(ALG_EDDSA, &Kid::Bytes(vec![1])).unwrap();
        let arr = |items: Vec<Value>| Value::Tag(TAG_SIGN1, Box::new(Value::Array(items)));
        let good = || vec![Value::bytes(prot.clone()), Value::Map(vec![]), Value::bytes(vec![]), Value::bytes(vec![0; 64])];
        assert!(sign1_decode(&enc(arr(good())), lim()).is_ok());
        assert_eq!(sign1_decode(&enc(Value::Array(good())), lim()).unwrap_err().code(), C::CoseTag);
        assert_eq!(sign1_decode(&enc(Value::Tag(TAG_SIGN, Box::new(Value::Array(good())))), lim()).unwrap_err().code(), C::CoseTag);
        assert_eq!(sign1_decode(&enc(arr(vec![])), lim()).unwrap_err().code(), C::CoseStructure);
        let mut g = good();
        g[2] = Value::Null;
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseStructure);
        let mut g = good();
        g[0] = Value::bytes(vec![]);
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseHeader);
        let mut g = good();
        g[0] = Value::bytes(enc(cbor::int_map(vec![(1, Value::int(-8))])));
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseHeader);
        let mut g = good();
        g[0] = Value::bytes(enc(cbor::int_map(vec![(1, Value::int(-49)), (4, Value::bytes(vec![1]))])));
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseAlg);
        let mut g = good();
        g[0] = Value::bytes(enc(cbor::int_map(vec![(1, Value::int(-8)), (4, Value::int(1))])));
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseKid);
        let mut g = good();
        g[0] = Value::bytes(enc(cbor::int_map(vec![(1, Value::int(-8)), (4, Value::bytes(vec![1; 256]))])));
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseKid);
        let mut g = good();
        g[0] = Value::bytes(enc(Value::Array(vec![])));
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseHeader);
        let mut g = good();
        g[3] = Value::bytes(vec![0; 63]);
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseSignature);
        let mut g = good();
        g[1] = Value::Map(vec![(Value::int(1), Value::int(1))]);
        assert_eq!(sign1_decode(&enc(arr(g)), lim()).unwrap_err().code(), C::CoseHeader);
        assert_eq!(encode_protected(-8, &Kid::Text(String::new())).unwrap_err().code(), C::CoseKid);
    }

    #[test]
    fn sign_round_trip_and_errors() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let kid = keys::fw_key_id(sk.verifying_key().as_bytes());
        let f = |tbs: &[u8]| CoseSigner::sign(&sk, tbs);
        let signer = SignSigner { alg: ALG_EDDSA, kid, sign: &f };
        let msg = sign_encode(b"m", std::slice::from_ref(&signer)).unwrap();
        let parsed = sign_decode(&msg, lim()).unwrap();
        assert_eq!(parsed.signatures.len(), 1);
        assert!(parsed.signature_for(ALG_EDDSA).is_some());
        assert!(parsed.signature_for(ALG_ML_DSA_65).is_none());
        assert_eq!(sign_encode(b"m", &[]).unwrap_err().code(), C::CoseStructure);
        let dup = [SignSigner { alg: ALG_EDDSA, kid, sign: &f }, SignSigner { alg: ALG_EDDSA, kid, sign: &f }];
        assert_eq!(sign_encode(b"m", &dup).unwrap_err().code(), C::CoseDuplicateAlg);
        let bad = [SignSigner { alg: ALG_ES256, kid, sign: &f }];
        assert_eq!(sign_encode(b"m", &bad).unwrap_err().code(), C::CoseAlg);
        let wrong = [SignSigner { alg: ALG_ML_DSA_65, kid, sign: &f }];
        assert_eq!(sign_encode(b"m", &wrong).unwrap_err().code(), C::CoseSignature);

        let enc = |v: Value| cbor::encode(&v).unwrap();
        let prot = encode_protected(ALG_EDDSA, &Kid::Bytes(kid.to_vec())).unwrap();
        let sig = || Value::Array(vec![Value::bytes(prot.clone()), Value::Map(vec![]), Value::bytes(vec![0; 64])]);
        let wrap = |body: Value, sigs: Value| {
            enc(Value::Tag(TAG_SIGN, Box::new(Value::Array(vec![body, Value::Map(vec![]), Value::bytes(vec![1]), sigs]))))
        };
        assert!(sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![sig()])), lim()).is_ok());
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![0xa0]), Value::Array(vec![sig()])), lim()).unwrap_err().code(), C::CoseHeader);
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![])), lim()).unwrap_err().code(), C::CoseStructure);
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![]), Value::Null), lim()).unwrap_err().code(), C::CoseStructure);
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![Value::Null])), lim()).unwrap_err().code(), C::CoseStructure);
        assert_eq!(
            sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![sig(), sig()])), lim()).unwrap_err().code(),
            C::CoseDuplicateAlg
        );
        let short_kid = encode_protected(ALG_EDDSA, &Kid::Bytes(vec![1; 7])).unwrap();
        let s = Value::Array(vec![Value::bytes(short_kid), Value::Map(vec![]), Value::bytes(vec![0; 64])]);
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![s])), lim()).unwrap_err().code(), C::CoseKid);
        let text_kid = encode_protected(ALG_EDDSA, &Kid::Text("abcdefgh".into())).unwrap();
        let s = Value::Array(vec![Value::bytes(text_kid), Value::Map(vec![]), Value::bytes(vec![0; 64])]);
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![s])), lim()).unwrap_err().code(), C::CoseKid);
        let s = Value::Array(vec![Value::bytes(prot.clone()), Value::Map(vec![]), Value::bytes(vec![0; 3])]);
        assert_eq!(sign_decode(&wrap(Value::bytes(vec![]), Value::Array(vec![s])), lim()).unwrap_err().code(), C::CoseSignature);
    }

    #[test]
    fn encrypt0_errors() {
        let good = encrypt0_encode(&[0; 12], &[4; 65], &[0; 48], &[0; 16]).unwrap();
        assert!(encrypt0_decode(&good, lim()).is_ok());
        assert_eq!(encrypt0_encode(&[0; 11], &[4; 65], &[0; 48], &[0; 16]).unwrap_err().code(), C::CoseHeader);
        assert_eq!(encrypt0_encode(&[0; 12], &[4; 64], &[0; 48], &[0; 16]).unwrap_err().code(), C::CoseHeader);
        assert_eq!(encrypt0_encode(&[0; 12], &[4; 65], &[0; 47], &[0; 16]).unwrap_err().code(), C::CoseHeader);
        let short = encrypt0_encode(&[0; 12], &[4; 65], &[0; 48], &[0; 15]).unwrap();
        assert_eq!(encrypt0_decode(&short, lim()).unwrap_err().code(), C::CoseStructure);
        let enc = |v: Value| cbor::encode(&v).unwrap();
        let mk = |prot: Vec<u8>, unprot: Value| {
            enc(Value::Tag(TAG_ENCRYPT0, Box::new(Value::Array(vec![Value::bytes(prot), unprot, Value::bytes(vec![0; 16])]))))
        };
        let unprot = || {
            cbor::int_map(vec![
                (HDR_IV, Value::bytes(vec![0; 12])),
                (HDR_IRONMESH_HPKE, cbor::int_map(vec![(1, Value::bytes(vec![4; 65])), (2, Value::bytes(vec![0; 48]))])),
            ])
        };
        assert_eq!(encrypt0_decode(&mk(vec![], unprot()), lim()).unwrap_err().code(), C::CoseHeader);
        assert_eq!(encrypt0_decode(&mk(vec![0xa1, 0x01, 0x01], unprot()), lim()).unwrap_err().code(), C::CoseAlg);
        // alg must be the integer 3: float 3.0 (f94200) and text "3" are COSE_ALG.
        assert_eq!(encrypt0_decode(&mk(vec![0xa1, 0x01, 0xf9, 0x42, 0x00], unprot()), lim()).unwrap_err().code(), C::CoseAlg);
        assert_eq!(encrypt0_decode(&mk(vec![0xa1, 0x01, 0x61, 0x33], unprot()), lim()).unwrap_err().code(), C::CoseAlg);
        assert_eq!(encrypt0_decode(&mk(vec![0xa0], unprot()), lim()).unwrap_err().code(), C::CoseHeader);
        assert_eq!(encrypt0_decode(&mk(ENCRYPT0_PROTECTED.to_vec(), Value::Map(vec![])), lim()).unwrap_err().code(), C::CoseHeader);
        let bad_iv = cbor::int_map(vec![
            (HDR_IV, Value::bytes(vec![0; 11])),
            (HDR_IRONMESH_HPKE, cbor::int_map(vec![(1, Value::bytes(vec![4; 65])), (2, Value::bytes(vec![0; 48]))])),
        ]);
        assert_eq!(encrypt0_decode(&mk(ENCRYPT0_PROTECTED.to_vec(), bad_iv), lim()).unwrap_err().code(), C::CoseHeader);
        let bad_hpke = cbor::int_map(vec![(HDR_IV, Value::bytes(vec![0; 12])), (HDR_IRONMESH_HPKE, Value::Null)]);
        assert_eq!(encrypt0_decode(&mk(ENCRYPT0_PROTECTED.to_vec(), bad_hpke), lim()).unwrap_err().code(), C::CoseHeader);
        let bad_enc = cbor::int_map(vec![
            (HDR_IV, Value::bytes(vec![0; 12])),
            (HDR_IRONMESH_HPKE, cbor::int_map(vec![(1, Value::bytes(vec![4; 64])), (2, Value::bytes(vec![0; 48]))])),
        ]);
        assert_eq!(encrypt0_decode(&mk(ENCRYPT0_PROTECTED.to_vec(), bad_enc), lim()).unwrap_err().code(), C::CoseHeader);
        let bad_wrap = cbor::int_map(vec![
            (HDR_IV, Value::bytes(vec![0; 12])),
            (HDR_IRONMESH_HPKE, cbor::int_map(vec![(1, Value::bytes(vec![4; 65])), (2, Value::bytes(vec![0; 4]))])),
        ]);
        assert_eq!(encrypt0_decode(&mk(ENCRYPT0_PROTECTED.to_vec(), bad_wrap), lim()).unwrap_err().code(), C::CoseHeader);
    }
}
