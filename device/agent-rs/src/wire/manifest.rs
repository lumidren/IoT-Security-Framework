//! Firmware manifest (`WIRE_FORMAT.md` §6): encoding, hybrid verification and the pure
//! acceptance rules `accept_image` / `accept_patch`.

use sha2::{Digest, Sha256};

use super::cbor::{self, DecodeLimits, Value};
use super::cose::{self, SignSigner};
use super::envelope::Fields;
use super::error::{err, ErrorCode as C, WireError, WireResult};
use super::ids;
use super::keys::{self, PublicKey, ALG_EDDSA, ALG_ML_DSA_65, ML_DSA_65_PUBLIC_KEY_SIZE};

const MAX_TSTR: usize = 64;

/// A detached signing function over `Sig_structure` bytes.
pub type SignFn<'a> = dyn Fn(&[u8]) -> WireResult<Vec<u8>> + 'a;

/// Manifest key 8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaInfo {
    /// Hash of the base image.
    pub base_sha256: [u8; 32],
    /// Hash of the patch.
    pub patch_sha256: [u8; 32],
    /// Patch size.
    pub patch_size: u64,
}

/// The manifest map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// 1
    pub product: String,
    /// 2
    pub version: String,
    /// 3
    pub version_code: u64,
    /// 4
    pub image_sha256: [u8; 32],
    /// 5
    pub image_size: u64,
    /// 6
    pub created_at: u64,
    /// 7
    pub min_version_code: u64,
    /// 8
    pub delta: Option<DeltaInfo>,
    /// 9
    pub signing_key_id: String,
}

impl Manifest {
    /// Integer-keyed map value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        cbor::int_map(vec![
            (1, Value::text(self.product.clone())),
            (2, Value::text(self.version.clone())),
            (3, Value::int(self.version_code)),
            (4, Value::bytes(self.image_sha256.to_vec())),
            (5, Value::int(self.image_size)),
            (6, Value::int(self.created_at)),
            (7, Value::int(self.min_version_code)),
            (
                8,
                self.delta.as_ref().map_or(Value::Null, |d| {
                    cbor::int_map(vec![
                        (1, Value::bytes(d.base_sha256.to_vec())),
                        (2, Value::bytes(d.patch_sha256.to_vec())),
                        (3, Value::int(d.patch_size)),
                    ])
                }),
            ),
            (9, Value::text(self.signing_key_id.clone())),
        ])
    }

    fn from_map(m: &[(Value, Value)]) -> WireResult<Self> {
        let f = Fields::new(m, C::MfField);
        f.expect_keys(&[1, 2, 3, 4, 5, 6, 7, 8, 9], &[], "manifest: key set")?;
        let delta = match f.get(8) {
            Some(Value::Null) | None => None,
            Some(Value::Map(dm)) => {
                let df = Fields::new(dm, C::MfField);
                df.expect_keys(&[1, 2, 3], &[], "delta: key set")?;
                Some(DeltaInfo {
                    base_sha256: df.bstr32(1, "delta.base_sha256")?,
                    patch_sha256: df.bstr32(2, "delta.patch_sha256")?,
                    patch_size: df.uint(3, "delta.patch_size")?,
                })
            }
            Some(_) => return Err(err(C::MfField, "delta: expected null or map")),
        };
        let product = f.tstr(1, 1, MAX_TSTR, "product")?;
        if !ids::is_product(&product) {
            return Err(err(C::MfField, "product: invalid format"));
        }
        let version = f.tstr(2, 1, MAX_TSTR, "version")?;
        if !ids::is_semver(&version) {
            return Err(err(C::MfField, "version: not a semantic version"));
        }
        let manifest = Manifest {
            product,
            version,
            version_code: f.uint(3, "version_code")?,
            image_sha256: f.bstr32(4, "image_sha256")?,
            image_size: f.uint(5, "image_size")?,
            created_at: f.uint(6, "created_at")?,
            min_version_code: f.uint(7, "min_version_code")?,
            delta,
            signing_key_id: f.tstr(9, 1, MAX_TSTR, "signing_key_id")?,
        };
        if manifest.min_version_code > manifest.version_code {
            return Err(err(C::MfField, "min_version_code must not exceed version_code"));
        }
        Ok(manifest)
    }
}

/// Canonical CBOR of a (validated) manifest.
///
/// # Errors
/// `MF_FIELD` for invalid fields.
pub fn encode_manifest(manifest: &Manifest) -> WireResult<Vec<u8>> {
    let v = manifest.to_value();
    Manifest::from_map(v.as_map().unwrap_or(&[]))?;
    cbor::encode(&v)
}

/// Strictly decode and validate a manifest map.
///
/// # Errors
/// `MF_STRUCTURE` (not a canonical CBOR map) or `MF_FIELD`.
pub fn decode_manifest(data: &[u8], limits: DecodeLimits) -> WireResult<Manifest> {
    let m = cbor::decode_map(data, limits)
        .map_err(|e| WireError::with(C::MfStructure, format!("manifest is not a canonical CBOR map ({})", e.code())))?;
    Manifest::from_map(&m)
}

/// Sign a manifest with Ed25519 (and optionally an ML-DSA-65 signer function).
///
/// # Errors
/// Manifest validation or COSE errors.
pub fn sign_manifest(payload: &[u8], ed25519: &ed25519_dalek::SigningKey, mldsa: Option<(&[u8], &SignFn<'_>)>) -> WireResult<Vec<u8>> {
    decode_manifest(payload, DecodeLimits::default())?;
    let ed_sign = |tbs: &[u8]| keys::CoseSigner::sign(ed25519, tbs);
    let mut signers = vec![SignSigner { alg: ALG_EDDSA, kid: keys::fw_key_id(ed25519.verifying_key().as_bytes()), sign: &ed_sign }];
    if let Some((pk, f)) = mldsa {
        signers.push(SignSigner { alg: ALG_ML_DSA_65, kid: keys::fw_key_id(pk), sign: f });
    }
    cose::sign_encode(payload, &signers)
}

/// Result of [`verify_manifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    /// The decoded manifest.
    pub manifest: Manifest,
    /// Exact signed payload bytes.
    pub payload: Vec<u8>,
    /// kid of the Ed25519 key that verified.
    pub ed25519_kid: [u8; 8],
    /// An ML-DSA-65 signature was present and verified.
    pub pq_verified: bool,
}

/// Verify a signed manifest against the bundle's raw `fw_signing_pubkeys` (`WIRE_FORMAT.md` §6.3).
///
/// # Errors
/// `CBOR_*`/`COSE_*` structure errors, `MF_STRUCTURE` (bad trusted key), `COSE_SIGNATURE`,
/// `COSE_UNKNOWN_KEY`, `COSE_PQ_REQUIRED`, `MLDSA_NOT_AVAILABLE`, `MF_*`.
pub fn verify_manifest(data: &[u8], trusted: &[Vec<u8>], require_pq: bool, limits: DecodeLimits) -> WireResult<VerifiedManifest> {
    let message = cose::sign_decode(data, limits)?;
    let mut ed_keys: Vec<([u8; 8], &[u8])> = Vec::new();
    let mut pq_keys: Vec<([u8; 8], &[u8])> = Vec::new();
    for raw in trusted {
        match raw.len() {
            32 => ed_keys.push((keys::fw_key_id(raw), raw)),
            ML_DSA_65_PUBLIC_KEY_SIZE => pq_keys.push((keys::fw_key_id(raw), raw)),
            n => return Err(WireError::with(C::MfStructure, format!("trusted key of unsupported size {n}"))),
        }
    }
    let ed_sig = message.signature_for(ALG_EDDSA).ok_or_else(|| err(C::CoseSignature, "mandatory Ed25519 signature missing"))?;
    let raw_ed = ed_keys
        .iter()
        .find(|(kid, _)| *kid == ed_sig.kid)
        .map(|(_, k)| *k)
        .ok_or_else(|| err(C::CoseUnknownKey, "Ed25519 signing key is not trusted"))?;
    let pk = PublicKey::ed25519_from_raw(raw_ed).map_err(|e| e.recode(C::CoseSignature))?;
    keys::raw_verify(&pk, ALG_EDDSA, &message.to_be_signed(ed_sig)?, &ed_sig.signature)?;

    let mut pq_verified = false;
    let pq_sig = message.signature_for(ALG_ML_DSA_65);
    if require_pq {
        let pq_sig = pq_sig.ok_or_else(|| err(C::CosePqRequired, "ML-DSA-65 signature required but absent"))?;
        if !keys::mldsa_available() {
            return Err(err(C::MldsaNotAvailable, "no ML-DSA-65 backend in this build"));
        }
        let raw_pq = pq_keys
            .iter()
            .find(|(kid, _)| *kid == pq_sig.kid)
            .map(|(_, k)| *k)
            .ok_or_else(|| err(C::CoseUnknownKey, "ML-DSA-65 signing key is not trusted"))?;
        if !mldsa_verify(raw_pq, &message.to_be_signed(pq_sig)?, &pq_sig.signature) {
            return Err(err(C::CoseSignature, "ML-DSA-65 signature verification failed"));
        }
        pq_verified = true;
    } else if let (Some(pq_sig), true) = (pq_sig, keys::mldsa_available()) {
        if let Some((_, raw_pq)) = pq_keys.iter().find(|(kid, _)| *kid == pq_sig.kid) {
            if !mldsa_verify(raw_pq, &message.to_be_signed(pq_sig)?, &pq_sig.signature) {
                return Err(err(C::CoseSignature, "ML-DSA-65 signature verification failed"));
            }
            pq_verified = true;
        }
    }
    let ed25519_kid = ed_sig.kid;
    let manifest = decode_manifest(&message.payload, limits)?;
    Ok(VerifiedManifest { manifest, payload: message.payload, ed25519_kid, pq_verified })
}

#[cfg(feature = "pq")]
fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    keys::mldsa65_verify(pk, msg, sig)
}

#[cfg(not(feature = "pq"))]
fn mldsa_verify(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
    false
}

/// Outcome of an acceptance rule: `Ok(())` or the rejecting code.
pub type Acceptance = Result<(), C>;

/// `accept_image` (`WIRE_FORMAT.md` §6.4), given the image length and SHA-256.
pub fn accept_image_digest(
    manifest: &Manifest,
    image_len: u64,
    image_sha256: &[u8; 32],
    current_version_code: u64,
    product: &str,
) -> Acceptance {
    if manifest.product != product {
        return Err(C::MfProduct);
    }
    if manifest.version_code <= current_version_code {
        return Err(C::MfRollback);
    }
    if current_version_code < manifest.min_version_code {
        return Err(C::MfMinVersion);
    }
    if image_len != manifest.image_size {
        return Err(C::MfSizeMismatch);
    }
    if *image_sha256 != manifest.image_sha256 {
        return Err(C::MfHashMismatch);
    }
    Ok(())
}

/// `accept_image` over an in-memory image.
pub fn accept_image(manifest: &Manifest, image: &[u8], current_version_code: u64, product: &str) -> Acceptance {
    let digest: [u8; 32] = Sha256::digest(image).into();
    accept_image_digest(manifest, image.len() as u64, &digest, current_version_code, product)
}

/// `accept_patch` given the patch length and SHA-256.
pub fn accept_patch_digest(manifest: &Manifest, patch_len: u64, patch_sha256: &[u8; 32], current_fw_hash: &[u8; 32]) -> Acceptance {
    let Some(delta) = &manifest.delta else {
        return Err(C::MfNoDelta);
    };
    if delta.base_sha256 != *current_fw_hash {
        return Err(C::DeltaBaseHash);
    }
    if patch_len != delta.patch_size {
        return Err(C::MfSizeMismatch);
    }
    if *patch_sha256 != delta.patch_sha256 {
        return Err(C::MfHashMismatch);
    }
    Ok(())
}

/// `accept_patch` over an in-memory patch.
pub fn accept_patch(manifest: &Manifest, patch: &[u8], current_fw_hash: &[u8; 32]) -> Acceptance {
    let digest: [u8; 32] = Sha256::digest(patch).into();
    accept_patch_digest(manifest, patch.len() as u64, &digest, current_fw_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            product: "gateway-rpi".into(),
            version: "2.4.1".into(),
            version_code: 10,
            image_sha256: Sha256::digest(b"img").into(),
            image_size: 3,
            created_at: 1,
            min_version_code: 5,
            delta: Some(DeltaInfo { base_sha256: [1; 32], patch_sha256: Sha256::digest(b"p").into(), patch_size: 1 }),
            signing_key_id: "k".into(),
        }
    }

    #[test]
    fn round_trip_and_acceptance() {
        let m = sample();
        let bytes = encode_manifest(&m).unwrap();
        assert_eq!(decode_manifest(&bytes, DecodeLimits::default()).unwrap(), m);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let signed = sign_manifest(&bytes, &sk, None).unwrap();
        let trusted = vec![sk.verifying_key().to_bytes().to_vec()];
        let v = verify_manifest(&signed, &trusted, false, DecodeLimits::default()).unwrap();
        assert!(!v.pq_verified);
        assert_eq!(verify_manifest(&signed, &[vec![1; 3]], false, DecodeLimits::default()).unwrap_err().code(), C::MfStructure);
        assert_eq!(accept_image(&m, b"img", 9, "gateway-rpi"), Ok(()));
        assert_eq!(accept_image(&m, b"img", 9, "x"), Err(C::MfProduct));
        assert_eq!(accept_image(&m, b"img", 10, "gateway-rpi"), Err(C::MfRollback));
        assert_eq!(accept_image(&m, b"img", 4, "gateway-rpi"), Err(C::MfMinVersion));
        assert_eq!(accept_image(&m, b"im", 9, "gateway-rpi"), Err(C::MfSizeMismatch));
        assert_eq!(accept_image(&m, b"imh", 9, "gateway-rpi"), Err(C::MfHashMismatch));
        assert_eq!(accept_patch(&m, b"p", &[1; 32]), Ok(()));
        assert_eq!(accept_patch(&m, b"p", &[2; 32]), Err(C::DeltaBaseHash));
        assert_eq!(accept_patch(&m, b"pp", &[1; 32]), Err(C::MfSizeMismatch));
        assert_eq!(accept_patch(&m, b"q", &[1; 32]), Err(C::MfHashMismatch));
        let mut full = m.clone();
        full.delta = None;
        assert_eq!(accept_patch(&full, b"p", &[1; 32]), Err(C::MfNoDelta));
    }

    #[test]
    fn field_errors() {
        let mut m = sample();
        m.min_version_code = 11;
        assert_eq!(encode_manifest(&m).unwrap_err().code(), C::MfField);
        let mut m = sample();
        m.product = "Bad".into();
        assert_eq!(encode_manifest(&m).unwrap_err().code(), C::MfField);
        let mut m = sample();
        m.version = "\u{0662}.4.1".into();
        assert_eq!(encode_manifest(&m).unwrap_err().code(), C::MfField);
        let mut m = sample();
        m.version = "1".into();
        assert_eq!(encode_manifest(&m).unwrap_err().code(), C::MfField);
        assert_eq!(decode_manifest(&[0x00], DecodeLimits::default()).unwrap_err().code(), C::MfStructure);
        assert_eq!(decode_manifest(&[0xff], DecodeLimits::default()).unwrap_err().code(), C::MfStructure);
        let mut v = sample().to_value();
        if let Value::Map(e) = &mut v {
            e[7].1 = Value::int(1);
        }
        assert_eq!(decode_manifest(&cbor::encode(&v).unwrap(), DecodeLimits::default()).unwrap_err().code(), C::MfField);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        assert_eq!(sign_manifest(&[0xa0], &sk, None).unwrap_err().code(), C::MfField);
    }
}
