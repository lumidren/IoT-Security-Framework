//! Public keys, raw COSE signature verification and the signer abstraction.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use sha2::{Digest, Sha256};

use super::error::{err, ErrorCode as C, WireResult};

/// COSE `ES256` (ECDSA P-256 / SHA-256).
pub const ALG_ES256: i64 = -7;
/// COSE `EdDSA` (Ed25519).
pub const ALG_EDDSA: i64 = -8;
/// COSE `ML-DSA-65`.
pub const ALG_ML_DSA_65: i64 = -49;
/// COSE `A256GCM`.
pub const ALG_A256GCM: i64 = 3;

/// ML-DSA-65 public key size.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
/// ML-DSA-65 signature size.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// Expected signature length for a COSE algorithm.
#[must_use]
pub fn signature_size(alg: i64) -> Option<usize> {
    match alg {
        ALG_ES256 | ALG_EDDSA => Some(64),
        ALG_ML_DSA_65 => Some(ML_DSA_65_SIGNATURE_SIZE),
        _ => None,
    }
}

/// A verification key for COSE_Sign1 messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// ECDSA P-256 (ES256).
    P256(p256::ecdsa::VerifyingKey),
    /// Ed25519 (EdDSA).
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// Parse a 65-byte uncompressed SEC1 P-256 point.
    ///
    /// # Errors
    /// `COSE_KEY_TYPE` if the bytes are not a valid point.
    pub fn p256_from_sec1(raw: &[u8]) -> WireResult<Self> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(raw).map(PublicKey::P256).map_err(|_| err(C::CoseKeyType, "invalid P-256 public key"))
    }

    /// Parse a raw 32-byte Ed25519 public key.
    ///
    /// # Errors
    /// `COSE_KEY_TYPE` if the bytes are not a valid key.
    pub fn ed25519_from_raw(raw: &[u8]) -> WireResult<Self> {
        let arr: [u8; 32] = raw.try_into().map_err(|_| err(C::CoseKeyType, "Ed25519 key must be 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr).map(PublicKey::Ed25519).map_err(|_| err(C::CoseKeyType, "invalid Ed25519 public key"))
    }

    /// The COSE algorithm implied by the key type.
    #[must_use]
    pub fn alg(&self) -> i64 {
        match self {
            PublicKey::P256(_) => ALG_ES256,
            PublicKey::Ed25519(_) => ALG_EDDSA,
        }
    }

    /// Raw bytes (65-byte uncompressed point or 32-byte Ed25519 key).
    #[must_use]
    pub fn raw(&self) -> Vec<u8> {
        match self {
            PublicKey::P256(k) => k.to_encoded_point(false).as_bytes().to_vec(),
            PublicKey::Ed25519(k) => k.to_bytes().to_vec(),
        }
    }
}

/// Verify a COSE wire-form signature (`r || s` for ES256, 64 bytes for EdDSA).
///
/// # Errors
/// `COSE_ALG` if `alg` does not match the key type, `COSE_SIGNATURE` on any verification failure.
pub fn raw_verify(key: &PublicKey, alg: i64, data: &[u8], signature: &[u8]) -> WireResult<()> {
    if alg != key.alg() {
        return Err(err(C::CoseAlg, "algorithm does not match the key type"));
    }
    if Some(signature.len()) != signature_size(alg) {
        return Err(err(C::CoseSignature, "signature has the wrong length"));
    }
    let ok = match key {
        PublicKey::P256(k) => p256::ecdsa::Signature::from_slice(signature).ok().is_some_and(|sig| k.verify(data, &sig).is_ok()),
        PublicKey::Ed25519(k) => {
            ed25519_dalek::Signature::from_slice(signature).ok().is_some_and(|sig| k.verify_strict(data, &sig).is_ok())
        }
    };
    if ok {
        Ok(())
    } else {
        Err(err(C::CoseSignature, "signature verification failed"))
    }
}

/// `kid` of a firmware-signing key: `SHA-256(raw public key)[0:8]`.
#[must_use]
pub fn fw_key_id(raw_public_key: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(raw_public_key);
    let mut kid = [0u8; 8];
    kid.copy_from_slice(&digest[..8]);
    kid
}

/// Something that can produce a COSE signature over a to-be-signed byte string.
///
/// Implemented by in-memory keys (tests, fleet simulator) and by the device identity backends
/// (software / TPM / OP-TEE) through [`crate::identity::IdentitySigner`].
pub trait CoseSigner {
    /// COSE algorithm (`-7` or `-8`).
    fn alg(&self) -> i64;
    /// Sign the to-be-signed bytes, returning the COSE wire-form signature.
    ///
    /// # Errors
    /// Backend-specific failure, reported as `COSE_SIGNATURE`.
    fn sign(&self, tbs: &[u8]) -> WireResult<Vec<u8>>;
}

impl CoseSigner for ed25519_dalek::SigningKey {
    fn alg(&self) -> i64 {
        ALG_EDDSA
    }

    fn sign(&self, tbs: &[u8]) -> WireResult<Vec<u8>> {
        Ok(ed25519_dalek::Signer::sign(self, tbs).to_bytes().to_vec())
    }
}

impl CoseSigner for p256::ecdsa::SigningKey {
    fn alg(&self) -> i64 {
        ALG_ES256
    }

    fn sign(&self, tbs: &[u8]) -> WireResult<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.try_sign(tbs).map_err(|_| err(C::CoseSignature, "ECDSA signing failed"))?;
        Ok(sig.to_bytes().to_vec())
    }
}

/// Convert an ECDSA `r || s` signature into ASN.1 DER (for TLS and X.509).
///
/// # Errors
/// `COSE_SIGNATURE` if the input is not a valid 64-byte signature.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> WireResult<Vec<u8>> {
    let sig = p256::ecdsa::Signature::from_slice(raw).map_err(|_| err(C::CoseSignature, "invalid r||s signature"))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

/// ML-DSA-65 verification (FIPS 204, pure mode, empty context).
#[cfg(feature = "pq")]
#[must_use]
pub fn mldsa65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE || signature.len() != ML_DSA_65_SIGNATURE_SIZE {
        return false;
    }
    let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc);
    let Ok(sig) = Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    vk.verify_with_context(message, &[], &sig)
}

/// Whether this build can verify ML-DSA-65 signatures.
#[must_use]
pub const fn mldsa_available() -> bool {
    cfg!(feature = "pq")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_round_trip_and_der() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = PublicKey::P256(*sk.verifying_key());
        let sig = CoseSigner::sign(&sk, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
        raw_verify(&pk, ALG_ES256, b"hello", &sig).unwrap();
        assert_eq!(raw_verify(&pk, ALG_EDDSA, b"hello", &sig).unwrap_err().code(), C::CoseAlg);
        assert_eq!(raw_verify(&pk, ALG_ES256, b"hellO", &sig).unwrap_err().code(), C::CoseSignature);
        assert_eq!(raw_verify(&pk, ALG_ES256, b"hello", &sig[..63]).unwrap_err().code(), C::CoseSignature);
        assert_eq!(raw_verify(&pk, ALG_ES256, b"hello", &[0u8; 64]).unwrap_err().code(), C::CoseSignature);
        assert!(ecdsa_raw_to_der(&sig).unwrap().starts_with(&[0x30]));
        assert!(ecdsa_raw_to_der(&[0u8; 64]).is_err());
        let raw = pk.raw();
        assert_eq!(raw.len(), 65);
        assert_eq!(PublicKey::p256_from_sec1(&raw).unwrap(), pk);
        assert_eq!(PublicKey::p256_from_sec1(&raw[..10]).unwrap_err().code(), C::CoseKeyType);
        assert_eq!(CoseSigner::alg(&sk), ALG_ES256);
    }

    #[test]
    fn eddsa_round_trip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pk = PublicKey::Ed25519(sk.verifying_key());
        let sig = CoseSigner::sign(&sk, b"x").unwrap();
        raw_verify(&pk, ALG_EDDSA, b"x", &sig).unwrap();
        assert_eq!(raw_verify(&pk, ALG_EDDSA, b"y", &sig).unwrap_err().code(), C::CoseSignature);
        assert_eq!(PublicKey::ed25519_from_raw(&pk.raw()).unwrap(), pk);
        assert_eq!(PublicKey::ed25519_from_raw(&[1u8; 3]).unwrap_err().code(), C::CoseKeyType);
        assert_eq!(fw_key_id(&pk.raw()).len(), 8);
        assert_eq!(signature_size(99), None);
        assert_eq!(CoseSigner::alg(&sk), ALG_EDDSA);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn mldsa_rejects_bad_sizes() {
        assert!(!mldsa65_verify(&[0u8; 10], b"m", &[0u8; ML_DSA_65_SIGNATURE_SIZE]));
        assert!(!mldsa65_verify(&[0u8; ML_DSA_65_PUBLIC_KEY_SIZE], b"m", &[0u8; 3]));
        assert!(!mldsa65_verify(&[0u8; ML_DSA_65_PUBLIC_KEY_SIZE], b"m", &[0u8; ML_DSA_65_SIGNATURE_SIZE]));
        assert!(mldsa_available());
    }
}
