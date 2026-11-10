//! Device identity: one trait, three backends (`software`, `tpm`, `optee`).
//!
//! Private keys are generated inside the backend and never leave it in plaintext; callers only
//! ever see public keys, signatures over SHA-256 digests and ECDH shared secrets (for the
//! HPKE-wrapped Config). Three key slots exist: the factory **bootstrap** key, the current
//! **operational** key and a **pending** key generated for an enrollment in progress.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::envelope::{SeType, Tpm2Evidence};
use crate::wire::error::{ErrorCode, WireError, WireResult};
use crate::wire::hpke::EcdhRecipient;
use crate::wire::keys::{CoseSigner, ALG_ES256};

#[cfg(feature = "optee")]
pub mod optee;
pub mod software;
#[cfg(feature = "tpm")]
pub mod tpm;

/// Key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySlot {
    /// Factory bootstrap key (bootstrap certificate).
    Bootstrap,
    /// Current operational key.
    Operational,
    /// Key generated for an enrollment that has not completed yet.
    Pending,
}

impl KeySlot {
    /// File-name friendly name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            KeySlot::Bootstrap => "bootstrap",
            KeySlot::Operational => "operational",
            KeySlot::Pending => "pending",
        }
    }
}

/// Assurance level (`docs/DESIGN_CONTRACT.md` §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Assurance {
    /// Key in a secure element.
    Hardware,
    /// Key in software (lower assurance, OU `assurance:software`).
    Software,
}

/// Identity backend failure.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// I/O.
    #[error("identity I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The slot holds no key.
    #[error("no key in slot {0:?}")]
    NoKey(KeySlot),
    /// Cryptographic failure.
    #[error("identity crypto: {0}")]
    Crypto(String),
    /// Backend (TPM / TEE) failure.
    #[error("identity backend: {0}")]
    Backend(String),
    /// Insecure configuration (e.g. machine secret readable by others).
    #[error("insecure identity configuration: {0}")]
    Insecure(String),
}

/// The device identity provider.
pub trait IdentityProvider: Send + Sync + 'static {
    /// Device id (`dev-<16 hex>`), as minted by the Registry and carried in the certificate CN.
    fn device_id(&self) -> &str;
    /// Tenant id (certificate OU).
    fn tenant_id(&self) -> &str;
    /// Secure-element type reported in attestations.
    fn se_type(&self) -> SeType;
    /// Assurance level.
    fn assurance(&self) -> Assurance;
    /// Whether a slot holds a key.
    fn has_key(&self, slot: KeySlot) -> bool;
    /// Public key of a slot.
    ///
    /// # Errors
    /// [`IdentityError::NoKey`] or backend errors.
    fn public_key(&self, slot: KeySlot) -> Result<p256::PublicKey, IdentityError>;
    /// ECDSA P-256 signature (`r || s`) over a SHA-256 digest.
    ///
    /// # Errors
    /// [`IdentityError::NoKey`] or backend errors.
    fn sign(&self, slot: KeySlot, digest: &[u8; 32]) -> Result<[u8; 64], IdentityError>;
    /// ECDH with the slot key: x-coordinate of `sk * peer`.
    ///
    /// # Errors
    /// [`IdentityError::NoKey`] or backend errors.
    fn ecdh(&self, slot: KeySlot, peer: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>, IdentityError>;
    /// Generate a fresh key into the pending slot (replacing any previous pending key).
    ///
    /// # Errors
    /// Backend errors.
    fn generate_operational_key(&self) -> Result<p256::PublicKey, IdentityError>;
    /// Promote the pending key to operational (after the certificate for it was stored).
    ///
    /// # Errors
    /// [`IdentityError::NoKey`] or backend errors.
    fn commit_pending(&self) -> Result<(), IdentityError>;
    /// Generate the bootstrap key (factory mode only).
    ///
    /// # Errors
    /// Backend errors.
    fn generate_bootstrap_key(&self) -> Result<p256::PublicKey, IdentityError>;
    /// Hardware attestation evidence over `nonce` (TPM quote), `None` for other backends.
    ///
    /// # Errors
    /// Backend errors.
    fn attestation_evidence(&self, nonce: &[u8; 32]) -> Result<Option<Tpm2Evidence>, IdentityError>;
}

/// Shared provider handle.
pub type SharedIdentity = Arc<dyn IdentityProvider>;

/// COSE ES256 signer bound to one identity slot.
pub struct IdentitySigner {
    /// Provider.
    pub provider: SharedIdentity,
    /// Slot.
    pub slot: KeySlot,
}

impl CoseSigner for IdentitySigner {
    fn alg(&self) -> i64 {
        ALG_ES256
    }

    fn sign(&self, tbs: &[u8]) -> WireResult<Vec<u8>> {
        let digest: [u8; 32] = Sha256::digest(tbs).into();
        self.provider.sign(self.slot, &digest).map(|s| s.to_vec()).map_err(|e| WireError::with(ErrorCode::CoseSignature, e.to_string()))
    }
}

/// HPKE recipient bound to one identity slot (Config unwrap with the certificate key).
pub struct IdentityRecipient {
    /// Provider.
    pub provider: SharedIdentity,
    /// Slot.
    pub slot: KeySlot,
}

impl EcdhRecipient for IdentityRecipient {
    fn public_key_sec1(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToSec1Point;
        self.provider.public_key(self.slot).map(|pk| pk.to_sec1_point(false).as_bytes().to_vec()).unwrap_or_default()
    }

    fn ecdh(&self, peer: &p256::PublicKey) -> WireResult<Zeroizing<[u8; 32]>> {
        self.provider.ecdh(self.slot, peer).map_err(|e| WireError::with(ErrorCode::HpkeKey, e.to_string()))
    }
}

/// Verify that a provider's slot signs correctly (startup self-test).
///
/// # Errors
/// If signing or verification fails.
pub fn self_test(provider: &dyn IdentityProvider, slot: KeySlot) -> Result<(), IdentityError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let digest: [u8; 32] = Sha256::digest(b"ironmesh identity self-test").into();
    let sig = provider.sign(slot, &digest)?;
    let vk = p256::ecdsa::VerifyingKey::from(provider.public_key(slot)?);
    let sig = p256::ecdsa::Signature::from_slice(&sig).map_err(|e| IdentityError::Crypto(e.to_string()))?;
    vk.verify_prehash(&digest, &sig).map_err(|e| IdentityError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::software::{SecretSource, SoftwareIdentity};

    #[test]
    fn signer_and_recipient_adapters() {
        let dir = tempfile::tempdir().unwrap();
        let id = SoftwareIdentity::create(
            dir.path(),
            "dev-0000000000000001",
            "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11",
            &SecretSource::File(dir.path().join("secret")),
        )
        .unwrap();
        id.generate_bootstrap_key().unwrap();
        let shared: SharedIdentity = Arc::new(id);
        self_test(shared.as_ref(), KeySlot::Bootstrap).unwrap();
        let signer = IdentitySigner { provider: shared.clone(), slot: KeySlot::Bootstrap };
        let sig = signer.sign(b"abc").unwrap();
        let pk = crate::wire::keys::PublicKey::P256(p256::ecdsa::VerifyingKey::from(shared.public_key(KeySlot::Bootstrap).unwrap()));
        crate::wire::keys::raw_verify(&pk, ALG_ES256, b"abc", &sig).unwrap();
        assert_eq!(signer.alg(), ALG_ES256);
        let missing = IdentitySigner { provider: shared.clone(), slot: KeySlot::Operational };
        assert_eq!(missing.sign(b"x").unwrap_err().code(), ErrorCode::CoseSignature);
        let r = IdentityRecipient { provider: shared.clone(), slot: KeySlot::Bootstrap };
        assert_eq!(r.public_key_sec1().len(), 65);
        let wire = crate::wire::hpke::wrap_config(b"cfg", &shared.public_key(KeySlot::Bootstrap).unwrap(), None, None, None).unwrap();
        let pt = crate::wire::hpke::unwrap_config(&wire, &r, crate::wire::cbor::DecodeLimits::default()).unwrap();
        assert_eq!(&pt[..], b"cfg");
        let none = IdentityRecipient { provider: shared, slot: KeySlot::Pending };
        assert!(none.public_key_sec1().is_empty());
        assert_eq!(KeySlot::Pending.name(), "pending");
    }
}
