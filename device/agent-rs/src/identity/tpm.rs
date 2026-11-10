//! TPM 2.0 identity backend (cargo feature `tpm`, `tss-esapi` 7.x, needs `libtss2-esys` at build
//! and run time; compiled and tested in Linux CI only, see README "Platform support").
//!
//! Layout:
//! * a **persistent primary** storage key (ECC P-256, restricted decryption) in the owner
//!   hierarchy at `primary_handle` (default `0x81000101`), created and `EvictControl`-ed on first
//!   use;
//! * per slot (bootstrap / operational / pending) an **identity key child** of the primary:
//!   unrestricted ECC P-256 with `sign` and `decrypt` (so it can do ECDSA for TLS/COSE and
//!   `ECDH_ZGen` for the HPKE-wrapped Config) and `fixedTPM`/`fixedParent`; only the
//!   TPM-wrapped blobs (`TPM2B_PRIVATE`, `TPM2B_PUBLIC`) are stored on disk;
//! * an **AK**: restricted ECDSA-SHA256 signing child of the primary, certified at the factory
//!   (`ak.crt`), used for `TPM2_Quote` over PCRs 0, 2, 4, 7 (SHA-256 bank) with the EST nonce as
//!   qualifying data -> [`Tpm2Evidence`] `{quote: TPMS_ATTEST, signature: TPMT_SIGNATURE,
//!   ak_cert_der}`.
//!
//! `tss_esapi::Context` is neither `Send` nor `Sync`, so it lives on a dedicated worker thread
//! and requests are passed over a channel.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;

use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::constants::StructureTag;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::structures::{
    Data, Digest, EccParameter, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme, PcrSelectionListBuilder,
    PcrSlot, Private, Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::Context;
use zeroize::Zeroizing;

use super::{Assurance, IdentityError, IdentityProvider, KeySlot};
use crate::persist;
use crate::wire::envelope::{SeType, Tpm2Evidence};

/// Default persistent handle of the storage primary.
pub const DEFAULT_PRIMARY_HANDLE: u32 = 0x8100_0101;

/// TPM backend configuration.
#[derive(Debug, Clone)]
pub struct TpmConfig {
    /// TCTI, e.g. `device:/dev/tpmrm0` (default: `TPM2TOOLS_TCTI` / `TCTI` env or `device`).
    pub tcti: Option<String>,
    /// Persistent handle of the primary.
    pub primary_handle: u32,
    /// Directory with `identity.json` and the TPM-wrapped key blobs.
    pub dir: PathBuf,
    /// AK certificate (DER or PEM) issued at the factory.
    pub ak_cert_path: PathBuf,
}

enum Req {
    Generate(KeySlot, mpsc::Sender<Result<p256::PublicKey, IdentityError>>),
    Sign(KeySlot, [u8; 32], mpsc::Sender<Result<[u8; 64], IdentityError>>),
    Ecdh(KeySlot, p256::PublicKey, mpsc::Sender<Result<Zeroizing<[u8; 32]>, IdentityError>>),
    Quote([u8; 32], mpsc::Sender<Result<(Vec<u8>, Vec<u8>), IdentityError>>),
    EnsureAk(mpsc::Sender<Result<p256::PublicKey, IdentityError>>),
}

/// TPM-backed identity.
pub struct TpmIdentity {
    cfg: TpmConfig,
    device_id: String,
    tenant_id: String,
    tx: Mutex<mpsc::Sender<Req>>,
}

fn be(e: impl std::fmt::Display) -> IdentityError {
    IdentityError::Backend(e.to_string())
}

fn blob_paths(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let d = dir.join("tpm");
    (d.join(format!("{name}.pub")), d.join(format!("{name}.priv")))
}

fn sha256_scheme() -> HashScheme {
    HashScheme::new(HashingAlgorithm::Sha256)
}

fn identity_template() -> Result<Public, IdentityError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(true)
        .with_restricted(false)
        .build()
        .map_err(be)?;
    let params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_signing_key(true)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .build()
        .map_err(be)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(be)
}

fn ak_template() -> Result<Public, IdentityError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .build()
        .map_err(be)?;
    let params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(sha256_scheme()))
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()
        .map_err(be)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(be)
}

fn primary_template() -> Result<Public, IdentityError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .with_no_da(true)
        .build()
        .map_err(be)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(SymmetricDefinitionObject::AES_128_CFB, EccCurve::NistP256)
                .build()
                .map_err(be)?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(be)
}

fn public_to_p256(public: &Public) -> Result<p256::PublicKey, IdentityError> {
    let Public::Ecc { unique, .. } = public else {
        return Err(IdentityError::Backend("TPM key is not an ECC key".into()));
    };
    let x = unique.x().value();
    let y = unique.y().value();
    if x.len() > 32 || y.len() > 32 {
        return Err(IdentityError::Backend("TPM ECC point too large".into()));
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb[32 - x.len()..].copy_from_slice(x);
    yb[32 - y.len()..].copy_from_slice(y);
    let point = p256::Sec1Point::from_affine_coordinates(&xb.into(), &yb.into(), false);
    Option::from(p256::PublicKey::from_sec1_point(&point)).ok_or_else(|| IdentityError::Backend("TPM returned an invalid point".into()))
}

struct Worker {
    ctx: Context,
    cfg: TpmConfig,
    primary: Option<KeyHandle>,
}

impl Worker {
    fn primary(&mut self) -> Result<KeyHandle, IdentityError> {
        if let Some(h) = self.primary {
            return Ok(h);
        }
        let persistent = PersistentTpmHandle::new(self.cfg.primary_handle).map_err(be)?;
        let handle = match self.ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
            Ok(h) => KeyHandle::from(h),
            Err(_) => {
                let template = primary_template()?;
                let created = self
                    .ctx
                    .execute_with_nullauth_session(|c| c.create_primary(Hierarchy::Owner, template, None, None, None, None))
                    .map_err(be)?;
                let obj: ObjectHandle = created.key_handle.into();
                let persisted = self
                    .ctx
                    .execute_with_nullauth_session(|c| c.evict_control(Provision::Owner, obj, Persistent::Persistent(persistent)))
                    .map_err(be)?;
                let _ = self.ctx.flush_context(obj);
                KeyHandle::from(persisted)
            }
        };
        self.primary = Some(handle);
        Ok(handle)
    }

    fn create_child(&mut self, name: &str, template: Public) -> Result<p256::PublicKey, IdentityError> {
        let parent = self.primary()?;
        let created = self.ctx.execute_with_nullauth_session(|c| c.create(parent, template, None, None, None, None)).map_err(be)?;
        let (pub_path, priv_path) = blob_paths(&self.cfg.dir, name);
        persist::ensure_private_dir(&self.cfg.dir.join("tpm"))?;
        persist::write_atomic(&pub_path, &created.out_public.marshall().map_err(be)?)?;
        persist::write_atomic(&priv_path, created.out_private.value())?;
        public_to_p256(&created.out_public)
    }

    fn load(&mut self, name: &str) -> Result<(KeyHandle, Public), IdentityError> {
        let (pub_path, priv_path) = blob_paths(&self.cfg.dir, name);
        let public_bytes = persist::read_bounded(&pub_path, 4096)?.ok_or(IdentityError::Backend(format!("no TPM key {name}")))?;
        let private_bytes = persist::read_bounded(&priv_path, 4096)?.ok_or(IdentityError::Backend(format!("no TPM key {name}")))?;
        let public = Public::unmarshall(&public_bytes).map_err(be)?;
        let private = Private::try_from(private_bytes).map_err(be)?;
        let parent = self.primary()?;
        let p2 = public.clone();
        let handle = self.ctx.execute_with_nullauth_session(|c| c.load(parent, private, p2)).map_err(be)?;
        Ok((handle, public))
    }

    fn sign(&mut self, slot: KeySlot, digest: [u8; 32]) -> Result<[u8; 64], IdentityError> {
        let (handle, _) = self.load(slot.name())?;
        let validation: HashcheckTicket =
            TPMT_TK_HASHCHECK { tag: StructureTag::Hashcheck.into(), hierarchy: TPM2_RH_NULL, digest: Default::default() }
                .try_into()
                .map_err(be)?;
        let result = self.ctx.execute_with_nullauth_session(|c| {
            c.sign(handle, Digest::try_from(digest.to_vec())?, SignatureScheme::EcDsa { hash_scheme: sha256_scheme() }, validation)
        });
        let _ = self.ctx.flush_context(handle.into());
        match result.map_err(be)? {
            Signature::EcDsa(sig) => {
                let (r, s) = (sig.signature_r().value(), sig.signature_s().value());
                if r.len() > 32 || s.len() > 32 {
                    return Err(IdentityError::Backend("TPM signature component too large".into()));
                }
                let mut out = [0u8; 64];
                out[32 - r.len()..32].copy_from_slice(r);
                out[64 - s.len()..].copy_from_slice(s);
                Ok(out)
            }
            _ => Err(IdentityError::Backend("TPM returned a non-ECDSA signature".into())),
        }
    }

    fn ecdh(&mut self, slot: KeySlot, peer: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let (handle, _) = self.load(slot.name())?;
        let point = peer.to_sec1_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            return Err(IdentityError::Crypto("peer point at infinity".into()));
        };
        let in_point = EccPoint::new(EccParameter::try_from(x.to_vec()).map_err(be)?, EccParameter::try_from(y.to_vec()).map_err(be)?);
        let result = self.ctx.execute_with_nullauth_session(|c| c.ecdh_z_gen(handle, in_point));
        let _ = self.ctx.flush_context(handle.into());
        let z = result.map_err(be)?;
        let zx = z.x().value();
        if zx.len() > 32 {
            return Err(IdentityError::Backend("ECDH_ZGen result too large".into()));
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out[32 - zx.len()..].copy_from_slice(zx);
        Ok(out)
    }

    fn ensure_ak(&mut self) -> Result<p256::PublicKey, IdentityError> {
        let (pub_path, _) = blob_paths(&self.cfg.dir, "ak");
        if let Some(bytes) = persist::read_bounded(&pub_path, 4096)? {
            return public_to_p256(&Public::unmarshall(&bytes).map_err(be)?);
        }
        self.create_child("ak", ak_template()?)
    }

    fn quote(&mut self, nonce: [u8; 32]) -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
        self.ensure_ak()?;
        let (ak, _) = self.load("ak")?;
        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot2, PcrSlot::Slot4, PcrSlot::Slot7])
            .build()
            .map_err(be)?;
        let result =
            self.ctx.execute_with_nullauth_session(|c| c.quote(ak, Data::try_from(nonce.to_vec())?, SignatureScheme::Null, selection));
        let _ = self.ctx.flush_context(ak.into());
        let (attest, signature) = result.map_err(be)?;
        Ok((attest.marshall().map_err(be)?, signature.marshall().map_err(be)?))
    }

    fn run(mut self, rx: mpsc::Receiver<Req>) {
        while let Ok(req) = rx.recv() {
            match req {
                Req::Generate(slot, reply) => {
                    let _ = reply.send(identity_template().and_then(|t| self.create_child(slot.name(), t)));
                }
                Req::Sign(slot, digest, reply) => {
                    let _ = reply.send(self.sign(slot, digest));
                }
                Req::Ecdh(slot, peer, reply) => {
                    let _ = reply.send(self.ecdh(slot, &peer));
                }
                Req::Quote(nonce, reply) => {
                    let _ = reply.send(self.quote(nonce));
                }
                Req::EnsureAk(reply) => {
                    let _ = reply.send(self.ensure_ak());
                }
            }
        }
    }
}

impl TpmIdentity {
    /// Open the TPM and the identity directory (`identity.json` must exist).
    ///
    /// # Errors
    /// TPM or I/O errors.
    pub fn open(cfg: TpmConfig) -> Result<Self, IdentityError> {
        let (device_id, tenant_id, _) = super::software::read_identity_ids(&cfg.dir)?;
        let tcti = match &cfg.tcti {
            Some(t) => t.parse::<TctiNameConf>().map_err(be)?,
            None => TctiNameConf::from_environment_variable().unwrap_or(TctiNameConf::Device(Default::default())),
        };
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let worker_cfg = cfg.clone();
        std::thread::Builder::new()
            .name("ironmesh-tpm".into())
            .spawn(move || match Context::new(tcti) {
                Ok(ctx) => {
                    let _ = ready_tx.send(Ok(()));
                    Worker { ctx, cfg: worker_cfg, primary: None }.run(rx);
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(be(e)));
                }
            })
            .map_err(IdentityError::Io)?;
        ready_rx.recv().map_err(be)??;
        Ok(Self { cfg, device_id, tenant_id, tx: Mutex::new(tx) })
    }

    fn call<T>(&self, make: impl FnOnce(mpsc::Sender<Result<T, IdentityError>>) -> Req) -> Result<T, IdentityError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.lock().map_err(|_| be("TPM channel poisoned"))?.send(make(reply_tx)).map_err(|_| be("TPM worker stopped"))?;
        reply_rx.recv().map_err(|_| be("TPM worker stopped"))?
    }

    /// Ensure the AK exists and return its public key (factory mode prints it for certification).
    ///
    /// # Errors
    /// TPM errors.
    pub fn ensure_ak(&self) -> Result<p256::PublicKey, IdentityError> {
        self.call(Req::EnsureAk)
    }
}

impl IdentityProvider for TpmIdentity {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn se_type(&self) -> SeType {
        SeType::Tpm2
    }

    fn assurance(&self) -> Assurance {
        Assurance::Hardware
    }

    fn has_key(&self, slot: KeySlot) -> bool {
        blob_paths(&self.cfg.dir, slot.name()).0.exists()
    }

    fn public_key(&self, slot: KeySlot) -> Result<p256::PublicKey, IdentityError> {
        let (pub_path, _) = blob_paths(&self.cfg.dir, slot.name());
        let bytes = persist::read_bounded(&pub_path, 4096)?.ok_or(IdentityError::NoKey(slot))?;
        public_to_p256(&Public::unmarshall(&bytes).map_err(be)?)
    }

    fn sign(&self, slot: KeySlot, digest: &[u8; 32]) -> Result<[u8; 64], IdentityError> {
        if !self.has_key(slot) {
            return Err(IdentityError::NoKey(slot));
        }
        self.call(|r| Req::Sign(slot, *digest, r))
    }

    fn ecdh(&self, slot: KeySlot, peer: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        if !self.has_key(slot) {
            return Err(IdentityError::NoKey(slot));
        }
        self.call(|r| Req::Ecdh(slot, *peer, r))
    }

    fn generate_operational_key(&self) -> Result<p256::PublicKey, IdentityError> {
        self.call(|r| Req::Generate(KeySlot::Pending, r))
    }

    fn commit_pending(&self) -> Result<(), IdentityError> {
        let (pp, pv) = blob_paths(&self.cfg.dir, KeySlot::Pending.name());
        let (op, ov) = blob_paths(&self.cfg.dir, KeySlot::Operational.name());
        if !pp.exists() {
            return Err(IdentityError::NoKey(KeySlot::Pending));
        }
        std::fs::rename(&pv, &ov)?;
        std::fs::rename(&pp, &op)?;
        Ok(())
    }

    fn generate_bootstrap_key(&self) -> Result<p256::PublicKey, IdentityError> {
        self.ensure_ak()?;
        self.call(|r| Req::Generate(KeySlot::Bootstrap, r))
    }

    fn attestation_evidence(&self, nonce: &[u8; 32]) -> Result<Option<Tpm2Evidence>, IdentityError> {
        let (quote, signature) = self.call(|r| Req::Quote(*nonce, r))?;
        let ak_raw = persist::read_bounded(&self.cfg.ak_cert_path, 64 * 1024)?
            .ok_or_else(|| IdentityError::Backend(format!("AK certificate {} missing", self.cfg.ak_cert_path.display())))?;
        let ak_cert_der = crate::x509::pem_or_der_first(&ak_raw).map_err(|e| IdentityError::Backend(e.to_string()))?;
        Ok(Some(Tpm2Evidence { quote, signature, ak_cert_der }))
    }
}
