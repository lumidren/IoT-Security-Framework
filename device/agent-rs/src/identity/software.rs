//! Software identity backend (`assurance = software`, contract §10).
//!
//! P-256 keys are generated on the device and stored encrypted at rest:
//! `AES-256-GCM(key = HKDF-SHA256(machine secret [|| keyring secret], salt =
//! "ironmesh-software-kek-v1", info = device id), aad = "ironmesh-software-key|v1|<device>|<slot>")`.
//! The machine secret is a 32-byte file with mode 0600 (refused if group/other can read it) and,
//! with the `keyring` cargo feature, an additional secret held in the OS keyring. Secrets are
//! zeroized on drop. This backend is clearly **lower assurance** than a secure element: anyone
//! with root on the device can recover the key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Assurance, IdentityError, IdentityProvider, KeySlot};
use crate::persist;
use crate::wire::envelope::{SeType, Tpm2Evidence};
use crate::wire::hpke::EcdhRecipient;

const KEY_MAGIC: &[u8; 5] = b"IMSK1";
const SECRET_LEN: usize = 32;

/// Where the at-rest key-encryption secret comes from.
#[derive(Debug, Clone)]
pub enum SecretSource {
    /// A 32-byte machine secret file (created 0600 if missing).
    File(PathBuf),
    /// The machine secret file plus a second secret in the OS keyring (`keyring` feature).
    #[cfg(feature = "keyring")]
    FileAndKeyring(PathBuf),
    /// A fixed in-memory secret (tests and the fleet simulator only).
    Static([u8; 32]),
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    device_id: String,
    tenant_id: String,
    se_type: SeType,
}

/// Software identity.
pub struct SoftwareIdentity {
    dir: PathBuf,
    device_id: String,
    tenant_id: String,
    kek: Zeroizing<[u8; 32]>,
    keys: Mutex<HashMap<KeySlot, p256::SecretKey>>,
    persist_keys: bool,
}

impl std::fmt::Debug for SoftwareIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareIdentity").field("device_id", &self.device_id).field("dir", &self.dir).finish_non_exhaustive()
    }
}

fn load_machine_secret(path: &Path) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    if let Some(bytes) = persist::read_bounded(path, 1024)? {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(IdentityError::Insecure(format!("{} has mode {:o}; must be 0600", path.display(), mode & 0o777)));
            }
        }
        if bytes.len() != SECRET_LEN {
            return Err(IdentityError::Insecure(format!("{} must hold exactly 32 bytes", path.display())));
        }
        return Ok(Zeroizing::new(bytes));
    }
    let mut secret = Zeroizing::new(vec![0u8; SECRET_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut secret);
    persist::write_atomic(path, &secret)?;
    Ok(secret)
}

#[cfg(feature = "keyring")]
fn load_keyring_secret(device_id: &str) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let entry = keyring::Entry::new("ironmesh-agent", device_id).map_err(|e| IdentityError::Backend(e.to_string()))?;
    match entry.get_secret() {
        Ok(s) if s.len() == SECRET_LEN => Ok(Zeroizing::new(s)),
        Ok(_) => Err(IdentityError::Insecure("keyring secret has the wrong length".into())),
        Err(keyring::Error::NoEntry) => {
            let mut secret = Zeroizing::new(vec![0u8; SECRET_LEN]);
            rand::rngs::OsRng.fill_bytes(&mut secret);
            entry.set_secret(&secret).map_err(|e| IdentityError::Backend(e.to_string()))?;
            Ok(secret)
        }
        Err(e) => Err(IdentityError::Backend(e.to_string())),
    }
}

pub(crate) fn derive_kek(source: &SecretSource, device_id: &str) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let ikm: Zeroizing<Vec<u8>> = match source {
        SecretSource::File(p) => load_machine_secret(p)?,
        #[cfg(feature = "keyring")]
        SecretSource::FileAndKeyring(p) => {
            let mut v = load_machine_secret(p)?;
            v.extend_from_slice(&load_keyring_secret(device_id)?);
            v
        }
        SecretSource::Static(s) => Zeroizing::new(s.to_vec()),
    };
    let hk = Hkdf::<Sha256>::new(Some(b"ironmesh-software-kek-v1"), &ikm);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(device_id.as_bytes(), &mut kek[..]).map_err(|e| IdentityError::Crypto(e.to_string()))?;
    Ok(kek)
}

impl SoftwareIdentity {
    /// Create a new identity directory (factory mode).
    ///
    /// # Errors
    /// I/O errors or an insecure machine secret.
    pub fn create(dir: &Path, device_id: &str, tenant_id: &str, secret: &SecretSource) -> Result<Self, IdentityError> {
        persist::ensure_private_dir(dir)?;
        persist::ensure_private_dir(&dir.join("keys"))?;
        persist::write_json(
            &dir.join("identity.json"),
            &IdentityFile { device_id: device_id.into(), tenant_id: tenant_id.into(), se_type: SeType::Software },
        )?;
        Self::open(dir, secret)
    }

    /// Open an existing identity directory.
    ///
    /// # Errors
    /// I/O errors, a missing `identity.json`, an insecure secret or undecryptable keys.
    pub fn open(dir: &Path, secret: &SecretSource) -> Result<Self, IdentityError> {
        let file: IdentityFile = persist::read_json(&dir.join("identity.json"))?
            .ok_or_else(|| IdentityError::Backend(format!("{} has no identity.json", dir.display())))?;
        let kek = derive_kek(secret, &file.device_id)?;
        let id = Self {
            dir: dir.to_path_buf(),
            device_id: file.device_id,
            tenant_id: file.tenant_id,
            kek,
            keys: Mutex::new(HashMap::new()),
            persist_keys: true,
        };
        for slot in [KeySlot::Bootstrap, KeySlot::Operational, KeySlot::Pending] {
            if let Some(key) = id.load_key(slot)? {
                id.lock()?.insert(slot, key);
            }
        }
        Ok(id)
    }

    /// An identity whose keys live only in memory (fleet simulator / tests).
    #[must_use]
    pub fn ephemeral(device_id: &str, tenant_id: &str) -> Self {
        Self {
            dir: PathBuf::new(),
            device_id: device_id.into(),
            tenant_id: tenant_id.into(),
            kek: Zeroizing::new([0u8; 32]),
            keys: Mutex::new(HashMap::new()),
            persist_keys: false,
        }
    }

    /// Install a key directly (tests: deterministic keys).
    ///
    /// # Errors
    /// Persistence errors.
    pub fn install_key(&self, slot: KeySlot, key: p256::SecretKey) -> Result<(), IdentityError> {
        self.store_key(slot, &key)?;
        self.lock()?.insert(slot, key);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<KeySlot, p256::SecretKey>>, IdentityError> {
        self.keys.lock().map_err(|_| IdentityError::Backend("key store lock poisoned".into()))
    }

    fn key_path(&self, slot: KeySlot) -> PathBuf {
        self.dir.join("keys").join(format!("{}.key", slot.name()))
    }

    fn aad(&self, slot: KeySlot) -> Vec<u8> {
        format!("ironmesh-software-key|v1|{}|{}", self.device_id, slot.name()).into_bytes()
    }

    fn cipher(&self) -> Result<Aes256Gcm, IdentityError> {
        Aes256Gcm::new_from_slice(&self.kek[..]).map_err(|e| IdentityError::Crypto(e.to_string()))
    }

    fn store_key(&self, slot: KeySlot, key: &p256::SecretKey) -> Result<(), IdentityError> {
        if !self.persist_keys {
            return Ok(());
        }
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let scalar = Zeroizing::new(key.to_bytes());
        let ct = self
            .cipher()?
            .encrypt(&nonce.into(), Payload { msg: &scalar[..], aad: &self.aad(slot) })
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let mut blob = KEY_MAGIC.to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        persist::ensure_private_dir(&self.dir.join("keys"))?;
        persist::write_atomic(&self.key_path(slot), &blob)?;
        Ok(())
    }

    fn load_key(&self, slot: KeySlot) -> Result<Option<p256::SecretKey>, IdentityError> {
        let Some(blob) = persist::read_bounded(&self.key_path(slot), 4096)? else {
            return Ok(None);
        };
        if blob.len() != KEY_MAGIC.len() + 12 + 32 + 16 || !blob.starts_with(KEY_MAGIC) {
            return Err(IdentityError::Crypto(format!("{} is not a valid key blob", slot.name())));
        }
        let nonce: [u8; 12] = blob[5..17].try_into().map_err(|_| IdentityError::Crypto("bad nonce".into()))?;
        let pt = Zeroizing::new(
            self.cipher()?
                .decrypt(&nonce.into(), Payload { msg: &blob[17..], aad: &self.aad(slot) })
                .map_err(|_| IdentityError::Crypto(format!("{} key cannot be decrypted (wrong machine secret?)", slot.name())))?,
        );
        p256::SecretKey::from_slice(&pt).map(Some).map_err(|e| IdentityError::Crypto(e.to_string()))
    }

    fn with_key<T>(&self, slot: KeySlot, f: impl FnOnce(&p256::SecretKey) -> Result<T, IdentityError>) -> Result<T, IdentityError> {
        let keys = self.lock()?;
        let key = keys.get(&slot).ok_or(IdentityError::NoKey(slot))?;
        f(key)
    }

    fn generate_into(&self, slot: KeySlot) -> Result<p256::PublicKey, IdentityError> {
        let key = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let pk = key.public_key();
        self.install_key(slot, key)?;
        Ok(pk)
    }
}

impl IdentityProvider for SoftwareIdentity {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn se_type(&self) -> SeType {
        SeType::Software
    }

    fn assurance(&self) -> Assurance {
        Assurance::Software
    }

    fn has_key(&self, slot: KeySlot) -> bool {
        self.lock().map(|k| k.contains_key(&slot)).unwrap_or(false)
    }

    fn public_key(&self, slot: KeySlot) -> Result<p256::PublicKey, IdentityError> {
        self.with_key(slot, |k| Ok(k.public_key()))
    }

    fn sign(&self, slot: KeySlot, digest: &[u8; 32]) -> Result<[u8; 64], IdentityError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        self.with_key(slot, |k| {
            let sk = p256::ecdsa::SigningKey::from(k);
            let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).map_err(|e| IdentityError::Crypto(e.to_string()))?;
            let mut out = [0u8; 64];
            out.copy_from_slice(&sig.to_bytes());
            Ok(out)
        })
    }

    fn ecdh(&self, slot: KeySlot, peer: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        self.with_key(slot, |k| k.ecdh(peer).map_err(|e| IdentityError::Crypto(e.to_string())))
    }

    fn generate_operational_key(&self) -> Result<p256::PublicKey, IdentityError> {
        self.generate_into(KeySlot::Pending)
    }

    fn commit_pending(&self) -> Result<(), IdentityError> {
        let mut keys = self.lock()?;
        let key = keys.remove(&KeySlot::Pending).ok_or(IdentityError::NoKey(KeySlot::Pending))?;
        drop(keys);
        self.store_key(KeySlot::Operational, &key)?;
        if self.persist_keys {
            let _ = std::fs::remove_file(self.key_path(KeySlot::Pending));
        }
        self.lock()?.insert(KeySlot::Operational, key);
        Ok(())
    }

    fn generate_bootstrap_key(&self) -> Result<p256::PublicKey, IdentityError> {
        self.generate_into(KeySlot::Bootstrap)
    }

    fn attestation_evidence(&self, _nonce: &[u8; 32]) -> Result<Option<Tpm2Evidence>, IdentityError> {
        Ok(None)
    }
}

/// Device id / tenant id recorded in an identity directory (any backend).
///
/// # Errors
/// I/O errors or a missing file.
pub fn read_identity_ids(dir: &Path) -> Result<(String, String, SeType), IdentityError> {
    let file: IdentityFile = persist::read_json(&dir.join("identity.json"))?
        .ok_or_else(|| IdentityError::Backend(format!("{} has no identity.json", dir.display())))?;
    Ok((file.device_id, file.tenant_id, file.se_type))
}

/// Record the ids for a hardware backend's identity directory.
///
/// # Errors
/// I/O errors.
pub fn write_identity_ids(dir: &Path, device_id: &str, tenant_id: &str, se_type: SeType) -> Result<(), IdentityError> {
    persist::ensure_private_dir(dir)?;
    persist::write_json(&dir.join("identity.json"), &IdentityFile { device_id: device_id.into(), tenant_id: tenant_id.into(), se_type })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "dev-0000000000000001";
    const TEN: &str = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";

    #[test]
    fn keys_survive_reopen_and_are_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let src = SecretSource::File(dir.path().join("machine-secret"));
        let id = SoftwareIdentity::create(dir.path(), DEV, TEN, &src).unwrap();
        assert!(!id.has_key(KeySlot::Bootstrap));
        let bpk = id.generate_bootstrap_key().unwrap();
        let ppk = id.generate_operational_key().unwrap();
        assert_ne!(bpk, ppk);
        assert!(id.public_key(KeySlot::Operational).is_err());
        id.commit_pending().unwrap();
        assert!(matches!(id.commit_pending(), Err(IdentityError::NoKey(KeySlot::Pending))));
        assert_eq!(id.public_key(KeySlot::Operational).unwrap(), ppk);
        let raw = std::fs::read(dir.path().join("keys/operational.key")).unwrap();
        assert!(raw.starts_with(KEY_MAGIC));
        drop(id);
        let id = SoftwareIdentity::open(dir.path(), &src).unwrap();
        assert_eq!(id.public_key(KeySlot::Bootstrap).unwrap(), bpk);
        assert_eq!(id.public_key(KeySlot::Operational).unwrap(), ppk);
        assert!(!id.has_key(KeySlot::Pending));
        assert_eq!(id.device_id(), DEV);
        assert_eq!(id.tenant_id(), TEN);
        assert_eq!(id.se_type(), SeType::Software);
        assert_eq!(id.assurance(), Assurance::Software);
        assert!(id.attestation_evidence(&[0; 32]).unwrap().is_none());
        super::super::self_test(&id, KeySlot::Operational).unwrap();
        // A different machine secret cannot decrypt the keys.
        std::fs::write(dir.path().join("machine-secret"), [9u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path().join("machine-secret"), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(SoftwareIdentity::open(dir.path(), &src), Err(IdentityError::Crypto(_))));
        let (d, t, s) = read_identity_ids(dir.path()).unwrap();
        assert_eq!((d.as_str(), t.as_str(), s), (DEV, TEN, SeType::Software));
    }

    #[test]
    fn bad_secret_and_ephemeral() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("short"), [1u8; 3]).unwrap();
        let src = SecretSource::File(dir.path().join("short"));
        assert!(matches!(SoftwareIdentity::create(dir.path(), DEV, TEN, &src), Err(IdentityError::Insecure(_))));
        assert!(SoftwareIdentity::open(&dir.path().join("nope"), &SecretSource::Static([0; 32])).is_err());
        let e = SoftwareIdentity::ephemeral(DEV, TEN);
        e.generate_bootstrap_key().unwrap();
        let pk = e.public_key(KeySlot::Bootstrap).unwrap();
        let shared = e.ecdh(KeySlot::Bootstrap, &pk).unwrap();
        assert_eq!(shared.len(), 32);
        assert!(format!("{e:?}").contains(DEV));
        write_identity_ids(&dir.path().join("hw"), DEV, TEN, SeType::Tpm2).unwrap();
        assert_eq!(read_identity_ids(&dir.path().join("hw")).unwrap().2, SeType::Tpm2);
        std::fs::write(dir.path().join("keys-bad"), b"x").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_secret_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, [1u8; 32]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load_machine_secret(&p), Err(IdentityError::Insecure(_))));
    }
}
