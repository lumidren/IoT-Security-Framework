//! At-rest protection of agent state (threat model T-04, T-09, T-10, T-57).
//!
//! The root of the hierarchy is the **same machine-secret-derived key** that encrypts the
//! software identity's private keys (`identity::software`): HKDF-SHA256 over the 0600 machine
//! secret (plus the OS keyring secret with the `keyring` feature), salt
//! `"ironmesh-software-kek-v1"`, info = device id. Every use derives its own subkey with
//! `HKDF-SHA256(salt = "ironmesh-at-rest-v1", ikm = root, info = purpose)`, so the identity KEK
//! itself is never used for anything else and no two purposes share a key:
//!
//! | purpose | info string | use |
//! |---|---|---|
//! | anti-rollback floor | `ironmesh-anti-rollback-hmac-v1` | HMAC-SHA256 tag of `anti_rollback.json` |
//! | offline buffer | `ironmesh-offline-buffer-aead-v1` | AES-256-GCM of every buffered record |
//! | time floor | `ironmesh-time-floor-hmac-v1` | HMAC-SHA256 tag of `time_floor.json` |
//!
//! The machine secret is loaded for every identity backend (a TPM or OP-TEE identity keeps its
//! keys in hardware, but agent state still needs a key). Assurance is the software backend's:
//! anyone with root on the device can read the machine secret and forge or decrypt this state.
//! What it buys is protection against offline tampering and disk/image extraction without the
//! secret (e.g. a copied state directory, a backup, an SD card moved to another machine).

use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::identity::software::{derive_kek, SecretSource};
use crate::identity::IdentityError;
use crate::persist;

const SUBKEY_SALT: &[u8] = b"ironmesh-at-rest-v1";

/// What a subkey is used for (each maps to a distinct HKDF info string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// HMAC key of the anti-rollback floor record.
    AntiRollback,
    /// AES-256-GCM key of the offline ring buffer.
    OfflineBuffer,
    /// HMAC key of the authenticated time floor record.
    TimeFloor,
}

impl Purpose {
    /// HKDF info string.
    #[must_use]
    pub const fn info(self) -> &'static [u8] {
        match self {
            Purpose::AntiRollback => b"ironmesh-anti-rollback-hmac-v1",
            Purpose::OfflineBuffer => b"ironmesh-offline-buffer-aead-v1",
            Purpose::TimeFloor => b"ironmesh-time-floor-hmac-v1",
        }
    }
}

/// Root of the at-rest key hierarchy (zeroized on drop).
pub struct AtRestKey {
    root: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for AtRestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AtRestKey(..)")
    }
}

impl AtRestKey {
    /// Derive the root from the machine secret, exactly like the software identity's KEK.
    ///
    /// # Errors
    /// An unreadable or insecure machine secret (it is created 0600 if missing).
    pub fn load(source: &SecretSource, device_id: &str) -> Result<Self, IdentityError> {
        Ok(Self { root: derive_kek(source, device_id)? })
    }

    /// A fixed root (tests).
    #[must_use]
    pub fn from_bytes(root: [u8; 32]) -> Self {
        Self { root: Zeroizing::new(root) }
    }

    /// The subkey for one purpose.
    #[must_use]
    pub fn subkey(&self, purpose: Purpose) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(SUBKEY_SALT), &self.root[..]);
        let mut out = Zeroizing::new([0u8; 32]);
        // 32 bytes is far below HKDF-SHA256's 255 * 32 byte limit: expand cannot fail.
        if hk.expand(purpose.info(), &mut out[..]).is_err() {
            out.fill(0);
        }
        out
    }
}

/// Result of reading a [`SealedValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sealed {
    /// The record exists and its tag verifies.
    Valid(u64),
    /// No record on disk.
    Missing,
    /// The record exists but is unreadable, malformed or fails authentication.
    Invalid(String),
}

#[derive(Serialize, Deserialize)]
struct SealedFile {
    v: u8,
    value: u64,
    mac: String,
}

/// A single `u64` persisted as JSON with an HMAC-SHA256 tag
/// (`HMAC(key, "ironmesh-sealed|v1|<domain>|" || value_be64)`).
///
/// An HMAC proves the record was written by a holder of the key; it does **not** prove that it
/// is the latest record (an attacker can put back an older, validly tagged copy). Freshness
/// needs a monotonic counter outside the file system (see `ota::slots::AntiRollbackStore`).
#[derive(Clone)]
pub struct SealedValue {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    domain: &'static str,
}

impl std::fmt::Debug for SealedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedValue").field("path", &self.path).field("domain", &self.domain).finish_non_exhaustive()
    }
}

impl SealedValue {
    /// A sealed value at `path` keyed with `key`; `domain` is bound into every tag.
    #[must_use]
    pub fn new(path: &Path, key: Zeroizing<[u8; 32]>, domain: &'static str) -> Self {
        Self { path: path.to_path_buf(), key, domain }
    }

    /// File path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn mac(&self, value: u64) -> Option<Hmac<Sha256>> {
        // HMAC accepts keys of any length, so this never returns None in practice.
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key[..]).ok()?;
        m.update(b"ironmesh-sealed|v1|");
        m.update(self.domain.as_bytes());
        m.update(b"|");
        m.update(&value.to_be_bytes());
        Some(m)
    }

    /// Read and authenticate.
    #[must_use]
    pub fn read(&self) -> Sealed {
        let bytes = match persist::read_bounded(&self.path, 4096) {
            Ok(None) => return Sealed::Missing,
            Ok(Some(b)) => b,
            Err(e) => return Sealed::Invalid(format!("unreadable: {e}")),
        };
        let file: SealedFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(e) => return Sealed::Invalid(format!("malformed: {e}")),
        };
        if file.v != 1 {
            return Sealed::Invalid(format!("unknown version {}", file.v));
        }
        let Ok(tag) = hex::decode(&file.mac) else { return Sealed::Invalid("tag is not hex".into()) };
        match self.mac(file.value).map(|m| m.verify_slice(&tag)) {
            Some(Ok(())) => Sealed::Valid(file.value),
            _ => Sealed::Invalid("authentication tag mismatch".into()),
        }
    }

    /// Write durably (atomic replace + fsync) and read the record back to confirm it.
    ///
    /// # Errors
    /// I/O errors, or a read-back that does not authenticate to `value`.
    pub fn write(&self, value: u64) -> std::io::Result<()> {
        let mac = self.mac(value).ok_or_else(|| std::io::Error::other("HMAC initialisation failed"))?;
        let mac = hex::encode(mac.finalize().into_bytes());
        persist::write_json(&self.path, &SealedFile { v: 1, value, mac })?;
        match self.read() {
            Sealed::Valid(v) if v == value => Ok(()),
            other => Err(std::io::Error::other(format!("{}: read-back after write failed: {other:?}", self.path.display()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_are_distinct_and_deterministic() {
        let k = AtRestKey::from_bytes([7; 32]);
        let a = k.subkey(Purpose::AntiRollback);
        let b = k.subkey(Purpose::OfflineBuffer);
        let t = k.subkey(Purpose::TimeFloor);
        assert_ne!(*a, *b);
        assert_ne!(*a, *t);
        assert_ne!(*b, *t);
        assert_ne!(*a, [7; 32]);
        assert_eq!(*a, *AtRestKey::from_bytes([7; 32]).subkey(Purpose::AntiRollback));
        assert_ne!(*a, *AtRestKey::from_bytes([8; 32]).subkey(Purpose::AntiRollback));
        assert_eq!(format!("{k:?}"), "AtRestKey(..)");
    }

    #[test]
    fn root_is_the_software_identity_kek() {
        let dir = tempfile::tempdir().unwrap();
        let src = SecretSource::File(dir.path().join("machine-secret"));
        let a = AtRestKey::load(&src, "dev-0000000000000001").unwrap();
        let b = AtRestKey::load(&src, "dev-0000000000000001").unwrap();
        assert_eq!(*a.subkey(Purpose::OfflineBuffer), *b.subkey(Purpose::OfflineBuffer));
        let kek = derive_kek(&src, "dev-0000000000000001").unwrap();
        assert_eq!(*a.root, *kek);
        let other = AtRestKey::load(&src, "dev-0000000000000002").unwrap();
        assert_ne!(*a.subkey(Purpose::OfflineBuffer), *other.subkey(Purpose::OfflineBuffer));
    }

    #[test]
    fn sealed_value_round_trip_and_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.json");
        let k = AtRestKey::from_bytes([1; 32]);
        let s = SealedValue::new(&p, k.subkey(Purpose::AntiRollback), "test");
        assert_eq!(s.read(), Sealed::Missing);
        s.write(42).unwrap();
        assert_eq!(s.read(), Sealed::Valid(42));
        assert_eq!(s.path(), p);
        assert!(format!("{s:?}").contains("test"));
        // Edit the value but keep the tag.
        let text = std::fs::read_to_string(&p).unwrap().replace("42", "7");
        std::fs::write(&p, text).unwrap();
        assert!(matches!(s.read(), Sealed::Invalid(m) if m.contains("mismatch")));
        // A different key or domain does not accept the record.
        s.write(9).unwrap();
        let wrong_key = SealedValue::new(&p, AtRestKey::from_bytes([2; 32]).subkey(Purpose::AntiRollback), "test");
        assert!(matches!(wrong_key.read(), Sealed::Invalid(_)));
        let wrong_domain = SealedValue::new(&p, k.subkey(Purpose::AntiRollback), "other");
        assert!(matches!(wrong_domain.read(), Sealed::Invalid(_)));
        // Malformed / legacy files.
        std::fs::write(&p, br#"{"min_version_code": 5}"#).unwrap();
        assert!(matches!(s.read(), Sealed::Invalid(m) if m.contains("malformed")));
        std::fs::write(&p, br#"{"v": 2, "value": 1, "mac": "00"}"#).unwrap();
        assert!(matches!(s.read(), Sealed::Invalid(m) if m.contains("version")));
        std::fs::write(&p, br#"{"v": 1, "value": 1, "mac": "zz"}"#).unwrap();
        assert!(matches!(s.read(), Sealed::Invalid(m) if m.contains("hex")));
    }

    #[test]
    fn sealed_write_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        // The target path is a directory: the atomic rename cannot replace it.
        let p = dir.path().join("blocked");
        std::fs::create_dir(&p).unwrap();
        let s = SealedValue::new(&p, AtRestKey::from_bytes([1; 32]).subkey(Purpose::AntiRollback), "test");
        assert!(s.write(1).is_err());
        assert!(matches!(s.read(), Sealed::Invalid(_)));
    }
}
