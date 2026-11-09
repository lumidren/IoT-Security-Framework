//! A/B slot storage: `/var/lib/ironmesh/slots/{a,b}/image.bin` + `slot.json`, the persisted
//! anti-rollback floor and the record of an update in progress.
//!
//! ## Anti-rollback floor (threat model T-57)
//!
//! The floor is the highest `version_code` ever committed (marked healthy). It is kept behind the
//! [`AntiRollbackStore`] trait:
//!
//! * [`HmacFileFloor`] (default, every build): `anti_rollback.json` holding the value and an
//!   HMAC-SHA256 tag keyed from the agent's at-rest key ([`crate::atrest`], the same
//!   machine-secret-derived key that protects the software identity). A record that is missing,
//!   unparsable or fails authentication is **never** read as zero: the caller substitutes the
//!   running image's `version_code` ([`SlotStore::anti_rollback`]) and the record is re-written.
//!   Writes are durable (atomic replace + fsync, then read back and re-verified) and fail closed:
//!   an update is neither staged nor committed unless the floor was raised first.
//! * **TPM NV counter (stronger option for builds with the `tpm` feature):** an HMAC tag proves
//!   who wrote the record but not that it is the latest one, so root can put back an older,
//!   validly tagged copy. A TPM 2.0 NV index of type *counter* (`TPMA_NV_COUNTER`,
//!   `TPM2_NV_Increment`, owner auth, `TPMA_NV_NO_DA`) only ever increases and survives
//!   re-imaging the disk. Two ways to use it behind this trait: store the floor directly as the
//!   counter value (raising to `v` = `v - current` increments, fine for small version-code
//!   gaps), or keep the HMAC file and bind the counter value into the tag, incrementing it on
//!   every raise so an older file no longer verifies. The TPM implementation is not part of this
//!   build (it needs `libtss2` and a TPM to test against); [`SlotStore::open_with_floor`] is the
//!   plug-in point.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::boot::Slot;
use crate::atrest::{AtRestKey, Purpose, Sealed, SealedValue};
use crate::persist;

/// Slot metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotMeta {
    /// Product.
    pub product: String,
    /// Version (semver).
    pub version: String,
    /// Version code.
    pub version_code: u64,
    /// Image SHA-256 (hex).
    pub sha256_hex: String,
    /// `valid`, `pending`, `invalid`.
    pub state: String,
}

/// An update waiting for its trial boot / health gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpdate {
    /// Campaign.
    pub campaign_id: String,
    /// Slot being tried.
    pub slot: Slot,
    /// Slot to return to.
    pub previous: Slot,
    /// Version code being installed.
    pub version_code: u64,
    /// Image hash.
    pub sha256_hex: String,
}

/// Persistent storage of the anti-rollback floor (see the module documentation).
pub trait AntiRollbackStore: Send + Sync + std::fmt::Debug {
    /// The stored floor, [`Sealed::Missing`] or [`Sealed::Invalid`] (never silently zero).
    fn read(&self) -> Sealed;
    /// Durably store `version_code`. `Ok` only once the value is guaranteed to survive a power
    /// loss and reads back authenticated.
    ///
    /// # Errors
    /// Any failure to persist; callers treat it as "the floor was not raised" and fail closed.
    fn write(&self, version_code: u64) -> std::io::Result<()>;
    /// Backend name for diagnostics (`hmac-file`, `tpm-nv-counter`, ...).
    fn kind(&self) -> &'static str;
}

/// Default floor store: `anti_rollback.json` with an HMAC-SHA256 tag.
#[derive(Debug, Clone)]
pub struct HmacFileFloor(SealedValue);

impl HmacFileFloor {
    /// File name inside the slot directory.
    pub const FILE: &'static str = "anti_rollback.json";

    /// Floor file in `dir`, keyed from the at-rest key.
    #[must_use]
    pub fn new(dir: &Path, key: &AtRestKey) -> Self {
        Self(SealedValue::new(&dir.join(Self::FILE), key.subkey(Purpose::AntiRollback), "anti-rollback-floor"))
    }
}

impl AntiRollbackStore for HmacFileFloor {
    fn read(&self) -> Sealed {
        self.0.read()
    }

    fn write(&self, version_code: u64) -> std::io::Result<()> {
        self.0.write(version_code)
    }

    fn kind(&self) -> &'static str {
        "hmac-file"
    }
}

/// A floor store for diagnostics without the at-rest key: reads as [`Sealed::Invalid`], refuses
/// writes (so nothing that relies on it can stage or commit an update).
#[derive(Debug, Clone)]
pub struct UnavailableFloor(pub String);

impl AntiRollbackStore for UnavailableFloor {
    fn read(&self) -> Sealed {
        Sealed::Invalid(format!("unavailable: {}", self.0))
    }

    fn write(&self, _version_code: u64) -> std::io::Result<()> {
        Err(std::io::Error::other(format!("anti-rollback floor unavailable: {}", self.0)))
    }

    fn kind(&self) -> &'static str {
        "unavailable"
    }
}

/// Slot directory.
#[derive(Debug, Clone)]
pub struct SlotStore {
    dir: PathBuf,
    floor: Arc<dyn AntiRollbackStore>,
}

impl SlotStore {
    /// Open (creating) the directory with the default [`HmacFileFloor`].
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(dir: &Path, key: &AtRestKey) -> std::io::Result<Self> {
        Self::open_with_floor(dir, Arc::new(HmacFileFloor::new(dir, key)))
    }

    /// Open (creating) the directory with a specific floor store (e.g. a TPM NV counter).
    ///
    /// # Errors
    /// I/O errors.
    pub fn open_with_floor(dir: &Path, floor: Arc<dyn AntiRollbackStore>) -> std::io::Result<Self> {
        persist::ensure_private_dir(dir)?;
        for s in [Slot::A, Slot::B] {
            persist::ensure_private_dir(&dir.join(s.name()))?;
        }
        Ok(Self { dir: dir.to_path_buf(), floor })
    }

    /// Root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Image path of a slot.
    #[must_use]
    pub fn image_path(&self, slot: Slot) -> PathBuf {
        self.dir.join(slot.name()).join("image.bin")
    }

    /// Temporary path used while writing a slot.
    #[must_use]
    pub fn staging_path(&self, slot: Slot) -> PathBuf {
        self.dir.join(slot.name()).join("image.bin.part")
    }

    /// Download directory.
    #[must_use]
    pub fn download_dir(&self) -> PathBuf {
        self.dir.join("download")
    }

    /// Metadata of a slot.
    #[must_use]
    pub fn meta(&self, slot: Slot) -> Option<SlotMeta> {
        persist::read_json(&self.dir.join(slot.name()).join("slot.json")).ok().flatten()
    }

    /// Write slot metadata.
    ///
    /// # Errors
    /// I/O errors.
    pub fn set_meta(&self, slot: Slot, meta: &SlotMeta) -> std::io::Result<()> {
        persist::write_json(&self.dir.join(slot.name()).join("slot.json"), meta)
    }

    /// Mark a slot's state.
    ///
    /// # Errors
    /// I/O errors.
    pub fn set_state(&self, slot: Slot, state: &str) -> std::io::Result<()> {
        if let Some(mut m) = self.meta(slot) {
            m.state = state.into();
            self.set_meta(slot, &m)?;
        }
        Ok(())
    }

    /// The raw floor record (diagnostics; use [`Self::anti_rollback`] for decisions).
    #[must_use]
    pub fn anti_rollback_record(&self) -> Sealed {
        self.floor.read()
    }

    /// Floor backend name.
    #[must_use]
    pub fn anti_rollback_kind(&self) -> &'static str {
        self.floor.kind()
    }

    /// Effective anti-rollback floor (the highest version code ever committed). A missing,
    /// unreadable or unauthenticated record yields `running_version_code`, never zero.
    #[must_use]
    pub fn anti_rollback(&self, running_version_code: u64) -> u64 {
        match self.floor.read() {
            Sealed::Valid(v) => v,
            Sealed::Missing | Sealed::Invalid(_) => running_version_code,
        }
    }

    /// Durably raise the floor to `version_code`. A valid record that is already at least as
    /// high is left alone; a missing or unauthenticated record is replaced.
    ///
    /// # Errors
    /// The floor could not be persisted (the caller must not apply / commit the update).
    pub fn raise_anti_rollback(&self, version_code: u64) -> std::io::Result<()> {
        match self.floor.read() {
            Sealed::Valid(v) if v >= version_code => Ok(()),
            _ => self.floor.write(version_code),
        }
    }

    /// Update in progress.
    #[must_use]
    pub fn pending_update(&self) -> Option<PendingUpdate> {
        persist::read_json(&self.dir.join("pending_update.json")).ok().flatten()
    }

    /// Record / clear the update in progress.
    ///
    /// # Errors
    /// I/O errors.
    pub fn set_pending_update(&self, p: Option<&PendingUpdate>) -> std::io::Result<()> {
        let path = self.dir.join("pending_update.json");
        match p {
            Some(p) => persist::write_json(&path, p),
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AtRestKey {
        AtRestKey::from_bytes([3; 32])
    }

    #[test]
    fn slot_store() {
        let dir = tempfile::tempdir().unwrap();
        let s = SlotStore::open(dir.path(), &key()).unwrap();
        assert!(s.meta(Slot::A).is_none());
        let m = SlotMeta { product: "p".into(), version: "1.0.0".into(), version_code: 3, sha256_hex: "00".into(), state: "valid".into() };
        s.set_meta(Slot::B, &m).unwrap();
        s.set_state(Slot::B, "pending").unwrap();
        s.set_state(Slot::A, "pending").unwrap();
        assert_eq!(s.meta(Slot::B).unwrap().state, "pending");
        assert_eq!(s.anti_rollback_record(), Sealed::Missing);
        assert_eq!(s.anti_rollback(3), 3, "missing floor = running version code, not zero");
        s.raise_anti_rollback(5).unwrap();
        s.raise_anti_rollback(4).unwrap();
        assert_eq!(s.anti_rollback(3), 5);
        assert_eq!(s.anti_rollback_kind(), "hmac-file");
        let p = PendingUpdate { campaign_id: "c".into(), slot: Slot::B, previous: Slot::A, version_code: 5, sha256_hex: "00".into() };
        s.set_pending_update(Some(&p)).unwrap();
        assert_eq!(s.pending_update(), Some(p));
        s.set_pending_update(None).unwrap();
        s.set_pending_update(None).unwrap();
        assert!(s.pending_update().is_none());
        assert!(s.image_path(Slot::A).ends_with("image.bin"));
        assert!(s.staging_path(Slot::A).ends_with("image.bin.part"));
        assert!(s.download_dir().ends_with("download"));
        assert_eq!(s.dir(), dir.path());
    }

    #[test]
    fn tampered_or_missing_floor_is_the_running_version_never_zero() {
        let dir = tempfile::tempdir().unwrap();
        let s = SlotStore::open(dir.path(), &key()).unwrap();
        s.raise_anti_rollback(500).unwrap();
        let path = dir.path().join(HmacFileFloor::FILE);
        // Lowering the value in the file breaks the tag.
        let text = std::fs::read_to_string(&path).unwrap().replace("500", "1");
        std::fs::write(&path, text).unwrap();
        assert!(matches!(s.anti_rollback_record(), Sealed::Invalid(_)));
        assert_eq!(s.anti_rollback(300), 300);
        // The legacy plain-JSON format is not authenticated either.
        std::fs::write(&path, br#"{"min_version_code": 0}"#).unwrap();
        assert_eq!(s.anti_rollback(300), 300);
        // A file written with another machine's key is rejected.
        let other = SlotStore::open(dir.path(), &AtRestKey::from_bytes([4; 32])).unwrap();
        other.raise_anti_rollback(1).unwrap();
        assert_eq!(s.anti_rollback(300), 300);
        // Deleted after first boot.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(s.anti_rollback(300), 300);
        // Healing re-writes an authenticated record.
        s.raise_anti_rollback(300).unwrap();
        assert_eq!(s.anti_rollback_record(), Sealed::Valid(300));
        // An unauthenticated record is replaced even by a lower value (it was never trusted).
        std::fs::write(&path, br#"{"v": 1, "value": 999, "mac": "00"}"#).unwrap();
        s.raise_anti_rollback(301).unwrap();
        assert_eq!(s.anti_rollback(0), 301);
    }

    #[test]
    fn floor_write_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let s = SlotStore::open(dir.path(), &key()).unwrap();
        std::fs::create_dir(dir.path().join(HmacFileFloor::FILE)).unwrap();
        assert!(s.raise_anti_rollback(7).is_err());
        assert_eq!(s.anti_rollback(6), 6);
    }

    #[derive(Debug, Default)]
    struct MemFloor(std::sync::Mutex<Option<u64>>);

    impl AntiRollbackStore for MemFloor {
        fn read(&self) -> Sealed {
            self.0.lock().unwrap().map_or(Sealed::Missing, Sealed::Valid)
        }
        fn write(&self, v: u64) -> std::io::Result<()> {
            *self.0.lock().unwrap() = Some(v);
            Ok(())
        }
        fn kind(&self) -> &'static str {
            "mem"
        }
    }

    #[test]
    fn unavailable_floor_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let s = SlotStore::open_with_floor(dir.path(), Arc::new(UnavailableFloor("no key".into()))).unwrap();
        assert!(matches!(s.anti_rollback_record(), Sealed::Invalid(m) if m.contains("no key")));
        assert_eq!(s.anti_rollback(4), 4);
        assert!(s.raise_anti_rollback(5).is_err());
        assert_eq!(s.anti_rollback_kind(), "unavailable");
    }

    #[test]
    fn pluggable_floor_store() {
        let dir = tempfile::tempdir().unwrap();
        let s = SlotStore::open_with_floor(dir.path(), Arc::new(MemFloor::default())).unwrap();
        assert_eq!(s.anti_rollback(9), 9);
        s.raise_anti_rollback(10).unwrap();
        assert_eq!(s.anti_rollback(9), 10);
        assert_eq!(s.anti_rollback_kind(), "mem");
        assert!(!dir.path().join(HmacFileFloor::FILE).exists());
    }
}
