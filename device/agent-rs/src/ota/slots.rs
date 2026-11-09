//! A/B slot storage: `/var/lib/ironmesh/slots/{a,b}/image.bin` + `slot.json`, the persisted
//! anti-rollback counter and the record of an update in progress.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::boot::Slot;
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct Counter {
    min_version_code: u64,
}

/// Slot directory.
#[derive(Debug, Clone)]
pub struct SlotStore {
    dir: PathBuf,
}

impl SlotStore {
    /// Open (creating) the directory.
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        persist::ensure_private_dir(dir)?;
        for s in [Slot::A, Slot::B] {
            persist::ensure_private_dir(&dir.join(s.name()))?;
        }
        Ok(Self { dir: dir.to_path_buf() })
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

    /// Persisted anti-rollback floor (the highest version code ever marked healthy).
    #[must_use]
    pub fn anti_rollback(&self) -> u64 {
        persist::read_json::<Counter>(&self.dir.join("anti_rollback.json")).ok().flatten().unwrap_or_default().min_version_code
    }

    /// Raise the anti-rollback floor (never lowers it).
    ///
    /// # Errors
    /// I/O errors.
    pub fn raise_anti_rollback(&self, version_code: u64) -> std::io::Result<()> {
        let current = self.anti_rollback();
        if version_code > current {
            persist::write_json(&self.dir.join("anti_rollback.json"), &Counter { min_version_code: version_code })?;
        }
        Ok(())
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

    #[test]
    fn slot_store() {
        let dir = tempfile::tempdir().unwrap();
        let s = SlotStore::open(dir.path()).unwrap();
        assert!(s.meta(Slot::A).is_none());
        let m = SlotMeta { product: "p".into(), version: "1.0.0".into(), version_code: 3, sha256_hex: "00".into(), state: "valid".into() };
        s.set_meta(Slot::B, &m).unwrap();
        s.set_state(Slot::B, "pending").unwrap();
        s.set_state(Slot::A, "pending").unwrap();
        assert_eq!(s.meta(Slot::B).unwrap().state, "pending");
        assert_eq!(s.anti_rollback(), 0);
        s.raise_anti_rollback(5).unwrap();
        s.raise_anti_rollback(4).unwrap();
        assert_eq!(s.anti_rollback(), 5);
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
}
