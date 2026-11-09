//! Boot control: which A/B slot is active, which is pending a trial boot, and the boot counter.
//!
//! [`FileBootControl`] keeps `state.json` (`active`, `pending`, `boot_count`) in the slot
//! directory and implements the bootloader contract itself (used on systems where the agent is
//! the payload, and in tests / DUT mode). [`FwSetenvBootControl`] drives a real bootloader through
//! the U-Boot environment (`fw_printenv` / `fw_setenv`), compatible with RAUC-style
//! `BOOT_ORDER` + `BOOT_<slot>_LEFT` counters:
//!
//! | Variable              | Meaning                                                           |
//! |-----------------------|-------------------------------------------------------------------|
//! | `BOOT_ORDER`          | `"A B"` / `"B A"`: first entry is tried first                    |
//! | `BOOT_A_LEFT`, `BOOT_B_LEFT` | remaining trial boots; U-Boot decrements before booting   |
//! | `ironmesh_pending`    | slot under trial (empty when none)                               |
//!
//! `set_pending(b)` writes `BOOT_ORDER="B A" BOOT_B_LEFT=<max> ironmesh_pending=b`;
//! `mark_good()` sets `BOOT_ORDER` to the running slot first, refills its counter and clears
//! `ironmesh_pending`; when U-Boot exhausts `BOOT_B_LEFT` it falls back to A on its own and the
//! agent observes `ironmesh_pending=b` while running A, i.e. a rollback.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::persist;

/// Slot name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    /// Slot A.
    A,
    /// Slot B.
    B,
}

impl Slot {
    /// The other slot.
    #[must_use]
    pub const fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// `"a"` / `"b"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }

    fn parse(s: &str) -> Option<Slot> {
        match s.trim().to_ascii_lowercase().as_str() {
            "a" => Some(Slot::A),
            "b" => Some(Slot::B),
            _ => None,
        }
    }
}

/// Persistent boot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootState {
    /// Last known-good slot.
    pub active: Slot,
    /// Slot under trial, if any.
    pub pending: Option<Slot>,
    /// Trial boots so far.
    pub boot_count: u32,
}

impl Default for BootState {
    fn default() -> Self {
        Self { active: Slot::A, pending: None, boot_count: 0 }
    }
}

/// Outcome of the boot-time decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOutcome {
    /// Normal boot of the active slot.
    Normal(Slot),
    /// Trial boot of a pending slot (health gate must pass).
    Trial(Slot),
    /// The pending slot failed (too many attempts) and was abandoned.
    RolledBack {
        /// Slot that failed.
        failed: Slot,
        /// Slot now running.
        running: Slot,
    },
}

impl BootOutcome {
    /// Slot that is running.
    #[must_use]
    pub fn running(self) -> Slot {
        match self {
            BootOutcome::Normal(s) | BootOutcome::Trial(s) => s,
            BootOutcome::RolledBack { running, .. } => running,
        }
    }
}

/// Boot control error.
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// I/O.
    #[error("boot control I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Bootloader tool failed.
    #[error("boot control: {0}")]
    Tool(String),
}

/// Bootloader contract.
pub trait BootControl: Send + Sync {
    /// Current persistent state.
    ///
    /// # Errors
    /// I/O or tool errors.
    fn state(&self) -> Result<BootState, BootError>;
    /// Arrange for `slot` to be tried on the next boot.
    ///
    /// # Errors
    /// I/O or tool errors.
    fn set_pending(&self, slot: Slot) -> Result<(), BootError>;
    /// Called once per (re)start of the agent: count the trial boot and decide.
    ///
    /// # Errors
    /// I/O or tool errors.
    fn on_boot(&self) -> Result<BootOutcome, BootError>;
    /// The running trial slot passed its health checks (`ota_mark_healthy`).
    ///
    /// # Errors
    /// I/O or tool errors.
    fn mark_good(&self) -> Result<(), BootError>;
    /// Abandon the pending slot (health deadline missed / `ironmesh-rollback.service`).
    ///
    /// # Errors
    /// I/O or tool errors.
    fn rollback(&self) -> Result<(), BootError>;
}

/// File-based boot control (`<slots>/state.json`).
#[derive(Debug)]
pub struct FileBootControl {
    path: PathBuf,
    max_attempts: u32,
    lock: Mutex<()>,
}

impl FileBootControl {
    /// New controller storing `state.json` in `dir`.
    #[must_use]
    pub fn new(dir: &Path, max_attempts: u32) -> Self {
        Self { path: dir.join("state.json"), max_attempts: max_attempts.max(1), lock: Mutex::new(()) }
    }

    fn load(&self) -> Result<BootState, BootError> {
        Ok(persist::read_json(&self.path)?.unwrap_or_default())
    }

    fn save(&self, s: &BootState) -> Result<(), BootError> {
        persist::write_json(&self.path, s)?;
        Ok(())
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, BootError> {
        self.lock.lock().map_err(|_| BootError::Tool("boot state lock poisoned".into()))
    }
}

impl BootControl for FileBootControl {
    fn state(&self) -> Result<BootState, BootError> {
        let _g = self.guard()?;
        self.load()
    }

    fn set_pending(&self, slot: Slot) -> Result<(), BootError> {
        let _g = self.guard()?;
        let mut s = self.load()?;
        s.pending = Some(slot);
        s.boot_count = 0;
        self.save(&s)
    }

    fn on_boot(&self) -> Result<BootOutcome, BootError> {
        let _g = self.guard()?;
        let mut s = self.load()?;
        let Some(pending) = s.pending else {
            return Ok(BootOutcome::Normal(s.active));
        };
        s.boot_count += 1;
        if s.boot_count > self.max_attempts {
            s.pending = None;
            s.boot_count = 0;
            self.save(&s)?;
            return Ok(BootOutcome::RolledBack { failed: pending, running: s.active });
        }
        self.save(&s)?;
        Ok(BootOutcome::Trial(pending))
    }

    fn mark_good(&self) -> Result<(), BootError> {
        let _g = self.guard()?;
        let mut s = self.load()?;
        if let Some(p) = s.pending.take() {
            s.active = p;
        }
        s.boot_count = 0;
        self.save(&s)
    }

    fn rollback(&self) -> Result<(), BootError> {
        let _g = self.guard()?;
        let mut s = self.load()?;
        // Make the next on_boot() see an exhausted trial so it reports the rollback.
        if s.pending.is_some() {
            s.boot_count = self.max_attempts;
        }
        self.save(&s)
    }
}

/// U-Boot / RAUC style boot control via `fw_printenv` / `fw_setenv`.
#[derive(Debug, Clone)]
pub struct FwSetenvBootControl {
    /// `fw_printenv` path.
    pub printenv: PathBuf,
    /// `fw_setenv` path.
    pub setenv: PathBuf,
    /// Trial boots per update.
    pub max_attempts: u32,
    /// Slot the kernel was booted from (e.g. parsed from `/proc/cmdline` `rauc.slot=`).
    pub booted: Slot,
}

impl FwSetenvBootControl {
    /// Detect the booted slot from `/proc/cmdline` (`rauc.slot=A|B` or `ironmesh.slot=a|b`).
    #[must_use]
    pub fn detect(max_attempts: u32) -> Self {
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let booted = cmdline
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix("rauc.slot=").or_else(|| kv.strip_prefix("ironmesh.slot=")))
            .and_then(Slot::parse)
            .unwrap_or(Slot::A);
        Self { printenv: "fw_printenv".into(), setenv: "fw_setenv".into(), max_attempts, booted }
    }

    fn get(&self, name: &str) -> Result<String, BootError> {
        let out = std::process::Command::new(&self.printenv).args(["-n", name]).output()?;
        if !out.status.success() {
            return Ok(String::new());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    fn set(&self, pairs: &[(&str, String)]) -> Result<(), BootError> {
        for (k, v) in pairs {
            let status = std::process::Command::new(&self.setenv).arg(k).arg(v).status()?;
            if !status.success() {
                return Err(BootError::Tool(format!("fw_setenv {k} failed: {status}")));
            }
        }
        Ok(())
    }

    fn upper(slot: Slot) -> &'static str {
        match slot {
            Slot::A => "A",
            Slot::B => "B",
        }
    }
}

impl BootControl for FwSetenvBootControl {
    fn state(&self) -> Result<BootState, BootError> {
        let order = self.get("BOOT_ORDER")?;
        let active = order.split_whitespace().next().and_then(Slot::parse).unwrap_or(self.booted);
        let pending = Slot::parse(&self.get("ironmesh_pending")?);
        let left: u32 = pending
            .map(|p| self.get(&format!("BOOT_{}_LEFT", Self::upper(p))))
            .transpose()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(self.max_attempts);
        let active = if pending == Some(active) { active.other() } else { active };
        Ok(BootState { active, pending, boot_count: self.max_attempts.saturating_sub(left) })
    }

    fn set_pending(&self, slot: Slot) -> Result<(), BootError> {
        let first = Self::upper(slot);
        let second = Self::upper(slot.other());
        self.set(&[
            ("ironmesh_pending", slot.name().to_owned()),
            (&format!("BOOT_{first}_LEFT"), self.max_attempts.to_string()),
            ("BOOT_ORDER", format!("{first} {second}")),
        ])
    }

    fn on_boot(&self) -> Result<BootOutcome, BootError> {
        let pending = Slot::parse(&self.get("ironmesh_pending")?);
        match pending {
            None => Ok(BootOutcome::Normal(self.booted)),
            Some(p) if p == self.booted => Ok(BootOutcome::Trial(p)),
            Some(p) => {
                // U-Boot fell back: the trial slot exhausted its attempts.
                self.set(&[("ironmesh_pending", String::new())])?;
                Ok(BootOutcome::RolledBack { failed: p, running: self.booted })
            }
        }
    }

    fn mark_good(&self) -> Result<(), BootError> {
        let first = Self::upper(self.booted);
        let second = Self::upper(self.booted.other());
        self.set(&[
            ("BOOT_ORDER", format!("{first} {second}")),
            (&format!("BOOT_{first}_LEFT"), self.max_attempts.to_string()),
            ("ironmesh_pending", String::new()),
        ])
    }

    fn rollback(&self) -> Result<(), BootError> {
        let first = Self::upper(self.booted.other());
        let second = Self::upper(self.booted);
        self.set(&[("BOOT_ORDER", format!("{first} {second}")), (&format!("BOOT_{second}_LEFT"), "0".into())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_boot_control_trial_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let b = FileBootControl::new(dir.path(), 2);
        assert_eq!(b.on_boot().unwrap(), BootOutcome::Normal(Slot::A));
        b.set_pending(Slot::B).unwrap();
        assert_eq!(b.on_boot().unwrap(), BootOutcome::Trial(Slot::B));
        assert_eq!(b.on_boot().unwrap(), BootOutcome::Trial(Slot::B));
        let out = b.on_boot().unwrap();
        assert_eq!(out, BootOutcome::RolledBack { failed: Slot::B, running: Slot::A });
        assert_eq!(out.running(), Slot::A);
        assert_eq!(b.state().unwrap(), BootState { active: Slot::A, pending: None, boot_count: 0 });
        b.set_pending(Slot::B).unwrap();
        assert_eq!(b.on_boot().unwrap().running(), Slot::B);
        b.mark_good().unwrap();
        assert_eq!(b.state().unwrap().active, Slot::B);
        assert_eq!(b.on_boot().unwrap(), BootOutcome::Normal(Slot::B));
        b.set_pending(Slot::A).unwrap();
        b.rollback().unwrap();
        assert!(matches!(b.on_boot().unwrap(), BootOutcome::RolledBack { failed: Slot::A, running: Slot::B }));
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::parse(" B\n"), Some(Slot::B));
        assert_eq!(Slot::parse("c"), None);
    }

    #[cfg(unix)]
    #[test]
    fn fw_setenv_with_fake_tools() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("env");
        std::fs::create_dir(&env).unwrap();
        let printenv = dir.path().join("fw_printenv");
        let setenv = dir.path().join("fw_setenv");
        std::fs::write(&printenv, format!("#!/bin/sh\ncat \"{}/$2\" 2>/dev/null\n", env.display())).unwrap();
        std::fs::write(&setenv, format!("#!/bin/sh\nprintf '%s' \"$2\" > \"{}/$1\"\n", env.display())).unwrap();
        for p in [&printenv, &setenv] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut b = FwSetenvBootControl { printenv, setenv, max_attempts: 3, booted: Slot::A };
        assert_eq!(b.on_boot().unwrap(), BootOutcome::Normal(Slot::A));
        b.set_pending(Slot::B).unwrap();
        assert_eq!(b.state().unwrap().pending, Some(Slot::B));
        b.booted = Slot::B;
        assert_eq!(b.on_boot().unwrap(), BootOutcome::Trial(Slot::B));
        b.mark_good().unwrap();
        assert_eq!(b.state().unwrap().pending, None);
        b.set_pending(Slot::A).unwrap();
        b.rollback().unwrap();
        assert!(matches!(b.on_boot().unwrap(), BootOutcome::RolledBack { .. }));
        let _ = FwSetenvBootControl::detect(3);
    }
}
