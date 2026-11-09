//! Encrypted configuration (type 9 inside COSE_Encrypt0 with an HPKE-wrapped CEK, contract §5):
//! decrypt with the operational certificate key, verify the inner tenant-signed envelope, apply
//! monotonically versioned settings.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::commands::Effect;
use crate::persist;
use crate::shadow::interpret;
use crate::wire::envelope::Config;

#[derive(Serialize, Deserialize, Default)]
struct ConfigFile {
    version: u64,
    keys: Vec<String>,
}

/// Applied configuration state.
#[derive(Debug)]
pub struct ConfigState {
    path: Option<PathBuf>,
    version: u64,
    keys: Vec<String>,
}

impl ConfigState {
    /// Load.
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f: ConfigFile = persist::read_json(path)?.unwrap_or_default();
        Ok(Self { path: Some(path.to_path_buf()), version: f.version, keys: f.keys })
    }

    /// Volatile state.
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, version: 0, keys: Vec::new() }
    }

    /// Applied version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Setting names applied by the last config.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// Apply a verified config; `None` when its version is not newer.
    ///
    /// Only the version and setting *names* are persisted here; values take effect through the
    /// returned effects (the plaintext never leaves the device process).
    ///
    /// # Errors
    /// I/O errors.
    pub fn apply(&mut self, cfg: &Config) -> std::io::Result<Option<Vec<Effect>>> {
        if cfg.version <= self.version {
            return Ok(None);
        }
        let (accepted, effects) = interpret(&cfg.settings);
        self.version = cfg.version;
        self.keys = accepted.into_iter().map(|(k, _)| k).collect();
        if let Some(p) = &self.path {
            persist::write_json(p, &ConfigFile { version: self.version, keys: self.keys.clone() })?;
        }
        Ok(Some(effects))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::cbor::Value;

    #[test]
    fn versions_are_monotonic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.json");
        let mut c = ConfigState::open(&p).unwrap();
        let cfg = Config {
            version: 12,
            settings: vec![("log_level".into(), Value::text("info")), ("telemetry_interval_s".into(), Value::int(60))],
        };
        let eff = c.apply(&cfg).unwrap().unwrap();
        assert_eq!(eff.len(), 2);
        assert!(c.apply(&cfg).unwrap().is_none());
        let c2 = ConfigState::open(&p).unwrap();
        assert_eq!(c2.version(), 12);
        assert_eq!(c2.keys().len(), 2);
        assert_eq!(ConfigState::in_memory().version(), 0);
    }
}
