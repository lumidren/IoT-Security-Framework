//! Device shadow: apply tenant-signed desired state (type 4) and report it (type 3).
//!
//! Desired documents carry a monotonically increasing `version`; stale or replayed versions are
//! ignored. Known keys (`telemetry_interval_s`, `log_level`) take effect immediately; unknown
//! keys are accepted and echoed so the cloud sees the device converge.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::commands::{valid_interval, Effect, LOG_LEVELS};
use crate::persist;
use crate::wire::cbor::{self, Value};
use crate::wire::envelope::{AppMap, ShadowState};

#[derive(Serialize, Deserialize, Default)]
struct ShadowFile {
    version: u64,
    reported_cbor_hex: String,
}

/// Persisted shadow state.
#[derive(Debug)]
pub struct Shadow {
    path: Option<PathBuf>,
    version: u64,
    reported: AppMap,
}

fn map_to_hex(m: &AppMap) -> String {
    let v = Value::Map(m.iter().map(|(k, v)| (Value::text(k.clone()), v.clone())).collect());
    hex::encode(cbor::encode(&v).unwrap_or_default())
}

fn map_from_hex(h: &str) -> AppMap {
    hex::decode(h)
        .ok()
        .and_then(|b| cbor::decode(&b).ok())
        .and_then(|v| v.as_map().map(|m| m.iter().filter_map(|(k, v)| k.as_text().map(|k| (k.to_owned(), v.clone()))).collect()))
        .unwrap_or_default()
}

/// Validate known keys and translate them into effects; returns the accepted entries.
#[must_use]
pub fn interpret(settings: &AppMap) -> (AppMap, Vec<Effect>) {
    let mut accepted = Vec::new();
    let mut effects = Vec::new();
    for (k, v) in settings {
        match k.as_str() {
            "telemetry_interval_s" => {
                if let Some(i) = valid_interval(v) {
                    effects.push(Effect::TelemetryInterval(i));
                    accepted.push((k.clone(), v.clone()));
                }
            }
            "log_level" => {
                if let Some(l) = v.as_text().filter(|l| LOG_LEVELS.contains(l)) {
                    effects.push(Effect::LogLevel(l.to_owned()));
                    accepted.push((k.clone(), v.clone()));
                }
            }
            _ => accepted.push((k.clone(), v.clone())),
        }
    }
    (accepted, effects)
}

impl Shadow {
    /// Load from `path`.
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f: ShadowFile = persist::read_json(path)?.unwrap_or_default();
        Ok(Self { path: Some(path.to_path_buf()), version: f.version, reported: map_from_hex(&f.reported_cbor_hex) })
    }

    /// Volatile shadow.
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, version: 0, reported: Vec::new() }
    }

    /// Last applied version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Apply a desired document; `None` if stale.
    ///
    /// # Errors
    /// I/O errors persisting the new state.
    pub fn apply_desired(&mut self, desired: &ShadowState) -> std::io::Result<Option<(ShadowState, Vec<Effect>)>> {
        if desired.version <= self.version && self.version != 0 {
            return Ok(None);
        }
        let (accepted, effects) = interpret(&desired.state);
        for (k, v) in accepted {
            self.reported.retain(|(rk, _)| *rk != k);
            self.reported.push((k, v));
        }
        self.reported.sort_by(|a, b| a.0.cmp(&b.0));
        self.version = desired.version;
        if let Some(p) = &self.path {
            persist::write_json(p, &ShadowFile { version: self.version, reported_cbor_hex: map_to_hex(&self.reported) })?;
        }
        Ok(Some((ShadowState { state: self.reported.clone(), version: self.version }, effects)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_state_versions() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("shadow.json");
        let mut s = Shadow::open(&p).unwrap();
        let d = ShadowState {
            state: vec![
                ("telemetry_interval_s".into(), Value::int(10)),
                ("log_level".into(), Value::text("nope")),
                ("x".into(), Value::Bool(true)),
            ],
            version: 3,
        };
        let (rep, eff) = s.apply_desired(&d).unwrap().unwrap();
        assert_eq!(rep.version, 3);
        assert_eq!(eff, vec![Effect::TelemetryInterval(10)]);
        assert_eq!(rep.state.len(), 2);
        assert!(s.apply_desired(&d).unwrap().is_none());
        let s2 = Shadow::open(&p).unwrap();
        assert_eq!(s2.version(), 3);
        let mut m = Shadow::in_memory();
        let d2 = ShadowState { state: vec![("log_level".into(), Value::text("debug"))], version: 1 };
        assert_eq!(m.apply_desired(&d2).unwrap().unwrap().1, vec![Effect::LogLevel("debug".into())]);
        assert!(map_from_hex("zz").is_empty());
    }
}
