//! Tenant-signed commands (type 5): expiry, idempotency (last 256 idempotency keys, persisted so
//! a reboot never re-executes a command) and the `CommandAck` with the echoed nonce.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::persist;
use crate::wire::cbor::{self, Value};
use crate::wire::envelope::{AckStatus, AppMap, Body, Command, CommandAck};

/// Number of idempotency keys remembered.
pub const IDEMPOTENCY_CAPACITY: usize = 256;

/// Side effects requested by commands, desired state and config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Change the telemetry interval (s; 0 disables).
    TelemetryInterval(u64),
    /// Change the log filter.
    LogLevel(String),
    /// Reboot after a delay (s).
    Reboot(u64),
    /// Send one telemetry sample now.
    SendTelemetry,
    /// Renew the operational certificate now.
    Renew,
}

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    entries: Vec<(String, String)>,
}

/// Remembers the acks of the last [`IDEMPOTENCY_CAPACITY`] idempotency keys.
#[derive(Debug)]
pub struct IdempotencyCache {
    path: Option<PathBuf>,
    entries: VecDeque<(String, CommandAck)>,
}

fn ack_to_hex(ack: &CommandAck) -> String {
    hex::encode(cbor::encode(&Body::CommandAck(ack.clone()).to_value()).unwrap_or_default())
}

fn ack_from_hex(h: &str) -> Option<CommandAck> {
    let bytes = hex::decode(h).ok()?;
    let v = cbor::decode(&bytes).ok()?;
    match Body::from_map(6, v.as_map()?).ok()? {
        Body::CommandAck(a) => Some(a),
        _ => None,
    }
}

impl IdempotencyCache {
    /// Load from `path` (or start empty).
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file: CacheFile = persist::read_json(path)?.unwrap_or_default();
        let entries = file.entries.into_iter().filter_map(|(k, h)| ack_from_hex(&h).map(|a| (k, a))).collect();
        Ok(Self { path: Some(path.to_path_buf()), entries })
    }

    /// Volatile cache.
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, entries: VecDeque::new() }
    }

    /// Previous ack for a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&CommandAck> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, a)| a)
    }

    /// Record an ack (evicting the oldest beyond capacity) and persist.
    ///
    /// # Errors
    /// I/O errors.
    pub fn insert(&mut self, key: &str, ack: &CommandAck) -> std::io::Result<()> {
        self.entries.retain(|(k, _)| k != key);
        self.entries.push_back((key.to_owned(), ack.clone()));
        while self.entries.len() > IDEMPOTENCY_CAPACITY {
            self.entries.pop_front();
        }
        if let Some(p) = &self.path {
            let file = CacheFile { entries: self.entries.iter().map(|(k, a)| (k.clone(), ack_to_hex(a))).collect() };
            persist::write_json(p, &file)?;
        }
        Ok(())
    }

    /// Number of remembered keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Sort an application map into canonical CBOR key order (as a decoder returns it).
#[must_use]
pub fn canonical_app_map(mut m: AppMap) -> AppMap {
    m.sort_by_cached_key(|(k, _)| cbor::encode(&Value::text(k.clone())).unwrap_or_default());
    m
}

fn arg<'a>(args: &'a AppMap, name: &str) -> Option<&'a Value> {
    args.iter().find_map(|(k, v)| (k == name).then_some(v))
}

/// Allowed log levels.
pub const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// Validate a telemetry interval (0 = off, else 5..=86400 s).
#[must_use]
pub fn valid_interval(v: &Value) -> Option<u64> {
    match v.as_int() {
        Some(0) => Some(0),
        Some(i) if (5..=86_400).contains(&i) => Some(i as u64),
        _ => None,
    }
}

fn ack(cmd: &Command, status: AckStatus, result: Option<AppMap>, error: Option<&str>) -> CommandAck {
    CommandAck { cmd_id: cmd.cmd_id.clone(), status: status as u8, result, error: error.map(str::to_owned) }
}

/// Execute a verified command; returns the ack body and the side effects to apply.
#[must_use]
pub fn execute(cmd: &Command, now_unix: u64) -> (CommandAck, Vec<Effect>) {
    if now_unix > cmd.expires_at {
        return (ack(cmd, AckStatus::Expired, None, Some("command expired")), Vec::new());
    }
    let ok = |result: AppMap, effects: Vec<Effect>| (ack(cmd, AckStatus::Ok, Some(canonical_app_map(result)), None), effects);
    let rejected = |why: &str| (ack(cmd, AckStatus::Rejected, None, Some(why)), Vec::new());
    match cmd.name.as_str() {
        "ping" => ok(vec![("pong".into(), Value::Bool(true)), ("ts".into(), Value::int(now_unix))], Vec::new()),
        "reboot" => {
            let delay = arg(&cmd.args, "delay_s").and_then(Value::as_int).unwrap_or(0);
            if !(0..=3600).contains(&delay) {
                return rejected("delay_s must be 0..3600");
            }
            ok(vec![("rebooting".into(), Value::Bool(true))], vec![Effect::Reboot(delay as u64)])
        }
        "collect_telemetry" => ok(Vec::new(), vec![Effect::SendTelemetry]),
        "rotate_certificate" => ok(Vec::new(), vec![Effect::Renew]),
        "set_log_level" => match arg(&cmd.args, "level").and_then(Value::as_text) {
            Some(l) if LOG_LEVELS.contains(&l) => ok(vec![("level".into(), Value::text(l))], vec![Effect::LogLevel(l.to_owned())]),
            _ => rejected("level must be one of error, warn, info, debug, trace"),
        },
        "set_telemetry_interval" => match arg(&cmd.args, "interval_s").and_then(valid_interval) {
            Some(i) => ok(vec![("interval_s".into(), Value::int(i))], vec![Effect::TelemetryInterval(i)]),
            None => rejected("interval_s must be 0 or 5..86400"),
        },
        _ => rejected("unknown command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(name: &str, args: AppMap) -> Command {
        Command {
            cmd_id: "123e4567-e89b-12d3-a456-426614174000".into(),
            name: name.into(),
            args,
            idempotency_key: "k1".into(),
            expires_at: 100,
        }
    }

    #[test]
    fn execution_rules() {
        assert_eq!(execute(&cmd("ping", vec![]), 101).0.status, AckStatus::Expired as u8);
        assert_eq!(execute(&cmd("ping", vec![]), 50).0.status, 0);
        let (a, e) = execute(&cmd("reboot", vec![("delay_s".into(), Value::int(5))]), 50);
        assert_eq!((a.status, e), (0, vec![Effect::Reboot(5)]));
        assert_eq!(execute(&cmd("reboot", vec![("delay_s".into(), Value::int(-1))]), 50).0.status, 1);
        assert_eq!(execute(&cmd("collect_telemetry", vec![]), 50).1, vec![Effect::SendTelemetry]);
        assert_eq!(execute(&cmd("rotate_certificate", vec![]), 50).1, vec![Effect::Renew]);
        assert_eq!(
            execute(&cmd("set_log_level", vec![("level".into(), Value::text("debug"))]), 50).1,
            vec![Effect::LogLevel("debug".into())]
        );
        assert_eq!(execute(&cmd("set_log_level", vec![("level".into(), Value::text("loud"))]), 50).0.status, 1);
        assert_eq!(
            execute(&cmd("set_telemetry_interval", vec![("interval_s".into(), Value::int(10))]), 50).1,
            vec![Effect::TelemetryInterval(10)]
        );
        assert_eq!(execute(&cmd("set_telemetry_interval", vec![("interval_s".into(), Value::int(1))]), 50).0.status, 1);
        let (a, _) = execute(&cmd("format_disk", vec![]), 50);
        assert_eq!(a.status, 1);
        assert_eq!(a.error.as_deref(), Some("unknown command"));
    }

    #[test]
    fn idempotency_persists_and_evicts() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("idem.json");
        let mut c = IdempotencyCache::open(&p).unwrap();
        assert!(c.is_empty());
        let (a, _) = execute(&cmd("ping", vec![]), 1);
        for i in 0..300 {
            c.insert(&format!("k{i}"), &a).unwrap();
        }
        assert_eq!(c.len(), IDEMPOTENCY_CAPACITY);
        assert!(c.get("k0").is_none());
        assert_eq!(c.get("k299"), Some(&a));
        let c2 = IdempotencyCache::open(&p).unwrap();
        assert_eq!(c2.get("k299"), Some(&a));
        let mut m = IdempotencyCache::in_memory();
        m.insert("x", &a).unwrap();
        m.insert("x", &a).unwrap();
        assert_eq!(m.len(), 1);
        assert!(ack_from_hex("zz").is_none());
        assert_eq!(valid_interval(&Value::int(0)), Some(0));
    }
}
