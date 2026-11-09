//! Outbound sequence counter (persisted before use) and the persisted inbound replay store.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::persist;
use crate::wire::cose::Kid;
use crate::wire::envelope::{InMemoryReplayStore, ReplayStore};
use crate::wire::ids::Direction;

/// Wall clock with an adjustable offset (DUT `set_clock`) and a monotonic origin.
#[derive(Debug)]
pub struct Clock {
    offset_s: AtomicI64,
    origin: Instant,
}

impl Default for Clock {
    fn default() -> Self {
        Self { offset_s: AtomicI64::new(0), origin: Instant::now() }
    }
}

impl Clock {
    /// System time.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Unix seconds including the offset.
    #[must_use]
    pub fn now_unix(&self) -> u64 {
        let sys = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
        u64::try_from(sys.saturating_add(self.offset_s.load(Ordering::Relaxed))).unwrap_or(0)
    }

    /// Make `now_unix()` return `unix_s` from now on.
    pub fn set_unix(&self, unix_s: u64) {
        let sys = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
        self.offset_s.store(i64::try_from(unix_s).unwrap_or(i64::MAX) - sys, Ordering::Relaxed);
    }

    /// Milliseconds since the clock was created (monotonic).
    #[must_use]
    pub fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct SeqFile {
    /// Every value below this may already have been used.
    reserved_until: u64,
}

/// Strictly increasing outbound `seq`, persisted **before** a value is handed out.
///
/// Values are reserved in blocks of `block` (1 = persist every message): the file always holds
/// an upper bound of every value ever returned, so after a crash or reboot the counter resumes
/// above it and never reuses a sequence number (`WIRE_FORMAT.md` §3.7).
#[derive(Debug)]
pub struct SeqCounter {
    path: Option<PathBuf>,
    state: Mutex<(u64, u64)>, // (next, reserved_until)
    block: u64,
}

impl SeqCounter {
    /// Load (or create) the counter stored at `path`.
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(path: &Path, block: u64) -> std::io::Result<Self> {
        let stored: Option<SeqFile> = persist::read_json(path)?;
        let next = match stored {
            // A restart burns one value past the persisted bound, and the bump is persisted at
            // once: every boot moves the counter strictly forward even if nothing is sent, so
            // `status.seq_out` after a reboot is always greater than before (conformance C-RPL-4)
            // and matches the C core, which resumes above its reserved high-water mark.
            Some(file) => {
                let bumped = file.reserved_until.max(1).saturating_add(1);
                persist::write_json(path, &SeqFile { reserved_until: bumped })?;
                bumped
            }
            None => 1,
        };
        Ok(Self { path: Some(path.to_path_buf()), state: Mutex::new((next, next)), block: block.max(1) })
    }

    /// A volatile counter (tests).
    #[must_use]
    pub fn in_memory(start: u64) -> Self {
        Self { path: None, state: Mutex::new((start, u64::MAX)), block: 1 }
    }

    /// Reserve and return the next sequence number.
    ///
    /// # Errors
    /// The value is only returned once its reservation is durable.
    pub fn next(&self) -> std::io::Result<u64> {
        let mut guard = self.state.lock().map_err(|_| std::io::Error::other("seq lock poisoned"))?;
        let (next, reserved) = *guard;
        if next >= reserved {
            let new_reserved = next.saturating_add(self.block);
            if let Some(path) = &self.path {
                persist::write_json(path, &SeqFile { reserved_until: new_reserved })?;
            }
            guard.1 = new_reserved;
        }
        guard.0 = next.saturating_add(1);
        Ok(next)
    }

    /// The next value that would be returned (DUT `status.seq_out`).
    #[must_use]
    pub fn peek(&self) -> u64 {
        self.state.lock().map(|g| g.0).unwrap_or(0)
    }
}

/// On-disk format version of the replay store.
pub const REPLAY_FORMAT: u32 = 2;

/// Downlink message types (each has its own replay stream).
const DOWNLINK_TYPES: [u8; 4] = [4, 5, 7, 9];

#[derive(Serialize, Deserialize, Default)]
struct ReplayFile {
    /// 2 = per-stream entries (`WIRE_FORMAT.md` §3.6 step 11). Absent = legacy v1.
    #[serde(default)]
    format: u32,
    /// v2: one entry per replay stream.
    #[serde(default)]
    streams: Vec<StreamEntry>,
    /// v1 (legacy): one entry per sender kid.
    #[serde(default, skip_serializing)]
    entries: Vec<LegacyEntry>,
}

#[derive(Serialize, Deserialize)]
struct StreamEntry {
    /// Uplink: hex device kid. Downlink: `"<tenant kid>/<type>"`.
    stream: String,
    direction: Direction,
    last_seq: u64,
}

#[derive(Deserialize)]
struct LegacyEntry {
    kid: String,
    kid_is_text: bool,
    direction: Direction,
    last_seq: u64,
}

fn bad(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// Inbound replay store persisted to a JSON file: one last-accepted `seq` per replay stream
/// (device kid for uplink, `"<tenant kid>/<type>"` for downlink).
///
/// A legacy (v1) file keyed by the bare tenant kid is migrated conservatively: its last `seq`
/// becomes the floor of every downlink stream (4, 5, 7, 9), so no previously accepted message
/// can be replayed after the upgrade.
#[derive(Debug)]
pub struct FileReplayStore {
    path: PathBuf,
    inner: InMemoryReplayStore,
}

impl FileReplayStore {
    /// Load (or create) the store at `path`.
    ///
    /// # Errors
    /// I/O or format errors.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file: ReplayFile = persist::read_json(path)?.unwrap_or_default();
        let mut inner = InMemoryReplayStore::new();
        if file.format > REPLAY_FORMAT {
            return Err(bad(format!("replay store format {} is newer than this agent ({REPLAY_FORMAT})", file.format)));
        }
        for e in file.streams {
            let kid = match e.direction {
                Direction::Downlink => Kid::Text(e.stream),
                Direction::Uplink => Kid::Bytes(hex::decode(&e.stream).map_err(bad)?),
            };
            inner.insert(kid, e.direction, e.last_seq);
        }
        let migrated = !file.entries.is_empty();
        for e in file.entries {
            match (e.direction, e.kid_is_text) {
                (Direction::Downlink, true) => {
                    for t in DOWNLINK_TYPES {
                        let stream = crate::wire::envelope::replay_stream(&Kid::Text(e.kid.clone()), Direction::Downlink, t);
                        let floor = inner.last_seq(&stream, Direction::Downlink).unwrap_or(0).max(e.last_seq);
                        inner.insert(stream, Direction::Downlink, floor);
                    }
                }
                (dir, false) => inner.insert(Kid::Bytes(hex::decode(&e.kid).map_err(bad)?), dir, e.last_seq),
                (dir, true) => inner.insert(Kid::Text(e.kid), dir, e.last_seq),
            }
        }
        let store = Self { path: path.to_path_buf(), inner };
        if migrated {
            store.save(&store.inner)?;
        }
        Ok(store)
    }

    fn save(&self, candidate: &InMemoryReplayStore) -> std::io::Result<()> {
        let streams = candidate
            .entries()
            .into_iter()
            .map(|(kid, direction, last_seq)| StreamEntry {
                stream: match kid {
                    Kid::Text(t) => t,
                    Kid::Bytes(b) => hex::encode(b),
                },
                direction,
                last_seq,
            })
            .collect();
        persist::write_json(&self.path, &ReplayFile { format: REPLAY_FORMAT, streams, entries: Vec::new() })
    }
}

impl ReplayStore for FileReplayStore {
    fn check_and_record(&mut self, kid: &Kid, direction: Direction, seq: u64) -> bool {
        let mut candidate = self.inner.clone();
        if !candidate.check_and_record(kid, direction, seq) {
            return false;
        }
        match self.save(&candidate) {
            Ok(()) => {
                self.inner = candidate;
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot persist replay store; rejecting message (fail closed)");
                false
            }
        }
    }

    fn last_seq(&self, kid: &Kid, direction: Direction) -> Option<u64> {
        self.inner.last_seq(kid, direction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_never_reused_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("seq.json");
        let c = SeqCounter::open(&p, 10).unwrap();
        let a: Vec<u64> = (0..3).map(|_| c.next().unwrap()).collect();
        assert_eq!(a, vec![1, 2, 3]);
        assert_eq!(c.peek(), 4);
        drop(c);
        let c = SeqCounter::open(&p, 10).unwrap();
        let n = c.next().unwrap();
        assert!(n > 3, "{n}");
        let strict = SeqCounter::open(&dir.path().join("s2.json"), 1).unwrap();
        for _ in 0..5 {
            strict.next().unwrap();
        }
        drop(strict);
        let after = SeqCounter::open(&dir.path().join("s2.json"), 1).unwrap().next().unwrap();
        assert!(after > 5, "{after}");
        // Reboots without sending still move the counter forward every time.
        let idle = dir.path().join("idle.json");
        let first = SeqCounter::open(&idle, 1).unwrap();
        first.next().unwrap();
        let before = first.peek();
        drop(first);
        let mut last = before;
        for _ in 0..3 {
            let reopened = SeqCounter::open(&idle, 1).unwrap().peek();
            assert!(reopened > last, "{reopened} <= {last}");
            last = reopened;
        }
        let m = SeqCounter::in_memory(7);
        assert_eq!(m.next().unwrap(), 7);
    }

    #[test]
    fn legacy_replay_file_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("replay.json");
        std::fs::write(
            &p,
            r#"{"entries":[{"kid":"tenant-cmd-x","kid_is_text":true,"direction":"downlink","last_seq":9},{"kid":"0102","kid_is_text":false,"direction":"uplink","last_seq":3}]}"#,
        )
        .unwrap();
        let mut s = FileReplayStore::open(&p).unwrap();
        for t in DOWNLINK_TYPES {
            let stream = Kid::Text(format!("tenant-cmd-x/{t}"));
            assert_eq!(s.last_seq(&stream, Direction::Downlink), Some(9));
            assert!(!s.check_and_record(&stream, Direction::Downlink, 9));
        }
        assert_eq!(s.last_seq(&Kid::Bytes(vec![1, 2]), Direction::Uplink), Some(3));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"format\": 2") && text.contains("tenant-cmd-x/7"), "{text}");
        std::fs::write(&p, r#"{"format":99,"streams":[]}"#).unwrap();
        assert!(FileReplayStore::open(&p).is_err());
    }

    #[test]
    fn replay_store_persists() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("replay.json");
        let k = Kid::Text("tenant-cmd-x/5".into());
        let b = Kid::Bytes(vec![1, 2]);
        {
            let mut s = FileReplayStore::open(&p).unwrap();
            assert!(s.check_and_record(&k, Direction::Downlink, 5));
            assert!(!s.check_and_record(&k, Direction::Downlink, 5));
            assert!(s.check_and_record(&b, Direction::Uplink, 1));
        }
        let mut s = FileReplayStore::open(&p).unwrap();
        assert_eq!(s.last_seq(&k, Direction::Downlink), Some(5));
        assert_eq!(s.last_seq(&b, Direction::Uplink), Some(1));
        assert!(!s.check_and_record(&k, Direction::Downlink, 4));
        assert!(s.check_and_record(&k, Direction::Downlink, 6));
    }

    #[test]
    fn clock_offset() {
        let c = Clock::new();
        c.set_unix(1_000);
        assert!((1_000..1_003).contains(&c.now_unix()));
        assert!(c.monotonic_ms() < 10_000);
    }
}
