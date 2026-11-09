//! Persistent offline ring buffer of signed uplink envelopes (contract §4: 10 000 messages,
//! replayed in order on reconnect).
//!
//! On-disk format: an append-only log `buffer.log` of records
//! `len:u32be | crc32:u32be | seq:u64be | nonce:12 | AES-256-GCM(topic_len:u16be | topic | payload)`
//! plus `buffer.head` (JSON: byte offset of the oldest live record). Only an index (offset,
//! length, seq) is kept in memory; payloads are read back from disk when flushed. A torn last
//! record (power loss) is detected by its length/CRC and truncated on open. When the dead prefix
//! grows beyond half the file the log is compacted with an atomic rewrite. When full, the oldest
//! record is dropped.
//!
//! **Encryption at rest (threat model T-04/T-09).** Every record is sealed with AES-256-GCM under
//! a key derived from the agent's at-rest key (`atrest::Purpose::OfflineBuffer`, HKDF info
//! `ironmesh-offline-buffer-aead-v1`), a fresh random 96-bit nonce and the record's `seq`
//! (8 bytes big-endian) as associated data, so the topic and the signed envelope are not readable
//! from a copied disk and a record cannot be moved to another `seq`. The CRC only detects torn
//! writes; authenticity comes from the GCM tag. A record whose tag does not verify (corruption,
//! tampering, a different machine secret, or a plaintext record written by an older agent) is
//! dropped and counted ([`RingBuffer::corrupt_dropped`]), never sent. The `seq` is stored in the
//! clear for the index; message lengths are visible.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::persist;

/// Maximum size of one buffered record (topic + payload).
pub const MAX_RECORD: usize = 64 * 1024;
const NONCE: usize = 12;
const TAG: usize = 16;
/// Smallest valid record body: seq, nonce, tag and the encrypted topic length.
const MIN_BODY: usize = 8 + NONCE + TAG + 2;
const MAX_BODY: usize = MIN_BODY + MAX_RECORD;
const COMPACT_MIN: u64 = 1 << 20;

/// A buffered message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Envelope sequence number.
    pub seq: u64,
    /// MQTT topic.
    pub topic: String,
    /// Signed envelope bytes.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    offset: u64,
    len: u32,
    seq: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Head {
    offset: u64,
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

enum Store {
    Disk { dir: PathBuf, file: File, end: u64, head: u64, sync: bool, cipher: Box<Aes256Gcm> },
    Memory(VecDeque<Record>),
}

/// The ring buffer.
pub struct RingBuffer {
    store: Store,
    index: VecDeque<Entry>,
    capacity: usize,
    dropped: u64,
    corrupt: u64,
}

impl std::fmt::Debug for RingBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingBuffer").field("len", &self.len()).field("capacity", &self.capacity).finish()
    }
}

fn check_size(r: &Record) -> io::Result<()> {
    if r.topic.len() + r.payload.len() > MAX_RECORD || r.topic.len() > usize::from(u16::MAX) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "record too large for the offline buffer"));
    }
    Ok(())
}

/// Frame and seal one record: `len | crc32 | seq | nonce | GCM(topic_len | topic | payload)`.
fn encode_record(r: &Record, cipher: &Aes256Gcm) -> io::Result<Vec<u8>> {
    check_size(r)?;
    let topic = r.topic.as_bytes();
    let mut pt = Zeroizing::new(Vec::with_capacity(2 + topic.len() + r.payload.len()));
    pt.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    pt.extend_from_slice(topic);
    pt.extend_from_slice(&r.payload);
    let mut nonce = [0u8; NONCE];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aad = r.seq.to_be_bytes();
    let ct = cipher
        .encrypt(&nonce.into(), Payload { msg: &pt, aad: &aad })
        .map_err(|_| io::Error::other("offline buffer: record encryption failed"))?;
    let mut body = Vec::with_capacity(8 + NONCE + ct.len());
    body.extend_from_slice(&aad);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Clear-text `seq` of a record body (index only; authenticated when the record is opened).
fn body_seq(body: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(body.get(..8)?.try_into().ok()?))
}

/// Authenticate and decrypt a record body.
fn open_body(body: &[u8], cipher: &Aes256Gcm) -> Option<Record> {
    let seq = body_seq(body)?;
    let nonce: [u8; NONCE] = body.get(8..8 + NONCE)?.try_into().ok()?;
    let pt = Zeroizing::new(cipher.decrypt(&nonce.into(), Payload { msg: body.get(8 + NONCE..)?, aad: &body[..8] }).ok()?);
    let tl = usize::from(u16::from_be_bytes(pt.get(..2)?.try_into().ok()?));
    let topic = std::str::from_utf8(pt.get(2..2 + tl)?).ok()?.to_owned();
    Some(Record { seq, topic, payload: pt.get(2 + tl..)?.to_vec() })
}

impl RingBuffer {
    /// Open (or create) a disk-backed buffer in `dir`, sealed with `key` (the
    /// `atrest::Purpose::OfflineBuffer` subkey).
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(dir: &Path, capacity: usize, sync: bool, key: &[u8; 32]) -> io::Result<Self> {
        let cipher = Box::new(Aes256Gcm::new_from_slice(key).map_err(|_| io::Error::other("offline buffer key"))?);
        persist::ensure_private_dir(dir)?;
        let log = dir.join("buffer.log");
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&log)?;
        let head: Head = persist::read_json(&dir.join("buffer.head"))?.unwrap_or_default();
        let len = file.metadata()?.len();
        let mut index = VecDeque::new();
        let mut pos = head.offset.min(len);
        file.seek(SeekFrom::Start(pos))?;
        let mut reader = io::BufReader::new(&file);
        loop {
            let mut hdr = [0u8; 8];
            if reader.read_exact(&mut hdr).is_err() {
                break;
            }
            let blen = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
            let crc = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            if !(MIN_BODY..=MAX_BODY).contains(&blen) {
                break;
            }
            let mut body = vec![0u8; blen];
            if reader.read_exact(&mut body).is_err() || crc32(&body) != crc {
                break;
            }
            let Some(seq) = body_seq(&body) else { break };
            index.push_back(Entry { offset: pos, len: (8 + blen) as u32, seq });
            pos += (8 + blen) as u64;
        }
        drop(reader);
        if pos < len {
            tracing::warn!(valid = pos, len, "offline buffer: truncating torn tail");
            file.set_len(pos)?;
        }
        let mut rb = Self {
            store: Store::Disk { dir: dir.to_path_buf(), file, end: pos, head: head.offset.min(pos), sync, cipher },
            index,
            capacity: capacity.max(1),
            dropped: 0,
            corrupt: 0,
        };
        while rb.index.len() > rb.capacity {
            rb.drop_front()?;
        }
        Ok(rb)
    }

    /// A volatile buffer (fleet simulator).
    #[must_use]
    pub fn in_memory(capacity: usize) -> Self {
        Self { store: Store::Memory(VecDeque::new()), index: VecDeque::new(), capacity: capacity.max(1), dropped: 0, corrupt: 0 }
    }

    /// Number of buffered messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Messages dropped because the buffer was full (since open).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Records dropped because they failed authentication or were malformed (since open); such
    /// records are never sent.
    #[must_use]
    pub fn corrupt_dropped(&self) -> u64 {
        self.corrupt
    }

    /// Sequence numbers of the oldest and newest message.
    #[must_use]
    pub fn seq_range(&self) -> Option<(u64, u64)> {
        Some((self.index.front()?.seq, self.index.back()?.seq))
    }

    /// Append a message (dropping the oldest when full).
    ///
    /// # Errors
    /// I/O errors or an oversized record.
    pub fn push(&mut self, record: Record) -> io::Result<()> {
        match &mut self.store {
            Store::Disk { file, end, sync, cipher, .. } => {
                let bytes = encode_record(&record, cipher)?;
                file.seek(SeekFrom::Start(*end))?;
                file.write_all(&bytes)?;
                if *sync {
                    file.sync_data()?;
                }
                self.index.push_back(Entry { offset: *end, len: bytes.len() as u32, seq: record.seq });
                *end += bytes.len() as u64;
            }
            Store::Memory(q) => {
                check_size(&record)?;
                self.index.push_back(Entry { offset: 0, len: 0, seq: record.seq });
                q.push_back(record);
            }
        }
        while self.index.len() > self.capacity {
            self.drop_front()?;
            self.dropped += 1;
        }
        Ok(())
    }

    /// Read the oldest authentic message without removing it. Records that fail the CRC or
    /// the AES-GCM tag are dropped (and counted in [`Self::corrupt_dropped`]) on the way.
    ///
    /// # Errors
    /// I/O errors.
    pub fn peek(&mut self) -> io::Result<Option<Record>> {
        loop {
            let Some(entry) = self.index.front().copied() else { return Ok(None) };
            let opened = match &mut self.store {
                Store::Memory(q) => return Ok(q.front().cloned()),
                Store::Disk { file, cipher, .. } => {
                    let mut buf = vec![0u8; entry.len as usize];
                    file.seek(SeekFrom::Start(entry.offset))?;
                    file.read_exact(&mut buf)?;
                    let crc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    if crc32(&buf[8..]) == crc {
                        open_body(&buf[8..], cipher).filter(|r| r.seq == entry.seq)
                    } else {
                        None
                    }
                }
            };
            if let Some(rec) = opened {
                return Ok(Some(rec));
            }
            tracing::warn!(seq = entry.seq, "offline buffer: record failed authentication; dropped, not sent");
            self.corrupt += 1;
            self.drop_front()?;
        }
    }

    /// Remove the oldest message (after it was delivered).
    ///
    /// # Errors
    /// I/O errors.
    pub fn pop(&mut self) -> io::Result<()> {
        self.drop_front()
    }

    fn drop_front(&mut self) -> io::Result<()> {
        let Some(entry) = self.index.pop_front() else { return Ok(()) };
        match &mut self.store {
            Store::Memory(q) => {
                q.pop_front();
            }
            Store::Disk { dir, head, .. } => {
                *head = entry.offset + u64::from(entry.len);
                persist::write_json(&dir.join("buffer.head"), &Head { offset: *head })?;
            }
        }
        self.maybe_compact()
    }

    fn maybe_compact(&mut self) -> io::Result<()> {
        let Store::Disk { dir, file, end, head, .. } = &mut self.store else { return Ok(()) };
        if *head < COMPACT_MIN || *head * 2 < *end {
            return Ok(());
        }
        let mut live = vec![0u8; usize::try_from(*end - *head).unwrap_or(0)];
        file.seek(SeekFrom::Start(*head))?;
        file.read_exact(&mut live)?;
        let log = dir.join("buffer.log");
        persist::write_atomic(&log, &live)?;
        let shift = *head;
        *file = OpenOptions::new().read(true).write(true).open(&log)?;
        *end -= shift;
        *head = 0;
        persist::write_json(&dir.join("buffer.head"), &Head { offset: 0 })?;
        for e in &mut self.index {
            e.offset -= shift;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn rec(seq: u64, n: usize) -> Record {
        Record { seq, topic: "im/v1/t/d/telemetry".into(), payload: vec![seq as u8; n] }
    }

    fn open(dir: &Path, cap: usize, sync: bool) -> RingBuffer {
        RingBuffer::open(dir, cap, sync, &KEY).unwrap()
    }

    /// Byte offset and length of every record in the log.
    fn frames(log: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 8 <= log.len() {
            let blen = u32::from_be_bytes(log[pos..pos + 4].try_into().unwrap()) as usize;
            out.push((pos, 8 + blen));
            pos += 8 + blen;
        }
        out
    }

    fn fix_crc(log: &mut [u8], (off, len): (usize, usize)) {
        let crc = crc32(&log[off + 8..off + len]);
        log[off + 4..off + 8].copy_from_slice(&crc.to_be_bytes());
    }

    #[test]
    fn persists_in_order_and_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = open(dir.path(), 3, true);
            for s in 1..=5 {
                b.push(rec(s, 10)).unwrap();
            }
            assert_eq!(b.len(), 3);
            assert_eq!(b.dropped(), 2);
            assert_eq!(b.seq_range(), Some((3, 5)));
        }
        let mut b = open(dir.path(), 3, false);
        assert_eq!(b.len(), 3);
        assert_eq!(b.peek().unwrap().unwrap(), rec(3, 10));
        b.pop().unwrap();
        drop(b);
        let mut b = open(dir.path(), 3, false);
        let mut seqs = Vec::new();
        while let Some(r) = b.peek().unwrap() {
            seqs.push(r.seq);
            b.pop().unwrap();
        }
        assert_eq!(seqs, vec![4, 5]);
        assert!(b.is_empty());
        assert!(b.peek().unwrap().is_none());
        b.pop().unwrap();
        assert!(format!("{b:?}").contains("RingBuffer"));
    }

    #[test]
    fn torn_tail_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = open(dir.path(), 10, false);
            b.push(rec(1, 5)).unwrap();
            b.push(rec(2, 5)).unwrap();
        }
        let log = dir.path().join("buffer.log");
        let len = std::fs::metadata(&log).unwrap().len();
        let f = OpenOptions::new().write(true).open(&log).unwrap();
        f.set_len(len - 3).unwrap();
        let b = open(dir.path(), 10, false);
        assert_eq!(b.len(), 1);
        assert_eq!(b.seq_range(), Some((1, 1)));
    }

    #[test]
    fn compaction_and_memory_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = open(dir.path(), 10_000, false);
        for s in 0..400 {
            b.push(rec(s, 4000)).unwrap();
        }
        for _ in 0..300 {
            b.pop().unwrap();
        }
        let size = std::fs::metadata(dir.path().join("buffer.log")).unwrap().len();
        assert!(size < 300 * 4000, "log was compacted: {size}");
        assert_eq!(b.peek().unwrap().unwrap().seq, 300);
        drop(b);
        let mut b = open(dir.path(), 10_000, false);
        assert_eq!(b.len(), 100);
        assert_eq!(b.peek().unwrap().unwrap().seq, 300);
        assert!(b.push(Record { seq: 1, topic: "t".into(), payload: vec![0; MAX_RECORD + 1] }).is_err());

        let mut m = RingBuffer::in_memory(2);
        for s in 1..=3 {
            m.push(rec(s, 1)).unwrap();
        }
        assert_eq!(m.peek().unwrap().unwrap().seq, 2);
        m.pop().unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn records_are_encrypted_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = open(dir.path(), 10, false);
        let secret = Record { seq: 7, topic: "im/v1/tenant/device/telemetry".into(), payload: b"cpu=42;secret-payload".to_vec() };
        b.push(secret.clone()).unwrap();
        b.push(secret.clone()).unwrap();
        let log = std::fs::read(dir.path().join("buffer.log")).unwrap();
        let find = |needle: &[u8]| log.windows(needle.len()).any(|w| w == needle);
        assert!(!find(b"secret-payload"), "payload must not be stored in the clear");
        assert!(!find(b"telemetry"), "topic must not be stored in the clear");
        let f = frames(&log);
        assert_eq!(f.len(), 2);
        assert_ne!(log[f[0].0 + 16..f[0].0 + 28], log[f[1].0 + 16..f[1].0 + 28], "fresh nonce per record");
        assert_eq!(b.peek().unwrap().unwrap(), secret);
        assert_eq!(b.corrupt_dropped(), 0);
    }

    #[test]
    fn tampered_records_are_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = open(dir.path(), 10, false);
            for s in 1..=4 {
                b.push(rec(s, 32)).unwrap();
            }
        }
        let path = dir.path().join("buffer.log");
        let mut log = std::fs::read(&path).unwrap();
        let f = frames(&log);
        // Record 1: flip a ciphertext byte, re-compute the CRC (so only the GCM tag catches it).
        log[f[0].0 + 40] ^= 1;
        fix_crc(&mut log, f[0]);
        // Record 3: move it to another seq (the seq is the associated data).
        log[f[2].0 + 8 + 7] = 9;
        fix_crc(&mut log, f[2]);
        std::fs::write(&path, &log).unwrap();
        let mut b = open(dir.path(), 10, false);
        assert_eq!(b.len(), 4, "the CRC scan still indexes every frame");
        let mut seqs = Vec::new();
        while let Some(r) = b.peek().unwrap() {
            assert_eq!(r, rec(r.seq, 32));
            seqs.push(r.seq);
            b.pop().unwrap();
        }
        assert_eq!(seqs, vec![2, 4]);
        assert_eq!(b.corrupt_dropped(), 2);
    }

    #[test]
    fn wrong_key_or_legacy_plaintext_is_never_sent() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = open(dir.path(), 10, false);
            b.push(rec(1, 8)).unwrap();
            b.push(rec(2, 8)).unwrap();
        }
        let mut other = RingBuffer::open(dir.path(), 10, false, &[0x43; 32]).unwrap();
        assert!(other.peek().unwrap().is_none());
        assert_eq!(other.corrupt_dropped(), 2);
        assert!(other.is_empty());
        drop(other);
        // A pre-encryption (plaintext) record: seq | topic_len | topic | payload.
        let mut body = 5u64.to_be_bytes().to_vec();
        body.extend_from_slice(&5u16.to_be_bytes());
        body.extend_from_slice(b"topic");
        body.extend_from_slice(&[0u8; 40]);
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&crc32(&body).to_be_bytes());
        frame.extend_from_slice(&body);
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("buffer.log"), &frame).unwrap();
        let mut b = open(dir2.path(), 10, false);
        assert_eq!(b.len(), 1);
        assert!(b.peek().unwrap().is_none());
        assert_eq!(b.corrupt_dropped(), 1);
    }
}
