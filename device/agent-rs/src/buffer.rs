//! Persistent offline ring buffer of signed uplink envelopes (contract §4: 10 000 messages,
//! replayed in order on reconnect).
//!
//! On-disk format: an append-only log `buffer.log` of records
//! `len:u32be | crc32:u32be | seq:u64be | topic_len:u16be | topic | payload` plus `buffer.head`
//! (JSON: byte offset of the oldest live record). Only an index (offset, length, seq) is kept in
//! memory; payloads are read back from disk when flushed. A torn last record (power loss) is
//! detected by its length/CRC and truncated on open. When the dead prefix grows beyond half the
//! file the log is compacted with an atomic rewrite. When full, the oldest record is dropped.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::persist;

/// Maximum size of one buffered record (topic + payload).
pub const MAX_RECORD: usize = 64 * 1024;
const HEADER: usize = 4 + 4 + 8 + 2;
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
    Disk { dir: PathBuf, file: File, end: u64, head: u64, sync: bool },
    Memory(VecDeque<Record>),
}

/// The ring buffer.
pub struct RingBuffer {
    store: Store,
    index: VecDeque<Entry>,
    capacity: usize,
    dropped: u64,
}

impl std::fmt::Debug for RingBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingBuffer").field("len", &self.len()).field("capacity", &self.capacity).finish()
    }
}

fn encode_record(r: &Record) -> io::Result<Vec<u8>> {
    let topic = r.topic.as_bytes();
    if topic.len() + r.payload.len() > MAX_RECORD || topic.len() > usize::from(u16::MAX) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "record too large for the offline buffer"));
    }
    let mut body = Vec::with_capacity(8 + 2 + topic.len() + r.payload.len());
    body.extend_from_slice(&r.seq.to_be_bytes());
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic);
    body.extend_from_slice(&r.payload);
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_body(body: &[u8]) -> Option<Record> {
    let seq = u64::from_be_bytes(body.get(..8)?.try_into().ok()?);
    let tl = usize::from(u16::from_be_bytes(body.get(8..10)?.try_into().ok()?));
    let topic = std::str::from_utf8(body.get(10..10 + tl)?).ok()?.to_owned();
    Some(Record { seq, topic, payload: body.get(10 + tl..)?.to_vec() })
}

impl RingBuffer {
    /// Open (or create) a disk-backed buffer in `dir`.
    ///
    /// # Errors
    /// I/O errors.
    pub fn open(dir: &Path, capacity: usize, sync: bool) -> io::Result<Self> {
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
            if !(HEADER - 8..=MAX_RECORD + HEADER).contains(&blen) {
                break;
            }
            let mut body = vec![0u8; blen];
            if reader.read_exact(&mut body).is_err() || crc32(&body) != crc {
                break;
            }
            let Some(rec) = decode_body(&body) else { break };
            index.push_back(Entry { offset: pos, len: (8 + blen) as u32, seq: rec.seq });
            pos += (8 + blen) as u64;
        }
        drop(reader);
        if pos < len {
            tracing::warn!(valid = pos, len, "offline buffer: truncating torn tail");
            file.set_len(pos)?;
        }
        let mut rb = Self {
            store: Store::Disk { dir: dir.to_path_buf(), file, end: pos, head: head.offset.min(pos), sync },
            index,
            capacity: capacity.max(1),
            dropped: 0,
        };
        while rb.index.len() > rb.capacity {
            rb.drop_front()?;
        }
        Ok(rb)
    }

    /// A volatile buffer (fleet simulator).
    #[must_use]
    pub fn in_memory(capacity: usize) -> Self {
        Self { store: Store::Memory(VecDeque::new()), index: VecDeque::new(), capacity: capacity.max(1), dropped: 0 }
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
        let bytes = encode_record(&record)?;
        match &mut self.store {
            Store::Disk { file, end, sync, .. } => {
                file.seek(SeekFrom::Start(*end))?;
                file.write_all(&bytes)?;
                if *sync {
                    file.sync_data()?;
                }
                self.index.push_back(Entry { offset: *end, len: bytes.len() as u32, seq: record.seq });
                *end += bytes.len() as u64;
            }
            Store::Memory(q) => {
                self.index.push_back(Entry { offset: 0, len: bytes.len() as u32, seq: record.seq });
                q.push_back(record);
            }
        }
        while self.index.len() > self.capacity {
            self.drop_front()?;
            self.dropped += 1;
        }
        Ok(())
    }

    /// Read the oldest message without removing it.
    ///
    /// # Errors
    /// I/O errors or on-disk corruption.
    pub fn peek(&mut self) -> io::Result<Option<Record>> {
        let Some(entry) = self.index.front().copied() else { return Ok(None) };
        match &mut self.store {
            Store::Memory(q) => Ok(q.front().cloned()),
            Store::Disk { file, .. } => {
                let mut buf = vec![0u8; entry.len as usize];
                file.seek(SeekFrom::Start(entry.offset))?;
                file.read_exact(&mut buf)?;
                let crc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                if crc32(&buf[8..]) != crc {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "offline buffer record corrupted"));
                }
                decode_body(&buf[8..])
                    .map(Some)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offline buffer record malformed"))
            }
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

    fn rec(seq: u64, n: usize) -> Record {
        Record { seq, topic: "im/v1/t/d/telemetry".into(), payload: vec![seq as u8; n] }
    }

    #[test]
    fn persists_in_order_and_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = RingBuffer::open(dir.path(), 3, true).unwrap();
            for s in 1..=5 {
                b.push(rec(s, 10)).unwrap();
            }
            assert_eq!(b.len(), 3);
            assert_eq!(b.dropped(), 2);
            assert_eq!(b.seq_range(), Some((3, 5)));
        }
        let mut b = RingBuffer::open(dir.path(), 3, false).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b.peek().unwrap().unwrap(), rec(3, 10));
        b.pop().unwrap();
        drop(b);
        let mut b = RingBuffer::open(dir.path(), 3, false).unwrap();
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
            let mut b = RingBuffer::open(dir.path(), 10, false).unwrap();
            b.push(rec(1, 5)).unwrap();
            b.push(rec(2, 5)).unwrap();
        }
        let log = dir.path().join("buffer.log");
        let len = std::fs::metadata(&log).unwrap().len();
        let f = OpenOptions::new().write(true).open(&log).unwrap();
        f.set_len(len - 3).unwrap();
        let b = RingBuffer::open(dir.path(), 10, false).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b.seq_range(), Some((1, 1)));
    }

    #[test]
    fn compaction_and_memory_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = RingBuffer::open(dir.path(), 10_000, false).unwrap();
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
        let mut b = RingBuffer::open(dir.path(), 10_000, false).unwrap();
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
}
