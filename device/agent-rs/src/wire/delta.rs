//! IronMesh block-delta format `IMDELTA1` (`device/common/DELTA_FORMAT.md`).
//!
//! [`DeltaApplier`] is a streaming state machine with bounded memory: it keeps at most one
//! partially received operation (≤ 65 538 bytes) plus one 4 KiB block, accepts the patch in
//! arbitrary chunk sizes and reports exactly the error codes of §6 in the order of §4.

use sha2::{Digest, Sha256};

use super::error::{err, ErrorCode as C, WireError};

/// Header magic.
pub const MAGIC: &[u8; 8] = b"IMDELTA1";
/// Block size.
pub const BLOCK_SIZE: usize = 4096;
/// Header size.
pub const HEADER_SIZE: usize = 92;
const OP_COPY: u8 = 0x01;
const OP_LITERAL: u8 = 0x02;
const OP_END: u8 = 0x03;
const COPY_OP_SIZE: usize = 5;
const LITERAL_HEADER_SIZE: usize = 3;
/// Reference applier limit on `target_size`.
pub const DEFAULT_MAX_TARGET_SIZE: u64 = 1 << 30;
const HASH_CHUNK: usize = 64 * 1024;

/// Parsed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaHeader {
    /// Base image length.
    pub base_size: u64,
    /// Base image hash.
    pub base_sha256: [u8; 32],
    /// Target image hash.
    pub target_sha256: [u8; 32],
    /// Target image length.
    pub target_size: u64,
}

fn be_u64(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x))
}

impl DeltaHeader {
    /// Parse and validate the 92-byte header.
    ///
    /// # Errors
    /// `DELTA_TRUNCATED`, `DELTA_MAGIC`, `DELTA_BLOCK_SIZE`.
    pub fn parse(data: &[u8]) -> Result<Self, WireError> {
        let h = data.get(..HEADER_SIZE).ok_or_else(|| err(C::DeltaTruncated, "patch shorter than the 92-byte header"))?;
        if &h[0..8] != MAGIC {
            return Err(err(C::DeltaMagic, "bad magic"));
        }
        if be_u64(&h[8..12]) != BLOCK_SIZE as u64 {
            return Err(err(C::DeltaBlockSize, "block size is not 4096"));
        }
        let mut base_sha256 = [0u8; 32];
        base_sha256.copy_from_slice(&h[20..52]);
        let mut target_sha256 = [0u8; 32];
        target_sha256.copy_from_slice(&h[52..84]);
        Ok(Self { base_size: be_u64(&h[12..20]), base_sha256, target_sha256, target_size: be_u64(&h[84..92]) })
    }

    /// Serialize.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
        out[12..20].copy_from_slice(&self.base_size.to_be_bytes());
        out[20..52].copy_from_slice(&self.base_sha256);
        out[52..84].copy_from_slice(&self.target_sha256);
        out[84..92].copy_from_slice(&self.target_size.to_be_bytes());
        out
    }
}

/// Random-access reader for the base image.
pub trait BaseReader {
    /// Read up to `buf.len()` bytes at `offset`; return the number read.
    ///
    /// # Errors
    /// I/O errors (reported by the applier as `DELTA_BOUNDS`).
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl BaseReader for &[u8] {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(self.len());
        let n = buf.len().min(self.len() - start);
        buf[..n].copy_from_slice(&self[start..start + n]);
        Ok(n)
    }
}

impl BaseReader for std::fs::File {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        self.seek(SeekFrom::Start(offset))?;
        let mut total = 0;
        while total < buf.len() {
            let n = self.read(&mut buf[total..])?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }
}

/// Failure while applying a patch: a format error or a sink (output) I/O error.
#[derive(Debug)]
pub enum ApplyError {
    /// Format rejection (`DELTA_*`).
    Wire(WireError),
    /// The output sink failed.
    Sink(std::io::Error),
}

impl From<WireError> for ApplyError {
    fn from(e: WireError) -> Self {
        ApplyError::Wire(e)
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Wire(e) => write!(f, "{e}"),
            ApplyError::Sink(e) => write!(f, "delta output failed: {e}"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl ApplyError {
    /// Wire code if this is a format error.
    #[must_use]
    pub fn code(&self) -> Option<C> {
        match self {
            ApplyError::Wire(e) => Some(e.code()),
            ApplyError::Sink(_) => None,
        }
    }
}

/// Streaming patch applier.
pub struct DeltaApplier<R: BaseReader, W: FnMut(&[u8]) -> std::io::Result<()>> {
    base: R,
    base_len: u64,
    sink: W,
    max_target_size: u64,
    pending: Vec<u8>,
    header: Option<DeltaHeader>,
    produced: u64,
    hasher: Sha256,
    done: bool,
    block: Vec<u8>,
}

impl<R: BaseReader, W: FnMut(&[u8]) -> std::io::Result<()>> DeltaApplier<R, W> {
    /// New applier over a base image of `base_len` bytes writing output to `sink`.
    pub fn new(base: R, base_len: u64, sink: W, max_target_size: u64) -> Self {
        Self {
            base,
            base_len,
            sink,
            max_target_size,
            pending: Vec::new(),
            header: None,
            produced: 0,
            hasher: Sha256::new(),
            done: false,
            block: vec![0u8; BLOCK_SIZE],
        }
    }

    /// Parsed header once available.
    #[must_use]
    pub fn header(&self) -> Option<&DeltaHeader> {
        self.header.as_ref()
    }

    /// Bytes produced so far.
    #[must_use]
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// Feed the next chunk of patch bytes.
    ///
    /// # Errors
    /// Any `DELTA_*` code, or a sink failure.
    pub fn feed(&mut self, mut data: &[u8]) -> Result<(), ApplyError> {
        if self.header.is_none() {
            let need = HEADER_SIZE - self.pending.len();
            let take = need.min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.pending.len() < HEADER_SIZE {
                return Ok(());
            }
            let header = DeltaHeader::parse(&self.pending)?;
            self.pending.clear();
            self.start(header)?;
        }
        loop {
            if self.done && (!data.is_empty() || !self.pending.is_empty()) {
                return Err(err(C::DeltaTrailing, "bytes after END").into());
            }
            if self.pending.is_empty() {
                if data.is_empty() {
                    return Ok(());
                }
                // Fast path: execute complete ops straight from the input slice.
                match self.try_op(data)? {
                    Some(n) => data = &data[n..],
                    None => {
                        self.pending.extend_from_slice(data);
                        return Ok(());
                    }
                }
            } else {
                // Top up the partial op only as far as it needs (bounded by one op).
                let need = self.op_need(&self.pending)?;
                if self.pending.len() < need {
                    let take = (need - self.pending.len()).min(data.len());
                    self.pending.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if self.pending.len() < self.op_need(&self.pending)? {
                        if data.is_empty() {
                            return Ok(());
                        }
                        continue;
                    }
                }
                let pending = std::mem::take(&mut self.pending);
                if self.try_op(&pending)?.is_none() {
                    self.pending = pending;
                    return Ok(());
                }
            }
        }
    }

    /// Bytes required for the op starting at `buf[0]` (validating what can be validated early).
    fn op_need(&self, buf: &[u8]) -> Result<usize, ApplyError> {
        match buf.first() {
            None => Ok(1),
            Some(&OP_COPY) => Ok(COPY_OP_SIZE),
            Some(&OP_END) => Ok(1),
            Some(&OP_LITERAL) => {
                if buf.len() < LITERAL_HEADER_SIZE {
                    return Ok(LITERAL_HEADER_SIZE);
                }
                let len = usize::from(u16::from_be_bytes([buf[1], buf[2]]));
                if len == 0 {
                    return Err(err(C::DeltaLiteralLen, "LITERAL length must be >= 1").into());
                }
                Ok(LITERAL_HEADER_SIZE + len)
            }
            Some(_) => Err(err(C::DeltaOp, "unknown op").into()),
        }
    }

    /// Execute one op from the start of `buf` if complete; returns bytes consumed.
    fn try_op(&mut self, buf: &[u8]) -> Result<Option<usize>, ApplyError> {
        let need = self.op_need(buf)?;
        if buf.len() < need {
            return Ok(None);
        }
        match buf[0] {
            OP_COPY => {
                let idx = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                self.copy(u64::from(idx))?;
            }
            OP_LITERAL => {
                self.emit_external(&buf[LITERAL_HEADER_SIZE..need])?;
            }
            _ => self.end()?,
        }
        Ok(Some(need))
    }

    fn start(&mut self, header: DeltaHeader) -> Result<(), ApplyError> {
        if header.base_size != self.base_len {
            return Err(WireError::with(
                C::DeltaBaseSize,
                format!("header base_size {} != base image {}", header.base_size, self.base_len),
            )
            .into());
        }
        if header.target_size > self.max_target_size {
            return Err(err(C::DeltaTooLarge, "target_size exceeds the configured limit").into());
        }
        let mut hasher = Sha256::new();
        let mut chunk = vec![0u8; HASH_CHUNK];
        let mut offset = 0u64;
        while offset < header.base_size {
            let len = usize::try_from((header.base_size - offset).min(HASH_CHUNK as u64)).unwrap_or(HASH_CHUNK);
            self.read_base(offset, &mut chunk[..len])?;
            hasher.update(&chunk[..len]);
            offset += len as u64;
        }
        if <[u8; 32]>::from(hasher.finalize()) != header.base_sha256 {
            return Err(err(C::DeltaBaseHash, "base image does not match base_sha256").into());
        }
        self.header = Some(header);
        Ok(())
    }

    fn read_base(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ApplyError> {
        match self.base.read_at(offset, buf) {
            Ok(n) if n == buf.len() => Ok(()),
            _ => Err(err(C::DeltaBounds, "base image reader returned a short read").into()),
        }
    }

    fn copy(&mut self, idx: u64) -> Result<(), ApplyError> {
        let base_size = self.header.map_or(0, |h| h.base_size);
        let start = idx * BLOCK_SIZE as u64;
        if start + BLOCK_SIZE as u64 > base_size {
            return Err(WireError::with(C::DeltaBounds, format!("COPY block {idx} outside the base image")).into());
        }
        let mut block = std::mem::take(&mut self.block);
        let result = self.read_base(start, &mut block).and_then(|()| self.emit_external(&block));
        self.block = block;
        result
    }

    fn emit_external(&mut self, data: &[u8]) -> Result<(), ApplyError> {
        let target_size = self.header.map_or(0, |h| h.target_size);
        if self.produced + data.len() as u64 > target_size {
            return Err(err(C::DeltaOverflow, "output exceeds target_size").into());
        }
        self.produced += data.len() as u64;
        self.hasher.update(data);
        (self.sink)(data).map_err(ApplyError::Sink)
    }

    fn end(&mut self) -> Result<(), ApplyError> {
        let header = self.header.unwrap_or(DeltaHeader { base_size: 0, base_sha256: [0; 32], target_sha256: [0; 32], target_size: 0 });
        if self.produced != header.target_size {
            return Err(WireError::with(C::DeltaShort, format!("produced {} of {} bytes", self.produced, header.target_size)).into());
        }
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        if digest != header.target_sha256 {
            return Err(err(C::DeltaTargetHash, "output does not match target_sha256").into());
        }
        self.done = true;
        Ok(())
    }

    /// Signal the end of the patch.
    ///
    /// # Errors
    /// `DELTA_TRUNCATED` (inside header or op) or `DELTA_MISSING_END`.
    pub fn finish(self) -> Result<DeltaHeader, ApplyError> {
        match self.header {
            Some(h) if self.done => Ok(h),
            Some(_) if self.pending.is_empty() => Err(err(C::DeltaMissingEnd, "patch ended without an END op").into()),
            _ => Err(err(C::DeltaTruncated, "patch ended inside the header or an op").into()),
        }
    }
}

/// Apply a patch in memory with full validation.
///
/// # Errors
/// Any `DELTA_*` code.
pub fn apply_delta(old: &[u8], patch: &[u8], max_target_size: u64) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    let result = {
        let mut applier = DeltaApplier::new(
            old,
            old.len() as u64,
            |d: &[u8]| {
                out.extend_from_slice(d);
                Ok(())
            },
            max_target_size,
        );
        applier.feed(patch).and_then(|()| applier.finish().map(|_| ()))
    };
    match result {
        Ok(()) => Ok(out),
        Err(ApplyError::Wire(e)) => Err(e),
        Err(ApplyError::Sink(e)) => Err(WireError::with(C::DeltaBounds, e.to_string())),
    }
}

/// Reference encoder (`DELTA_FORMAT.md` §5).
#[must_use]
pub fn make_delta(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut index: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
    for (i, block) in old.chunks_exact(BLOCK_SIZE).enumerate() {
        index.entry(Sha256::digest(block).into()).or_insert(i);
    }
    let header = DeltaHeader {
        base_size: old.len() as u64,
        base_sha256: Sha256::digest(old).into(),
        target_sha256: Sha256::digest(new).into(),
        target_size: new.len() as u64,
    };
    let mut out = header.encode().to_vec();
    for block in new.chunks(BLOCK_SIZE) {
        let matched = (block.len() == BLOCK_SIZE)
            .then(|| index.get(&<[u8; 32]>::from(Sha256::digest(block))).copied())
            .flatten()
            .filter(|i| old.get(i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE) == Some(block));
        if let Some(i) = matched {
            out.push(OP_COPY);
            out.extend_from_slice(&(i as u32).to_be_bytes());
        } else {
            out.push(OP_LITERAL);
            out.extend_from_slice(&(block.len() as u16).to_be_bytes());
            out.extend_from_slice(block);
        }
    }
    out.push(OP_END);
    out
}

/// Structural inspection without a base: `(header, copies, literal_bytes)`.
///
/// # Errors
/// Structural `DELTA_*` codes.
pub fn inspect_delta(patch: &[u8]) -> Result<(DeltaHeader, u64, u64), WireError> {
    let header = DeltaHeader::parse(patch)?;
    let mut pos = HEADER_SIZE;
    let (mut copies, mut literal) = (0u64, 0u64);
    loop {
        let Some(&op) = patch.get(pos) else {
            return Err(err(C::DeltaMissingEnd, "patch ended without an END op"));
        };
        match op {
            OP_COPY => {
                if pos + COPY_OP_SIZE > patch.len() {
                    return Err(err(C::DeltaTruncated, "truncated COPY"));
                }
                copies += 1;
                pos += COPY_OP_SIZE;
            }
            OP_LITERAL => {
                let Some(l) = patch.get(pos + 1..pos + 3) else {
                    return Err(err(C::DeltaTruncated, "truncated LITERAL"));
                };
                let len = usize::from(u16::from_be_bytes([l[0], l[1]]));
                if len == 0 {
                    return Err(err(C::DeltaLiteralLen, "LITERAL length must be >= 1"));
                }
                if pos + LITERAL_HEADER_SIZE + len > patch.len() {
                    return Err(err(C::DeltaTruncated, "truncated LITERAL"));
                }
                literal += len as u64;
                pos += LITERAL_HEADER_SIZE + len;
            }
            OP_END => {
                if pos + 1 != patch.len() {
                    return Err(err(C::DeltaTrailing, "bytes after END"));
                }
                return Ok((header, copies, literal));
            }
            _ => return Err(err(C::DeltaOp, "unknown op")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    fn apply_chunked(old: &[u8], patch: &[u8], chunk: usize) -> Result<Vec<u8>, ApplyError> {
        let mut out = Vec::new();
        let mut a = DeltaApplier::new(
            old,
            old.len() as u64,
            |d: &[u8]| {
                out.extend_from_slice(d);
                Ok(())
            },
            DEFAULT_MAX_TARGET_SIZE,
        );
        for c in patch.chunks(chunk.max(1)) {
            a.feed(c)?;
        }
        a.finish()?;
        Ok(out)
    }

    #[test]
    fn round_trip_all_chunk_sizes() {
        let old = data(3 * BLOCK_SIZE + 100, 1);
        let mut new = old.clone();
        new[BLOCK_SIZE + 7] ^= 0xff;
        new.extend_from_slice(&data(5000, 9));
        let patch = make_delta(&old, &new);
        let (h, copies, lit) = inspect_delta(&patch).unwrap();
        assert_eq!(h.target_size, new.len() as u64);
        assert_eq!(copies, 2);
        assert!(lit > 0);
        for chunk in [1, 2, 3, 5, 91, 92, 93, 4096, 4099, patch.len()] {
            assert_eq!(apply_chunked(&old, &patch, chunk).unwrap(), new, "chunk {chunk}");
        }
        assert_eq!(apply_delta(&old, &patch, DEFAULT_MAX_TARGET_SIZE).unwrap(), new);
        assert_eq!(apply_delta(&old, &patch, 10).unwrap_err().code(), C::DeltaTooLarge);
    }

    #[test]
    fn error_cases() {
        let old = data(BLOCK_SIZE, 1);
        let patch = make_delta(&old, &old);
        let code = |p: &[u8]| apply_delta(&old, p, DEFAULT_MAX_TARGET_SIZE).unwrap_err().code();
        assert_eq!(code(&patch[..50]), C::DeltaTruncated);
        let mut p = patch.clone();
        p.push(0);
        assert_eq!(code(&p), C::DeltaTrailing);
        let mut p = patch[..HEADER_SIZE].to_vec();
        assert_eq!(code(&p), C::DeltaMissingEnd);
        p.push(9);
        assert_eq!(code(&p), C::DeltaOp);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[2, 0, 0]);
        assert_eq!(code(&p), C::DeltaLiteralLen);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[1, 0, 0, 0, 1]);
        assert_eq!(code(&p), C::DeltaBounds);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[1, 0, 0]);
        assert_eq!(code(&p), C::DeltaTruncated);
        let mut p = patch.clone();
        p[0] = b'X';
        assert_eq!(code(&p), C::DeltaMagic);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaMagic);
        let mut p = patch.clone();
        p[10] = 0x20;
        assert_eq!(code(&p), C::DeltaBlockSize);
        assert_eq!(apply_delta(&old[..10], &patch, DEFAULT_MAX_TARGET_SIZE).unwrap_err().code(), C::DeltaBaseSize);
        let mut other = old.clone();
        other[0] ^= 1;
        assert_eq!(apply_delta(&other, &patch, DEFAULT_MAX_TARGET_SIZE).unwrap_err().code(), C::DeltaBaseHash);
        // inspect errors
        let mut p = patch[..HEADER_SIZE].to_vec();
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaMissingEnd);
        p.extend_from_slice(&[1, 0]);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaTruncated);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[2, 0]);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaTruncated);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[2, 0, 0]);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaLiteralLen);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[2, 0, 5, 1]);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaTruncated);
        let mut p = patch[..HEADER_SIZE].to_vec();
        p.extend_from_slice(&[3, 3]);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaTrailing);
        p.pop();
        p.pop();
        p.push(7);
        assert_eq!(inspect_delta(&p).unwrap_err().code(), C::DeltaOp);
    }

    #[test]
    fn sink_error_and_file_reader() {
        let old = data(BLOCK_SIZE * 2, 3);
        let patch = make_delta(&old, &old);
        let mut a =
            DeltaApplier::new(&old[..], old.len() as u64, |_d: &[u8]| Err(std::io::Error::other("disk full")), DEFAULT_MAX_TARGET_SIZE);
        let e = a.feed(&patch).unwrap_err();
        assert!(e.code().is_none());
        assert!(e.to_string().contains("disk full"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base");
        std::fs::write(&path, &old).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let mut out = Vec::new();
        let mut a = DeltaApplier::new(
            f,
            old.len() as u64,
            |d: &[u8]| {
                out.extend_from_slice(d);
                Ok(())
            },
            DEFAULT_MAX_TARGET_SIZE,
        );
        a.feed(&patch).unwrap();
        assert!(a.header().is_some());
        assert_eq!(a.produced(), old.len() as u64);
        a.finish().unwrap();
        assert_eq!(out, old);
        let w = ApplyError::from(err(C::DeltaOp, "x"));
        assert_eq!(w.to_string(), "DELTA_OP: x");
    }
}
