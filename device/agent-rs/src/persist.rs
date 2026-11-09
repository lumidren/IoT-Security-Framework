//! Crash-safe file persistence helpers: atomic replace (write temp, fsync, rename, fsync dir)
//! and owner-only permissions (0600 files / 0700 directories on Unix).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Maximum size accepted by [`read_bounded`] callers that do not specify one.
pub const DEFAULT_MAX_FILE: u64 = 4 * 1024 * 1024;

/// Create `dir` (and parents) with mode 0700 on Unix.
///
/// # Errors
/// I/O errors.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Atomically replace `path` with `data` (owner-only permissions, durable on return).
///
/// # Errors
/// I/O errors.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    if !dir.as_os_str().is_empty() {
        fs::create_dir_all(dir)?;
    }
    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));
    {
        let mut f = open_private(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Read a file of at most `max` bytes; `Ok(None)` if it does not exist.
///
/// # Errors
/// I/O errors, or `InvalidData` if the file is larger than `max`.
pub fn read_bounded(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{} exceeds {max} bytes", path.display())));
    }
    Ok(Some(buf))
}

/// Read and deserialize a JSON file; `Ok(None)` if missing.
///
/// # Errors
/// I/O or JSON errors (as `InvalidData`).
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match read_bounded(path, DEFAULT_MAX_FILE)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))),
    }
}

/// Serialize to JSON and write atomically.
///
/// # Errors
/// I/O or serialization errors.
pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    write_atomic(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        ensure_private_dir(&sub).unwrap();
        let p = sub.join("x.json");
        assert!(read_json::<Vec<u32>>(&p).unwrap().is_none());
        write_json(&p, &vec![1u32, 2]).unwrap();
        assert_eq!(read_json::<Vec<u32>>(&p).unwrap().unwrap(), vec![1, 2]);
        write_atomic(&p, b"not json").unwrap();
        assert!(read_json::<Vec<u32>>(&p).is_err());
        assert!(read_bounded(&p, 2).is_err());
        assert_eq!(read_bounded(&p, 100).unwrap().unwrap(), b"not json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
