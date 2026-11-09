//! Small helpers shared by the harness, the adapters and the cases.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;

/// Wall-clock Unix seconds.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Wall-clock Unix milliseconds.
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// `n` random bytes.
#[must_use]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

/// A fresh contract device id (`dev-` + 16 lower-case hex). Every case uses its own id so the
/// policy service's persistent deny list from one case never leaks into another.
#[must_use]
pub fn new_device_id() -> String {
    format!("dev-{}", hex::encode(random_bytes(8)))
}

/// A random UUIDv4 (lower-case, hyphenated).
#[must_use]
pub fn uuid4() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// A positive 128-bit certificate serial (contract §2): leading bit cleared, never zero.
#[must_use]
pub fn random_serial() -> Vec<u8> {
    let mut s = random_bytes(16);
    s[0] &= 0x7f;
    s[0] |= 0x01;
    s
}

/// Shell-style wildcard match (`*` any run, `?` one char), case-insensitive.
#[must_use]
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_uppercase().chars().collect();
    let t: Vec<char> = text.to_ascii_uppercase().chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Nearest-rank percentile of a sample (`q` in 0..=100). `None` for an empty sample.
#[must_use]
pub fn percentile(samples: &[f64], q: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = ((q / 100.0) * v.len() as f64).ceil().max(1.0) as usize;
    v.get(rank.min(v.len()) - 1).copied()
}

/// Locate the repository root (the directory holding `docs/DESIGN_CONTRACT.md`), starting at
/// `start` and walking up.
#[must_use]
pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start.to_path_buf());
    while let Some(dir) = cur {
        if dir.join("docs").join("DESIGN_CONTRACT.md").is_file() && dir.join("device").is_dir() {
            return Some(dir);
        }
        cur = dir.parent().map(Path::to_path_buf);
    }
    None
}

/// The repository root: `$IRONMESH_REPO_ROOT`, else derived from the current directory, else from
/// this crate's manifest directory at build time.
#[must_use]
pub fn repo_root() -> PathBuf {
    if let Ok(p) = std::env::var("IRONMESH_REPO_ROOT") {
        return PathBuf::from(p);
    }
    if let Some(r) = std::env::current_dir().ok().and_then(|d| find_repo_root(&d)) {
        return r;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    find_repo_root(&manifest).unwrap_or(manifest)
}

/// Poll `f` every 20 ms until it returns `Some` or `timeout` elapses.
pub async fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// PEM-encode DER.
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    ironmesh_agent::x509::to_pem(label, der)
}

/// Decode the first PEM block with label (CERTIFICATE REQUEST, ...).
#[must_use]
pub fn pem_block(text: &[u8], label: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let text = String::from_utf8_lossy(text);
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text[start..].find(&end)?;
    let b64: String = text[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Escape text for XML attribute and element content.
#[must_use]
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' && c != '\r' => out.push_str(&format!("&#{};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Escape text for a Markdown table cell.
#[must_use]
pub fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard() {
        assert!(wildcard_match("C-OTA-*", "C-OTA-5"));
        assert!(wildcard_match("c-ota-*", "C-OTA-5"));
        assert!(!wildcard_match("C-OTA-*", "C-TLS-1"));
        assert!(wildcard_match("C-*-1", "C-TLS-1"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("C-TLS-?", "C-TLS-4"));
        assert!(!wildcard_match("C-TLS-?", "C-TLS-10"));
    }

    #[test]
    fn ids() {
        let d = new_device_id();
        assert!(ironmesh_agent::wire::ids::is_device_id(&d), "{d}");
        let u = uuid4();
        assert!(ironmesh_agent::wire::ids::is_uuid4(&u), "{u}");
        let s = random_serial();
        assert_eq!(s.len(), 16);
        assert!(s[0] & 0x80 == 0 && s[0] != 0);
    }

    #[test]
    fn percentiles() {
        let v: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(percentile(&v, 50.0), Some(10.0));
        assert_eq!(percentile(&v, 95.0), Some(19.0));
        assert_eq!(percentile(&v, 100.0), Some(20.0));
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(percentile(&[3.0], 95.0), Some(3.0));
    }

    #[test]
    fn escaping() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
        assert_eq!(xml_escape("\u{1}"), "&#1;");
        assert_eq!(md_cell("a|b\nc"), "a\\|b c");
    }
}
