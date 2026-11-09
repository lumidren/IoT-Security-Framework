//! Device telemetry (contract §5 Telemetry body): CPU, memory, network counters, temperature,
//! uptime, process list (top 10 by CPU), failed authentication attempts and firmware hash.
//!
//! `auth_failures` is the number of failed logins observed **since the previous report**
//! (parsed from `/var/log/auth.log`, falling back to `journalctl --since`); on non-Linux hosts it
//! is always 0.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sysinfo::{Components, Networks, ProcessesToUpdate, System};

use crate::wire::envelope::Telemetry;

/// Running firmware identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareInfo {
    /// SHA-256 of the active image (or of the agent binary).
    pub hash: [u8; 32],
    /// Semantic version.
    pub version: String,
}

/// SHA-256 of a file (streaming).
///
/// # Errors
/// I/O errors.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// SHA-256 of the running executable (fallback firmware hash).
#[must_use]
pub fn running_binary_hash() -> [u8; 32] {
    std::env::current_exe().ok().and_then(|p| sha256_file(&p).ok()).unwrap_or([0u8; 32])
}

const AUTH_FAILURE_PATTERNS: [&str; 6] = [
    "Failed password",
    "authentication failure",
    "Invalid user",
    "Failed publickey",
    "Connection closed by authenticating user",
    "maximum authentication attempts exceeded",
];

/// Count lines that indicate a failed authentication.
#[must_use]
pub fn count_auth_failures(text: &str) -> u64 {
    text.lines().filter(|l| AUTH_FAILURE_PATTERNS.iter().any(|p| l.contains(p))).count() as u64
}

/// Incremental reader of failed authentication attempts.
#[derive(Debug)]
pub struct AuthFailureCounter {
    path: PathBuf,
    offset: Option<u64>,
    last_journal: u64,
    max_read: u64,
}

impl AuthFailureCounter {
    /// New counter for `auth_log`; the first call only establishes the baseline.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path, offset: None, last_journal: 0, max_read: 4 * 1024 * 1024 }
    }

    /// Failures since the previous call.
    pub fn poll(&mut self, now_unix: u64) -> u64 {
        if !cfg!(target_os = "linux") {
            return 0;
        }
        match self.poll_file() {
            Some(n) => n,
            None => self.poll_journal(now_unix),
        }
    }

    fn poll_file(&mut self) -> Option<u64> {
        let mut f = std::fs::File::open(&self.path).ok()?;
        let len = f.metadata().ok()?.len();
        let start = match self.offset {
            None => {
                self.offset = Some(len);
                return Some(0);
            }
            Some(o) if o > len => 0, // rotated / truncated
            Some(o) => o,
        };
        let to_read = (len - start).min(self.max_read);
        f.seek(SeekFrom::Start(len - to_read)).ok()?;
        let mut buf = Vec::with_capacity(to_read as usize);
        f.take(to_read).read_to_end(&mut buf).ok()?;
        self.offset = Some(len);
        Some(count_auth_failures(&String::from_utf8_lossy(&buf)))
    }

    fn poll_journal(&mut self, now_unix: u64) -> u64 {
        if self.last_journal == 0 {
            self.last_journal = now_unix;
            return 0;
        }
        let since = format!("@{}", self.last_journal);
        self.last_journal = now_unix;
        let out = std::process::Command::new("journalctl")
            .args(["--since", &since, "--no-pager", "-q", "-o", "cat", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"])
            .output();
        match out {
            Ok(o) if o.status.success() => count_auth_failures(&String::from_utf8_lossy(&o.stdout[..o.stdout.len().min(4 << 20)])),
            _ => 0,
        }
    }
}

/// A telemetry source.
pub trait TelemetrySource: Send {
    /// Collect one sample.
    fn collect(&mut self, fw: &FirmwareInfo, now_unix: u64) -> Telemetry;
}

/// Real host telemetry via `sysinfo`.
pub struct SystemTelemetry {
    sys: System,
    networks: Networks,
    components: Components,
    auth: AuthFailureCounter,
}

impl std::fmt::Debug for SystemTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemTelemetry").finish_non_exhaustive()
    }
}

impl SystemTelemetry {
    /// New collector.
    #[must_use]
    pub fn new(auth_log: PathBuf) -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        Self {
            sys,
            networks: Networks::new_with_refreshed_list(),
            components: Components::new_with_refreshed_list(),
            auth: AuthFailureCounter::new(auth_log),
        }
    }
}

fn finite(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

impl TelemetrySource for SystemTelemetry {
    fn collect(&mut self, fw: &FirmwareInfo, now_unix: u64) -> Telemetry {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.networks.refresh();
        self.components.refresh();
        let total = self.sys.total_memory();
        let mem_pct = if total == 0 { 0.0 } else { self.sys.used_memory() as f64 * 100.0 / total as f64 };
        let (rx, tx) = self
            .networks
            .iter()
            .fold((0u64, 0u64), |(r, t), (_, d)| (r.saturating_add(d.total_received()), t.saturating_add(d.total_transmitted())));
        let temps: Vec<f64> = self.components.iter().map(|c| f64::from(c.temperature())).filter(|t| t.is_finite() && *t > -50.0).collect();
        let temp_c = temps.iter().copied().fold(f64::NAN, f64::max);
        let mut procs: Vec<(f32, String)> =
            self.sys.processes().values().map(|p| (p.cpu_usage(), p.name().to_string_lossy().into_owned())).collect();
        procs.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let top_procs = procs.iter().take(10).map(|(_, n)| n.chars().take(64).collect()).collect();
        Telemetry {
            cpu_pct: finite(f64::from(self.sys.global_cpu_usage())),
            mem_pct: finite(mem_pct),
            net_rx_bytes: rx,
            net_tx_bytes: tx,
            temp_c: finite(temp_c),
            uptime_s: System::uptime(),
            auth_failures: self.auth.poll(now_unix),
            fw_hash: fw.hash,
            fw_version: fw.version.clone(),
            proc_count: Some(self.sys.processes().len() as u64),
            top_procs: Some(top_procs),
            rssi: None,
            free_heap: None,
            lat: None,
            lon: None,
        }
    }
}

/// Deterministic synthetic telemetry (DUT mode, tests).
#[derive(Debug, Default)]
pub struct StaticTelemetry {
    /// Samples taken.
    pub count: u64,
}

impl TelemetrySource for StaticTelemetry {
    fn collect(&mut self, fw: &FirmwareInfo, _now: u64) -> Telemetry {
        self.count += 1;
        Telemetry {
            cpu_pct: 1.5,
            mem_pct: 20.25,
            net_rx_bytes: self.count * 100,
            net_tx_bytes: self.count * 50,
            temp_c: 40.5,
            uptime_s: self.count,
            auth_failures: 0,
            fw_hash: fw.hash,
            fw_version: fw.version.clone(),
            proc_count: Some(1),
            top_procs: Some(vec!["ironmesh-agent".into()]),
            rssi: None,
            free_heap: None,
            lat: None,
            lon: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_parsing_and_hash() {
        let log =
            "Jan 1 sshd[1]: Failed password for root from 1.2.3.4\nJan 1 sshd[1]: Accepted publickey\nJan 1 sshd[2]: Invalid user bob\n";
        assert_eq!(count_auth_failures(log), 2);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("auth.log");
        std::fs::write(&p, log).unwrap();
        let mut c = AuthFailureCounter::new(p.clone());
        let first = c.poll(1);
        assert_eq!(first, 0);
        if cfg!(target_os = "linux") {
            std::fs::write(&p, format!("{log}{log}")).unwrap();
            assert_eq!(c.poll(2), 2);
            std::fs::write(&p, "Failed password\n").unwrap();
            assert_eq!(c.poll(3), 1);
        }
        assert_eq!(sha256_file(&p).unwrap().len(), 32);
        assert_ne!(running_binary_hash(), [0u8; 32]);
    }

    #[test]
    fn system_telemetry_is_valid() {
        let fw = FirmwareInfo { hash: [1; 32], version: "1.0.0".into() };
        let mut s = SystemTelemetry::new(PathBuf::from("/nonexistent/auth.log"));
        let t = s.collect(&fw, 1);
        assert!(t.cpu_pct.is_finite() && t.mem_pct >= 0.0);
        assert!(t.top_procs.as_ref().is_some_and(|p| p.len() <= 10));
        // It must be encodable as a valid Telemetry body.
        let msg = crate::wire::envelope::Message { seq: 1, ts: 1, body: crate::wire::envelope::Body::Telemetry(t), nonce: None };
        crate::wire::envelope::encode_payload(&msg).unwrap();
        let mut st = StaticTelemetry::default();
        assert_eq!(st.collect(&fw, 0).uptime_s, 1);
        assert!(format!("{s:?}").contains("SystemTelemetry"));
        assert_eq!(finite(f64::NAN), 0.0);
    }
}
