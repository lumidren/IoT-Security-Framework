//! Process and host sampling with `sysinfo`: CPU % and resident set size of the fleet process,
//! the harness process (broker + EST doubles, verifier) and the policy service, plus the host's
//! available memory for the abort guard. Also the run environment for the report.

use std::path::Path;
use std::process::Command;

use serde::Serialize;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// One process at one instant.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ProcSample {
    /// CPU since the previous sample, in % of one logical CPU (can exceed 100).
    pub cpu_pct: f64,
    /// Resident set size (Windows: working set), MiB.
    pub rss_mb: f64,
    /// The process exists.
    pub alive: bool,
}

/// Samples a fixed set of processes.
pub struct Sampler {
    sys: System,
    pids: Vec<Option<Pid>>,
}

/// Host memory at one instant, MiB.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct HostMemory {
    /// Total RAM.
    pub total_mb: f64,
    /// Available RAM.
    pub available_mb: f64,
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

impl Sampler {
    /// Sampler for `pids` (in report order); primes the CPU counters.
    #[must_use]
    pub fn new(pids: &[Option<u32>]) -> Self {
        let mut s = Self { sys: System::new(), pids: pids.iter().map(|p| p.map(Pid::from_u32)).collect() };
        let _ = s.sample();
        s
    }

    /// Replace one pid (e.g. once the fleet process has been spawned).
    pub fn set_pid(&mut self, slot: usize, pid: Option<u32>) {
        if let Some(p) = self.pids.get_mut(slot) {
            *p = pid.map(Pid::from_u32);
        }
    }

    /// Sample every process and the host memory.
    pub fn sample(&mut self) -> (Vec<ProcSample>, HostMemory) {
        let pids: Vec<Pid> = self.pids.iter().flatten().copied().collect();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::Some(&pids), true, ProcessRefreshKind::new().with_cpu().with_memory());
        self.sys.refresh_memory();
        let procs = self
            .pids
            .iter()
            .map(|p| match p.and_then(|p| self.sys.process(p)) {
                Some(pr) => ProcSample { cpu_pct: f64::from(pr.cpu_usage()), rss_mb: mib(pr.memory()), alive: true },
                None => ProcSample::default(),
            })
            .collect();
        (procs, HostMemory { total_mb: mib(self.sys.total_memory()), available_mb: mib(self.sys.available_memory()) })
    }
}

/// The machine and toolchain the run happened on.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Environment {
    /// CPU model.
    pub cpu_model: String,
    /// Physical cores.
    pub physical_cores: usize,
    /// Logical CPUs.
    pub logical_cpus: usize,
    /// RAM, MiB.
    pub ram_total_mb: f64,
    /// Available RAM when the run started, MiB.
    pub ram_available_at_start_mb: f64,
    /// Operating system.
    pub os: String,
    /// `rustc --version`.
    pub rustc: String,
    /// `go version`.
    pub go: String,
    /// Git commit (and whether the tree was modified).
    pub git_commit: String,
    /// Ephemeral TCP port range (Windows `netsh int ipv4 show dynamicport tcp`), if known.
    pub tcp_dynamic_ports: String,
}

fn command_line(cmd: &mut Command) -> String {
    cmd.output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace("\r\n", " ").replace('\n', " "))
        .unwrap_or_else(|| "unknown".into())
}

impl Environment {
    /// Collect.
    #[must_use]
    pub fn collect(repo: &Path, go: &Path) -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_all();
        sys.refresh_memory();
        let cpu_model = sys.cpus().first().map(|c| c.brand().trim().to_owned()).unwrap_or_default();
        let dynamic = if cfg!(windows) {
            let raw = command_line(Command::new("netsh").args(["int", "ipv4", "show", "dynamicport", "tcp"]));
            let nums: Vec<&str> = raw.split_whitespace().filter(|w| w.chars().all(|c| c.is_ascii_digit())).collect();
            match nums.as_slice() {
                [start, count, ..] => format!("start {start}, {count} ports"),
                _ => raw,
            }
        } else {
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").map(|s| s.trim().to_owned()).unwrap_or_default()
        };
        Self {
            cpu_model,
            physical_cores: sys.physical_core_count().unwrap_or(0),
            logical_cpus: sys.cpus().len(),
            ram_total_mb: mib(sys.total_memory()),
            ram_available_at_start_mb: mib(sys.available_memory()),
            os: System::long_os_version().unwrap_or_default(),
            rustc: command_line(Command::new("rustc").arg("--version")),
            go: command_line(Command::new(go).arg("version")),
            git_commit: format!(
                "{}{}",
                crate::report::git_commit(repo),
                if crate::report::git_dirty(repo) { " (working tree modified)" } else { "" }
            ),
            tcp_dynamic_ports: dynamic,
        }
    }
}
