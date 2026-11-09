//! Reports: JUnit XML ([`junit`]), the per-target Markdown report ([`markdown`]), the
//! machine-readable `results.json` and the cross-target `SUMMARY.md` ([`summary`]).

pub mod junit;
pub mod markdown;
pub mod summary;

use serde::{Deserialize, Serialize};

use crate::cases::{CaseResult, Verdict};

/// One target run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    /// Target name.
    pub target: String,
    /// Cloud mode (`hermetic` / `stack`).
    pub mode: String,
    /// Start (RFC 3339 UTC).
    pub started_at: String,
    /// Duration (s).
    pub seconds: f64,
    /// `git rev-parse HEAD`.
    pub git_commit: String,
    /// Host description.
    pub host: String,
    /// `(name, value)` facts about the environment (binaries, keys, policy service, DUT build).
    pub environment: Vec<(String, String)>,
    /// Results in table order.
    pub results: Vec<StoredResult>,
}

/// A serialisable [`CaseResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredResult {
    /// Id.
    pub id: String,
    /// Title.
    pub title: String,
    /// Criterion.
    pub criterion: String,
    /// `passed` / `failed` / `not_applicable` / `error`.
    pub verdict: String,
    /// Reason.
    pub reason: String,
    /// Measurements.
    pub measurements: Vec<(String, String)>,
    /// Evidence.
    pub evidence: Vec<String>,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Seconds.
    pub seconds: f64,
    /// Series.
    pub series: Vec<(String, Vec<f64>)>,
}

impl From<&CaseResult> for StoredResult {
    fn from(r: &CaseResult) -> Self {
        Self {
            id: r.id.clone(),
            title: r.title.clone(),
            criterion: r.criterion.clone(),
            verdict: verdict_key(r.verdict).into(),
            reason: r.reason.clone(),
            measurements: r.measurements.clone(),
            evidence: r.evidence.clone(),
            warnings: r.warnings.clone(),
            seconds: r.seconds,
            series: r.series.clone(),
        }
    }
}

/// Serialised verdict key.
#[must_use]
pub const fn verdict_key(v: Verdict) -> &'static str {
    match v {
        Verdict::Passed => "passed",
        Verdict::Failed => "failed",
        Verdict::NotApplicable => "not_applicable",
        Verdict::Error => "error",
    }
}

impl StoredResult {
    /// Short label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self.verdict.as_str() {
            "passed" => "pass",
            "failed" => "FAIL",
            "not_applicable" => "n/a",
            _ => "ERROR",
        }
    }

    /// A measurement by name.
    #[must_use]
    pub fn measurement(&self, name: &str) -> Option<&str> {
        self.measurements.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// A series by name.
    #[must_use]
    pub fn series(&self, name: &str) -> Option<&[f64]> {
        self.series.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_slice())
    }
}

impl RunReport {
    /// Counts `(passed, failed, n/a, errors)`.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let c = |k: &str| self.results.iter().filter(|r| r.verdict == k).count();
        (c("passed"), c("failed"), c("not_applicable"), c("error"))
    }
}

/// `git rev-parse HEAD` of `repo`, or `unknown`.
#[must_use]
pub fn git_commit(repo: &std::path::Path) -> String {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".into())
}

/// Whether the working tree has local modifications (reported next to the commit).
#[must_use]
pub fn git_dirty(repo: &std::path::Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| !o.stdout.is_empty())
}
