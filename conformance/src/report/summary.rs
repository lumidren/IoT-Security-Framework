//! `results/SUMMARY.md`: case x target matrix, revocation latency statistics and OTA rejection
//! evidence across every `results/<target>/results.json`.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;

use super::markdown::headline;
use super::RunReport;
use crate::util::{md_cell, percentile};

/// Load every `<dir>/<target>/results.json`.
///
/// # Errors
/// Unreadable directory.
pub fn load_all(dir: &Path) -> Result<Vec<RunReport>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path().join("results.json");
        if p.is_file() {
            if let Ok(r) = serde_json::from_str::<RunReport>(&std::fs::read_to_string(&p)?) {
                out.push(r);
            }
        }
    }
    let order = |t: &str| match t {
        "agent-rs" => 0,
        "esp32-host" => 1,
        "esp32-hil" => 2,
        _ => 3,
    };
    out.sort_by_key(|r| order(&r.target));
    Ok(out)
}

fn stats(v: &[f64]) -> String {
    if v.is_empty() {
        return "-".into();
    }
    format!(
        "n={} p50 {:.3} s, p95 {:.3} s, max {:.3} s",
        v.len(),
        percentile(v, 50.0).unwrap_or(f64::NAN),
        percentile(v, 95.0).unwrap_or(f64::NAN),
        v.iter().copied().fold(0.0, f64::max)
    )
}

/// Render the summary.
#[must_use]
pub fn render(runs: &[RunReport], interop: &[RunReport], generated_at: &str, commit: &str) -> String {
    let mut s = String::new();
    s.push_str("# IronMesh conformance summary\n\n");
    let _ = writeln!(s, "Generated {generated_at} from `git rev-parse HEAD` = `{commit}`.\n");
    s.push_str("| Target | Run started | Commit | Mode | Passed | Failed | N/A | Errors |\n|---|---|---|---|---|---|---|---|\n");
    for r in runs {
        let (p, f, n, e) = r.counts();
        let _ = writeln!(
            s,
            "| `{}` | {} | `{}` | {} | {p} | {f} | {n} | {e} |",
            r.target,
            r.started_at,
            &r.git_commit[..r.git_commit.len().min(12)],
            r.mode
        );
    }
    s.push_str("\n## Matrix\n\n| Case | Title |");
    for r in runs {
        let _ = write!(s, " `{}` |", r.target);
    }
    s.push_str("\n|---|---|");
    for _ in runs {
        s.push_str("---|");
    }
    s.push('\n');
    let ids: Vec<(String, String)> =
        runs.first().map(|r| r.results.iter().map(|c| (c.id.clone(), c.title.clone())).collect()).unwrap_or_default();
    for (id, title) in &ids {
        let _ = write!(s, "| {id} | {} |", md_cell(title));
        for r in runs {
            let cell = r.results.iter().find(|c| &c.id == id).map(|c| {
                let h = headline(c);
                if h.is_empty() {
                    c.label().to_string()
                } else {
                    format!("{} ({})", c.label(), md_cell(&h))
                }
            });
            let _ = write!(s, " {} |", cell.unwrap_or_else(|| "not run".into()));
        }
        s.push('\n');
    }
    s.push_str("\n## Revocation reaction time (C-REV-1, budget < 10 s)\n\n");
    s.push_str(
        "| Target | revoke -> broker disconnect | revoke -> reconnect denied (end to end) | revoke -> kick call |\n|---|---|---|---|\n",
    );
    for r in runs {
        if let Some(c) = r.results.iter().find(|c| c.id == "C-REV-1") {
            let _ = writeln!(
                s,
                "| `{}` | {} | {} | {} |",
                r.target,
                stats(c.series("revoke_to_disconnect_s").unwrap_or(&[])),
                stats(c.series("revoke_to_denied_s").unwrap_or(&[])),
                stats(c.series("revoke_to_kick_s").unwrap_or(&[]))
            );
        }
    }
    s.push_str(
        "\n## OTA rejection evidence\n\n| Target | Case | Verdict | Final state (error) | ota_state sequence |\n|---|---|---|---|---|\n",
    );
    for r in runs {
        for c in r.results.iter().filter(|c| c.id.starts_with("C-OTA-")) {
            let seq = c
                .evidence
                .iter()
                .find(|e| e.starts_with("ota_state sequence"))
                .map(|e| e.trim_start_matches("ota_state sequence: ").to_owned())
                .unwrap_or_default();
            let _ = writeln!(s, "| `{}` | {} | {} | {} | {} |", r.target, c.id, c.label(), md_cell(&headline(c)), md_cell(&seq));
        }
    }
    let mut failures = String::new();
    for r in runs {
        for c in r.results.iter().filter(|c| c.verdict == "failed" || c.verdict == "error") {
            let _ = writeln!(failures, "- `{}` {}: {}", r.target, c.id, c.reason.replace('\n', " "));
        }
    }
    if !failures.is_empty() {
        s.push_str("\n## Failures\n\n");
        s.push_str(&failures);
    }
    let mut na = String::new();
    for r in runs {
        for c in r.results.iter().filter(|c| c.verdict == "not_applicable") {
            let _ = writeln!(na, "- `{}` {}: {}", r.target, c.id, c.reason.replace('\n', " "));
        }
    }
    if !na.is_empty() {
        s.push_str("\n## Not applicable (with reasons)\n\n");
        s.push_str(&na);
    }
    if !interop.is_empty() {
        s.push_str("\n## Real PKI interoperability probe (`--pki-bin`)\n\n");
        s.push_str(
            "The same suite with the real `services/pki` binary (key ceremony by the real `pkictl`, in-memory store, file KMS) as the \
             enrollment authority instead of the in-process EST server; everything else as above. Downlink / OTA cases are not \
             applicable in this mode: the harness does not yet provision the tenant command key and firmware keys through the \
             PKI tenant-policy API (`PUT /v1/tenants/{t}/command-key`, `/firmware-keys`), so the real PKI's bundles carry none.\n\n",
        );
        if interop.iter().flat_map(|r| &r.results).any(|c| c.reason.contains("invalid attestation payload")) {
            s.push_str(
                "**Root cause of the failures below (not a DUT bug):** `services/pki/internal/attest/statement.go` `Parse` decodes the \
                 attestation COSE_Sign1 payload as the bare map `{1: nonce, 2: csr_hash, 3: fw_hash, 4: fw_version, 5: se_type, 6: evidence}` \
                 (DESIGN_CONTRACT §3 read literally), while both devices - like the Python reference and \
                 `device/common/vectors/attestation_software.json` - send a type-10 *envelope* `{1: seq, 2: ts, 3: 10, 4: {Attestation body}}` \
                 as WIRE_FORMAT §4 / Appendix B.3 specifies. The PKI rejects every enrollment with 400 `invalid attestation payload` \
                 (key 1 is the integer seq, not the nonce bstr), before the lifecycle check (hence 400 instead of 403 in C-ENR-2). No \
                 WIRE_FORMAT-conformant device can enroll with the real PKI until one side changes.\n\n",
            );
        }
        s.push_str("| Target | Run started | Passed | Failed | N/A | Errors |\n|---|---|---|---|---|---|\n");
        for r in interop {
            let (p, f, n, e) = r.counts();
            let _ = writeln!(s, "| `{}` | {} | {p} | {f} | {n} | {e} |", r.target, r.started_at);
        }
        s.push_str("\n| Case |");
        for r in interop {
            let _ = write!(s, " `{}` |", r.target);
        }
        s.push_str("\n|---|");
        for _ in interop {
            s.push_str("---|");
        }
        s.push('\n');
        let ids: Vec<String> = interop.first().map(|r| r.results.iter().map(|c| c.id.clone()).collect()).unwrap_or_default();
        for id in &ids {
            let _ = write!(s, "| {id} |");
            for r in interop {
                let cell = r.results.iter().find(|c| &c.id == id).map(|c| {
                    let why = if c.verdict == "failed" {
                        format!(": {}", md_cell(&c.reason.chars().take(140).collect::<String>()))
                    } else {
                        String::new()
                    };
                    format!("{}{why}", c.label())
                });
                let _ = write!(s, " {} |", cell.unwrap_or_else(|| "not run".into()));
            }
            s.push('\n');
        }
    }
    let mut warns = String::new();
    for r in runs {
        for c in &r.results {
            for w in &c.warnings {
                let _ = writeln!(warns, "- `{}` {}: {}", r.target, c.id, w.replace('\n', " "));
            }
        }
    }
    if !warns.is_empty() {
        s.push_str("\n## Warnings (contract deviations outside the pass criteria)\n\n");
        s.push_str(&warns);
    }
    s
}
