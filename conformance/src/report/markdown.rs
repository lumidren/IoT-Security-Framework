//! The per-target Markdown report.

use std::fmt::Write as _;

use super::{RunReport, StoredResult};
use crate::util::md_cell;

/// The headline value shown in the matrix for a case.
#[must_use]
pub fn headline(r: &StoredResult) -> String {
    let pick = |names: &[&str]| names.iter().find_map(|n| r.measurement(n).map(|v| format!("{n}: {v}")));
    let v = match r.id.as_str() {
        "C-TLS-1" => pick(&["tls_version"]).map(|t| format!("{t}, alpn {}", r.measurement("alpn").unwrap_or("?"))),
        "C-TLS-2" | "C-TLS-3" => pick(&["connect_failed.reason"]),
        "C-TLS-4" => pick(&["broker_observed_resumed"]),
        "C-TLS-5" => pick(&["attempts_observed"]).map(|a| format!("{a}, max gap {} s", r.measurement("max_gap_s").unwrap_or("?"))),
        "C-ENR-2" => pick(&["http_status"]),
        "C-ROT-2" => pick(&["renewed_at_fraction_of_lifetime"]),
        "C-REV-1" => r.measurement("revoke -> reconnect denied (end to end)").map(|s| format!("denied {s}")),
        "C-REV-2" => r
            .measurement("revoke B -> DUT reconnect presenting B refused")
            .map(|s| format!("superseded serial refused, renewed admitted; own serial refused in {s}")),
        "C-OTA-1" | "C-OTA-2" | "C-OTA-3" | "C-OTA-4" => {
            r.measurement("final_state").map(|s| format!("{s} ({})", r.measurement("error").filter(|e| !e.is_empty()).unwrap_or("-")))
        }
        "C-OTA-5" => pick(&["new_version_code"]),
        "C-OTA-6" => pick(&["seconds_apply_to_rollback"]),
        "C-OTA-7" => r.measurement("patch_bytes").map(|p| format!("patch {p} B / image {} B", r.measurement("image_bytes").unwrap_or("?"))),
        "C-RPL-1" | "C-RPL-2" | "C-RPL-3" => pick(&["rejection_code"]),
        "C-RPL-4" => r.measurement("seq_out_before").map(|b| format!("seq_out {b} -> {}", r.measurement("seq_out_after").unwrap_or("?"))),
        "C-HOOK-1" => pick(&["exit_code"]),
        _ => None,
    };
    v.unwrap_or_default()
}

/// Render the report.
#[must_use]
pub fn render(r: &RunReport) -> String {
    let (p, f, n, e) = r.counts();
    let mut s = String::new();
    let _ = writeln!(s, "# IronMesh conformance report: `{}`\n", r.target);
    let _ = writeln!(s, "| | |\n|---|---|");
    let _ = writeln!(s, "| Run started | {} |", r.started_at);
    let _ = writeln!(s, "| Duration | {:.0} s |", r.seconds);
    let _ = writeln!(s, "| Git commit | `{}` |", r.git_commit);
    let _ = writeln!(s, "| Cloud mode | {} |", r.mode);
    let _ = writeln!(s, "| Host | {} |", md_cell(&r.host));
    for (k, v) in &r.environment {
        let _ = writeln!(s, "| {} | {} |", md_cell(k), md_cell(v));
    }
    let _ = writeln!(s, "\n**Result: {p} passed, {f} failed, {n} not applicable, {e} errors** (of {}).\n", r.results.len());
    s.push_str("| Case | Title | Verdict | Measured | Time |\n|---|---|---|---|---|\n");
    for c in &r.results {
        let _ = writeln!(s, "| {} | {} | {} | {} | {:.1} s |", c.id, md_cell(&c.title), c.label(), md_cell(&headline(c)), c.seconds);
    }
    if let Some(rev) = r.results.iter().find(|c| c.id == "C-REV-1" && !c.measurements.is_empty()) {
        s.push_str("\n## Revocation reaction time (C-REV-1)\n\n");
        s.push_str(
            "Path: harness PKI revokes the certificate (CRL regenerated) and pushes the signed event to the **real** policy service \
             (`POST /internal/v1/revocations`, bearer + `X-IronMesh-Signature` HMAC) -> policy deny-lists the device and calls the broker's \
             EMQX management API `DELETE /api/v5/clients/{id}` -> session dropped -> the DUT's reconnect is refused by the real authn hook.\n\n",
        );
        s.push_str("| Interval | Value |\n|---|---|\n");
        for (k, v) in &rev.measurements {
            let _ = writeln!(s, "| {} | {} |", md_cell(k), md_cell(v));
        }
    }
    let ota: Vec<&StoredResult> = r.results.iter().filter(|c| c.id.starts_with("C-OTA-")).collect();
    if !ota.is_empty() {
        s.push_str("\n## OTA results\n\n| Case | Verdict | Outcome | Evidence |\n|---|---|---|---|\n");
        for c in ota {
            let ev: Vec<&str> = c
                .evidence
                .iter()
                .filter(|e| e.contains("ota_state sequence") || e.contains("ota_slots"))
                .map(String::as_str)
                .take(2)
                .collect();
            let _ = writeln!(s, "| {} | {} | {} | {} |", c.id, c.label(), md_cell(&headline(c)), md_cell(&ev.join("; ")));
        }
    }
    s.push_str("\n## Case details\n");
    for c in &r.results {
        let _ = writeln!(s, "\n### {} {} - {}\n", c.id, c.title, c.label());
        let _ = writeln!(s, "*Criterion:* {}\n", c.criterion);
        if !c.reason.is_empty() {
            let what = if c.verdict == "not_applicable" { "Reason" } else { "Failure" };
            let _ = writeln!(s, "**{what}:** {}\n", c.reason.replace('\n', " "));
        }
        if !c.measurements.is_empty() {
            s.push_str("| Measurement | Value |\n|---|---|\n");
            for (k, v) in &c.measurements {
                let _ = writeln!(s, "| {} | {} |", md_cell(k), md_cell(v));
            }
            s.push('\n');
        }
        for e in &c.evidence {
            let _ = writeln!(s, "- {}", e.replace('\n', " "));
        }
        for w in &c.warnings {
            let _ = writeln!(s, "- **warning:** {}", w.replace('\n', " "));
        }
    }
    s
}
