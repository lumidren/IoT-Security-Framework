//! `timeseries.csv` and the per-run `report.md`.

use std::fmt::Write as _;

use super::stats::Summary;
use super::{ProcStats, Row, RunSummary};
use crate::util::md_cell;

/// The CSV time series (one row per sample).
#[must_use]
pub fn csv(rows: &[Row]) -> String {
    let mut s = String::from(
        "t_s,phase,started,enrolled,connected,ever_connected,broker_sessions,connects_per_s,telemetry_accepted_per_s,device_acked_per_s,\
         pub_count,pub_p50_ms,pub_p95_ms,pub_p99_ms,pub_max_ms,authz_count,authz_p50_ms,authz_p99_ms,authn_count,authn_p99_ms,\
         errors_total,publish_timeouts,fleet_cpu_pct,fleet_rss_mb,harness_cpu_pct,harness_rss_mb,policy_cpu_pct,policy_rss_mb,\
         total_rss_mb,host_available_mb,verifier_backlog\n",
    );
    for r in rows {
        let _ = writeln!(
            s,
            "{:.1},{},{},{},{},{},{},{:.1},{:.1},{:.1},{},{:.2},{:.2},{:.2},{:.2},{},{:.2},{:.2},{},{:.2},{},{},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{:.0},{}",
            r.t_s,
            r.phase,
            r.started,
            r.enrolled,
            r.connected,
            r.ever_connected,
            r.broker_sessions,
            r.connects_per_s,
            r.telemetry_accepted_per_s,
            r.device_acked_per_s,
            r.publish.count,
            r.publish.p50_ms,
            r.publish.p95_ms,
            r.publish.p99_ms,
            r.publish.max_ms,
            r.authz.count,
            r.authz.p50_ms,
            r.authz.p99_ms,
            r.authn.count,
            r.authn.p99_ms,
            r.errors_total,
            r.publish_timeouts,
            r.fleet.cpu_pct,
            r.fleet.rss_mb,
            r.harness.cpu_pct,
            r.harness.rss_mb,
            r.policy.cpu_pct,
            r.policy.rss_mb,
            r.total_rss_mb,
            r.host_available_mb,
            r.verifier_backlog
        );
    }
    s
}

/// A horizontal bar of `width` cells for `v` on a `0..=max` scale.
#[must_use]
pub fn bar(v: f64, max: f64, width: usize) -> String {
    let filled = if max > 0.0 { ((v / max) * width as f64).round().clamp(0.0, width as f64) as usize } else { 0 };
    format!("{}{}", "#".repeat(filled), ".".repeat(width - filled))
}

/// At most `n` rows, evenly spaced, always including the last one.
#[must_use]
pub fn downsample(rows: &[Row], n: usize) -> Vec<&Row> {
    if rows.len() <= n || n < 2 {
        return rows.iter().collect();
    }
    let step = (rows.len() - 1) as f64 / (n - 1) as f64;
    (0..n).map(|i| &rows[((i as f64 * step).round() as usize).min(rows.len() - 1)]).collect()
}

fn chart(out: &mut String, title: &str, rows: &[&Row], unit: &str, f: impl Fn(&Row) -> f64) {
    let max = rows.iter().map(|r| f(r)).fold(0.0, f64::max);
    let _ = writeln!(out, "**{title}** (full scale = {max:.0} {unit})\n\n```text");
    for r in rows {
        let _ = writeln!(out, "{:>6.0} s {:<7} |{}| {:>9.1}", r.t_s, r.phase, bar(f(r), max, 40), f(r));
    }
    out.push_str("```\n\n");
}

fn lat_row(out: &mut String, name: &str, s: &Summary) {
    let _ = writeln!(
        out,
        "| {name} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |",
        s.count, s.p50_ms, s.p95_ms, s.p99_ms, s.max_ms, s.mean_ms
    );
}

fn proc_row(out: &mut String, name: &str, s: &ProcStats) {
    let _ = writeln!(out, "| {name} | {:.0} | {:.0} | {:.0} | {:.0} |", s.cpu_mean_pct, s.cpu_max_pct, s.rss_mean_mb, s.rss_max_mb);
}

fn map_rows<K: std::fmt::Display, V: std::fmt::Display>(out: &mut String, title: &str, m: impl IntoIterator<Item = (K, V)>) {
    let items: Vec<(K, V)> = m.into_iter().collect();
    if items.is_empty() {
        let _ = writeln!(out, "* {title}: none");
        return;
    }
    let _ = writeln!(out, "* {title}:");
    for (k, v) in items {
        let _ = writeln!(out, "  * `{}`: {}", md_cell(&k.to_string()), md_cell(&v.to_string()));
    }
}

/// The per-run Markdown report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render(s: &RunSummary, rows: &[Row]) -> String {
    let mut o = String::new();
    let verdict = if s.outcome.completed && s.verification.passed { "PASS" } else { "NOT PASSED" };
    let _ = writeln!(o, "# IronMesh load test `{}`: {verdict}\n", s.run);
    match &s.outcome.abort_reason {
        Some(r) => {
            let _ = writeln!(o, "**Aborted:** {}\n", md_cell(r));
        }
        None if !s.outcome.completed => o.push_str("**Did not reach the sustained window.**\n\n"),
        None => {}
    }
    let _ = writeln!(
        o,
        "{} of {} devices enrolled and connected through the real agent-rs device stack and the real policy service; \
         {:.0} telemetry messages/s accepted during {:.0} s of sustained load; publish -> PUBACK p50 / p95 / p99 / max \
         {} ms; every device's last `seq` accepted: {}.\n",
        s.devices.ever_connected,
        s.devices.requested,
        s.throughput.sustain_telemetry_per_s,
        s.outcome.sustain_s,
        s.latency.publish_sustain.short(),
        if s.verification.passed { "yes" } else { "NO" }
    );
    let e = &s.environment;
    o.push_str("## Environment\n\n| | |\n|---|---|\n");
    let _ = writeln!(o, "| CPU | {} ({} cores, {} logical) |", e.cpu_model, e.physical_cores, e.logical_cpus);
    let _ = writeln!(o, "| RAM | {:.0} MiB ({:.0} MiB available at start) |", e.ram_total_mb, e.ram_available_at_start_mb);
    let _ = writeln!(o, "| OS | {} |", e.os);
    let _ = writeln!(o, "| Rust | {} |", e.rustc);
    let _ = writeln!(o, "| Go | {} |", e.go);
    let _ = writeln!(o, "| Git commit | {} |", e.git_commit);
    let _ = writeln!(o, "| TCP ephemeral ports | {} |", e.tcp_dynamic_ports);
    let _ = writeln!(o, "| Started | {} |\n", s.started_at);
    let _ = writeln!(o, "```sh\n{}\n```\n", s.command);
    let c = &s.config;
    let _ = writeln!(
        o,
        "Configuration: {} devices, start rate {}/s in stages {:?} % with {} s holds, telemetry every {} s, sustain {} s, \
         {:.1} % of the devices get one command, policy hook pool {}, publish timeout {} s, backoff scale {}.\n",
        c.devices,
        c.rate,
        c.stages,
        c.stage_hold_s,
        c.interval_s,
        c.sustain_s,
        c.cmd_fraction * 100.0,
        c.hook_pool,
        c.publish_timeout_s,
        c.backoff_scale
    );

    o.push_str("## Devices and rates\n\n| Metric | Value |\n|---|---|\n");
    let d = &s.devices;
    let t = &s.throughput;
    let rows_kv: Vec<(&str, String)> = vec![
        ("Provisioned (identity, bootstrap cert, manufacture record)", d.provisioned.to_string()),
        ("Factory provisioning time", format!("{:.1} s", s.outcome.provision_s)),
        ("Device tasks started", d.started.to_string()),
        ("Enrolled (EST + attestation)", d.enrolled.to_string()),
        ("Connected at least once (CONNACK + SUBACK)", d.ever_connected.to_string()),
        ("Never connected", d.never_connected.to_string()),
        ("Broker sessions at the end of the sustained window", d.connected_end_of_sustain.to_string()),
        ("Peak broker sessions", d.broker_peak_sessions.to_string()),
        ("Ramp duration (incl. stage holds)", format!("{:.0} s", s.outcome.ramp_s)),
        ("Target start rate", format!("{:.0} devices/s", t.target_start_rate)),
        ("Achieved first-connect rate (holds excluded)", format!("{:.1} devices/s", t.achieved_connect_rate)),
        ("Sustained window", format!("{:.0} s", s.outcome.sustain_s)),
        ("Telemetry accepted by the broker, sustained", format!("{} ({:.1}/s)", t.telemetry_accepted_sustain, t.sustain_telemetry_per_s)),
        ("Offered rate at the end (sessions / interval)", format!("{:.1}/s", t.expected_telemetry_per_s)),
        ("Telemetry accepted by the broker, whole run", t.telemetry_accepted_total.to_string()),
        ("Telemetry PUBACKs received by devices, whole run", t.device_acked_total.to_string()),
    ];
    for (k, v) in rows_kv {
        let _ = writeln!(o, "| {k} | {v} |");
    }

    o.push_str("\n## Latency (ms)\n\n| Path | n | p50 | p95 | p99 | max | mean |\n|---|---|---|---|---|---|---|\n");
    let l = &s.latency;
    lat_row(&mut o, "Telemetry publish -> PUBACK, sustained (device)", &l.publish_sustain);
    lat_row(&mut o, "Telemetry publish -> PUBACK, ramp (device)", &l.publish_ramp);
    lat_row(&mut o, "Connect: TCP + TLS 1.3 mTLS + CONNACK (device)", &l.connect);
    lat_row(&mut o, "EST enrollment with attestation (device)", &l.enroll);
    lat_row(&mut o, "Command round trip (inject -> verified CommandAck)", &l.command_rtt);
    lat_row(&mut o, "Policy authn hook round trip (broker)", &l.authn_hook);
    lat_row(&mut o, "Policy authz hook round trip (broker)", &l.authz_hook);
    lat_row(&mut o, "... of which waiting for a hook pool connection", &l.hook_pool_wait);
    let _ = writeln!(o, "\n{}\n", s.policy.latency_note);

    let cm = &s.commands;
    o.push_str("## Downlink commands\n\n");
    let _ = writeln!(
        o,
        "{} tenant-signed `ping` commands injected as `svc-registry` (policy-authorized), {} acked with a verified \
         CommandAck (cmd_id + nonce echo), {} not delivered (device not subscribed at that moment), {} injection errors, \
         {} unacked at the end, {} mismatching acks. Device side: {} executed, {} rejected. Ack status codes: {:?}.\n",
        cm.sent,
        cm.acked,
        cm.not_delivered,
        cm.inject_errors,
        cm.unacked,
        cm.ack_mismatch,
        cm.executed_on_devices,
        cm.rejected_by_devices,
        cm.ack_status
    );

    let p = &s.policy;
    o.push_str("## Policy service (`/metrics` before -> after)\n\n| Counter | Delta |\n|---|---|\n");
    for (k, v) in [
        ("authn allow", p.authn_allow),
        ("authn deny", p.authn_deny),
        ("authz allow", p.authz_allow),
        ("authz deny", p.authz_deny),
        ("authz cache hit", p.authz_cache_hit),
        ("authz cache miss", p.authz_cache_miss),
        ("registry lookups", p.registry_lookups),
        ("process CPU seconds", p.process_cpu_seconds),
    ] {
        let _ = writeln!(o, "| {k} | {} |", if v.fract() == 0.0 { format!("{v:.0}") } else { format!("{v:.1}") });
    }
    o.push_str("\nEvery changed series is in `summary.json` (`policy.deltas`).\n\n");

    let v = &s.verification;
    o.push_str("## End-to-end verification\n\n");
    let _ = writeln!(
        o,
        "* Uplinks verified (COSE_Sign1 ES256 with the presented certificate key, profile, timestamp, per-device replay stream): {} \
         ({} telemetry, {} CommandAck)\n* Replay rejections: {}\n* Devices with at least one PUBACKed uplink: {}; last PUBACKed `seq` \
         equal to the verifier's last accepted `seq`: {}; different: {}\n* Peak verifier backlog: {} messages\n* Result: **{}**\n",
        v.uplinks_verified,
        v.telemetry_verified,
        v.acks_verified,
        v.replay_rejections,
        v.devices_with_acked_uplinks,
        v.last_seq_matched,
        v.last_seq_mismatched,
        v.verifier_peak_backlog,
        if v.passed { "passed" } else { "FAILED" }
    );
    for m in &v.mismatch_examples {
        let _ = writeln!(o, "  * {}", md_cell(m));
    }

    let er = &s.errors;
    o.push_str("\n## Errors\n\n");
    map_rows(
        &mut o,
        "Device side (class: count, first example)",
        er.fleet.iter().map(|(k, c)| (k.clone(), format!("{} ({})", c.count, c.example))),
    );
    map_rows(&mut o, "Broker TLS handshake failures", er.broker_handshake.iter());
    map_rows(&mut o, "Broker -> policy hook transport errors", er.broker_hook.iter());
    map_rows(&mut o, "Broker session ends by cause", er.broker_closes.iter());
    let _ = writeln!(
        o,
        "* CONNECTs refused: {}; PUBLISHes denied: {}; SUBSCRIBE filters denied: {}",
        er.connects_denied, er.publishes_denied, er.subscribes_denied
    );
    map_rows(&mut o, "EST attempts by HTTP status", er.est_status.iter());
    map_rows(&mut o, "Uplink verification failures", er.verifier.iter());

    let r = &s.resources;
    o.push_str("\n## Resources (sysinfo, every sample; CPU in % of one logical CPU)\n\n");
    o.push_str("| Process | CPU mean | CPU max | RSS mean (MiB) | RSS max (MiB) |\n|---|---|---|---|---|\n");
    proc_row(&mut o, "fleet, sustained", &r.fleet_sustain);
    proc_row(&mut o, "harness (broker + EST doubles, verifier), sustained", &r.harness_sustain);
    proc_row(&mut o, "policy service, sustained", &r.policy_sustain);
    proc_row(&mut o, "fleet, whole run", &r.fleet_all);
    proc_row(&mut o, "harness, whole run", &r.harness_all);
    proc_row(&mut o, "policy service, whole run", &r.policy_all);
    let _ = writeln!(
        o,
        "\nPeak combined RSS {:.0} MiB (abort cap {:.0} MiB); lowest host available memory {:.0} MiB (abort floor {:.0} MiB). \
         Fleet RSS per connected device {:.1} KiB; harness RSS per broker session {:.1} KiB (end of the sustained window). \
         Broker -> policy hook pool: {} connections max, {} opened.\n",
        r.peak_total_rss_mb,
        r.rss_cap_mb,
        r.min_host_available_mb,
        r.min_available_floor_mb,
        r.fleet_rss_per_device_kib,
        r.harness_rss_per_session_kib,
        r.hook_pool.0,
        r.hook_pool.1
    );

    o.push_str("## Time series\n\n");
    let ds = downsample(rows, 40);
    chart(&mut o, "Connected devices", &ds, "devices", |r| r.connected as f64);
    chart(&mut o, "Telemetry accepted by the broker", &ds, "msg/s", |r| r.telemetry_accepted_per_s);
    chart(&mut o, "Publish -> PUBACK p99 per interval", &ds, "ms", |r| r.publish.p99_ms);
    chart(&mut o, "Combined RSS (fleet + harness + policy)", &ds, "MiB", |r| r.total_rss_mb);
    chart(&mut o, "Combined CPU (fleet + harness + policy)", &ds, "% of one CPU", |r| {
        r.fleet.cpu_pct + r.harness.cpu_pct + r.policy.cpu_pct
    });
    o.push_str("| t (s) | phase | connected | tele/s | pub p50 | pub p99 | authz p99 | fleet CPU % | fleet MiB | harness CPU % | harness MiB | policy CPU % | policy MiB | avail MiB |\n");
    o.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for r in &ds {
        let _ = writeln!(
            o,
            "| {:.0} | {} | {} | {:.0} | {:.1} | {:.1} | {:.1} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} |",
            r.t_s,
            r.phase,
            r.connected,
            r.telemetry_accepted_per_s,
            r.publish.p50_ms,
            r.publish.p99_ms,
            r.authz.p99_ms,
            r.fleet.cpu_pct,
            r.fleet.rss_mb,
            r.harness.cpu_pct,
            r.harness.rss_mb,
            r.policy.cpu_pct,
            r.policy.rss_mb,
            r.host_available_mb
        );
    }
    o.push_str("\nFull resolution: `timeseries.csv`. Machine-readable results: `summary.json`.\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_and_downsampling() {
        assert_eq!(bar(5.0, 10.0, 10), "#####.....");
        assert_eq!(bar(20.0, 10.0, 4), "####");
        assert_eq!(bar(1.0, 0.0, 3), "...");
        let rows: Vec<Row> = (0..100).map(|i| Row { t_s: f64::from(i), ..Row::default() }).collect();
        let d = downsample(&rows, 10);
        assert_eq!(d.len(), 10);
        assert_eq!(d[0].t_s, 0.0);
        assert_eq!(d[9].t_s, 99.0);
        assert_eq!(downsample(&rows[..5], 10).len(), 5);
    }

    #[test]
    fn csv_has_one_line_per_row_and_a_header() {
        let rows = vec![Row { t_s: 5.0, phase: "ramp".into(), connected: 10, ..Row::default() }; 3];
        let c = csv(&rows);
        assert_eq!(c.lines().count(), 4);
        let header_cols = c.lines().next().unwrap().split(',').count();
        assert!(c.lines().skip(1).all(|l| l.split(',').count() == header_cols));
        assert!(c.lines().nth(1).unwrap().starts_with("5.0,ramp,0,0,10,"));
    }
}
