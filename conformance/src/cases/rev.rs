//! C-REV-1: revocation reaction time, end to end through the real policy service.
//!
//! One iteration: a fresh device enrolls and connects; the harness revokes its operational
//! certificate exactly as the PKI does (CRL regenerated, signed event `POST
//! /internal/v1/revocations` with bearer + HMAC to the real policy service); the policy service
//! deny-lists the device and kicks the session through the broker's EMQX management API
//! (`DELETE /api/v5/clients/{id}`); the broker drops the session; the DUT's reconnect attempt is
//! denied by the policy's authn hook (CONNACK 0x87). Measured from the start of the revoke:
//! `kick` (management API call received), `disconnect` (session closed on the broker),
//! `denied` (first CONNECT refused by the real authn). Budget (contract §2): < 10 s.

use std::time::{Duration, Instant};

use anyhow::Result;

use super::{brief, ensure, fail, online, Ctx, Outcome};
use crate::harness::broker::{CloseCause, ObsKind};
use crate::harness::policy;
use crate::harness::RevokeScope;
use crate::util;

const BUDGET: Duration = Duration::from_secs(10);

struct Iteration {
    kick_s: f64,
    disconnect_s: f64,
    denied_s: f64,
    dut_disconnected_s: f64,
    ack_s: f64,
}

async fn iteration(ctx: &Ctx, n: usize) -> Result<Iteration> {
    let broker = ctx.cloud.broker("C-REV-1 broker-side timing")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let serial = dut.cert_serial().await?;
    let m = dut.mark();
    let t = ctx.cloud.revoke(dut.id(), &serial).await?;
    let t0 = t.started;
    let id = dut.id().to_owned();
    let kick = broker
        .wait_obs(t0, BUDGET + Duration::from_secs(5), |o| matches!(&o.kind, ObsKind::Kick { client_id, found: true } if *client_id == id))
        .await
        .ok_or_else(|| fail(format!("iteration {n}: the policy service did not kick the session")))?;
    let closed = broker
        .wait_obs(
            t0,
            Duration::from_secs(5),
            |o| matches!(&o.kind, ObsKind::Closed { client_id, cause: CloseCause::Kicked } if *client_id == id),
        )
        .await
        .ok_or_else(|| fail(format!("iteration {n}: the broker did not drop the session")))?;
    let dut_disc = dut.expect_event(m, "disconnected", Duration::from_secs(10)).await?;
    let denied = broker
        .wait_obs(
            t0,
            BUDGET + Duration::from_secs(5),
            |o| matches!(&o.kind, ObsKind::Connect { client_id, authn_allow: false, .. } if *client_id == id),
        )
        .await
        .ok_or_else(|| fail(format!("iteration {n}: the DUT made no reconnect attempt that could be denied")))?;
    let failed = dut
        .link
        .wait_event(m, "connect_failed", Duration::from_secs(10), |_| true)
        .await
        .ok_or_else(|| fail(format!("iteration {n}: no connect_failed after the revocation")))?;
    if n == 0 {
        ctx.evidence(format!("revocation path: {}", t.path));
        ctx.evidence(format!("DUT disconnected {} then connect_failed {}", brief(&dut_disc.data), brief(&failed.data)));
        if let ObsKind::Connect { cert_serial, reason_code, .. } = &denied.kind {
            ctx.evidence(format!(
                "reconnect with revoked serial {cert_serial:?} answered CONNACK 0x{reason_code:02x} by the policy authn hook"
            ));
        }
    }
    if failed.data["reason"] != "not_authorized" {
        ctx.warn(format!("iteration {n}: connect_failed.reason = {} (CONNACK 0x87 maps to not_authorized)", failed.data["reason"]));
    }
    // The revoked certificate must stay locked out.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let readmitted = broker
        .observations_since(t0)
        .iter()
        .any(|o| matches!(&o.kind, ObsKind::Connect { client_id, authn_allow: true, .. } if *client_id == id));
    ensure(!readmitted, format!("iteration {n}: the revoked device was admitted again"))?;
    let secs = |i: Instant| i.saturating_duration_since(t0).as_secs_f64();
    let it = Iteration {
        kick_s: secs(kick.at),
        disconnect_s: secs(closed.at),
        denied_s: secs(denied.at),
        dut_disconnected_s: dut_disc.seen.saturating_duration_since(t0).as_secs_f64(),
        ack_s: secs(t.acknowledged),
    };
    ctx.stop(&dut).await;
    Ok(it)
}

fn stats(v: &[f64]) -> String {
    format!(
        "p50 {:.3} s, p95 {:.3} s, max {:.3} s",
        util::percentile(v, 50.0).unwrap_or(f64::NAN),
        util::percentile(v, 95.0).unwrap_or(f64::NAN),
        v.iter().copied().fold(0.0, f64::max)
    )
}

/// C-REV-1.
pub async fn rev_1(ctx: &Ctx) -> Result<Outcome> {
    let n = ctx.options.rev_iterations.max(1);
    let policy = ctx.cloud.hermetic("C-REV-1 timing").map(|h| h.policy_client.clone()).ok();
    let kicks_before = match &policy {
        Some(p) => p.metric("ironmesh_kick_total", "result=\"ok\"").await.unwrap_or(0.0),
        None => 0.0,
    };
    let mut its = Vec::with_capacity(n);
    for i in 0..n {
        its.push(iteration(ctx, i).await?);
    }
    let kick: Vec<f64> = its.iter().map(|i| i.kick_s).collect();
    let disc: Vec<f64> = its.iter().map(|i| i.disconnect_s).collect();
    let denied: Vec<f64> = its.iter().map(|i| i.denied_s).collect();
    let dut_disc: Vec<f64> = its.iter().map(|i| i.dut_disconnected_s).collect();
    let ack: Vec<f64> = its.iter().map(|i| i.ack_s).collect();
    ctx.measure("iterations", n);
    ctx.measure("revoke -> policy 202", stats(&ack));
    ctx.measure("revoke -> kick (EMQX API)", stats(&kick));
    ctx.measure("revoke -> broker disconnect", stats(&disc));
    ctx.measure("revoke -> DUT disconnected event", stats(&dut_disc));
    ctx.measure("revoke -> reconnect denied (end to end)", stats(&denied));
    ctx.series("revoke_to_disconnect_s", disc.clone());
    ctx.series("revoke_to_denied_s", denied.clone());
    ctx.series("revoke_to_kick_s", kick.clone());
    if let Some(p) = &policy {
        let kicks = p.metric("ironmesh_kick_total", "result=\"ok\"").await.unwrap_or(0.0) - kicks_before;
        let sum = p.metric("ironmesh_revocation_latency_seconds_sum", "").await.unwrap_or(f64::NAN);
        let count = p.metric("ironmesh_revocation_latency_seconds_count", "").await.unwrap_or(f64::NAN);
        ctx.evidence(format!(
            "policy /metrics: ironmesh_kick_total{{result=ok}} +{kicks}, ironmesh_revocation_latency_seconds count {count} sum {sum:.3} s (mean {:.3} s, revoked_at -> kick)",
            sum / count
        ));
        if let Ok(h) = ctx.cloud.hermetic("") {
            let log = h.policy.lock().await.log_file.clone();
            for l in policy::log_lines(&log, "revoked session kicked", 1) {
                ctx.evidence(format!("policy log: {}", l.chars().take(240).collect::<String>()));
            }
        }
    }
    let worst = denied.iter().chain(&disc).copied().fold(0.0, f64::max);
    ensure(worst < BUDGET.as_secs_f64(), format!("revocation took {worst:.3} s (budget {} s)", BUDGET.as_secs()))?;
    Ok(Outcome::Pass)
}

/// Lower-case hex without leading zeros (the policy service's `NormalizeSerial`).
fn norm_serial(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    let t = t.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.to_owned()
    }
}

/// The policy's `/v1/revocations` entry for `serial` (polled until present).
async fn policy_entry(p: &policy::PolicyClient, serial: &str, timeout: Duration) -> Option<serde_json::Value> {
    let want = norm_serial(serial);
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(items) = p.revocations().await {
            if let Some(e) = items.into_iter().rev().find(|e| e["serial_hex"].as_str().is_some_and(|s| norm_serial(s) == want)) {
                return Some(e);
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// C-REV-2: a single-certificate revocation (`device_deny=false`) refuses the revoked serial at
/// CONNECT while the device's renewed certificate stays admitted.
///
/// 1. The device enrolls (serial A), connects and renews (serial B); the broker sees a session
///    with B.
/// 2. A is revoked as superseded, `device_deny=false`: by the real PKI's own supersede-on-renewal
///    (`PKI_SUPERSEDE_GRACE`) with `--pki-bin`, by the harness PKI publishing the same event
///    otherwise.
/// 3. The B session is not kicked (the policy's precise kick); a CONNECT presenting A - the
///    certificate the device itself presented earlier, rendered as EMQX renders it - is refused by
///    the policy authn hook with reason `revoked_serial`; the device reconnects and B is admitted.
/// 4. B is revoked by a single-certificate revocation with reason `affiliationChanged`
///    (`device_deny=false`): the session is kicked and the device's own reconnect presenting B is
///    refused at CONNECT (`revoked_serial`).
///
/// Throughout, the device id is never deny-listed (`ironmesh_auth_failures_total{reason="revoked"}`
/// unchanged).
pub async fn rev_2(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("C-REV-2 broker-side CONNECT observation")?;
    let h = ctx.cloud.hermetic("C-REV-2 policy decisions")?;
    let p = h.policy_client.clone();
    let log = h.policy.lock().await.log_file.clone();
    let failures = |reason: &'static str| {
        let p = p.clone();
        async move { p.metric("ironmesh_auth_failures_total", &format!("reason=\"{reason}\"")).await.unwrap_or(f64::NAN) }
    };
    let (revoked0, serial0) = (failures("revoked").await, failures("revoked_serial").await);

    // 1. Enroll (A), connect, renew (B).
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let id = dut.id().to_owned();
    let old = dut.cert_serial().await?;
    let old_der = broker
        .client_certs(&id)
        .into_iter()
        .find(|d| crate::harness::pki::cert_facts(d).is_ok_and(|f| f.serial_hex == old))
        .ok_or_else(|| fail("the broker did not capture the certificate the device presented"))?;
    let m = dut.mark();
    let since = Instant::now();
    dut.ok("renew", serde_json::json!({})).await?;
    let e = dut.expect_any(m, &["cert_renewed", "renew_failed"], Duration::from_secs(30)).await?;
    ensure(e.name == "cert_renewed", format!("renewal failed: {}", e.data))?;
    let new = e.data["new_serial_hex"].as_str().unwrap_or_default().to_owned();
    ensure(!new.is_empty() && new != old, "the renewal did not change the serial")?;
    // The session must run on B before A is revoked (the real PKI supersedes A PKI_SUPERSEDE_GRACE
    // after the renewal): a device that keeps its A session is reconnected explicitly right away.
    let on_b = |o: &crate::harness::broker::Obs| matches!(&o.kind, ObsKind::Connect { client_id, cert_serial: Some(s), authn_allow: true, .. } if *client_id == id && *s == new);
    if broker.wait_obs(since, Duration::from_millis(1500), on_b).await.is_none() {
        let mk = dut.mark();
        dut.ok("disconnect", serde_json::json!({})).await?;
        let _ = dut.expect_event(mk, "disconnected", Duration::from_secs(5)).await;
        dut.connect().await?;
        broker.wait_obs(since, Duration::from_secs(8), on_b).await.ok_or_else(|| fail("no broker session with the renewed certificate"))?;
    }
    ensure(broker.session_serial(&id).as_deref() == Some(new.as_str()), "the broker session does not present the renewed certificate")?;
    let on_b_after = since.elapsed();
    if let Some(grace) = ctx.cloud.supersedes_on_renewal() {
        ensure(
            on_b_after < grace,
            format!(
                "the device ran on B only {:.1} s after the renewal (PKI_SUPERSEDE_GRACE {} s)",
                on_b_after.as_secs_f64(),
                grace.as_secs()
            ),
        )?;
    }
    ctx.measure("serial A (renewed away)", &old);
    ctx.measure("serial B (renewed)", &new);

    // 2. Single-certificate revocation of A (superseded, device_deny=false).
    let t_a = Instant::now();
    match ctx.cloud.supersedes_on_renewal() {
        Some(grace) => {
            let rec = util::wait_for_async(grace + Duration::from_secs(20), || async {
                ctx.cloud.pki_certificate_record(&old).await.ok().filter(|r| r["status"] == "revoked")
            })
            .await
            .ok_or_else(|| fail(format!("the real PKI did not supersede serial {old} within {} s of the renewal", grace.as_secs() + 20)))?;
            ctx.evidence(format!(
                "real PKI supersede-on-renewal (PKI_SUPERSEDE_GRACE {} s): GET /v1/certificates/{old} -> status {}, revocation {}",
                grace.as_secs(),
                rec["status"],
                brief(&rec["revocation"])
            ));
            ensure(
                rec["revocation"]["reason"] == "superseded",
                format!("revocation reason {} (want superseded)", rec["revocation"]["reason"]),
            )?;
        }
        None => {
            let t = ctx.cloud.revoke_with(&id, &old, &RevokeScope::Certificate { reason: "superseded".into() }).await?;
            ctx.evidence(format!("revocation of A: {}", t.path));
        }
    }
    let entry_a = policy_entry(&p, &old, Duration::from_secs(10))
        .await
        .ok_or_else(|| fail(format!("the policy service never applied the revocation of serial {old}")))?;
    ctx.evidence(format!("policy GET /v1/revocations (single-use service JWT) entry for A: {}", brief(&entry_a)));
    ensure(entry_a["reason"] == "superseded", format!("policy recorded reason {} for A", entry_a["reason"]))?;
    // 3a. The renewed session survives: no kick, the broker session still presents B.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let kicked = broker.observations_since(t_a).into_iter().any(|o| {
        matches!(&o.kind, ObsKind::Kick { client_id, found: true } if *client_id == id)
            || matches!(&o.kind, ObsKind::Closed { client_id, cause: CloseCause::Kicked } if *client_id == id)
    });
    ensure(!kicked, "the session with the renewed certificate was kicked by the revocation of the superseded one")?;
    if entry_a["kicked"] == true {
        ctx.warn(
            "policy GET /v1/revocations reports kicked=true (with kicked_at) for the superseded serial although no kick was sent: \
             the cache records KickSkipped (internal/revocation/cache.go markKicked) but internal/mgmt/api.go revocationItem does \
             not expose it",
        );
    }
    ensure(broker.session_serial(&id).as_deref() == Some(new.as_str()), "the broker session does not present the renewed certificate")?;
    let skipped: Vec<String> = policy::log_lines(&log, "kick skipped", 50).into_iter().filter(|l| l.contains(&id)).collect();
    ensure(!skipped.is_empty(), "the policy log does not record the skipped kick of the superseded serial")?;
    ctx.evidence(format!("policy log: {}", skipped[0].chars().take(260).collect::<String>()));
    // 3b. A CONNECT presenting A is refused by serial.
    let before = failures("revoked_serial").await;
    let d = broker.replay_connect_authn(&id, &old_der, "127.0.0.1").await?;
    ensure(!d.allow, "a CONNECT presenting the superseded certificate was admitted")?;
    let after = failures("revoked_serial").await;
    ensure(after - before >= 1.0, format!("the CONNECT presenting A was denied, but not for revoked_serial ({before} -> {after})"))?;
    ctx.measure("CONNECT presenting A (cert_pem + cert_serial)", "deny, reason revoked_serial");
    // 3c. The device reconnects with B and is admitted.
    let t_b = Instant::now();
    let mk = dut.mark();
    dut.ok("disconnect", serde_json::json!({})).await?;
    let _ = dut.expect_event(mk, "disconnected", Duration::from_secs(5)).await;
    dut.connect().await?;
    let admitted = broker
        .wait_obs(t_b, Duration::from_secs(10), |o| matches!(&o.kind, ObsKind::Connect { client_id, cert_serial: Some(s), authn_allow: true, .. } if *client_id == id && *s == new))
        .await
        .ok_or_else(|| fail("the device was not admitted with its renewed certificate after A was revoked"))?;
    if let ObsKind::Connect { reason_code, session_present, .. } = &admitted.kind {
        ctx.evidence(format!("reconnect presenting B: authn allow, CONNACK 0x{reason_code:02x}, session_present {session_present}"));
    }
    ctx.measure("CONNECT presenting B after A was revoked", "allow");

    // 4. Single-certificate revocation of the current certificate B: refused by serial at CONNECT.
    let mark = dut.mark();
    let t = ctx.cloud.revoke_with(&id, &new, &RevokeScope::Certificate { reason: "affiliationChanged".into() }).await?;
    ctx.evidence(format!("revocation of B: {}", t.path));
    let t0 = t.started;
    let kick = broker
        .wait_obs(t0, BUDGET + Duration::from_secs(5), |o| matches!(&o.kind, ObsKind::Kick { client_id, found: true } if *client_id == id))
        .await
        .ok_or_else(|| fail("the policy service did not kick the session whose certificate was revoked"))?;
    let _ = dut.expect_event(mark, "disconnected", Duration::from_secs(10)).await?;
    let denied = broker
        .wait_obs(t0, BUDGET + Duration::from_secs(5), |o| matches!(&o.kind, ObsKind::Connect { client_id, authn_allow: false, cert_serial: Some(s), .. } if *client_id == id && *s == new))
        .await
        .ok_or_else(|| fail("the device made no reconnect attempt presenting B that could be refused"))?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let readmitted = broker
        .observations_since(t0)
        .iter()
        .any(|o| matches!(&o.kind, ObsKind::Connect { client_id, authn_allow: true, .. } if *client_id == id));
    ensure(!readmitted, "the device was admitted again with its revoked certificate")?;
    let entry_b = policy_entry(&p, &new, Duration::from_secs(5)).await.ok_or_else(|| fail("no policy revocation entry for B"))?;
    ctx.evidence(format!("policy GET /v1/revocations entry for B: {}", brief(&entry_b)));
    let secs = |i: Instant| i.saturating_duration_since(t0).as_secs_f64();
    ctx.measure("revoke B -> kick", format!("{:.3} s", secs(kick.at)));
    ctx.measure("revoke B -> DUT reconnect presenting B refused", format!("{:.3} s", secs(denied.at)));

    // The device id was never deny-listed; both refusals were by serial.
    let (revoked1, serial1) = (failures("revoked").await, failures("revoked_serial").await);
    ctx.measure("ironmesh_auth_failures_total{reason=revoked_serial}", format!("+{}", serial1 - serial0));
    ctx.measure("ironmesh_auth_failures_total{reason=revoked} (device-level)", format!("+{}", revoked1 - revoked0));
    ensure(revoked1 - revoked0 == 0.0, format!("the device id was deny-listed ({} device-level denials)", revoked1 - revoked0))?;
    ensure(serial1 - serial0 >= 2.0, format!("expected at least 2 revoked_serial denials, saw {}", serial1 - serial0))?;
    for l in policy::log_lines(&log, "authn deny", 400).into_iter().filter(|l| l.contains(&id)).take(2) {
        ctx.evidence(format!("policy log: {}", l.chars().take(260).collect::<String>()));
    }
    ensure(secs(denied.at) < BUDGET.as_secs_f64(), format!("refusal took {:.3} s (budget {} s)", secs(denied.at), BUDGET.as_secs()))?;
    Ok(Outcome::Pass)
}
