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
