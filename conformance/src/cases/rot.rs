//! C-ROT-1/2: certificate rotation on request and automatically at 50 % of the lifetime.

use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::json;

use super::{brief, ensure, fail, online, Ctx, Outcome};
use crate::harness::broker::ObsKind;
use crate::harness::pki;
use crate::util;

/// After a renewal: the broker must accept a session with the new certificate (the DUT reconnects
/// by itself or, if it keeps the old session, after an explicit disconnect/connect).
pub(crate) async fn reconnect_with(ctx: &Ctx, dut: &crate::dut::Dut, new_serial: &str, since: Instant) -> Result<bool> {
    let broker = ctx.cloud.broker("broker-side session check")?;
    let pred = |o: &crate::harness::broker::Obs| matches!(&o.kind, ObsKind::Connect { client_id, cert_serial: Some(s), authn_allow: true, .. } if client_id == dut.id() && s == new_serial);
    if broker.wait_obs(since, Duration::from_secs(8), pred).await.is_some() {
        return Ok(true);
    }
    let m = dut.mark();
    dut.ok("disconnect", json!({})).await?;
    let _ = dut.expect_event(m, "disconnected", Duration::from_secs(5)).await;
    dut.connect().await?;
    broker.wait_obs(since, Duration::from_secs(8), pred).await.ok_or_else(|| fail("no broker session with the renewed certificate"))?;
    Ok(false)
}

/// C-ROT-1.
pub async fn rot_1(ctx: &Ctx) -> Result<Outcome> {
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let old_serial = dut.cert_serial().await?;
    let old = pki::cert_facts(&ctx.cloud.certificate(&old_serial).await?)?;
    let m = dut.mark();
    let since = Instant::now();
    dut.ok("renew", json!({})).await?;
    let e = dut.expect_any(m, &["cert_renewed", "renew_failed"], Duration::from_secs(30)).await?;
    ctx.evidence(format!("{} {}", e.name, brief(&e.data)));
    ensure(e.name == "cert_renewed", format!("renewal failed: {}", e.data))?;
    let new_serial = e.data["new_serial_hex"].as_str().unwrap_or_default().to_owned();
    ensure(
        e.data["old_serial_hex"] == old_serial.as_str(),
        format!("cert_renewed.old_serial_hex {} != {old_serial}", e.data["old_serial_hex"]),
    )?;
    ensure(!new_serial.is_empty() && new_serial != old_serial, "the serial did not change")?;
    let new = pki::cert_facts(&ctx.cloud.certificate(&new_serial).await?)?;
    ensure(new.spki_sha256 != old.spki_sha256, "the renewed certificate certifies the old key (same SPKI)")?;
    ensure(new.cn == old.cn && new.cn.as_deref() == Some(dut.id()), "the identity (CN) changed")?;
    ensure(e.data["not_after"].as_u64() == Some(new.not_after), "cert_renewed.not_after does not match the certificate")?;
    if let Ok(recs) = ctx.cloud.enrollments(dut.id()) {
        let r = recs.iter().rev().find(|r| r.status == 200).ok_or_else(|| fail("no successful EST request recorded"))?;
        ctx.evidence(format!(
            "EST: op={}, client cert serial {}, attestation kid {:?}, CSR fresh key {}",
            if r.reenroll { "simplereenroll" } else { "simpleenroll" },
            r.client_serial_hex,
            r.attestation.as_ref().map(|a| a.kid_hex.clone()),
            r.csr_key_fresh
        ));
        ensure(r.reenroll, "renewal did not use simplereenroll")?;
        ensure(r.client_serial_hex == old_serial, "simplereenroll was not authenticated with the current operational certificate")?;
        ensure(
            r.attestation.as_ref().is_some_and(|a| a.kid_hex == old_serial && a.signature_ok),
            "attestation not signed by the current identity key",
        )?;
    }
    ctx.measure("old_serial", &old_serial);
    ctx.measure("new_serial", &new_serial);
    ctx.measure("spki_changed", true);
    let auto = reconnect_with(ctx, &dut, &new_serial, since).await?;
    // With the real PKI the previous certificate is superseded PKI_SUPERSEDE_GRACE after the
    // renewal; a device still on it is then kicked by the policy and reconnects with the new one.
    let kicked = ctx.cloud.broker("").is_ok_and(|b| {
        b.observations_since(since).iter().any(|o| matches!(&o.kind, ObsKind::Kick { client_id, found: true } if client_id == dut.id()))
    });
    if kicked {
        ctx.evidence(
            "the session on the previous certificate was kicked after the PKI superseded it; the DUT reconnected with the renewed one",
        );
    }
    ctx.measure("reconnected_automatically", auto && !kicked);
    // Uplinks are now signed with the new key, kid = new serial.
    let r = dut.ok("send_telemetry", json!({"count": 1})).await?;
    let last = r["last_seq"].as_u64().unwrap_or(0);
    let verified = util::wait_for(Duration::from_secs(10), || {
        ctx.verified_uplinks(dut.id(), "/telemetry").ok()?.into_iter().filter_map(Result::ok).find(|v| v.message.seq == last)
    })
    .await
    .ok_or_else(|| fail("telemetry after the renewal did not verify"))?;
    let kid = match &verified.sender_kid {
        ironmesh_agent::wire::cose::Kid::Bytes(b) => hex::encode(b),
        ironmesh_agent::wire::cose::Kid::Text(t) => t.clone(),
    };
    ensure(kid == new_serial, format!("telemetry kid {kid} != new serial {new_serial}"))?;
    ctx.evidence(format!("telemetry seq {last} verified with the renewed key (kid {kid})"));
    Ok(Outcome::Pass)
}

/// C-ROT-2.
pub async fn rot_2(ctx: &Ctx) -> Result<Outcome> {
    const LIFETIME: u64 = 40;
    let dut = ctx.launch().await?;
    ctx.cloud.set_cert_lifetime(dut.id(), LIFETIME)?;
    online(ctx, &dut).await?;
    let serial = dut.cert_serial().await?;
    let cert = pki::cert_facts(&ctx.cloud.certificate(&serial).await?)?;
    let lifetime = (cert.not_after - cert.not_before) as f64;
    ctx.measure("test_cert_lifetime_s", lifetime);
    let m = dut.mark();
    let wait = Duration::from_secs((lifetime * 0.75) as u64 + 15);
    let e = dut.link.wait_any(m, &["cert_renewed", "renew_failed"], wait, |_| true).await;
    let renewals = dut.link.named_since(m, "renew_failed");
    let e = e.ok_or_else(|| fail(format!("no automatic renewal within {wait:?} of a {lifetime} s certificate")))?;
    ctx.evidence(format!("{} {}", e.name, brief(&e.data)));
    ensure(e.name == "cert_renewed", format!("automatic renewal failed: {} ({} renew_failed)", e.data, renewals.len()))?;
    ensure(
        ctx.cloud.enrollments(dut.id())?.iter().filter(|r| r.reenroll && r.status == 200).count() >= 1,
        "no simplereenroll reached the EST server",
    )?;
    // When did it happen, relative to the certificate's lifetime?
    let renew_at = ctx
        .cloud
        .enrollments(dut.id())?
        .into_iter()
        .find(|r| r.reenroll && r.status == 200)
        .map(|r| util::now_unix() as f64 - r.at.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    let fraction = (renew_at - cert.not_before as f64) / lifetime;
    ctx.measure("renewed_at_fraction_of_lifetime", format!("{fraction:.3}"));
    ctx.evidence(format!("renewal at {:.1} s of {lifetime} s (contract §2: 50 % + up to 10 % jitter)", renew_at - cert.not_before as f64));
    ensure((0.45..=0.70).contains(&fraction), format!("renewal at {:.0} % of the lifetime (expected 50-60 %)", fraction * 100.0))?;
    let new_serial = e.data["new_serial_hex"].as_str().unwrap_or_default().to_owned();
    ensure(new_serial != serial, "the serial did not change")?;
    let since = Instant::now() - Duration::from_secs(5);
    let auto = reconnect_with(ctx, &dut, &new_serial, since).await?;
    // With the real PKI the previous certificate is superseded PKI_SUPERSEDE_GRACE after the
    // renewal; a device still on it is then kicked by the policy and reconnects with the new one.
    let kicked = ctx.cloud.broker("").is_ok_and(|b| {
        b.observations_since(since).iter().any(|o| matches!(&o.kind, ObsKind::Kick { client_id, found: true } if client_id == dut.id()))
    });
    if kicked {
        ctx.evidence(
            "the session on the previous certificate was kicked after the PKI superseded it; the DUT reconnected with the renewed one",
        );
    }
    ctx.measure("reconnected_automatically", auto && !kicked);
    Ok(Outcome::Pass)
}
