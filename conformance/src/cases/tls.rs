//! C-TLS-1..5: mutual TLS 1.3 with ALPN, pinning against a rogue broker, TLS 1.2 refusal,
//! session resumption and bounded reconnect backoff.

use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::json;

use super::{brief, ensure, fail, online, Ctx, Outcome};
use crate::dut::Resumption;
use crate::harness::broker::{BrokerMode, ObsKind};

/// C-TLS-1.
pub async fn tls_1(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("C-TLS-1 broker-side handshake inspection")?;
    let dut = ctx.launch().await?;
    let since = Instant::now();
    dut.enroll().await?;
    let serial = dut.cert_serial().await?;
    let c = dut.connect().await?;
    ctx.evidence(format!("connected {}", brief(&c.data)));
    ensure(c.data["tls_version"] == "TLSv1.3", format!("connected.tls_version = {} (expected TLSv1.3)", c.data["tls_version"]))?;
    ensure(c.data["alpn"] == "mqtt", format!("connected.alpn = {} (expected mqtt)", c.data["alpn"]))?;
    ctx.measure("tls_version", c.data["tls_version"].as_str().unwrap_or("?"));
    ctx.measure("alpn", c.data["alpn"].as_str().unwrap_or("?"));
    // Cross-check on the wire.
    let hs = broker
        .wait_obs(
            since,
            Duration::from_secs(5),
            |o| matches!(&o.kind, ObsKind::Handshake { ok: true, client_cn: Some(cn), .. } if cn == dut.id()),
        )
        .await
        .ok_or_else(|| fail("the broker saw no successful handshake from the device"))?;
    if let ObsKind::Handshake { version, alpn, client_serial, .. } = &hs.kind {
        ctx.evidence(format!("broker handshake: version {version:?}, alpn {alpn:?}, client cert serial {client_serial:?}"));
        ensure(version.as_deref() == Some("TLSv1.3"), format!("broker negotiated {version:?}"))?;
        ensure(alpn.as_deref() == Some("mqtt"), format!("broker negotiated ALPN {alpn:?}"))?;
        ensure(client_serial.as_deref() == Some(serial.as_str()), "the device did not present its operational certificate")?;
    }
    let connect = broker
        .wait_obs(since, Duration::from_secs(5), |o| matches!(&o.kind, ObsKind::Connect { client_id, .. } if client_id == dut.id()))
        .await
        .ok_or_else(|| fail("the broker saw no CONNECT"))?;
    if let ObsKind::Connect { clean_start, session_expiry, keep_alive, receive_maximum, authn_allow, .. } = connect.kind {
        ctx.evidence(format!(
            "CONNECT: client id = CN, clean_start={clean_start}, session_expiry={session_expiry:?}, keep_alive={keep_alive}, receive_maximum={receive_maximum:?}; policy authn allow={authn_allow}"
        ));
        ensure(authn_allow, "the real policy service denied the CONNECT")?;
        // Contract §4 session parameters (outside the table criterion: warnings only).
        if clean_start {
            ctx.warn("CONNECT uses clean_start=true (contract §4: false)");
        }
        if session_expiry != Some(7 * 86_400) {
            ctx.warn(format!("session expiry interval {session_expiry:?} (contract §4: 604800 s)"));
        }
        if keep_alive != 60 {
            ctx.warn(format!("keep-alive {keep_alive} s (contract §4: 60 s)"));
        }
        if receive_maximum != Some(32) {
            ctx.warn(format!("receive maximum {receive_maximum:?} (contract §4: 32)"));
        }
    }
    Ok(Outcome::Pass)
}

async fn failing_broker(ctx: &Ctx, modes: &[BrokerMode], want: &str) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker fault injection")?;
    let dut = ctx.launch().await?;
    dut.enroll().await?;
    let mut problems = Vec::new();
    for mode in modes {
        broker.set_mode(*mode);
        let since = Instant::now();
        let m = dut.mark();
        dut.ok("connect", json!({})).await?;
        let e = dut.expect_any(m, &["connect_failed", "connected"], Duration::from_secs(30)).await;
        let _ = dut.call("disconnect", json!({})).await; // stop retrying before the next mode
        broker.set_mode(BrokerMode::Normal);
        let e = e?;
        ctx.evidence(format!("broker mode {mode:?}: {} {}", e.name, brief(&e.data)));
        let obs = broker.observations_since(since);
        let handshakes: Vec<String> = obs
            .iter()
            .filter_map(|o| match &o.kind {
                ObsKind::Handshake { ok, error, version, mode: m, .. } if m == mode => {
                    Some(format!("ok={ok} version={version:?} error={error:?}"))
                }
                _ => None,
            })
            .collect();
        ctx.evidence(format!("broker-side handshakes in mode {mode:?}: {handshakes:?}"));
        let connects = obs.iter().filter(|o| matches!(&o.kind, ObsKind::Connect { client_id, .. } if client_id == dut.id())).count();
        ctx.measure(&format!("{mode:?}: connect_failed.reason"), e.data["reason"].as_str().unwrap_or(e.name.as_str()));
        ctx.measure(&format!("{mode:?}: CONNECT packets observed"), connects);
        if e.name != "connect_failed" {
            problems.push(format!("{mode:?}: the DUT connected"));
            continue;
        }
        if connects != 0 {
            problems.push(format!("{mode:?}: {connects} MQTT CONNECT packet(s) reached the broker"));
        }
        if e.data["reason"] != want {
            problems.push(format!("{mode:?}: connect_failed.reason = {} (expected {want})", e.data["reason"]));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    ensure(problems.is_empty(), problems.join("; "))?;
    Ok(Outcome::Pass)
}

/// C-TLS-2: two rogue brokers, one whose CA has its own name (unknown issuer) and one whose CA
/// impersonates the Services CA's subject name (same name, different key - the realistic attack).
pub async fn tls_2(ctx: &Ctx) -> Result<Outcome> {
    failing_broker(ctx, &[BrokerMode::RogueUnknownCa, BrokerMode::Rogue], "tls_pin_mismatch").await
}

/// C-TLS-3.
pub async fn tls_3(ctx: &Ctx) -> Result<Outcome> {
    failing_broker(ctx, &[BrokerMode::Tls12Only], "tls_handshake").await
}
/// C-TLS-4.
pub async fn tls_4(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker-side resumption check")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let m = dut.mark();
    dut.ok("disconnect", json!({})).await?;
    dut.expect_event(m, "disconnected", Duration::from_secs(10)).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let since = Instant::now();
    let c = dut.connect().await?;
    ctx.evidence(format!("second connected {}", brief(&c.data)));
    let hs = broker
        .wait_obs(
            since,
            Duration::from_secs(5),
            |o| matches!(&o.kind, ObsKind::Handshake { ok: true, client_cn: Some(cn), .. } if cn == dut.id()),
        )
        .await
        .ok_or_else(|| fail("no second handshake observed"))?;
    let broker_resumed = matches!(hs.kind, ObsKind::Handshake { resumed: true, .. });
    let dut_resumed = c.data["resumed"] == true;
    ctx.measure("dut_reported_resumed", dut_resumed);
    ctx.measure("broker_observed_resumed", broker_resumed);
    ctx.measure("session_present", c.data["session_present"].clone());
    if c.data["session_present"] != true {
        ctx.warn("second CONNECT got session_present=false although clean_start=false with a 7-day expiry was expected");
    }
    match ctx.profile.resumption {
        Resumption::Resumed => {
            ensure(dut_resumed, "second connected.resumed=false")?;
            ensure(broker_resumed, "the DUT reported resumed=true but the broker performed a full handshake")?;
        }
        Resumption::TicketOffered => {
            ctx.evidence("target semantics: ticket offered (the broker-side resumed handshake is the criterion)".to_string());
            ensure(broker_resumed, "the device did not offer (or the broker did not accept) its TLS 1.3 session ticket")?;
            if !dut_resumed {
                ctx.warn("the broker resumed the session but the DUT reported resumed=false");
            }
        }
    }
    Ok(Outcome::Pass)
}

/// Full-jitter bound check result.
#[derive(Debug, Clone)]
pub struct BackoffAnalysis {
    /// Gaps (s) between the disconnect and successive failed attempts.
    pub gaps: Vec<f64>,
    /// Upper bound per gap (s, scaled).
    pub bounds: Vec<f64>,
    /// Gaps over their bound (+ tolerance).
    pub violations: Vec<String>,
    /// Some gap well below its bound (jitter present).
    pub jitter_seen: bool,
    /// Largest gap exceeds 4 x base (delays grow).
    pub growth_seen: bool,
    /// Gaps under the cap that were checked.
    pub capped_checked: usize,
}

/// Check gaps against `min(cap, base * 2^k) * scale` with full jitter.
#[must_use]
pub fn analyse_backoff(gaps: &[f64], scale: f64) -> BackoffAnalysis {
    let base = 1.0;
    let cap = 300.0;
    let mut bounds = Vec::new();
    let mut violations = Vec::new();
    let mut jitter_seen = false;
    let mut capped_checked = 0;
    for (k, g) in gaps.iter().enumerate() {
        let raw = base * 2f64.powi(k as i32);
        let bound = raw.min(cap) * scale;
        if raw >= cap {
            capped_checked += 1;
        }
        let tol = 0.25 + 0.1 * bound;
        if *g > bound + tol {
            violations.push(format!("gap {k}: {g:.3} s > bound {bound:.3} s (+{tol:.3} s tolerance)"));
        }
        if bound >= 0.5 && *g < 0.75 * bound {
            jitter_seen = true;
        }
        bounds.push(bound);
    }
    let growth_seen = gaps.iter().copied().fold(0.0, f64::max) > 4.0 * base * scale;
    BackoffAnalysis { gaps: gaps.to_vec(), bounds, violations, jitter_seen, growth_seen, capped_checked }
}

/// C-TLS-5.
pub async fn tls_5(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker-side connect refusal")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let scale = ctx.profile.backoff_scale;
    // Clock-scaled targets can reach the 300 s cap: gap k is capped from k = 9 (2^9 > 300).
    let (min_gaps, max_gaps, limit) = if scale < 1.0 { (13, 14, Duration::from_secs(90)) } else { (5, 9, Duration::from_secs(240)) };
    broker.refuse(dut.id(), Some(0x88)); // CONNACK "server unavailable"
    let m = dut.mark();
    broker.drop_session(dut.id());
    let disc = dut.expect_event(m, "disconnected", Duration::from_secs(15)).await?;
    let started = Instant::now();
    let mut gaps: Vec<f64> = Vec::new();
    let mut last_ms = disc.at_ms;
    let mut seen = 0usize;
    let mut state_backoff = false;
    loop {
        let fails = dut.link.named_since(m, "connect_failed");
        while seen < fails.len() {
            let f = &fails[seen];
            gaps.push(f.at_ms.saturating_sub(last_ms) as f64 / 1000.0);
            last_ms = f.at_ms;
            seen += 1;
        }
        let a = analyse_backoff(&gaps, scale);
        if gaps.len() >= max_gaps || (gaps.len() >= min_gaps && a.jitter_seen && a.growth_seen) || started.elapsed() > limit {
            break;
        }
        if !state_backoff {
            state_backoff = dut.status().await.map(|s| s["state"] == "backoff").unwrap_or(false);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    broker.refuse(dut.id(), None);
    let a = analyse_backoff(&gaps, scale);
    let reasons: Vec<String> =
        dut.link.named_since(m, "connect_failed").iter().take(3).map(|e| e.data["reason"].as_str().unwrap_or("?").to_owned()).collect();
    ctx.evidence(format!("connect_failed reasons (first 3): {reasons:?}; status.state=backoff observed: {state_backoff}"));
    let table: Vec<String> = a.gaps.iter().zip(&a.bounds).map(|(g, b)| format!("{g:.3}<={b:.3}")).collect();
    ctx.evidence(format!("gap_k <= min(300, 2^k) x scale [s]: {}", table.join(", ")));
    ctx.measure("clock_scale", scale);
    ctx.measure("attempts_observed", gaps.len());
    ctx.measure("max_gap_s", format!("{:.3}", a.gaps.iter().copied().fold(0.0, f64::max)));
    ctx.measure("capped_gaps_checked", a.capped_checked);
    ctx.series("backoff_gaps_s", a.gaps.clone());
    // Restore connectivity (an explicit connect resets the attempt counter).
    let m2 = dut.mark();
    let _ = dut.call("disconnect", json!({})).await;
    dut.ok("connect", json!({})).await?;
    let back = dut.expect_any(m2, &["connected"], Duration::from_secs(30)).await;
    ensure(gaps.len() >= min_gaps, format!("only {} reconnect attempts within {:?}", gaps.len(), limit))?;
    ensure(a.violations.is_empty(), format!("backoff bound exceeded: {}", a.violations.join("; ")))?;
    ensure(a.growth_seen, "reconnect delays did not grow (no gap above 4 x base)")?;
    ensure(a.jitter_seen, "no jitter: every delay sat at its upper bound (full jitter expected)")?;
    if scale >= 1.0 {
        ctx.warn(format!(
            "no clock scaling on this target: bound and jitter verified for {} attempts (up to {:.0} s); the 300 s cap was not reached",
            gaps.len(),
            a.bounds.last().copied().unwrap_or(0.0)
        ));
    } else {
        ensure(a.capped_checked >= 3, format!("only {} attempts reached the cap", a.capped_checked))?;
    }
    back.map_err(|e| fail(format!("did not reconnect after the refusal was lifted: {e}")))?;
    Ok(Outcome::Pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_analysis() {
        // Full jitter at scale 0.02: every gap below its bound, some well below, growth to the cap.
        let gaps = [0.0, 0.01, 0.05, 0.1, 0.2, 0.3, 0.9, 1.5, 4.0, 5.9, 2.0, 4.5, 3.3];
        let a = analyse_backoff(&gaps, 0.02);
        assert!(a.violations.is_empty(), "{:?}", a.violations);
        assert!(a.jitter_seen && a.growth_seen);
        assert_eq!(a.capped_checked, 4);
        // No cap: delays keep doubling past 300 s x scale.
        let gaps = [0.0, 0.01, 0.05, 0.1, 0.2, 0.3, 0.9, 1.5, 4.0, 9.0, 18.0];
        assert!(!analyse_backoff(&gaps, 0.02).violations.is_empty());
        // No jitter: always at the bound.
        let gaps: Vec<f64> = (0..8).map(|k| 2f64.powi(k)).collect();
        let a = analyse_backoff(&gaps, 1.0);
        assert!(!a.jitter_seen && a.violations.is_empty());
        // No growth.
        let a = analyse_backoff(&[0.1; 8], 1.0);
        assert!(!a.growth_seen);
    }
}
