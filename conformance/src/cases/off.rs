//! C-OFF-1: offline buffering (`net_down`) and in-order resync (`net_up`), followed by a
//! broker-side session drop (partition seen from the broker) with the same no-gap requirement.

use std::time::Duration;

use anyhow::Result;
use serde_json::json;

use super::{brief, ensure, fail, online, wait_reconnected, Ctx, Outcome};
use crate::util;

/// C-OFF-1.
pub async fn off_1(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker-side delivery check")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let r0 = dut.ok("send_telemetry", json!({"count": 2})).await?;
    let first0 = r0["first_seq"].as_u64().unwrap_or(0);
    let last0 = r0["last_seq"].as_u64().unwrap_or(0);
    // Let the two online messages reach the broker (authz is asynchronous) before cutting the link.
    util::wait_for(Duration::from_secs(10), || {
        let s: Vec<u64> =
            ctx.verified_uplinks(dut.id(), "/telemetry").ok()?.into_iter().filter_map(Result::ok).map(|v| v.message.seq).collect();
        s.contains(&last0).then_some(())
    })
    .await
    .ok_or_else(|| fail("telemetry sent while online did not reach the broker"))?;
    let m = dut.mark();
    dut.ok("net_down", json!({})).await?;
    let d = dut.expect_event(m, "disconnected", Duration::from_secs(10)).await?;
    ctx.evidence(format!("net_down -> disconnected {}", brief(&d.data)));
    let on_wire_before = broker.accepted_publishes(dut.id(), "/telemetry").len();
    let r = dut.ok("send_telemetry", json!({"count": 25})).await?;
    let (first, last) = (r["first_seq"].as_u64().unwrap_or(0), r["last_seq"].as_u64().unwrap_or(0));
    let st = dut.status().await?;
    ctx.evidence(format!("offline send_telemetry 25 -> {}, status.buffered={}", brief(&r), st["buffered"]));
    ensure(last >= first && last - first == 24, format!("send_telemetry(25) returned seqs {first}..{last}"))?;
    ensure(st["buffered"] == 25, format!("status.buffered = {} (expected 25)", st["buffered"]))?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    ensure(broker.accepted_publishes(dut.id(), "/telemetry").len() == on_wire_before, "packets left the device while net_down")?;
    let m = dut.mark();
    dut.ok("net_up", json!({})).await?;
    let f = dut.expect_event(m, "buffer_flushed", Duration::from_secs(30)).await?;
    ctx.evidence(format!("net_up -> buffer_flushed {}", brief(&f.data)));
    ensure(f.data["count"] == 25, format!("buffer_flushed.count = {}", f.data["count"]))?;
    ensure(
        f.data["first_seq"].as_u64() == Some(first) && f.data["last_seq"].as_u64() == Some(last),
        "buffer_flushed seq range differs from what was buffered",
    )?;
    ensure(dut.status().await?["buffered"] == 0, "buffer not empty after the flush")?;
    // Phase 2: the broker drops the session silently; telemetry sent around the drop still
    // arrives without gaps.
    let m = dut.mark();
    let dropped_at = std::time::Instant::now();
    broker.drop_session(dut.id());
    dut.expect_event(m, "disconnected", Duration::from_secs(15)).await?;
    let r2 = dut.ok("send_telemetry", json!({"count": 5})).await?;
    let last2 = r2["last_seq"].as_u64().unwrap_or(0);
    wait_reconnected(ctx, &dut, m, dropped_at, Duration::from_secs(20)).await?;
    // Wire check: verified, in order, no gaps from the first message to the last.
    let seqs = util::wait_for(Duration::from_secs(20), || {
        let s: Vec<u64> =
            ctx.verified_uplinks(dut.id(), "/telemetry").ok()?.into_iter().filter_map(Result::ok).map(|v| v.message.seq).collect();
        s.contains(&last2).then_some(s)
    })
    .await
    .ok_or_else(|| fail("the telemetry sent around the broker-side drop never arrived"))?;
    let bad = ctx.verified_uplinks(dut.id(), "/telemetry")?.into_iter().filter(Result::is_err).count();
    // QoS 1 is at-least-once: a retransmitted duplicate is legal, so compare distinct seqs.
    let total = seqs.len();
    let mut seqs = seqs;
    let mut seen = std::collections::HashSet::new();
    seqs.retain(|s| seen.insert(*s));
    if seqs.len() != total {
        ctx.evidence(format!("{} duplicate deliveries (QoS 1 retransmissions) ignored", total - seqs.len()));
    }
    ctx.evidence(format!("telemetry seqs on the wire ({}): {:?}", seqs.len(), seqs));
    ensure(bad == 0, format!("{bad} telemetry messages failed signature verification"))?;
    ensure(seqs.windows(2).all(|w| w[1] > w[0]), "telemetry arrived out of order")?;
    let expected: Vec<u64> = (first0..=last2).collect();
    let missing: Vec<u64> = expected.iter().filter(|s| !seqs.contains(s)).copied().collect();
    // Seqs consumed by other uplink types (none expected here) would show up as gaps.
    ctx.measure("buffered_and_flushed", 25);
    ctx.measure("telemetry_on_wire", seqs.len());
    ensure(missing.is_empty(), format!("gaps in the delivered telemetry: missing seqs {missing:?}"))?;
    Ok(Outcome::Pass)
}
