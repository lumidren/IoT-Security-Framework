//! C-RPL-1..4: replay, timestamp skew, forged signature, outbound `seq` across reboot.

use std::time::Duration;

use anyhow::Result;
use ironmesh_agent::wire::envelope::{self, Body};
use ironmesh_agent::wire::ids::TopicClass;
use serde_json::json;

use super::{brief, ensure, fail, online, Ctx, Outcome};
use crate::dut::Dut;
use crate::harness::downlink::{self, Downlink};
use crate::util;

fn cmd_id(d: &Downlink) -> String {
    match &d.message.body {
        Body::Command(c) => c.cmd_id.clone(),
        _ => String::new(),
    }
}

async fn inject_cmd(ctx: &Ctx, dut: &Dut, d: &Downlink) -> Result<usize> {
    let m = dut.mark();
    let n = ctx.cloud.inject(dut.id(), TopicClass::CmdReq, d.wire.clone(), false).await?;
    ensure(n > 0, "the command was not delivered (no subscription on cmd/req)")?;
    Ok(m)
}

fn command(ctx: &Ctx, seq: Option<u64>, ts: Option<u64>, key: Option<&ed25519_dalek::SigningKey>) -> Result<Downlink> {
    let body = downlink::command_body(&ctx.profile.benign_command, &format!("idem-{}", util::uuid4()), 600);
    let seq = seq.unwrap_or_else(|| ctx.cloud.signer.next_seq(5));
    let ts = ts.unwrap_or_else(util::now_unix);
    ctx.cloud.signer.sign_with(key.unwrap_or(ctx.cloud.signer.key()), seq, ts, body, Some(downlink::nonce16()))
}

async fn expect_rejection(ctx: &Ctx, dut: &Dut, m: usize, code: &str) -> Result<()> {
    let e = dut.link.wait_any(m, &["message_rejected", "command_executed"], Duration::from_secs(10), |_| true).await;
    let e = e.ok_or_else(|| fail(format!("no message_rejected within 10 s (expected {code})")))?;
    ctx.evidence(format!("{} {}", e.name, brief(&e.data)));
    ensure(e.name == "message_rejected", format!("the command was executed: {}", e.data))?;
    ensure(e.data["code"] == code, format!("message_rejected.code = {} (expected {code})", e.data["code"]))?;
    ctx.measure("rejection_code", e.data["code"].as_str().unwrap_or("?"));
    let rej = dut.ok("rejections", json!({"since_ms": 0})).await?;
    let listed = rej["items"].as_array().is_some_and(|a| a.iter().any(|i| i["code"] == code));
    ensure(listed, format!("`rejections` does not list {code}: {}", brief(&rej)))?;
    Ok(())
}

async fn executed(dut: &Dut, m: usize, id: &str, timeout: Duration) -> Option<crate::dut::Event> {
    let id = id.to_owned();
    dut.link.wait_event(m, "command_executed", timeout, move |d| d["cmd_id"] == id.as_str()).await
}

/// C-RPL-1.
pub async fn rpl_1(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let cmd = command(ctx, None, None, None)?;
    let id = cmd_id(&cmd);
    let m = inject_cmd(ctx, &dut, &cmd).await?;
    let e = executed(&dut, m, &id, Duration::from_secs(10)).await.ok_or_else(|| fail("the original command was not executed"))?;
    ctx.evidence(format!("original seq {}: command_executed {}", cmd.message.seq, brief(&e.data)));
    // The CommandAck on the wire echoes cmd_id and nonce (verified with the device key).
    let ack = util::wait_for(Duration::from_secs(10), || {
        ctx.verified_uplinks(dut.id(), "/cmd/ack")
            .ok()?
            .into_iter()
            .filter_map(Result::ok)
            .find(|v| envelope::check_ack(&cmd.message, &v.message).is_ok())
    })
    .await;
    match &ack {
        Some(a) => ctx.evidence(format!("signed CommandAck seq {} echoes cmd_id and nonce", a.message.seq)),
        None => ctx.warn("no verifiable CommandAck echoing cmd_id/nonce reached the broker"),
    }
    let m2 = inject_cmd(ctx, &dut, &cmd).await?;
    expect_rejection(ctx, &dut, m2, "ENV_REPLAY").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let n = dut.link.named_since(0, "command_executed").iter().filter(|e| e.data["cmd_id"] == id.as_str()).count();
    ctx.measure("command_executed_count", n);
    ensure(n == 1, format!("the command was executed {n} times"))?;
    let acks = ctx
        .verified_uplinks(dut.id(), "/cmd/ack")
        .unwrap_or_default()
        .into_iter()
        .filter_map(Result::ok)
        .filter(|v| matches!(&v.message.body, Body::CommandAck(a) if a.cmd_id == id))
        .count();
    ctx.measure("command_acks_on_wire", acks);
    ensure(acks <= 1, format!("{acks} CommandAcks for one command"))?;
    Ok(Outcome::Pass)
}

/// C-RPL-2.
pub async fn rpl_2(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let stale = command(ctx, None, Some(util::now_unix() - 400), None)?;
    ctx.evidence(format!("command seq {} with ts = now - 400 s (window 300 s)", stale.message.seq));
    let m = inject_cmd(ctx, &dut, &stale).await?;
    expect_rejection(ctx, &dut, m, "ENV_TS_SKEW").await?;
    ensure(executed(&dut, m, &cmd_id(&stale), Duration::from_secs(2)).await.is_none(), "the stale command was executed")?;
    // Future-dated beyond the window is rejected too.
    let future = command(ctx, None, Some(util::now_unix() + 400), None)?;
    let m = inject_cmd(ctx, &dut, &future).await?;
    expect_rejection(ctx, &dut, m, "ENV_TS_SKEW").await?;
    Ok(Outcome::Pass)
}

/// C-RPL-3.
pub async fn rpl_3(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let seq = ctx.cloud.signer.next_seq(5);
    let attacker = ctx.cloud.keys.attacker.clone();
    let forged = command(ctx, Some(seq), None, Some(&attacker))?;
    ctx.evidence(format!("command seq {seq} with kid tenant-cmd-<tenant> signed by a non-tenant Ed25519 key"));
    let m = inject_cmd(ctx, &dut, &forged).await?;
    expect_rejection(ctx, &dut, m, "COSE_SIGNATURE").await?;
    ensure(executed(&dut, m, &cmd_id(&forged), Duration::from_secs(2)).await.is_none(), "the forged command was executed")?;
    // The forgery must not have advanced the replay window: the genuine command with the same
    // seq is accepted (WIRE_FORMAT §3.6 step 11).
    let genuine = command(ctx, Some(seq), None, None)?;
    let m = inject_cmd(ctx, &dut, &genuine).await?;
    let ok = executed(&dut, m, &cmd_id(&genuine), Duration::from_secs(10)).await;
    ensure(
        ok.is_some(),
        "after the forgery, a genuine command with the same seq was not executed (replay store advanced on a rejected message)",
    )?;
    ctx.evidence("a genuine command with the forged seq was executed afterwards (store not advanced by the forgery)");
    Ok(Outcome::Pass)
}

/// C-RPL-4.
pub async fn rpl_4(ctx: &Ctx) -> Result<Outcome> {
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let r = dut.ok("send_telemetry", json!({"count": 3})).await?;
    let last_before = r["last_seq"].as_u64().unwrap_or(0);
    let before = dut.status().await?["seq_out"].as_u64().ok_or_else(|| fail("status.seq_out missing"))?;
    let m = dut.mark();
    dut.ok("reboot", json!({})).await?;
    let rb = dut.expect_event(m, "rebooted", Duration::from_secs(30)).await?;
    ctx.evidence(format!("rebooted {}", brief(&rb.data)));
    ensure(rb.data["reason"] == "requested", format!("rebooted.reason = {}", rb.data["reason"]))?;
    let after = dut.status().await?["seq_out"].as_u64().ok_or_else(|| fail("status.seq_out missing after reboot"))?;
    ctx.measure("seq_out_before", before);
    ctx.measure("seq_out_after", after);
    ctx.measure("last_seq_sent_before", last_before);
    if dut.link.wait_event(m, "connected", Duration::from_secs(20), |_| true).await.is_none() {
        dut.connect().await?;
    }
    let r = dut.ok("send_telemetry", json!({"count": 1})).await?;
    let first_after = r["first_seq"].as_u64().unwrap_or(0);
    ctx.measure("first_seq_sent_after", first_after);
    ensure(first_after > last_before, format!("a seq was reused after the reboot ({first_after} <= {last_before})"))?;
    // Wire-level: every verified telemetry uplink has a strictly larger seq than the previous one.
    let seqs = util::wait_for(Duration::from_secs(10), || {
        let mut s: Vec<u64> =
            ctx.verified_uplinks(dut.id(), "/telemetry").ok()?.into_iter().filter_map(Result::ok).map(|v| v.message.seq).collect();
        let mut seen = std::collections::HashSet::new();
        s.retain(|x| seen.insert(*x)); // QoS 1 duplicates are legal
        s.contains(&first_after).then_some(s)
    })
    .await
    .unwrap_or_default();
    ctx.evidence(format!("telemetry seqs on the wire: {seqs:?}"));
    ensure(seqs.windows(2).all(|w| w[1] > w[0]), "uplink seqs on the wire are not strictly increasing")?;
    ensure(after > before, format!("status.seq_out after reboot ({after}) is not greater than before ({before})"))?;
    Ok(Outcome::Pass)
}
