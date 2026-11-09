//! C-ACL-1..3: topic ACLs, decided by the real policy service's Rego policy through the broker's
//! authz hook (`deny_action = disconnect`, as configured for EMQX).

use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine;
use ironmesh_agent::wire::ids::TopicClass;
use serde_json::json;

use super::{brief, ensure, fail, online, wait_reconnected, Ctx, Outcome};
use crate::dut::Dut;
use crate::harness::broker::ObsKind;
use crate::util;

/// Publish `topic` raw and report how it ended: `Ok(publish_result.ok)` or `Err("disconnected")`.
async fn probe_publish(ctx: &Ctx, dut: &Dut, topic: &str, retain: bool) -> Result<(String, Option<bool>)> {
    let broker = ctx.cloud.broker("broker-side ACL observation")?;
    let since = Instant::now();
    let m = dut.mark();
    let payload = base64::engine::general_purpose::STANDARD.encode(b"conformance-acl-probe");
    dut.ok("publish_raw", json!({"topic": topic, "payload_b64": payload, "qos": 1, "retain": retain})).await?;
    let e = dut.expect_any(m, &["publish_result", "disconnected"], Duration::from_secs(15)).await?;
    // Give a publish_result that follows a disconnect a moment to arrive.
    let r = dut.link.wait_event(m, "publish_result", Duration::from_millis(1500), |_| true).await;
    let ok = r.as_ref().map(|r| r.data["ok"] == true);
    let obs = broker.wait_obs(since, Duration::from_secs(5), |o| matches!(&o.kind, ObsKind::Publish { topic: t, .. } if t == topic)).await;
    let allowed = matches!(obs.as_ref().map(|o| &o.kind), Some(ObsKind::Publish { allowed: true, .. }));
    ctx.evidence(format!(
        "publish_raw {topic} retain={retain}: first event {} {}; publish_result {}; policy authz allowed={allowed}",
        e.name,
        brief(&e.data),
        r.map(|r| brief(&r.data)).unwrap_or_else(|| "(none)".into())
    ));
    ensure(obs.is_some(), format!("the broker never saw the PUBLISH to {topic}"))?;
    ensure(!allowed, format!("the policy service allowed the PUBLISH to {topic}"))?;
    // deny_action = disconnect: the broker closes the session after the denied PUBLISH.
    let dropped = broker
        .wait_obs(since, Duration::from_secs(3), |o| {
            matches!(&o.kind, ObsKind::Closed { client_id, cause: crate::harness::broker::CloseCause::DeniedPublish } if client_id == dut.id())
        })
        .await
        .is_some();
    if dropped {
        dut.link
            .wait_event(m, "disconnected", Duration::from_secs(10), |_| true)
            .await
            .ok_or_else(|| fail("the broker dropped the session but the DUT reported no `disconnected`"))?;
        wait_reconnected(ctx, dut, m, since, Duration::from_secs(20)).await?;
        Ok(("disconnected".into(), ok))
    } else {
        Ok(("publish_result".into(), ok))
    }
}
/// C-ACL-1.
pub async fn acl_1(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker-side ACL observation")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let other_device = util::new_device_id();
    let other_tenant = util::uuid4();
    let targets = vec![
        ctx.cloud.topic(&other_device, TopicClass::Telemetry)?,
        ctx.cloud.topic(&other_device, TopicClass::CmdAck)?,
        format!("im/v1/{other_tenant}/{}/telemetry", dut.id()),
        ctx.cloud.topic(dut.id(), TopicClass::CmdReq)?,
    ];
    for t in &targets {
        let (how, ok) = probe_publish(ctx, &dut, t, false).await?;
        ensure(ok != Some(true), format!("publish_result.ok=true for {t}"))?;
        ensure(broker.accepted_on_topic(t) == 0, format!("a subscriber of {t} would have received the message"))?;
        ctx.measure(&format!("outcome {t}"), how);
    }
    // Control: the device's own telemetry topic is accepted.
    let r = dut.ok("send_telemetry", json!({"count": 1})).await?;
    ensure(r["last_seq"].is_u64(), "send_telemetry failed on the own topic")?;
    let own = ctx.cloud.topic(dut.id(), TopicClass::Telemetry)?;
    util::wait_for(Duration::from_secs(10), || (broker.accepted_on_topic(&own) > 0).then_some(()))
        .await
        .ok_or_else(|| fail("control publish on the device's own telemetry topic was not accepted"))?;
    Ok(Outcome::Pass)
}

/// C-ACL-2.
pub async fn acl_2(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker-side ACL observation")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let t = &ctx.cloud.tenant_id;
    let other = util::new_device_id();
    let filters = vec![
        ctx.cloud.topic(&other, TopicClass::CmdReq)?,
        ctx.cloud.topic(&other, TopicClass::Config)?,
        format!("im/v1/{t}/#"),
        format!("im/v1/{t}/+/cmd/req"),
        format!("im/v1/{t}/{}/#", dut.id()),
        "#".to_string(),
        "$SYS/#".to_string(),
        "$share/bridge/im/v1/#".to_string(),
        ctx.cloud.topic(dut.id(), TopicClass::Telemetry)?,
    ];
    for f in &filters {
        let since = Instant::now();
        let m = dut.mark();
        dut.ok("subscribe_raw", json!({"topic": f})).await?;
        let e = dut.expect_any(m, &["subscribe_result", "disconnected"], Duration::from_secs(15)).await?;
        ctx.evidence(format!("subscribe_raw {f}: {} {}", e.name, brief(&e.data)));
        if e.name == "disconnected" {
            wait_reconnected(ctx, &dut, m, since, Duration::from_secs(20)).await?;
            ctx.warn(format!("the session dropped on SUBSCRIBE {f} (EMQX answers SUBACK 0x87)"));
        } else {
            ensure(e.data["granted"] == false, format!("subscribe_result.granted=true for {f}"))?;
            ctx.measure(&format!("reason_code {f}"), e.data["reason_code"].clone());
        }
        let obs =
            broker.wait_obs(since, Duration::from_secs(5), |o| matches!(&o.kind, ObsKind::Subscribe { filter, .. } if filter == f)).await;
        ensure(matches!(obs.map(|o| o.kind), Some(ObsKind::Subscribe { granted: false, .. })), format!("the broker granted {f}"))?;
    }
    // Control: the own command topic is granted.
    let own = ctx.cloud.topic(dut.id(), TopicClass::CmdReq)?;
    let m = dut.mark();
    dut.ok("subscribe_raw", json!({"topic": own})).await?;
    let e = dut.expect_event(m, "subscribe_result", Duration::from_secs(15)).await?;
    ensure(e.data["granted"] == true, format!("the device's own {own} was not granted: {}", e.data))?;
    Ok(Outcome::Pass)
}

/// C-ACL-3.
pub async fn acl_3(ctx: &Ctx) -> Result<Outcome> {
    let broker = ctx.cloud.broker("broker-side ACL observation")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let topic = ctx.cloud.topic(dut.id(), TopicClass::Telemetry)?;
    let (how, ok) = probe_publish(ctx, &dut, &topic, true).await?;
    ctx.measure("outcome", how);
    ensure(ok != Some(true), "publish_result.ok=true for a retained telemetry publish")?;
    ensure(broker.retained(&topic).is_none(), "the broker holds a retained telemetry message")?;
    // Retained is allowed only for cloud downlinks; the same flag on events/cmd/ack is refused too.
    let events = ctx.cloud.topic(dut.id(), TopicClass::Events)?;
    let (how2, ok2) = probe_publish(ctx, &dut, &events, true).await?;
    ctx.measure("outcome events (retained)", how2);
    ensure(ok2 != Some(true) && broker.retained(&events).is_none(), "retained publish on events accepted")?;
    Ok(Outcome::Pass)
}
