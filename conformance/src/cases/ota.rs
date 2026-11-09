//! C-OTA-1..7: signed A/B updates. The artifact server serves unsigned, tampered, untrusted-key,
//! downgrade, delta and valid images; the health-failing update is a valid image whose new boot
//! cannot reach the broker (the contract health check is "MQTT connected + telemetry acked"), so
//! the device must roll back on its own.

use std::time::Duration;

use anyhow::Result;
use ironmesh_agent::wire::envelope::Body;
use ironmesh_agent::wire::ids::TopicClass;
use serde_json::{json, Value};

use super::{brief, ensure, fail, online, wait_reconnected, Ctx, Outcome};
use crate::dut::Dut;
use crate::harness::downlink;
use crate::harness::ota::{self, Artifact, BuildSpec, Variant};
use crate::util;

const FINAL_STATES: [&str; 3] = ["success", "rejected", "rolled_back"];

struct Sent {
    campaign: String,
    url: String,
    mark: usize,
}

fn active_slot(slots: &Value) -> (String, String) {
    let active = slots["active_slot"].as_str().unwrap_or_default().to_owned();
    let sha = slots["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["name"] == active.as_str()))
        .and_then(|s| s["sha256_hex"].as_str())
        .unwrap_or_default()
        .to_owned();
    (active, sha)
}

/// The image the update starts from (the running factory image when the harness knows it).
async fn base_image(ctx: &Ctx, dut: &Dut) -> Result<Option<Vec<u8>>> {
    let slots = dut.ok("ota_slots", json!({})).await?;
    let (_, sha) = active_slot(&slots);
    Ok(ctx.profile.factory_image.clone().filter(|img| hex::encode(ota::sha256(img)) == sha))
}

async fn send(ctx: &Ctx, dut: &Dut, art: &Artifact) -> Result<Sent> {
    let url = ctx.cloud.host_artifact(art.served.clone())?;
    let campaign = util::uuid4();
    let dl = ctx.cloud.signer.sign(downlink::ota_notify_body(&campaign, art.notify_manifest.clone(), &url, art.delta_from), None)?;
    let mark = dut.mark();
    let n = ctx.cloud.inject(dut.id(), TopicClass::OtaNotify, dl.wire, false).await?;
    ensure(n > 0, "the OtaNotify was not delivered (no subscription on ota/notify)")?;
    ctx.evidence(format!(
        "OtaNotify campaign {campaign}: version_code {}, image {} B sha256 {}, served {} B{}",
        art.manifest.version_code,
        art.image.len(),
        hex::encode(art.manifest.image_sha256),
        art.served.len(),
        if art.delta_from.is_some() { " (IMDELTA1 patch)" } else { "" }
    ));
    Ok(Sent { campaign, url, mark })
}

async fn wait_final(dut: &Dut, s: &Sent, timeout: Duration) -> Result<crate::dut::Event> {
    let c = s.campaign.clone();
    dut.link
        .wait_event(s.mark, "ota_state", timeout, move |d| {
            d["campaign_id"] == c.as_str() && FINAL_STATES.contains(&d["state"].as_str().unwrap_or(""))
        })
        .await
        .ok_or_else(|| {
            let seen: Vec<String> = dut.link.named_since(s.mark, "ota_state").iter().map(|e| brief(&e.data)).collect();
            fail(format!("no final ota_state for campaign {} within {timeout:?}; ota_state events: {seen:?}", s.campaign))
        })
}

fn states(dut: &Dut, s: &Sent) -> Vec<String> {
    dut.link
        .named_since(s.mark, "ota_state")
        .iter()
        .filter(|e| e.data["campaign_id"] == s.campaign.as_str())
        .map(|e| {
            format!(
                "{}{}",
                e.data["state"].as_str().unwrap_or("?"),
                e.data["error"].as_str().filter(|x| !x.is_empty()).map(|x| format!("({x})")).unwrap_or_default()
            )
        })
        .collect()
}

/// OtaStatus uplinks of a campaign seen by the broker (verified signatures): `(state, error)`.
fn status_uplinks(ctx: &Ctx, dut: &Dut, campaign: &str) -> Vec<(u8, Option<String>, Option<[u8; 32]>)> {
    ctx.verified_uplinks(dut.id(), "/ota/status")
        .unwrap_or_default()
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|v| match v.message.body {
            Body::OtaStatus(s) if s.campaign_id == campaign => Some((s.state, s.error, s.fw_hash)),
            _ => None,
        })
        .collect()
}

fn spec<'a>(ctx: &'a Ctx, image: Vec<u8>, version_code: u64, base: Option<&'a [u8]>) -> BuildSpec<'a> {
    BuildSpec {
        product: &ctx.profile.product,
        version: "1.1.0",
        version_code,
        image,
        base,
        key: &ctx.cloud.keys.firmware,
        untrusted: &ctx.cloud.keys.untrusted_firmware,
    }
}

async fn rejection(ctx: &Ctx, variant: Variant, canonical_error: &str, error_required: bool) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let before = dut.ok("ota_slots", json!({})).await?;
    let vc = dut.status().await?["version_code"].as_u64().unwrap_or(dut.info.fw_version_code);
    let base = base_image(ctx, &dut).await?.unwrap_or_else(|| ota::firmware_image(1, 40_000));
    let image = ota::mutate_image(&base, 0x31, 512);
    let target_vc = if variant == Variant::Downgrade { vc } else { vc + 1 };
    let art = ota::build(variant, &spec(ctx, image, target_vc, None))?;
    let s = send(ctx, &dut, &art).await?;
    let e = wait_final(&dut, &s, Duration::from_secs(60)).await?;
    ctx.evidence(format!("ota_state sequence: {:?}", states(&dut, &s)));
    ctx.measure("final_state", e.data["state"].as_str().unwrap_or("?"));
    ctx.measure("error", e.data["error"].as_str().unwrap_or(""));
    ctx.measure("artifact_downloads", ctx.cloud.hermetic("").map(|h| h.artifacts.downloads(&s.url)).unwrap_or(0));
    ensure(e.data["state"] == "rejected", format!("final ota_state {} (expected rejected)", brief(&e.data)))?;
    let err = e.data["error"].as_str().unwrap_or_default();
    if err != canonical_error {
        if error_required {
            return Err(fail(format!("ota_state.error = {err:?} (expected {canonical_error:?})")));
        }
        ctx.warn(format!("ota_state.error = {err:?}; DUT_PROTOCOL's vocabulary suggests {canonical_error:?} for this case"));
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after = dut.ok("ota_slots", json!({})).await?;
    ctx.evidence(format!("ota_slots before {} after {}", brief(&before), brief(&after)));
    ensure(active_slot(&after) == active_slot(&before), "the active slot changed")?;
    ensure(after["pending_slot"].is_null(), format!("a slot is pending: {}", after["pending_slot"]))?;
    ensure(dut.link.named_since(s.mark, "rebooted").is_empty(), "the DUT rebooted")?;
    ensure(dut.status().await?["version_code"].as_u64() == Some(vc), "version_code changed")?;
    let ups = status_uplinks(ctx, &dut, &s.campaign);
    ctx.evidence(format!("signed OtaStatus uplinks (state, error): {:?}", ups.iter().map(|u| (u.0, u.1.clone())).collect::<Vec<_>>()));
    if !ups.iter().any(|u| u.0 == 7) {
        ctx.warn("no signed OtaStatus{state=7 rejected} reached the broker");
    }
    Ok(Outcome::Pass)
}

/// C-OTA-1.
pub async fn ota_1(ctx: &Ctx) -> Result<Outcome> {
    rejection(ctx, Variant::Unsigned, "unsigned", false).await
}

/// C-OTA-2.
pub async fn ota_2(ctx: &Ctx) -> Result<Outcome> {
    rejection(ctx, Variant::Tampered, "image_hash", true).await
}

/// C-OTA-3.
pub async fn ota_3(ctx: &Ctx) -> Result<Outcome> {
    rejection(ctx, Variant::UntrustedKey, "untrusted_key", false).await
}

/// C-OTA-4.
pub async fn ota_4(ctx: &Ctx) -> Result<Outcome> {
    rejection(ctx, Variant::Downgrade, "downgrade", false).await
}

/// Apply a valid full (or delta) update and wait for success. Returns the applied image.
async fn apply(ctx: &Ctx, dut: &Dut, variant: Variant, base: Option<&[u8]>, salt: u8) -> Result<Vec<u8>> {
    let vc = dut.status().await?["version_code"].as_u64().unwrap_or(0);
    let from = match base {
        Some(b) => b.to_vec(),
        None => base_image(ctx, dut).await?.unwrap_or_else(|| ota::firmware_image(2, 40_000)),
    };
    let image = ota::mutate_image(&from, salt, 4096 + usize::from(salt));
    let art = ota::build(variant, &spec(ctx, image.clone(), vc + 1, base))?;
    let s = send(ctx, dut, &art).await?;
    let rb = dut.link.wait_event(s.mark, "rebooted", Duration::from_secs(90), |d| d["reason"] == "ota_apply").await;
    let e = wait_final(dut, &s, Duration::from_secs(ctx.profile.health_timeout_s + 60)).await?;
    ctx.evidence(format!("ota_state sequence: {:?}", states(dut, &s)));
    let rb = rb.ok_or_else(|| fail("no rebooted{reason=ota_apply}"))?;
    ctx.evidence(format!("rebooted {}", brief(&rb.data)));
    ensure(e.data["state"] == "success", format!("final ota_state {}", brief(&e.data)))?;
    ensure(
        rb.data["version_code"].as_u64() == Some(vc + 1),
        format!("rebooted.version_code {} (expected {})", rb.data["version_code"], vc + 1),
    )?;
    let st = dut.status().await?;
    ensure(st["version_code"].as_u64() == Some(vc + 1), format!("status.version_code {} (expected {})", st["version_code"], vc + 1))?;
    let slots = dut.ok("ota_slots", json!({})).await?;
    let (active, sha) = active_slot(&slots);
    ctx.evidence(format!("ota_slots after: {}", brief(&slots)));
    ensure(
        sha == hex::encode(ota::sha256(&image)),
        format!("active slot {active} sha256 {sha} != the full image's {}", hex::encode(ota::sha256(&image))),
    )?;
    if let Some(slot) = slots["slots"].as_array().and_then(|a| a.iter().find(|x| x["name"] == active.as_str())) {
        if slot["state"] != "valid" {
            ctx.warn(format!("active slot state {} after success (expected valid)", slot["state"]));
        }
    }
    let ups = util::wait_for(Duration::from_secs(10), || {
        let u = status_uplinks(ctx, dut, &s.campaign);
        u.iter().any(|x| x.0 == 5).then_some(u)
    })
    .await;
    match ups {
        Some(u) => {
            let ok = u.iter().find(|x| x.0 == 5).and_then(|x| x.2).map(|h| h == ota::sha256(&image)).unwrap_or(false);
            ctx.evidence(format!("signed OtaStatus{{state=5 success}} uplink, fw_hash matches the image: {ok}"));
        }
        None => ctx.warn("no signed OtaStatus{state=5} reached the broker"),
    }
    if variant == Variant::Delta {
        ctx.measure("patch_bytes", art.served.len());
        ctx.measure("image_bytes", art.image.len());
    }
    Ok(image)
}

/// C-OTA-5.
pub async fn ota_5(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let before = dut.ok("ota_slots", json!({})).await?;
    let image = apply(ctx, &dut, Variant::Valid, None, 0x51).await?;
    let after = dut.ok("ota_slots", json!({})).await?;
    ensure(active_slot(&after).0 != active_slot(&before).0, "the active slot did not switch")?;
    ctx.measure("new_version_code", dut.status().await?["version_code"].clone());
    ctx.measure("image_sha256", hex::encode(ota::sha256(&image)));
    Ok(Outcome::Pass)
}

/// C-OTA-6.
pub async fn ota_6(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let broker = ctx.cloud.broker("C-OTA-6 broker-side refusal after the update boot")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let before = dut.ok("ota_slots", json!({})).await?;
    let vc = dut.status().await?["version_code"].as_u64().unwrap_or(0);
    let base = base_image(ctx, &dut).await?.unwrap_or_else(|| ota::firmware_image(3, 40_000));
    let art = ota::build(Variant::Valid, &spec(ctx, ota::mutate_image(&base, 0x61, 700), vc + 1, None))?;
    // The live session survives; every CONNECT of the new image is refused.
    broker.refuse(dut.id(), Some(0x88));
    let s = send(ctx, &dut, &art).await?;
    let applied = dut.link.wait_event(s.mark, "rebooted", Duration::from_secs(90), |d| d["reason"] == "ota_apply").await;
    let rb = dut
        .link
        .wait_event(s.mark, "rebooted", Duration::from_secs(ctx.profile.health_timeout_s + 90), |d| d["reason"] == "rollback")
        .await;
    broker.refuse(dut.id(), None);
    let applied = applied.ok_or_else(|| fail("the update was never applied (no rebooted{reason=ota_apply})"))?;
    ctx.evidence(format!("rebooted {} then health check without broker access", brief(&applied.data)));
    let rb = rb.ok_or_else(|| {
        fail(format!("no rebooted{{reason=rollback}} within the health deadline ({} s) + 90 s", ctx.profile.health_timeout_s))
    })?;
    let rb_mark = dut.link.events_since(0).iter().position(|e| e.name == "rebooted" && e.data["reason"] == "rollback").unwrap_or(s.mark);
    ctx.evidence(format!("rebooted {}", brief(&rb.data)));
    let rolled = dut.link.wait_event(s.mark, "ota_state", Duration::from_secs(15), |d| d["state"] == "rolled_back").await;
    ctx.evidence(format!("ota_state sequence: {:?}", states(&dut, &s)));
    ensure(rb.data["version_code"].as_u64() == Some(vc), format!("rebooted.version_code {} (expected {vc})", rb.data["version_code"]))?;
    let after = dut.ok("ota_slots", json!({})).await?;
    ctx.evidence(format!("ota_slots before {} after {}", brief(&before), brief(&after)));
    ensure(active_slot(&after) == active_slot(&before), "the previous slot is not active")?;
    ensure(dut.status().await?["version_code"].as_u64() == Some(vc), "status.version_code is not the previous one")?;
    let rolled = rolled.ok_or_else(|| fail("no ota_state{state=rolled_back}"))?;
    ctx.measure("rollback_error", rolled.data["error"].as_str().unwrap_or(""));
    ctx.measure("seconds_apply_to_rollback", format!("{:.1}", rb.seen.saturating_duration_since(applied.seen).as_secs_f64()));
    // Back online, the device reports the rollback to the cloud.
    wait_reconnected(ctx, &dut, rb_mark, rb.seen, Duration::from_secs(30)).await?;
    let ups = util::wait_for(Duration::from_secs(10), || {
        let u = status_uplinks(ctx, &dut, &s.campaign);
        u.iter().any(|x| x.0 == 6).then_some(u)
    })
    .await;
    if ups.is_none() {
        ctx.warn("no signed OtaStatus{state=6 rolled_back} reached the broker after reconnecting");
    } else {
        ctx.evidence("signed OtaStatus{state=6 rolled_back} delivered after reconnecting");
    }
    Ok(Outcome::Pass)
}

/// C-OTA-7.
pub async fn ota_7(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let base = match base_image(ctx, &dut).await? {
        Some(b) => {
            ctx.evidence("delta base: the factory image (hash verified against ota_slots)");
            b
        }
        None => {
            ctx.evidence("delta base: a full update installed first (factory image unknown to the harness)");
            apply(ctx, &dut, Variant::Valid, None, 0x70).await?
        }
    };
    let image = apply(ctx, &dut, Variant::Delta, Some(&base), 0x71).await?;
    ctx.measure("applied_image_sha256", hex::encode(ota::sha256(&image)));
    Ok(Outcome::Pass)
}
