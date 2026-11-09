//! C-CFG-1: encrypted config delivery (sign-then-encrypt, HPKE to the device certificate key,
//! retained on the broker as COSE_Encrypt0 only).

use std::time::Duration;

use anyhow::Result;
use ironmesh_agent::wire::cbor::{DecodeLimits, Value};
use ironmesh_agent::wire::cose;
use ironmesh_agent::wire::ids::TopicClass;

use super::{brief, ensure, fail, online, Ctx, Outcome};
use crate::harness::{downlink, pki};

/// C-CFG-1.
pub async fn cfg_1(ctx: &Ctx) -> Result<Outcome> {
    if let Some(why) = ctx.cloud.bundle_limits() {
        return Ok(Outcome::NotApplicable(why));
    }
    let broker = ctx.cloud.broker("retained-copy inspection")?;
    let dut = ctx.launch().await?;
    online(ctx, &dut).await?;
    let serial = dut.cert_serial().await?;
    let cert = pki::cert_facts(&ctx.cloud.certificate(&serial).await?)?;
    let marker = "conformance-cfg-marker";
    let settings = vec![("log_level".to_string(), Value::text("info")), ("note".to_string(), Value::text(marker))];
    let inner = ctx.cloud.signer.sign(downlink::config_body(7, settings), None)?;
    let wrapped = downlink::wrap_config(&inner.wire, &cert.public_key_raw)?;
    let topic = ctx.cloud.topic(dut.id(), TopicClass::Config)?;
    let m = dut.mark();
    let n = ctx.cloud.inject(dut.id(), TopicClass::Config, wrapped.clone(), true).await?;
    ensure(n > 0, "the config was not delivered (no subscription on config)")?;
    ctx.evidence(format!(
        "Config v7 (tenant-signed, seq {}) HPKE-wrapped to the certificate key of {serial}, published retained",
        inner.message.seq
    ));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let rej = dut.link.named_since(m, "message_rejected");
    ensure(rej.is_empty(), format!("the config was rejected: {}", rej.iter().map(|e| brief(&e.data)).collect::<Vec<_>>().join(", ")))?;
    if let Some(a) = dut.link.named_since(m, "config_applied").first() {
        ctx.evidence(format!("config_applied {}", brief(&a.data)));
    }
    // Acceptance proof that works for every target: the same ciphertext again is a replay, which
    // is only possible if the first copy was decrypted, verified and recorded.
    let m = dut.mark();
    ctx.cloud.inject(dut.id(), TopicClass::Config, wrapped.clone(), false).await?;
    let e = dut
        .link
        .wait_event(m, "message_rejected", Duration::from_secs(10), |_| true)
        .await
        .ok_or_else(|| fail("re-delivery of the applied config was not rejected as a replay"))?;
    ctx.evidence(format!("re-delivery: message_rejected {}", brief(&e.data)));
    ensure(
        e.data["code"] == "ENV_REPLAY",
        format!("re-delivery rejected with {} (expected ENV_REPLAY: the first copy was not applied)", e.data["code"]),
    )?;
    ctx.measure("applied", "yes (replay of the same ciphertext rejected with ENV_REPLAY)");
    // The retained copy is ciphertext only.
    let retained = broker.retained(&topic).ok_or_else(|| fail("no retained config on the broker"))?;
    let enc = cose::encrypt0_decode(&retained, DecodeLimits::default())
        .map_err(|e| fail(format!("retained copy is not a COSE_Encrypt0: {e}")))?;
    let leaks = [marker.as_bytes(), b"log_level", b"tenant-cmd-"].iter().any(|needle| retained.windows(needle.len()).any(|w| w == *needle));
    ctx.measure("retained_bytes", retained.len());
    ctx.measure("retained_ciphertext_bytes", enc.ciphertext.len());
    ensure(!leaks, "the retained copy contains plaintext of the config")?;
    ensure(retained == wrapped, "the retained copy differs from the published Encrypt0")?;
    // Negative control: the same config wrapped to another key cannot be opened.
    let other = p256::SecretKey::random(&mut rand::rngs::OsRng);
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let inner2 = ctx.cloud.signer.sign(downlink::config_body(8, vec![("log_level".to_string(), Value::text("info"))]), None)?;
    let wrong = downlink::wrap_config(&inner2.wire, other.public_key().to_encoded_point(false).as_bytes())?;
    let m = dut.mark();
    ctx.cloud.inject(dut.id(), TopicClass::Config, wrong, false).await?;
    let e = dut
        .link
        .wait_event(m, "message_rejected", Duration::from_secs(10), |_| true)
        .await
        .ok_or_else(|| fail("a config for another key was not rejected"))?;
    ctx.evidence(format!("config wrapped to a foreign key: message_rejected {}", brief(&e.data)));
    ensure(e.data["code"] == "HPKE_OPEN", format!("foreign-key config rejected with {} (expected HPKE_OPEN)", e.data["code"]))?;
    Ok(Outcome::Pass)
}
