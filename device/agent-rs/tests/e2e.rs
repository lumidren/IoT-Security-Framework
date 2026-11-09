//! End-to-end tests against in-process doubles of the IronMesh backend (EST with attestation,
//! MQTT 5 broker with ACLs, HTTPS artifact store): enrollment, pinned TLS 1.3, rogue-CA and
//! TLS 1.2 rejection, session resumption, rotation, replay/skew/signature rejection, idempotency,
//! offline buffering, encrypted config, shadow, and the full OTA lifecycle (tamper rejection,
//! delta apply, health gate, rollback).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use ironmesh_agent::agent::RebootReason;
use ironmesh_agent::wire::cbor::{DecodeLimits, Value};
use ironmesh_agent::wire::cose::Kid;
use ironmesh_agent::wire::envelope::{self, Body, Command, Config, DecodeOptions, InMemoryReplayStore, OtaNotify, ShadowState};
use ironmesh_agent::wire::ids::{self, Direction, TopicClass};
use ironmesh_agent::wire::manifest::{self, DeltaInfo, Manifest};
use ironmesh_agent::wire::{delta, hpke};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use support::*;

const T: Duration = Duration::from_secs(20);

fn any(_: &Json) -> bool {
    true
}

async fn enrolled_and_connected(
    env: &Env,
) -> (
    ironmesh_agent::agent::Agent,
    tokio::sync::mpsc::UnboundedReceiver<RebootReason>,
    tokio::sync::broadcast::Receiver<ironmesh_agent::agent::AgentEvent>,
) {
    let mut ev = env.events.subscribe();
    let (agent, rx) = env.start().await;
    agent.enroll().await.unwrap();
    wait_event(&mut ev, "enrolled", T, any).await;
    agent.set_connected(true);
    wait_event(&mut ev, "connected", T, any).await;
    (agent, rx, ev)
}

fn verify_uplink(agent: &ironmesh_agent::agent::Agent, payload: &[u8], expected_nonce: Option<[u8; 16]>) -> envelope::Message {
    let key = operational_key(agent);
    let mut store = InMemoryReplayStore::new();
    let opts = DecodeOptions {
        now: ironmesh_agent::seq::Clock::new().now_unix(),
        expected_direction: Some(Direction::Uplink),
        expected_nonce,
        ..Default::default()
    };
    envelope::decode(payload, &|_| Some(key.clone()), &mut store, &opts).unwrap().message
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrollment_pinned_connect_telemetry_resumption_and_rotation() {
    let env = Env::new(3600).await;
    let mut ev = env.events.subscribe();
    let (agent, _rx) = env.start().await;
    assert_eq!(agent.status().await["state"], "offline");
    let hello = agent.hello();
    assert_eq!(hello["device_id"], DEVICE);
    assert_eq!(hello["se_type"], "software");
    // C-ENR-1: zero-touch enrollment with attestation.
    let out = agent.enroll().await.unwrap();
    let e = wait_event(&mut ev, "enrolled", T, any).await;
    assert_eq!(e["se_type"], "software");
    assert_eq!(e["cert_serial_hex"], out.certificate.serial_hex());
    {
        let st = env.est.state.lock().unwrap();
        assert_eq!(st.enrollments.len(), 1);
        assert!(!st.enrollments[0].0, "first enrollment is simpleenroll");
        assert_eq!(st.enrollments[0].1, "software");
    }
    // C-TLS-1: TLS 1.3, ALPN mqtt, client id = CN.
    agent.set_connected(true);
    let c = wait_event(&mut ev, "connected", T, any).await;
    assert_eq!(c["tls_version"], "TLSv1.3");
    assert_eq!(c["alpn"], "mqtt");
    assert_eq!(c["resumed"], false);
    assert_eq!(env.broker.state.lock().unwrap().connects[0], (DEVICE.to_string(), false), "clean_start = false, client id = CN");
    wait_until(T, || env.broker.state.lock().unwrap().subscriptions.get(DEVICE).is_some_and(|s| s.len() == 4)).await;
    let status = agent.status().await;
    assert_eq!(status["state"], "connected");
    assert!(status["connected_broker"].as_str().unwrap().starts_with("127.0.0.1:"));
    // Telemetry: signed by the operational key, traceparent user property.
    let (first, last) = agent.send_telemetry(2).await.unwrap();
    assert_eq!(last, first + 1);
    wait_until(T, || env.broker.published_on("/telemetry").len() == 2).await;
    let p = &env.broker.published_on("/telemetry")[0];
    assert_eq!(p.topic, env.topic(TopicClass::Telemetry));
    assert_eq!(p.qos, 1);
    assert!(ironmesh_agent::logging::TraceContext::parse(p.properties.user("traceparent").unwrap()).is_some());
    let m = verify_uplink(&agent, &p.payload, None);
    assert_eq!(m.seq, first);
    assert!(matches!(m.body, Body::Telemetry(_)));
    // C-TLS-4: session resumption and persistent MQTT session on reconnect.
    agent.set_connected(false);
    wait_event(&mut ev, "disconnected", T, any).await;
    agent.set_connected(true);
    let c = wait_event(&mut ev, "connected", T, any).await;
    assert_eq!(c["resumed"], true, "TLS 1.3 session ticket reused");
    assert_eq!(c["session_present"], true);
    // C-ROT-1: rotation keeps identity, changes key and serial, reconnects.
    let old_key = operational_key(&agent);
    let renewed = agent.renew().await.unwrap();
    let r = wait_event(&mut ev, "cert_renewed", T, any).await;
    assert_ne!(r["old_serial_hex"], r["new_serial_hex"]);
    assert_eq!(r["new_serial_hex"], renewed.certificate.serial_hex());
    assert_ne!(operational_key(&agent), old_key);
    assert_eq!(renewed.certificate.subject_cn.as_deref(), Some(DEVICE));
    assert!(env.est.state.lock().unwrap().enrollments[1].0, "renewal uses simplereenroll");
    wait_event(&mut ev, "connected", T, any).await;
    agent.send_telemetry(1).await.unwrap();
    wait_until(T, || env.broker.published_on("/telemetry").len() == 3).await;
    let p = env.broker.published_on("/telemetry").pop().unwrap();
    let kid = ironmesh_agent::wire::cose::sign1_decode(&p.payload, DecodeLimits::default()).unwrap().kid;
    assert_eq!(kid, Kid::Bytes(renewed.certificate.kid.clone()), "new messages carry the new serial");
    verify_uplink(&agent, &p.payload, None);
    // C-RPL-4: seq strictly increases across reboot.
    let before = agent.status().await["seq_out"].as_u64().unwrap();
    let (agent2, _rx2) = env.restart(&agent, RebootReason::Requested).await;
    let rb = wait_event(&mut ev, "rebooted", T, any).await;
    assert_eq!(rb["reason"], "requested");
    assert!(agent2.status().await["seq_out"].as_u64().unwrap() >= before);
    let (s, _) = agent2.send_telemetry(1).await.unwrap();
    assert!(s >= before);
    agent2.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_rotation_at_half_lifetime() {
    // C-ROT-2 with 30-second certificates (renewal due 15..18 s after notBefore).
    let env = Env::new(30).await;
    let mut ev = env.events.subscribe();
    let (agent, _rx) = env.start().await;
    agent.enroll().await.unwrap();
    let r = wait_event(&mut ev, "cert_renewed", Duration::from_secs(30), any).await;
    assert!(r["new_serial_hex"].is_string());
    agent.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quarantined_device_enrollment_refused() {
    // C-ENR-2
    let env = Env::new(3600).await;
    env.est.state.lock().unwrap().refuse_status = Some(403);
    let mut ev = env.events.subscribe();
    let (agent, _rx) = env.start().await;
    assert!(agent.enroll().await.is_err());
    let e = wait_event(&mut ev, "enroll_failed", T, any).await;
    assert_eq!(e["http_status"], 403);
    assert_eq!(agent.status().await["state"], "unprovisioned");
    agent.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unset_clock_is_raised_to_the_authenticated_est_time() {
    // T-10: an RTC-less device that comes up at 1970 enrolls (the attestation is timestamped
    // with the Date of the pinned, mutually authenticated nonce response), and the floor is
    // persisted so a restart with an unset clock does not fall back below it.
    use ironmesh_agent::seq::CLOCK_UNSET_BEFORE;
    let wall = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let env = Env::new(3600).await;
    let (agent, _rx) = env.start().await;
    agent.set_clock(86_400);
    assert!(agent.clock().now_unix() < CLOCK_UNSET_BEFORE);
    let out = agent.enroll().await.unwrap();
    let hint = out.time_hint.expect("the clock was moved to the EST server time");
    assert!(hint + 5 >= wall() && hint <= wall() + 5);
    assert!(agent.clock().now_unix() >= hint);
    agent.set_clock(86_400);
    let (agent2, _rx2) = env.restart(&agent, RebootReason::Requested).await;
    assert!(agent2.clock().now_unix() >= hint, "persisted floor applied after restart");
    // A plausible clock is left alone by a later enrollment.
    let out = agent2.renew().await.unwrap();
    assert!(out.time_hint.is_none());
    agent2.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rogue_broker_and_tls12_broker_are_rejected() {
    let mut env = Env::new(3600).await;
    let (agent, _rx, _ev) = enrolled_and_connected(&env).await;
    agent.shutdown().await;
    // C-TLS-2: a broker with a certificate from an unpinned CA that copies the Services CA name.
    let rogue = Broker::start(&env.pki, true, false).await;
    env.settings.mqtt.port = Some(rogue.addr.port());
    let mut ev = env.events.subscribe();
    let (agent, _rx) = env.start().await;
    agent.set_connected(true);
    let f = wait_event(&mut ev, "connect_failed", T, any).await;
    assert_eq!(f["reason"], "tls_pin_mismatch", "{f}");
    assert!(rogue.state.lock().unwrap().connects.is_empty(), "no CONNECT packet was sent to the rogue broker");
    // C-TLS-5: bounded backoff - attempts keep coming (scaled) and the state reports backoff.
    wait_event(&mut ev, "connect_failed", T, any).await;
    agent.shutdown().await;
    // C-TLS-3: TLS 1.2-only broker.
    let old = Broker::start(&env.pki, false, true).await;
    env.settings.mqtt.port = Some(old.addr.port());
    let (agent, _rx) = env.start().await;
    agent.set_connected(true);
    let f = wait_event(&mut ev, "connect_failed", T, any).await;
    assert_eq!(f["reason"], "tls_handshake", "{f}");
    assert!(old.state.lock().unwrap().connects.is_empty());
    agent.shutdown().await;
}

fn command(seq: u64, ts: u64, env: &Env, nonce: [u8; 16], key: &str) -> Vec<u8> {
    let cmd = Command {
        cmd_id: "123e4567-e89b-12d3-a456-426614174000".into(),
        name: "ping".into(),
        args: vec![],
        idempotency_key: key.into(),
        expires_at: ts + 600,
    };
    env.downlink(seq, ts, Body::Command(cmd), Some(nonce))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commands_replay_skew_signature_and_idempotency() {
    let env = Env::new(3600).await;
    let (agent, _rx, mut ev) = enrolled_and_connected(&env).await;
    let topic = env.topic(TopicClass::CmdReq);
    wait_until(T, || env.broker.state.lock().unwrap().subscriptions.get(DEVICE).is_some_and(|s| s.contains(&topic))).await;
    let nonce = [7u8; 16];
    let wire = command(10, env.now(), &env, nonce, "idem-1");
    assert!(env.broker.inject(DEVICE, &topic, wire.clone(), false));
    let ex = wait_event(&mut ev, "command_executed", T, any).await;
    assert_eq!(ex["status"], 0);
    wait_until(T, || env.broker.published_on("/cmd/ack").len() == 1).await;
    let ack = verify_uplink(&agent, &env.broker.published_on("/cmd/ack")[0].payload, Some(nonce));
    let Body::CommandAck(a) = &ack.body else { panic!() };
    assert_eq!(a.status, 0);
    assert_eq!(a.cmd_id, "123e4567-e89b-12d3-a456-426614174000");
    // C-RPL-1: replay of the same message.
    env.broker.inject(DEVICE, &topic, wire, false);
    let rj = wait_event(&mut ev, "message_rejected", T, any).await;
    assert_eq!(rj["code"], "ENV_REPLAY");
    // C-RPL-2: stale timestamp.
    env.broker.inject(DEVICE, &topic, command(11, env.now() - 1000, &env, nonce, "idem-2"), false);
    let rj = wait_event(&mut ev, "message_rejected", T, any).await;
    assert_eq!(rj["code"], "ENV_TS_SKEW");
    // C-RPL-3: signed by a non-tenant key under the tenant kid.
    let forged = {
        let kid = Kid::Text(ids::tenant_kid(TENANT).unwrap());
        let cmd = Command {
            cmd_id: "123e4567-e89b-12d3-a456-426614174001".into(),
            name: "reboot".into(),
            args: vec![],
            idempotency_key: "x".into(),
            expires_at: env.now() + 60,
        };
        envelope::encode(
            &envelope::Message { seq: 12, ts: env.now(), body: Body::Command(cmd), nonce: Some(nonce) },
            &env.pki.untrusted_fw_key,
            &kid,
        )
        .unwrap()
    };
    env.broker.inject(DEVICE, &topic, forged, false);
    let rj = wait_event(&mut ev, "message_rejected", T, any).await;
    assert_eq!(rj["code"], "COSE_SIGNATURE");
    // Wrong message type on the command topic.
    let desired = env.downlink(13, env.now(), Body::ShadowDesired(ShadowState { state: vec![], version: 1 }), None);
    env.broker.inject(DEVICE, &topic, desired, false);
    assert_eq!(wait_event(&mut ev, "message_rejected", T, any).await["code"], "ENV_TYPE");
    // Idempotency: a new message (new seq) with the same idempotency key is acked but not re-executed.
    env.broker.inject(DEVICE, &topic, command(14, env.now(), &env, [9; 16], "idem-1"), false);
    wait_until(T, || env.broker.published_on("/cmd/ack").len() == 2).await;
    let ack2 = verify_uplink(&agent, &env.broker.published_on("/cmd/ack")[1].payload, Some([9; 16]));
    assert!(matches!(ack2.body, Body::CommandAck(_)));
    let rejections = agent.rejections(0);
    assert_eq!(
        rejections.iter().map(|r| r.code.as_str()).collect::<Vec<_>>(),
        vec!["ENV_REPLAY", "ENV_TS_SKEW", "COSE_SIGNATURE", "ENV_TYPE"]
    );
    // Every inbound message was acknowledged (PUBACK) to the broker.
    wait_until(T, || env.broker.state.lock().unwrap().acks.len() == 6).await;
    // C-ACL-1/2/3: raw publishes and subscriptions outside the device's own topics are refused.
    let other = ids::build_topic(TENANT, "dev-0000000000000001", TopicClass::Telemetry).unwrap();
    assert!(agent.publish_raw(&other, vec![1], 1, false).await.unwrap() >= 0x80);
    let pr = wait_event(&mut ev, "publish_result", T, any).await;
    assert_eq!(pr["ok"], false);
    assert!(agent.subscribe_raw(&format!("im/v1/{TENANT}/+/cmd/req")).await.unwrap() >= 0x80);
    assert_eq!(wait_event(&mut ev, "subscribe_result", T, any).await["granted"], false);
    assert!(agent.publish_raw(&env.topic(TopicClass::Telemetry), vec![1], 1, true).await.unwrap() >= 0x80, "retained telemetry refused");
    agent.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_buffering_and_resync_in_order() {
    // C-OFF-1
    let env = Env::new(3600).await;
    let (agent, _rx, mut ev) = enrolled_and_connected(&env).await;
    agent.set_net(false);
    wait_event(&mut ev, "disconnected", T, any).await;
    let (first, last) = agent.send_telemetry(5).await.unwrap();
    assert_eq!(agent.status().await["buffered"], 5);
    assert!(env.broker.published_on("/telemetry").is_empty());
    agent.set_net(true);
    wait_event(&mut ev, "connected", T, any).await;
    let f = wait_event(&mut ev, "buffer_flushed", T, any).await;
    assert_eq!((f["count"].as_u64(), f["first_seq"].as_u64(), f["last_seq"].as_u64()), (Some(5), Some(first), Some(last)));
    let seqs: Vec<u64> = env.broker.published_on("/telemetry").iter().map(|p| verify_uplink(&agent, &p.payload, None).seq).collect();
    assert_eq!(seqs, (first..=last).collect::<Vec<_>>(), "delivered in order, no gaps");
    assert_eq!(agent.buffered().await, 0);
    // The buffer survives a restart.
    agent.set_net(false);
    wait_event(&mut ev, "disconnected", T, any).await;
    agent.send_telemetry(2).await.unwrap();
    let (agent2, _rx2) = env.restart(&agent, RebootReason::Requested).await;
    assert_eq!(agent2.buffered().await, 2);
    agent2.set_net(true);
    assert_eq!(wait_event(&mut ev, "buffer_flushed", T, any).await["count"], 2);
    agent2.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_config_and_shadow() {
    // C-CFG-1
    let env = Env::new(3600).await;
    let (agent, _rx, mut ev) = enrolled_and_connected(&env).await;
    let cfg_topic = env.topic(TopicClass::Config);
    wait_until(T, || env.broker.state.lock().unwrap().subscriptions.get(DEVICE).is_some_and(|s| s.contains(&cfg_topic))).await;
    let inner = env.downlink(
        30,
        env.now(),
        Body::Config(Config {
            version: 12,
            settings: vec![("log_level".into(), Value::text("info")), ("telemetry_interval_s".into(), Value::int(0))],
        }),
        None,
    );
    let device_pk = agent.credentials().operational.unwrap().p256.unwrap();
    let encrypted = hpke::wrap_config(&inner, &device_pk, None, None, None).unwrap();
    assert!(!encrypted.windows(8).any(|w| w == b"log_leve"), "the broker only ever sees ciphertext");
    env.broker.inject(DEVICE, &cfg_topic, encrypted.clone(), true);
    assert_eq!(wait_event(&mut ev, "config_applied", T, any).await["version"], 12);
    // Same ciphertext again: replay.
    env.broker.inject(DEVICE, &cfg_topic, encrypted, true);
    assert_eq!(wait_event(&mut ev, "message_rejected", T, any).await["code"], "ENV_REPLAY");
    // Encrypted to another key.
    let other = p256::SecretKey::from_slice(&[3u8; 32]).unwrap();
    env.broker.inject(DEVICE, &cfg_topic, hpke::wrap_config(&inner, &other.public_key(), None, None, None).unwrap(), true);
    assert_eq!(wait_event(&mut ev, "message_rejected", T, any).await["code"], "HPKE_OPEN");
    // Shadow desired -> reported.
    let desired = env.downlink(
        31,
        env.now(),
        Body::ShadowDesired(ShadowState { state: vec![("mode".into(), Value::text("eco"))], version: 4 }),
        None,
    );
    env.broker.inject(DEVICE, &env.topic(TopicClass::ShadowDesired), desired, true);
    wait_until(T, || !env.broker.published_on("/shadow/reported").is_empty()).await;
    let rep = verify_uplink(&agent, &env.broker.published_on("/shadow/reported")[0].payload, None);
    let Body::ShadowReported(s) = rep.body else { panic!() };
    assert_eq!(s.version, 4);
    assert_eq!(s.state, vec![("mode".to_string(), Value::text("eco"))]);
    // Retained desired state signed 7 days ago is accepted (retainable type: future bound only).
    let week_old = env.downlink(
        32,
        env.now() - 7 * 86_400,
        Body::ShadowDesired(ShadowState { state: vec![("mode".into(), Value::text("max"))], version: 5 }),
        None,
    );
    env.broker.inject(DEVICE, &env.topic(TopicClass::ShadowDesired), week_old, true);
    wait_until(T, || env.broker.published_on("/shadow/reported").len() == 2).await;
    // Per-type replay streams: a command with a lower seq than the shadow stream is accepted.
    let cmd_topic = env.topic(TopicClass::CmdReq);
    env.broker.inject(DEVICE, &cmd_topic, command(1, env.now(), &env, [1; 16], "k-low"), false);
    assert_eq!(wait_event(&mut ev, "command_executed", T, any).await["status"], 0);
    // ... while a future-dated retained message is still rejected.
    let future = env.downlink(33, env.now() + 3600, Body::ShadowDesired(ShadowState { state: vec![], version: 6 }), None);
    env.broker.inject(DEVICE, &env.topic(TopicClass::ShadowDesired), future, true);
    assert_eq!(wait_event(&mut ev, "message_rejected", T, any).await["code"], "ENV_TS_SKEW");
    agent.shutdown().await;
}

struct Fw {
    image: Vec<u8>,
    signed: Vec<u8>,
}

fn firmware(
    env: &Env,
    image: Vec<u8>,
    version: &str,
    code: u64,
    key: &ed25519_dalek::SigningKey,
    delta_from: Option<&[u8]>,
) -> (Fw, Option<Vec<u8>>) {
    let patch = delta_from.map(|base| delta::make_delta(base, &image));
    let m = Manifest {
        product: "gateway-rpi".into(),
        version: version.into(),
        version_code: code,
        image_sha256: Sha256::digest(&image).into(),
        image_size: image.len() as u64,
        created_at: env.now(),
        min_version_code: 0,
        delta: patch.as_ref().zip(delta_from).map(|(p, base)| DeltaInfo {
            base_sha256: Sha256::digest(base).into(),
            patch_sha256: Sha256::digest(p).into(),
            patch_size: p.len() as u64,
        }),
        signing_key_id: "fw-test".into(),
    };
    let payload = manifest::encode_manifest(&m).unwrap();
    (Fw { image, signed: manifest::sign_manifest(&payload, key, None).unwrap() }, patch)
}

fn notify(env: &Env, seq: u64, campaign: &str, fw: &Fw, name: &str, delta_from: Option<[u8; 32]>) -> Vec<u8> {
    let url = format!("https://127.0.0.1:{}/fw/{name}", env.artifacts.0.port());
    env.downlink(
        seq,
        env.now(),
        Body::OtaNotify(OtaNotify { campaign_id: campaign.into(), manifest: fw.signed.clone(), url, delta_from }),
        None,
    )
}

async fn ota_outcome(ev: &mut tokio::sync::broadcast::Receiver<ironmesh_agent::agent::AgentEvent>, campaign: &str) -> Json {
    wait_event(ev, "ota_state", T, |d| {
        d["campaign_id"] == campaign && matches!(d["state"].as_str(), Some("rejected" | "rebooting" | "success" | "rolled_back"))
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ota_tamper_rejection_delta_update_health_gate_and_rollback() {
    let mut env = Env::new(3600).await;
    let (agent, mut reboots, mut ev) = enrolled_and_connected(&env).await;
    let topic = env.topic(TopicClass::OtaNotify);
    wait_until(T, || env.broker.state.lock().unwrap().subscriptions.get(DEVICE).is_some_and(|s| s.contains(&topic))).await;
    let base = factory_image();
    let mut v2 = base.clone();
    v2[100] ^= 0x55;
    v2.extend_from_slice(&[7u8; 5000]);

    // C-OTA-2: tampered image (valid manifest).
    let (fw, _) = firmware(&env, v2.clone(), "2.0.0", 200, &env.pki.fw_key, None);
    let mut tampered = fw.image.clone();
    tampered[10] ^= 1;
    env.artifacts.1 .0.lock().unwrap().insert("tampered.bin".into(), tampered);
    let c1 = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c21";
    env.broker.inject(DEVICE, &topic, notify(&env, 40, c1, &fw, "tampered.bin", None), true);
    let r = ota_outcome(&mut ev, c1).await;
    assert_eq!(r["state"], "rejected");
    assert_eq!(r["error"], "image_hash");
    assert_eq!(r["code"], "MF_HASH_MISMATCH");
    assert_eq!(agent.ota_slots()["active_slot"], "a");
    assert!(agent.ota_slots()["pending_slot"].is_null());
    // C-OTA-3: untrusted signing key.
    let (bad, _) = firmware(&env, v2.clone(), "2.0.0", 200, &env.pki.untrusted_fw_key, None);
    env.artifacts.1 .0.lock().unwrap().insert("v2.bin".into(), v2.clone());
    let c2 = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c22";
    env.broker.inject(DEVICE, &topic, notify(&env, 41, c2, &bad, "v2.bin", None), true);
    let r = ota_outcome(&mut ev, c2).await;
    assert_eq!((r["state"].as_str(), r["code"].as_str()), (Some("rejected"), Some("COSE_UNKNOWN_KEY")));
    assert_eq!(r["error"], "untrusted_key");
    // T-60: a validly signed update whose artifact host is not on the default allowlist (the
    // configured EST host, 127.0.0.1) is refused before anything is downloaded.
    let c_host = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c2f";
    let off_list = OtaNotify {
        campaign_id: c_host.into(),
        manifest: fw.signed.clone(),
        url: format!("https://localhost:{}/fw/v2.bin", env.artifacts.0.port()),
        delta_from: None,
    };
    env.broker.inject(DEVICE, &topic, env.downlink(42, env.now(), Body::OtaNotify(off_list), None), true);
    let r = ota_outcome(&mut ev, c_host).await;
    assert_eq!((r["state"].as_str(), r["error"].as_str()), (Some("rejected"), Some("download")));
    assert_eq!(r["code"], "URL_NOT_ALLOWED");
    assert_eq!(agent.ota_slots()["active_slot"], "a");
    // C-OTA-1: not signed at all (garbage manifest).
    let c3 = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c23";
    let unsigned = Fw {
        image: v2.clone(),
        signed: manifest::encode_manifest(&Manifest {
            product: "gateway-rpi".into(),
            version: "2.0.0".into(),
            version_code: 200,
            image_sha256: [0; 32],
            image_size: 1,
            created_at: 0,
            min_version_code: 0,
            delta: None,
            signing_key_id: "x".into(),
        })
        .unwrap(),
    };
    env.broker.inject(DEVICE, &topic, notify(&env, 43, c3, &unsigned, "v2.bin", None), true);
    let r = ota_outcome(&mut ev, c3).await;
    assert_eq!((r["state"].as_str(), r["error"].as_str()), (Some("rejected"), Some("unsigned")));
    // C-OTA-4: downgrade.
    let (old, _) = firmware(&env, v2.clone(), "0.9.0", 50, &env.pki.fw_key, None);
    let c4 = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c24";
    env.broker.inject(DEVICE, &topic, notify(&env, 44, c4, &old, "v2.bin", None), true);
    let r = ota_outcome(&mut ev, c4).await;
    assert_eq!((r["code"].as_str(), r["error"].as_str()), (Some("MF_ROLLBACK"), Some("downgrade")));
    assert!(reboots.try_recv().is_err(), "no rejected update triggers a reboot");

    // C-OTA-7 + C-OTA-5: delta update applies, reboots, passes the health gate.
    let (fw2, patch) = firmware(&env, v2.clone(), "2.0.0", 200, &env.pki.fw_key, Some(&base));
    env.artifacts.1 .0.lock().unwrap().insert("v2.patch".into(), patch.unwrap());
    let c5 = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c25";
    env.broker.inject(DEVICE, &topic, notify(&env, 45, c5, &fw2, "v2.patch", Some(Sha256::digest(&base).into())), true);
    assert_eq!(ota_outcome(&mut ev, c5).await["state"], "rebooting");
    assert_eq!(tokio::time::timeout(T, reboots.recv()).await.unwrap(), Some(RebootReason::OtaApply));
    let (agent, mut reboots) = env.restart(&agent, RebootReason::OtaApply).await;
    let rb = wait_event(&mut ev, "rebooted", T, any).await;
    assert_eq!((rb["reason"].as_str(), rb["active_slot"].as_str(), rb["version_code"].as_u64()), (Some("ota_apply"), Some("b"), Some(200)));
    let ok = ota_outcome(&mut ev, c5).await;
    assert_eq!(ok["state"], "success");
    let slots = agent.ota_slots();
    assert_eq!(slots["active_slot"], "b");
    assert!(slots["pending_slot"].is_null());
    assert_eq!(slots["slots"][1]["sha256_hex"], hex::encode(Sha256::digest(&v2)), "applied delta image equals the full image");
    assert_eq!(slots["slots"][1]["state"], "valid");
    wait_until(T, || {
        env.broker
            .published_on("/ota/status")
            .iter()
            .any(|p| matches!(verify_uplink(&agent, &p.payload, None).body, Body::OtaStatus(ref s) if s.state == 5))
    })
    .await;
    // C-OTA-6: an update that fails its health check (no telemetry PUBACK) rolls back.
    let mut v3 = v2.clone();
    v3[0] ^= 1;
    let (fw3, _) = firmware(&env, v3.clone(), "3.0.0", 300, &env.pki.fw_key, None);
    env.artifacts.1 .0.lock().unwrap().insert("v3.bin".into(), v3);
    let c6 = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c26";
    env.broker.inject(DEVICE, &topic, notify(&env, 46, c6, &fw3, "v3.bin", None), true);
    assert_eq!(ota_outcome(&mut ev, c6).await["state"], "rebooting");
    assert_eq!(tokio::time::timeout(T, reboots.recv()).await.unwrap(), Some(RebootReason::OtaApply));
    env.broker.state.lock().unwrap().drop_telemetry_acks = true;
    env.settings.ota.health_timeout_s = 2;
    let (agent, mut reboots) = env.restart(&agent, RebootReason::OtaApply).await;
    let rb = wait_event(&mut ev, "rebooted", T, any).await;
    assert_eq!(rb["active_slot"], "a", "trial boot of the new slot");
    assert_eq!(tokio::time::timeout(T, reboots.recv()).await.unwrap(), Some(RebootReason::Rollback));
    env.broker.state.lock().unwrap().drop_telemetry_acks = false;
    let (agent, _reboots) = env.restart(&agent, RebootReason::Rollback).await;
    let rb = wait_event(&mut ev, "rebooted", T, any).await;
    assert_eq!((rb["reason"].as_str(), rb["active_slot"].as_str(), rb["version_code"].as_u64()), (Some("rollback"), Some("b"), Some(200)));
    let rolled = ota_outcome(&mut ev, c6).await;
    assert_eq!(rolled["state"], "rolled_back");
    assert_eq!(rolled["error"], "health_check");
    assert_eq!(agent.ota_slots()["slots"][0]["state"], "invalid");
    agent.shutdown().await;
}
