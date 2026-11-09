//! The fleet process of the load test (`ironmesh-conformance load-fleet --spec <file>`).
//!
//! Runs every simulated device in one tokio runtime, in a process of its own so its CPU and
//! memory can be measured apart from the cloud doubles and the policy service. Each device uses
//! the agent-rs device stack as a library: software identity on disk, EST enrollment with
//! attestation ([`ironmesh_agent::enroll`]), the pinned mTLS MQTT 5 client
//! ([`ironmesh_agent::mqtt`]), COSE_Sign1 telemetry from the fleet telemetry model
//! ([`ironmesh_agent::fleet::Model`]), downlink verification (tenant signature, timestamp,
//! replay) and command execution ([`ironmesh_agent::commands`]). The loop is
//! [`ironmesh_agent::fleet::run_device`] plus instrumentation (enroll / connect / publish->PUBACK
//! timings, error classes, last acknowledged `seq`) and the command path, which the plain fleet
//! simulator does not have.
//!
//! Control protocol with the orchestrator: one command per stdin line (`tick`, `phase <name>`,
//! `stop`); `tick` is answered with one [`FleetStatus`] JSON line on stdout. On `stop` (or stdin
//! EOF) every device disconnects, the [`FleetResult`] is written to the spec's `result_file` and
//! `{"done":true}` is printed.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ironmesh_agent::commands::{self, IdempotencyCache};
use ironmesh_agent::enroll::{self, Credentials, EnrollError, EnrollRequest};
use ironmesh_agent::est::EstError;
use ironmesh_agent::fleet::Model;
use ironmesh_agent::identity::software::{SecretSource, SoftwareIdentity};
use ironmesh_agent::identity::{IdentitySigner, KeySlot, SharedIdentity};
use ironmesh_agent::mqtt::codec::{Properties, Publish};
use ironmesh_agent::mqtt::{self, Backoff, MqttClient, MqttError, MqttOptions};
use ironmesh_agent::seq::{Clock, SeqCounter};
use ironmesh_agent::telemetry::FirmwareInfo;
use ironmesh_agent::tls::{self, ClientIdentity, PinnedVerifier};
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose::Kid;
use ironmesh_agent::wire::envelope::{self, Body, DecodeOptions, InMemoryReplayStore, Message, ReplayStore};
use ironmesh_agent::wire::ids::{self, Direction, TopicClass};
use ironmesh_agent::wire::keys::PublicKey;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::stats::{Recorder, Summary};

/// One device of the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Device id.
    pub id: String,
    /// Identity directory (software keys, bootstrap certificate).
    pub dir: PathBuf,
}

/// What the orchestrator hands the fleet process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSpec {
    /// Devices, in start order.
    pub devices: Vec<DeviceEntry>,
    /// Start offset of each device (ms after the fleet process is ready).
    pub schedule_ms: Vec<u64>,
    /// Factory trust anchors (PEM file).
    pub anchors_file: PathBuf,
    /// EST host.
    pub est_host: String,
    /// EST port.
    pub est_port: u16,
    /// Factory EST pins (hex SPKI SHA-256).
    pub est_pins_hex: Vec<String>,
    /// PKI bundle public key (hex Ed25519).
    pub bundle_pubkey_hex: String,
    /// Telemetry interval.
    pub interval_s: u64,
    /// Publish -> PUBACK timeout.
    pub publish_timeout_s: u64,
    /// TCP + TLS + CONNACK timeout.
    pub connect_timeout_s: u64,
    /// EST request timeout.
    pub est_timeout_s: u64,
    /// Reconnect / re-enroll backoff scale (1.0 = contract: base 1 s, cap 300 s, full jitter).
    pub backoff_scale: f64,
    /// Firmware version reported in telemetry and attestation.
    pub fw_version: String,
    /// Where to write the [`FleetResult`].
    pub result_file: PathBuf,
    /// Tokio worker threads (0: one per logical CPU).
    pub worker_threads: usize,
}

/// Answer to `tick`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetStatus {
    /// Milliseconds since the fleet process was ready.
    pub t_ms: u64,
    /// Device tasks started.
    pub started: u64,
    /// Devices with an operational certificate.
    pub enrolled: u64,
    /// Failed enrollment attempts.
    pub enroll_failures: u64,
    /// Devices with a live MQTT session (CONNACK + SUBACK).
    pub connected: u64,
    /// Devices that connected at least once.
    pub ever_connected: u64,
    /// Connection attempts.
    pub connect_attempts: u64,
    /// Failed connection attempts.
    pub connect_failures: u64,
    /// Telemetry PUBACKed with a success code.
    pub published_ok: u64,
    /// Telemetry answered with an error reason code.
    pub publish_errors: u64,
    /// Telemetry without PUBACK within the timeout.
    pub publish_timeouts: u64,
    /// Sessions lost after CONNACK.
    pub sessions_lost: u64,
    /// Commands received.
    pub cmds_received: u64,
    /// Commands verified and executed.
    pub cmds_executed: u64,
    /// Downlinks rejected by verification.
    pub downlink_rejected: u64,
    /// Every classified error.
    pub errors_total: u64,
    /// Telemetry publish -> PUBACK since the previous tick.
    pub publish_window: Summary,
    /// Connect (TCP + TLS 1.3 + CONNACK) since the previous tick.
    pub connect_window: Summary,
    /// Enrollment since the previous tick.
    pub enroll_window: Summary,
}

/// One error class.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorClass {
    /// Occurrences.
    pub count: u64,
    /// The first detail message.
    pub example: String,
}

/// Final per-device outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceOutcome {
    /// Device id.
    pub id: String,
    /// Enrolled.
    pub enrolled: bool,
    /// Successful connections.
    pub connects: u32,
    /// First CONNACK (ms after ready), 0 if never.
    pub first_connect_ms: u64,
    /// Highest uplink `seq` acknowledged by the broker with a success code (0: none).
    pub last_acked_seq: u64,
    /// Telemetry messages acknowledged.
    pub telemetry_acked: u64,
}

/// Written on stop.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetResult {
    /// Final counters.
    pub status: FleetStatus,
    /// Devices connected when `stop` arrived.
    pub connected_at_stop: u64,
    /// CommandAcks acknowledged by the broker.
    pub cmd_acks_published: u64,
    /// Errors by class.
    pub errors: BTreeMap<String, ErrorClass>,
    /// Enrollment latency (all).
    pub enroll_latency: Summary,
    /// Connect latency (all).
    pub connect_latency: Summary,
    /// Telemetry publish -> PUBACK, whole run.
    pub publish_latency_all: Summary,
    /// ... during the ramp.
    pub publish_latency_ramp: Summary,
    /// ... during the sustained window.
    pub publish_latency_sustain: Summary,
    /// Per device.
    pub devices: Vec<DeviceOutcome>,
}

#[derive(Default)]
struct DeviceState {
    enrolled: AtomicBool,
    connects: AtomicU32,
    first_connect_ms: AtomicU64,
    last_acked_seq: AtomicU64,
    telemetry_acked: AtomicU64,
}

const PHASE_RAMP: u8 = 0;
const PHASE_SUSTAIN: u8 = 1;
const PHASE_DRAIN: u8 = 2;

struct Shared {
    spec: FleetSpec,
    t0: Instant,
    phase: AtomicU8,
    devices: Vec<DeviceState>,
    started: AtomicU64,
    enrolled: AtomicU64,
    enroll_failures: AtomicU64,
    connected: AtomicU64,
    ever_connected: AtomicU64,
    connect_attempts: AtomicU64,
    connect_failures: AtomicU64,
    published_ok: AtomicU64,
    publish_errors: AtomicU64,
    publish_timeouts: AtomicU64,
    sessions_lost: AtomicU64,
    cmds_received: AtomicU64,
    cmds_executed: AtomicU64,
    cmd_acks_published: AtomicU64,
    downlink_rejected: AtomicU64,
    errors_total: AtomicU64,
    errors: Mutex<BTreeMap<String, ErrorClass>>,
    enroll_lat: Recorder,
    connect_lat: Recorder,
    publish_all: Recorder,
    publish_ramp: Recorder,
    publish_sustain: Recorder,
    bundle_key: Option<[u8; 32]>,
    est_pins: Vec<[u8; 32]>,
    fw_hash: [u8; 32],
}

impl Shared {
    fn new(spec: FleetSpec) -> Self {
        let bundle_key = hex::decode(&spec.bundle_pubkey_hex).ok().and_then(|b| b.try_into().ok());
        let est_pins = spec.est_pins_hex.iter().filter_map(|p| hex::decode(p).ok()).filter_map(|b| b.try_into().ok()).collect();
        let fw_hash: [u8; 32] =
            sha2::Digest::finalize(sha2::Digest::chain_update(sha2::Sha256::default(), spec.fw_version.as_bytes())).into();
        Self {
            devices: (0..spec.devices.len()).map(|_| DeviceState::default()).collect(),
            spec,
            t0: Instant::now(),
            phase: AtomicU8::new(PHASE_RAMP),
            started: AtomicU64::new(0),
            enrolled: AtomicU64::new(0),
            enroll_failures: AtomicU64::new(0),
            connected: AtomicU64::new(0),
            ever_connected: AtomicU64::new(0),
            connect_attempts: AtomicU64::new(0),
            connect_failures: AtomicU64::new(0),
            published_ok: AtomicU64::new(0),
            publish_errors: AtomicU64::new(0),
            publish_timeouts: AtomicU64::new(0),
            sessions_lost: AtomicU64::new(0),
            cmds_received: AtomicU64::new(0),
            cmds_executed: AtomicU64::new(0),
            cmd_acks_published: AtomicU64::new(0),
            downlink_rejected: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            errors: Mutex::new(BTreeMap::new()),
            enroll_lat: Recorder::new(),
            connect_lat: Recorder::new(),
            publish_all: Recorder::new(),
            publish_ramp: Recorder::new(),
            publish_sustain: Recorder::new(),
            bundle_key,
            est_pins,
            fw_hash,
        }
    }

    fn error(&self, class: &str, detail: &dyn std::fmt::Display) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
        let mut m = self.errors.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let e = m.entry(class.to_owned()).or_default();
        if e.count == 0 {
            e.example = detail.to_string().chars().take(300).collect();
        }
        e.count += 1;
    }

    fn record_publish(&self, d: Duration) {
        self.publish_all.record(d);
        match self.phase.load(Ordering::Relaxed) {
            PHASE_RAMP => self.publish_ramp.record(d),
            PHASE_SUSTAIN => self.publish_sustain.record(d),
            _ => {}
        }
    }

    fn status(&self) -> FleetStatus {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        FleetStatus {
            t_ms: u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX),
            started: l(&self.started),
            enrolled: l(&self.enrolled),
            enroll_failures: l(&self.enroll_failures),
            connected: l(&self.connected),
            ever_connected: l(&self.ever_connected),
            connect_attempts: l(&self.connect_attempts),
            connect_failures: l(&self.connect_failures),
            published_ok: l(&self.published_ok),
            publish_errors: l(&self.publish_errors),
            publish_timeouts: l(&self.publish_timeouts),
            sessions_lost: l(&self.sessions_lost),
            cmds_received: l(&self.cmds_received),
            cmds_executed: l(&self.cmds_executed),
            downlink_rejected: l(&self.downlink_rejected),
            errors_total: l(&self.errors_total),
            publish_window: self.publish_all.take_window(),
            connect_window: self.connect_lat.take_window(),
            enroll_window: self.enroll_lat.take_window(),
        }
    }
}

/// Error class of a failed enrollment.
#[must_use]
pub fn enroll_class(e: &EnrollError) -> String {
    match e {
        EnrollError::Est(EstError::Connect(f, _)) => format!("enroll: EST connect {}", f.as_str()),
        EnrollError::Est(EstError::Http { status, .. }) => format!("enroll: EST HTTP {status}"),
        EnrollError::Est(EstError::Protocol(_)) => "enroll: EST protocol".into(),
        EnrollError::Identity(_) => "enroll: identity backend".into(),
        EnrollError::Invalid(_) => "enroll: response rejected".into(),
        EnrollError::NotProvisioned(_) => "enroll: not provisioned".into(),
        EnrollError::Io(_) => "enroll: I/O".into(),
    }
}

/// Error class of a failed MQTT operation.
#[must_use]
pub fn mqtt_class(op: &str, e: &MqttError) -> String {
    match e {
        MqttError::Connect(f, _) => format!("{op}: {}", f.as_str()),
        MqttError::Closed(_) => format!("{op}: connection closed"),
        MqttError::Timeout => format!("{op}: timeout"),
        MqttError::Protocol(_) => format!("{op}: protocol"),
    }
}

async fn sleep_or_stop(d: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    if *stop.borrow() {
        return true;
    }
    tokio::select! {
        () = tokio::time::sleep(d) => *stop.borrow(),
        _ = stop.changed() => true,
    }
}

fn ms_since(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX).max(1)
}

struct Session {
    client: MqttClient,
    identity: SharedIdentity,
    kid: Kid,
    tenant_key: Option<PublicKey>,
}

impl Session {
    async fn publish(
        &self,
        sh: &Shared,
        seq: &SeqCounter,
        class: TopicClass,
        body: Body,
        nonce: Option<[u8; 16]>,
    ) -> Result<(u64, u8, Duration), MqttError> {
        let s = seq.next().map_err(|e| MqttError::Protocol(format!("seq store: {e}")))?;
        let msg = Message { seq: s, ts: Clock::new().now_unix(), body, nonce };
        let signer = IdentitySigner { provider: self.identity.clone(), slot: KeySlot::Operational };
        let wire = envelope::encode(&msg, &signer, &self.kid).map_err(|e| MqttError::Protocol(e.to_string()))?;
        let topic = ids::build_topic(self.identity.tenant_id(), self.identity.device_id(), class)
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        let t = Instant::now();
        let code = self.client.publish(&topic, wire, 1, false, Properties::new(), Duration::from_secs(sh.spec.publish_timeout_s)).await?;
        Ok((s, code, t.elapsed()))
    }
}

/// Verify a downlink like the agent does (`Agent::verify_downlink`): tenant signature, direction,
/// tenant, timestamp, type matches the topic, then the per-type replay stream.
fn verify_command(
    p: &Publish,
    identity: &SharedIdentity,
    tenant_key: Option<&PublicKey>,
    replay: &mut InMemoryReplayStore,
) -> Result<Message, String> {
    let t = ids::parse_topic(&p.topic).map_err(|e| e.to_string())?;
    if t.device_id != identity.device_id() || t.tenant_id != identity.tenant_id() || t.class != TopicClass::CmdReq {
        return Err("TOPIC_FORMAT: not this device's command topic".into());
    }
    let tenant = identity.tenant_id().to_owned();
    let tenant_kid = ids::tenant_kid(&tenant).map_err(|e| e.to_string())?;
    let resolver = |kid: &Kid| match kid {
        Kid::Text(k) if *k == tenant_kid => tenant_key.cloned(),
        _ => None,
    };
    let opts = DecodeOptions {
        now: Clock::new().now_unix(),
        max_skew: Some(300),
        expected_direction: Some(Direction::Downlink),
        expected_tenant: Some(&tenant),
        expected_nonce: None,
        limits: DecodeLimits::default(),
    };
    let mut probe = InMemoryReplayStore::new();
    let v = envelope::decode(&p.payload, &resolver, &mut probe, &opts).map_err(|e| format!("{}: {}", e.code().as_str(), e.detail()))?;
    if v.message.message_type() != TopicClass::CmdReq.message_type() {
        return Err(format!("ENV_TYPE: type {} on the command topic", v.message.message_type()));
    }
    let stream = envelope::replay_stream(&v.sender_kid, Direction::Downlink, v.message.message_type());
    if !replay.check_and_record(&stream, Direction::Downlink, v.message.seq) {
        return Err(format!("ENV_REPLAY: seq {} not greater than last accepted", v.message.seq));
    }
    Ok(v.message)
}

#[allow(clippy::too_many_lines)]
async fn run_device(sh: Arc<Shared>, idx: usize, mut stop: watch::Receiver<bool>) {
    let entry = sh.spec.devices[idx].clone();
    let state = &sh.devices[idx];
    let dir = entry.dir.clone();
    sh.started.fetch_add(1, Ordering::Relaxed);
    let identity: SharedIdentity = match SoftwareIdentity::open(&dir, &SecretSource::File(dir.join("machine-secret"))) {
        Ok(i) => Arc::new(i),
        Err(e) => return sh.error("identity: open", &e),
    };
    let seq = match SeqCounter::open(&dir.join("seq.json"), 100) {
        Ok(s) => s,
        Err(e) => return sh.error("identity: seq store", &e),
    };
    let mut model = Model::new(idx as u64, None, sh.fw_hash);
    let mut backoff = Backoff::mqtt();
    let mut replay = InMemoryReplayStore::new();
    let mut idem = IdempotencyCache::in_memory();
    let scale = sh.spec.backoff_scale;
    loop {
        if *stop.borrow() {
            return;
        }
        let now = Clock::new().now_unix();
        let mut creds = match Credentials::load(&dir, &identity, sh.bundle_key.as_ref(), &sh.spec.anchors_file) {
            Ok(c) => c,
            Err(e) => return sh.error("identity: credentials", &e),
        };
        if creds.operational_valid(now).is_none() || creds.bundle.is_none() {
            let pins = creds.bundle.as_ref().map(|b| b.ca_pins.clone()).unwrap_or_else(|| sh.est_pins.clone());
            let s = seq.next().unwrap_or(1);
            let req = EnrollRequest {
                identity: &identity,
                creds: &creds,
                dir: dir.clone(),
                est_host: &sh.spec.est_host,
                est_port: sh.spec.est_port,
                pins,
                bundle_key: sh.bundle_key,
                fw: FirmwareInfo { hash: sh.fw_hash, version: sh.spec.fw_version.clone() },
                seq: s,
                now,
                timeout: Duration::from_secs(sh.spec.est_timeout_s),
                force_bootstrap: creds.operational_valid(now).is_none(),
            };
            let t = Instant::now();
            match enroll::enroll(req).await {
                Ok(_) => {
                    sh.enroll_lat.record(t.elapsed());
                    if !state.enrolled.swap(true, Ordering::Relaxed) {
                        sh.enrolled.fetch_add(1, Ordering::Relaxed);
                    }
                    backoff.reset();
                }
                Err(e) => {
                    sh.enroll_failures.fetch_add(1, Ordering::Relaxed);
                    sh.error(&enroll_class(&e), &e);
                    if sleep_or_stop(backoff.next_delay().mul_f64(scale).max(Duration::from_millis(500)), &mut stop).await {
                        return;
                    }
                }
            }
            continue;
        }
        let (Some(op), Some(bundle)) = (creds.operational.take(), creds.bundle.take()) else { continue };
        let verifier = match PinnedVerifier::new(&creds.anchors, &bundle.ca_pins, tls::provider()) {
            Ok(v) => v,
            Err(e) => return sh.error("tls: pins", &e),
        };
        let cfg = match tls::client_config(
            Arc::new(verifier),
            Some(ClientIdentity { chain: vec![op.der.clone()], provider: identity.clone(), slot: KeySlot::Operational }),
            &[b"mqtt"],
        ) {
            Ok(c) => c,
            Err(e) => return sh.error("tls: client config", &e),
        };
        let mut opts = MqttOptions::new(identity.device_id());
        opts.connect_timeout = Duration::from_secs(sh.spec.connect_timeout_s);
        sh.connect_attempts.fetch_add(1, Ordering::Relaxed);
        let t = Instant::now();
        let (client, mut inbound, _info) = match mqtt::connect(cfg, &bundle.broker_host, bundle.broker_port, &opts).await {
            Ok(c) => c,
            Err(e) => {
                sh.connect_failures.fetch_add(1, Ordering::Relaxed);
                sh.error(&mqtt_class("connect", &e), &e);
                if sleep_or_stop(backoff.next_delay().mul_f64(scale).max(Duration::from_millis(500)), &mut stop).await {
                    return;
                }
                continue;
            }
        };
        sh.connect_lat.record(t.elapsed());
        let session = Session {
            client,
            identity: identity.clone(),
            kid: Kid::Bytes(op.kid.clone()),
            tenant_key: bundle.tenant_cmd_pubkey.and_then(|k| PublicKey::ed25519_from_raw(&k).ok()),
        };
        let cmd_topic = match ids::build_topic(identity.tenant_id(), identity.device_id(), TopicClass::CmdReq) {
            Ok(t) => t,
            Err(e) => return sh.error("topic", &e),
        };
        match session.client.subscribe(vec![(cmd_topic, 1)], Duration::from_secs(sh.spec.publish_timeout_s)).await {
            Ok(codes) if codes.iter().all(|c| *c < 0x80) => {}
            Ok(codes) => {
                sh.error("subscribe: denied", &format!("SUBACK {codes:?}"));
                session.client.disconnect().await;
                if sleep_or_stop(backoff.next_delay().mul_f64(scale).max(Duration::from_millis(500)), &mut stop).await {
                    return;
                }
                continue;
            }
            Err(e) => {
                sh.error(&mqtt_class("subscribe", &e), &e);
                session.client.abort().await;
                if sleep_or_stop(backoff.next_delay().mul_f64(scale).max(Duration::from_millis(500)), &mut stop).await {
                    return;
                }
                continue;
            }
        }
        backoff.reset();
        state.connects.fetch_add(1, Ordering::Relaxed);
        if state.first_connect_ms.load(Ordering::Relaxed) == 0 {
            state.first_connect_ms.store(ms_since(sh.t0), Ordering::Relaxed);
            sh.ever_connected.fetch_add(1, Ordering::Relaxed);
        }
        sh.connected.fetch_add(1, Ordering::Relaxed);
        let period = Duration::from_secs(sh.spec.interval_s.max(1));
        // Desynchronise devices so the broker does not see thundering herds (as fleet::run_device).
        let phase = Duration::from_millis((idx as u64).wrapping_mul(7919) % u64::try_from(period.as_millis()).unwrap_or(1000).max(1));
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + phase, period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let lost = loop {
            tokio::select! {
                _ = stop.changed() => {
                    session.client.disconnect().await;
                    sh.connected.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                m = inbound.recv() => match m {
                    Some(m) => {
                        sh.cmds_received.fetch_add(1, Ordering::Relaxed);
                        match verify_command(&m.publish, &identity, session.tenant_key.as_ref(), &mut replay) {
                            Ok(msg) => {
                                if let Body::Command(cmd) = &msg.body {
                                    let ack = match idem.get(&cmd.idempotency_key).cloned() {
                                        Some(a) => a,
                                        None => {
                                            let (a, _effects) = commands::execute(cmd, Clock::new().now_unix());
                                            let _ = idem.insert(&cmd.idempotency_key, &a);
                                            a
                                        }
                                    };
                                    sh.cmds_executed.fetch_add(1, Ordering::Relaxed);
                                    match session.publish(&sh, &seq, TopicClass::CmdAck, Body::CommandAck(ack), msg.nonce).await {
                                        Ok((s, code, _)) if code < 0x80 => {
                                            sh.cmd_acks_published.fetch_add(1, Ordering::Relaxed);
                                            state.last_acked_seq.fetch_max(s, Ordering::Relaxed);
                                        }
                                        Ok((_, code, _)) => sh.error("cmd ack: PUBACK error", &format!("reason 0x{code:02x}")),
                                        Err(e) => sh.error(&mqtt_class("cmd ack", &e), &e),
                                    }
                                }
                                m.ack(0).await;
                            }
                            Err(e) => {
                                sh.downlink_rejected.fetch_add(1, Ordering::Relaxed);
                                sh.error("downlink: rejected", &e);
                                m.ack(0x83).await;
                            }
                        }
                    }
                    None => break true,
                },
                _ = ticker.tick() => {
                    let body = Body::Telemetry(model.sample(period.as_secs(), &sh.spec.fw_version));
                    match session.publish(&sh, &seq, TopicClass::Telemetry, body, None).await {
                        Ok((s, code, d)) if code < 0x80 => {
                            sh.record_publish(d);
                            sh.published_ok.fetch_add(1, Ordering::Relaxed);
                            state.last_acked_seq.fetch_max(s, Ordering::Relaxed);
                            state.telemetry_acked.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok((_, code, _)) => {
                            sh.publish_errors.fetch_add(1, Ordering::Relaxed);
                            sh.error("publish: PUBACK error", &format!("reason 0x{code:02x}"));
                        }
                        Err(MqttError::Timeout) => {
                            sh.publish_timeouts.fetch_add(1, Ordering::Relaxed);
                            sh.error("publish: PUBACK timeout", &format!("no PUBACK within {} s", sh.spec.publish_timeout_s));
                        }
                        Err(e) => {
                            sh.publish_errors.fetch_add(1, Ordering::Relaxed);
                            sh.error(&mqtt_class("publish", &e), &e);
                            break true;
                        }
                    }
                }
            }
        };
        sh.connected.fetch_sub(1, Ordering::Relaxed);
        if lost {
            sh.sessions_lost.fetch_add(1, Ordering::Relaxed);
            let info = session.client.closed().await;
            sh.error("session: lost", &format!("{} (0x{:02x})", info.reason, info.reason_code));
        }
        if sleep_or_stop(backoff.next_delay().mul_f64(scale).max(Duration::from_millis(500)), &mut stop).await {
            return;
        }
    }
}

fn emit(line: &str) {
    let out = std::io::stdout();
    let mut out = out.lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

async fn fleet_run(spec: FleetSpec) -> Result<()> {
    let sh = Arc::new(Shared::new(spec));
    let (stop_tx, stop_rx) = watch::channel(false);
    let handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::with_capacity(sh.spec.devices.len())));
    let spawner = {
        let sh = sh.clone();
        let handles = handles.clone();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            for (i, off) in sh.spec.schedule_ms.clone().into_iter().enumerate() {
                let at = tokio::time::Instant::from_std(sh.t0 + Duration::from_millis(off));
                tokio::select! {
                    () = tokio::time::sleep_until(at) => {}
                    _ = stop.changed() => return,
                }
                if *stop.borrow() {
                    return;
                }
                let h = tokio::spawn(run_device(sh.clone(), i, stop.clone()));
                handles.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(h);
            }
        })
    };
    emit(&serde_json::json!({"ready": true, "devices": sh.spec.devices.len()}).to_string());
    let (line_tx, mut line_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if line_tx.send(l).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = line_tx.send("stop".into());
    });
    while let Some(line) = line_rx.recv().await {
        match line.trim() {
            "tick" => emit(&serde_json::to_string(&sh.status())?),
            "phase ramp" => sh.phase.store(PHASE_RAMP, Ordering::Relaxed),
            "phase sustain" => sh.phase.store(PHASE_SUSTAIN, Ordering::Relaxed),
            "phase drain" => sh.phase.store(PHASE_DRAIN, Ordering::Relaxed),
            "stop" => break,
            _ => {}
        }
    }
    let connected_at_stop = sh.connected.load(Ordering::Relaxed);
    sh.phase.store(PHASE_DRAIN, Ordering::Relaxed);
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), spawner).await;
    let tasks = std::mem::take(&mut *handles.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    for t in tasks {
        let _ = tokio::time::timeout_at(deadline, t).await;
    }
    let result = FleetResult {
        status: sh.status(),
        connected_at_stop,
        cmd_acks_published: sh.cmd_acks_published.load(Ordering::Relaxed),
        errors: sh.errors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
        enroll_latency: sh.enroll_lat.summary(),
        connect_latency: sh.connect_lat.summary(),
        publish_latency_all: sh.publish_all.summary(),
        publish_latency_ramp: sh.publish_ramp.summary(),
        publish_latency_sustain: sh.publish_sustain.summary(),
        devices: sh
            .spec
            .devices
            .iter()
            .zip(&sh.devices)
            .map(|(e, d)| DeviceOutcome {
                id: e.id.clone(),
                enrolled: d.enrolled.load(Ordering::Relaxed),
                connects: d.connects.load(Ordering::Relaxed),
                first_connect_ms: d.first_connect_ms.load(Ordering::Relaxed),
                last_acked_seq: d.last_acked_seq.load(Ordering::Relaxed),
                telemetry_acked: d.telemetry_acked.load(Ordering::Relaxed),
            })
            .collect(),
    };
    std::fs::write(&sh.spec.result_file, serde_json::to_vec(&result)?)
        .with_context(|| format!("write {}", sh.spec.result_file.display()))?;
    emit(&serde_json::json!({"done": true}).to_string());
    Ok(())
}

/// Entry point of `load-fleet`.
///
/// # Errors
/// Unreadable spec, runtime or result-file failures.
pub fn fleet_main(spec_path: &Path) -> Result<()> {
    let spec: FleetSpec = serde_json::from_slice(&std::fs::read(spec_path).with_context(|| format!("read {}", spec_path.display()))?)?;
    let mut b = tokio::runtime::Builder::new_multi_thread();
    if spec.worker_threads > 0 {
        b.worker_threads(spec.worker_threads);
    }
    let rt = b.enable_all().build()?;
    rt.block_on(fleet_run(spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classes_are_stable() {
        assert_eq!(enroll_class(&EnrollError::Est(EstError::Http { status: 403, reason: "x".into() })), "enroll: EST HTTP 403");
        assert_eq!(
            enroll_class(&EnrollError::Est(EstError::Connect(tls::ConnectFailure::Timeout, "t".into()))),
            "enroll: EST connect timeout"
        );
        assert_eq!(mqtt_class("connect", &MqttError::Connect(tls::ConnectFailure::NotAuthorized, "x".into())), "connect: not_authorized");
        assert_eq!(mqtt_class("publish", &MqttError::Timeout), "publish: timeout");
    }

    #[test]
    fn status_round_trips_as_json() {
        let s =
            FleetStatus { connected: 3, publish_window: Summary { count: 2, p50_ms: 1.5, ..Summary::default() }, ..FleetStatus::default() };
        let back: FleetStatus = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.connected, 3);
        assert_eq!(back.publish_window, s.publish_window);
    }
}
