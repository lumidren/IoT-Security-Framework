//! The agent runtime: supervisor state machine (`unprovisioned -> enrolling -> connecting ->
//! connected -> offline/backoff`), uplink publishing with the offline buffer, inbound dispatch
//! (commands, desired state, OTA, encrypted config), certificate renewal, telemetry and the OTA
//! health gate. The same control surface backs the systemd service, the DUT protocol and the
//! end-to-end tests.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::{json, Value as Json};
use tokio::sync::{broadcast, mpsc, watch, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;

use crate::buffer::{Record, RingBuffer};
use crate::commands::{self, Effect, IdempotencyCache};
use crate::config::ConfigState;
use crate::enroll::{self, Credentials, EnrollError, EnrollOutcome, EnrollRequest};
use crate::est::renewal::{self, RenewalAction};
use crate::identity::{IdentityRecipient, IdentitySigner, KeySlot, SharedIdentity};
use crate::logging::TraceContext;
use crate::mqtt::codec::{reason, Properties, Publish};
use crate::mqtt::{self, Backoff, MqttClient, MqttError, MqttOptions};
use crate::ota::boot::{BootControl, BootOutcome, Slot};
use crate::ota::slots::{PendingUpdate, SlotStore};
use crate::ota::{self, OtaContext, OtaReport, RunningFirmware};
use crate::seq::{Clock, FileReplayStore, SeqCounter};
use crate::settings::Settings;
use crate::shadow::Shadow;
use crate::telemetry::{self, FirmwareInfo, TelemetrySource};
use crate::tls::{self, ClientIdentity, ConnectFailure, PinnedVerifier};
use crate::wire::cbor::DecodeLimits;
use crate::wire::cose::Kid;
use crate::wire::envelope::{self, Body, CommandAck, DecodeOptions, Message, OtaState, OtaStatus, ReplayStore};
use crate::wire::ids::{self, Direction, TopicClass};
use crate::wire::keys::PublicKey;
use crate::wire::{hpke, ErrorCode, WireError};

/// Supervisor state (DUT `status.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// No usable certificate.
    Unprovisioned,
    /// Enrollment in progress.
    Enrolling,
    /// Connecting to the broker.
    Connecting,
    /// MQTT session established.
    Connected,
    /// Not connected (by request or link down).
    Offline,
    /// Waiting before the next reconnect attempt.
    Backoff,
    /// Restart pending.
    Rebooting,
}

impl AgentState {
    /// DUT name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AgentState::Unprovisioned => "unprovisioned",
            AgentState::Enrolling => "enrolling",
            AgentState::Connecting => "connecting",
            AgentState::Connected => "connected",
            AgentState::Offline => "offline",
            AgentState::Backoff => "backoff",
            AgentState::Rebooting => "rebooting",
        }
    }
}

/// Why the agent restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootReason {
    /// Operator / DUT request or `reboot` command.
    Requested,
    /// An update was staged.
    OtaApply,
    /// The health gate failed.
    Rollback,
    /// Watchdog.
    Watchdog,
}

impl RebootReason {
    /// DUT name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            RebootReason::Requested => "requested",
            RebootReason::OtaApply => "ota_apply",
            RebootReason::Rollback => "rollback",
            RebootReason::Watchdog => "watchdog",
        }
    }
}

/// An asynchronous event (DUT protocol event names).
#[derive(Debug, Clone, PartialEq)]
pub struct AgentEvent {
    /// Event name.
    pub name: &'static str,
    /// Monotonic time (ms).
    pub at_ms: u64,
    /// Payload.
    pub data: Json,
}

/// An inbound message that failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Monotonic time (ms).
    pub at_ms: u64,
    /// Wire error code.
    pub code: String,
    /// Topic.
    pub topic: String,
    /// Detail.
    pub detail: String,
}

/// Agent error.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// I/O.
    #[error("agent I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Enrollment.
    #[error(transparent)]
    Enroll(#[from] EnrollError),
    /// Boot control.
    #[error(transparent)]
    Boot(#[from] crate::ota::boot::BootError),
    /// Wire.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// MQTT.
    #[error(transparent)]
    Mqtt(#[from] MqttError),
    /// Not possible in the current state.
    #[error("{0}")]
    State(&'static str),
}

/// Everything needed to start an agent.
pub struct AgentOptions {
    /// Configuration.
    pub settings: Settings,
    /// Identity backend.
    pub identity: SharedIdentity,
    /// Boot control.
    pub boot: Arc<dyn BootControl>,
    /// Telemetry source.
    pub telemetry: Box<dyn TelemetrySource>,
    /// Clock (shared across in-process restarts).
    pub clock: Arc<Clock>,
    /// Event sink (shared across in-process restarts).
    pub events: broadcast::Sender<AgentEvent>,
    /// Set after an in-process restart; emitted as `rebooted`.
    pub boot_reason: Option<RebootReason>,
    /// Start connecting immediately (service mode) or wait for `connect` (DUT mode).
    pub auto_connect: bool,
    /// Initial link state (DUT `net_down` survives a reboot).
    pub net_up: bool,
}

/// `(certificate serial, pins, config)` of the cached MQTT TLS configuration.
type TlsCacheEntry = (Vec<u8>, Vec<[u8; 32]>, Arc<rustls::ClientConfig>);

struct Health {
    pending: PendingUpdate,
    deadline: tokio::time::Instant,
}

struct Shared {
    s: Settings,
    identity: SharedIdentity,
    clock: Arc<Clock>,
    boot: Arc<dyn BootControl>,
    slots: SlotStore,
    seq: SeqCounter,
    replay: Mutex<FileReplayStore>,
    buffer: AsyncMutex<RingBuffer>,
    idem: Mutex<IdempotencyCache>,
    shadow: Mutex<Shadow>,
    config: Mutex<ConfigState>,
    creds: RwLock<Credentials>,
    events: broadcast::Sender<AgentEvent>,
    rejections: Mutex<VecDeque<Rejection>>,
    state: Mutex<AgentState>,
    broker: Mutex<Option<String>>,
    client: Mutex<Option<MqttClient>>,
    net_up: watch::Sender<bool>,
    want: watch::Sender<bool>,
    stop: watch::Sender<bool>,
    telemetry: AsyncMutex<Box<dyn TelemetrySource>>,
    interval_s: AtomicU64,
    interval_changed: Notify,
    running: RwLock<RunningFirmware>,
    health: Mutex<Option<Health>>,
    health_acked: Notify,
    reboot_tx: mpsc::UnboundedSender<RebootReason>,
    tls_cache: Mutex<Option<TlsCacheEntry>>,
    ota_busy: AtomicBool,
    enroll_lock: AsyncMutex<()>,
    reconnect: Notify,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    renew_jitter: Mutex<Option<(Vec<u8>, f64)>>,
}

/// Handle to a running agent.
#[derive(Clone)]
pub struct Agent {
    sh: Arc<Shared>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn running_firmware(s: &Settings, slots: &SlotStore, slot: Slot) -> RunningFirmware {
    let meta = slots.meta(slot);
    let slot_image = slots.image_path(slot);
    let (fw_hash, image_path) = if slot_image.exists() {
        (telemetry::sha256_file(&slot_image).unwrap_or([0; 32]), Some(slot_image))
    } else if let Some(p) = &s.telemetry.fw_image {
        (telemetry::sha256_file(p).unwrap_or([0; 32]), Some(p.clone()))
    } else {
        (telemetry::running_binary_hash(), std::env::current_exe().ok())
    };
    let version = meta.as_ref().map_or_else(|| s.agent.fw_version.clone(), |m| m.version.clone());
    let code = meta.as_ref().map_or(s.agent.fw_version_code, |m| m.version_code);
    RunningFirmware { slot, version, version_code: code.max(slots.anti_rollback()), fw_hash, image_path }
}

impl Agent {
    /// Open all state, run the boot decision and spawn the background tasks.
    ///
    /// Returns the agent and the channel on which restart requests arrive (the owner restarts
    /// the process or, in DUT/test mode, re-creates the agent in-process).
    ///
    /// # Errors
    /// I/O, boot-control or credential errors.
    pub async fn start(opts: AgentOptions) -> Result<(Agent, mpsc::UnboundedReceiver<RebootReason>), AgentError> {
        let s = opts.settings;
        let state_dir = s.agent.state_dir.clone();
        crate::persist::ensure_private_dir(&state_dir)?;
        let slots = SlotStore::open(&s.ota.slots_dir)?;
        let outcome = opts.boot.on_boot()?;
        let running = running_firmware(&s, &slots, outcome.running());
        let creds = Credentials::load(&s.identity.dir, &opts.identity, s.bundle_key().as_ref(), &s.pki.ca_bundle)?;
        crate::logging::set_identity(opts.identity.tenant_id(), opts.identity.device_id());
        let (reboot_tx, reboot_rx) = mpsc::unbounded_channel();
        let (net_up, _) = watch::channel(opts.net_up);
        let (want, _) = watch::channel(opts.auto_connect);
        let (stop, _) = watch::channel(false);
        let sh = Arc::new(Shared {
            seq: SeqCounter::open(&state_dir.join("seq.json"), s.agent.seq_block)?,
            replay: Mutex::new(FileReplayStore::open(&state_dir.join("replay.json"))?),
            buffer: AsyncMutex::new(RingBuffer::open(&state_dir.join("buffer"), s.agent.buffer_capacity, false)?),
            idem: Mutex::new(IdempotencyCache::open(&state_dir.join("idempotency.json"))?),
            shadow: Mutex::new(Shadow::open(&state_dir.join("shadow.json"))?),
            config: Mutex::new(ConfigState::open(&state_dir.join("config.json"))?),
            interval_s: AtomicU64::new(s.telemetry.interval_s),
            identity: opts.identity,
            clock: opts.clock,
            boot: opts.boot,
            slots,
            creds: RwLock::new(creds),
            events: opts.events,
            rejections: Mutex::new(VecDeque::new()),
            state: Mutex::new(AgentState::Offline),
            broker: Mutex::new(None),
            client: Mutex::new(None),
            net_up,
            want,
            stop,
            telemetry: AsyncMutex::new(opts.telemetry),
            interval_changed: Notify::new(),
            running: RwLock::new(running),
            health: Mutex::new(None),
            health_acked: Notify::new(),
            reboot_tx,
            tls_cache: Mutex::new(None),
            ota_busy: AtomicBool::new(false),
            enroll_lock: AsyncMutex::new(()),
            reconnect: Notify::new(),
            tasks: Mutex::new(Vec::new()),
            renew_jitter: Mutex::new(None),
            s,
        });
        let agent = Agent { sh: sh.clone() };
        agent.after_boot(outcome, opts.boot_reason).await;
        let tasks =
            vec![tokio::spawn(supervisor(sh.clone())), tokio::spawn(telemetry_task(sh.clone())), tokio::spawn(renewal_task(sh.clone()))];
        lock(&sh.tasks).extend(tasks);
        Ok((agent, reboot_rx))
    }

    async fn after_boot(&self, outcome: BootOutcome, reason: Option<RebootReason>) {
        let sh = &self.sh;
        let mut reason = reason;
        let mut rolled_back = None;
        match outcome {
            BootOutcome::Trial(slot) => match sh.slots.pending_update().filter(|p| p.slot == slot) {
                Some(pending) => {
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(sh.s.ota.health_timeout_s);
                    *lock(&sh.health) = Some(Health { pending, deadline });
                    let h = sh.clone();
                    lock(&sh.tasks).push(tokio::spawn(health_task(h)));
                }
                None => {
                    let _ = sh.boot.mark_good();
                }
            },
            BootOutcome::RolledBack { failed, .. } => {
                reason = Some(RebootReason::Rollback);
                if let Some(p) = sh.slots.pending_update().filter(|p| p.slot == failed) {
                    let _ = sh.slots.set_state(failed, "invalid");
                    let _ = sh.slots.set_pending_update(None);
                    rolled_back = Some(p);
                }
            }
            BootOutcome::Normal(_) => {}
        }
        if let Some(r) = reason {
            let rf = read(&sh.running).clone();
            sh.emit("rebooted", json!({"active_slot": rf.slot.name(), "version_code": rf.version_code, "reason": r.name()}));
        }
        if let Some(p) = rolled_back {
            let report = OtaReport {
                campaign_id: p.campaign_id,
                state: OtaState::RolledBack,
                progress_pct: 100,
                error: Some("HEALTH_CHECK".into()),
                fw_hash: Some(read(&sh.running).fw_hash),
            };
            sh.publish_ota_report(&report, Some("health_check")).await;
        }
    }

    /// Subscribe to events.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<AgentEvent> {
        self.sh.events.subscribe()
    }

    /// Request (or stop) a broker connection.
    pub fn set_connected(&self, want: bool) {
        let _ = self.sh.want.send_replace(want);
    }

    /// Simulate link loss / recovery.
    pub fn set_net(&self, up: bool) {
        let _ = self.sh.net_up.send_replace(up);
    }

    /// Whether a broker connection is requested.
    #[must_use]
    pub fn wants_connection(&self) -> bool {
        *self.sh.want.borrow()
    }

    /// Current link state.
    #[must_use]
    pub fn net_is_up(&self) -> bool {
        *self.sh.net_up.borrow()
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> AgentState {
        *lock(&self.sh.state)
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> Arc<Clock> {
        self.sh.clock.clone()
    }

    /// Enroll now (bootstrap or re-enroll as appropriate).
    ///
    /// # Errors
    /// [`EnrollError`].
    pub async fn enroll(&self) -> Result<EnrollOutcome, EnrollError> {
        self.sh.enroll_now(false, false).await
    }

    /// Force `simplereenroll` now.
    ///
    /// # Errors
    /// [`EnrollError`].
    pub async fn renew(&self) -> Result<EnrollOutcome, EnrollError> {
        self.sh.enroll_now(false, true).await
    }

    /// Send `count` telemetry messages (buffered when offline); returns `(first_seq, last_seq)`.
    ///
    /// # Errors
    /// [`AgentError`].
    pub async fn send_telemetry(&self, count: u32) -> Result<(u64, u64), AgentError> {
        let mut first = None;
        let mut last = 0;
        for _ in 0..count.max(1) {
            let seq = self.sh.send_one_telemetry().await?;
            first.get_or_insert(seq);
            last = seq;
        }
        Ok((first.unwrap_or(last), last))
    }

    /// Publish bytes verbatim (ACL tests); returns the PUBACK reason code (QoS 1) or 0.
    ///
    /// # Errors
    /// Not connected / closed.
    pub async fn publish_raw(&self, topic: &str, payload: Vec<u8>, qos: u8, retain: bool) -> Result<u8, AgentError> {
        let client = lock(&self.sh.client).clone().ok_or(AgentError::State("not connected"))?;
        let r = client.publish(topic, payload, qos.min(1), retain, Properties::new(), self.sh.ack_timeout()).await;
        let (ok, code) = match &r {
            Ok(c) => (*c < 0x80, *c),
            Err(_) => (false, reason::UNSPECIFIED),
        };
        self.sh.emit("publish_result", json!({"topic": topic, "ok": ok, "reason_code": code}));
        Ok(r?)
    }

    /// Subscribe to a raw filter (ACL tests); returns the SUBACK reason code.
    ///
    /// # Errors
    /// Not connected / closed.
    pub async fn subscribe_raw(&self, topic: &str) -> Result<u8, AgentError> {
        let client = lock(&self.sh.client).clone().ok_or(AgentError::State("not connected"))?;
        let r = client.subscribe(vec![(topic.to_owned(), 1)], self.sh.ack_timeout()).await;
        let code = match &r {
            Ok(codes) => codes.first().copied().unwrap_or(reason::UNSPECIFIED),
            Err(_) => reason::UNSPECIFIED,
        };
        self.sh.emit("subscribe_result", json!({"topic": topic, "granted": code < 0x80, "reason_code": code}));
        r?;
        Ok(code)
    }

    /// DUT `hello`.
    #[must_use]
    pub fn hello(&self) -> Json {
        let rf = read(&self.sh.running).clone();
        json!({
            "target": "agent-rs",
            "fw_version": rf.version,
            "fw_version_code": rf.version_code,
            "se_type": self.sh.identity.se_type().as_str(),
            "device_id": self.sh.identity.device_id(),
            "tenant_id": self.sh.identity.tenant_id(),
            "protocol_version": 1,
        })
    }

    /// DUT `status`.
    pub async fn status(&self) -> Json {
        let buffered = self.sh.buffer.lock().await.len();
        let creds = read(&self.sh.creds).clone();
        let cert = creds.operational.as_ref().or(creds.bootstrap.as_ref());
        let boot = self.sh.boot.state().ok();
        let rf = read(&self.sh.running).clone();
        json!({
            "state": self.state().name(),
            "cert_serial_hex": cert.map(crate::x509::CertInfo::serial_hex),
            "cert_not_after": cert.map(|c| c.not_after),
            "seq_out": self.sh.seq.peek(),
            "buffered": buffered,
            "active_slot": rf.slot.name(),
            "pending_slot": boot.and_then(|b| b.pending).map(Slot::name),
            "version_code": rf.version_code,
            "connected_broker": lock(&self.sh.broker).clone(),
        })
    }

    /// DUT `ota_slots`.
    #[must_use]
    pub fn ota_slots(&self) -> Json {
        let boot = self.sh.boot.state().ok();
        let rf = read(&self.sh.running).clone();
        let slots: Vec<Json> = [Slot::A, Slot::B]
            .into_iter()
            .map(|s| {
                let m = self.sh.slots.meta(s);
                let running = s == rf.slot;
                json!({
                    "name": s.name(),
                    "version": m.as_ref().map_or_else(|| if running { rf.version.clone() } else { String::new() }, |m| m.version.clone()),
                    "version_code": m.as_ref().map_or(if running { rf.version_code } else { 0 }, |m| m.version_code),
                    "sha256_hex": m.as_ref().map_or_else(|| if running { hex::encode(rf.fw_hash) } else { String::new() }, |m| m.sha256_hex.clone()),
                    "state": m.as_ref().map_or_else(|| if running { "valid".to_owned() } else { "empty".to_owned() }, |m| m.state.clone()),
                })
            })
            .collect();
        json!({"active_slot": rf.slot.name(), "pending_slot": boot.and_then(|b| b.pending).map(Slot::name), "slots": slots})
    }

    /// DUT `rejections`.
    #[must_use]
    pub fn rejections(&self, since_ms: u64) -> Vec<Rejection> {
        lock(&self.sh.rejections).iter().filter(|r| r.at_ms >= since_ms).cloned().collect()
    }

    /// DUT `set_clock`.
    pub fn set_clock(&self, unix_s: u64) {
        self.sh.clock.set_unix(unix_s);
    }

    /// Request a restart.
    pub fn request_reboot(&self, reason: RebootReason) {
        self.sh.request_reboot(reason);
    }

    /// Credentials snapshot.
    #[must_use]
    pub fn credentials(&self) -> Credentials {
        read(&self.sh.creds).clone()
    }

    /// Running firmware.
    #[must_use]
    pub fn running_firmware(&self) -> RunningFirmware {
        read(&self.sh.running).clone()
    }

    /// Messages in the offline buffer.
    pub async fn buffered(&self) -> usize {
        self.sh.buffer.lock().await.len()
    }

    /// Stop all tasks and close the session (no DISCONNECT is sent if the link is down).
    pub async fn shutdown(&self) {
        let _ = self.sh.stop.send_replace(true);
        let client = lock(&self.sh.client).take();
        if let Some(c) = client {
            if self.net_is_up() {
                c.disconnect().await;
            } else {
                c.abort().await;
            }
        }
        let tasks: Vec<_> = lock(&self.sh.tasks).drain(..).collect();
        for t in tasks {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Shared {
    fn emit(&self, name: &'static str, data: Json) {
        let _ = self.events.send(AgentEvent { name, at_ms: self.clock.monotonic_ms(), data });
    }

    fn set_state(&self, st: AgentState) {
        let mut g = lock(&self.state);
        if *g != AgentState::Rebooting {
            *g = st;
        }
    }

    fn ack_timeout(&self) -> Duration {
        Duration::from_secs(self.s.mqtt.ack_timeout_s.max(1))
    }

    fn request_reboot(&self, reason: RebootReason) {
        *lock(&self.state) = AgentState::Rebooting;
        let _ = self.reboot_tx.send(reason);
    }

    fn reject(&self, topic: &str, e: &WireError) {
        let code = e.code().as_str().to_owned();
        tracing::warn!(topic, code = %code, detail = e.detail(), "inbound message rejected");
        let mut r = lock(&self.rejections);
        r.push_back(Rejection {
            at_ms: self.clock.monotonic_ms(),
            code: code.clone(),
            topic: topic.to_owned(),
            detail: e.detail().to_owned(),
        });
        while r.len() > 1000 {
            r.pop_front();
        }
        drop(r);
        self.emit("message_rejected", json!({"topic": topic, "code": code}));
    }

    fn topic(&self, class: TopicClass) -> Result<String, WireError> {
        ids::build_topic(self.identity.tenant_id(), self.identity.device_id(), class)
    }

    // -----------------------------------------------------------------------------------------
    // Enrollment
    // -----------------------------------------------------------------------------------------

    async fn enroll_now(self: &Arc<Self>, force_bootstrap: bool, force_reenroll: bool) -> Result<EnrollOutcome, EnrollError> {
        let _guard = self.enroll_lock.lock().await;
        let was_connected = lock(&self.client).is_some();
        if !was_connected {
            self.set_state(AgentState::Enrolling);
        }
        let creds = read(&self.creds).clone();
        let now = self.clock.now_unix();
        let renewing = force_reenroll || (!force_bootstrap && creds.operational_valid(now).is_some());
        if force_reenroll && creds.operational_valid(now).is_none() {
            let e = EnrollError::NotProvisioned("no valid operational certificate to renew".into());
            self.emit("renew_failed", json!({"http_status": 0, "reason": e.reason()}));
            return Err(e);
        }
        let pins = creds.bundle.as_ref().map(|b| b.ca_pins.clone()).unwrap_or_else(|| self.s.est_pins());
        let fw = {
            let rf = read(&self.running);
            FirmwareInfo { hash: rf.fw_hash, version: rf.version.clone() }
        };
        let seq = self.seq.next().map_err(EnrollError::Io)?;
        let req = EnrollRequest {
            identity: &self.identity,
            creds: &creds,
            dir: self.s.identity.dir.clone(),
            est_host: &self.s.pki.est_host,
            est_port: self.s.pki.est_port,
            pins,
            bundle_key: self.s.bundle_key(),
            fw,
            seq,
            now,
            timeout: Duration::from_secs(self.s.pki.timeout_s.max(1)),
            force_bootstrap,
        };
        let result = enroll::enroll(req).await;
        match &result {
            Ok(out) => {
                if let Ok(c) = Credentials::load(&self.s.identity.dir, &self.identity, self.s.bundle_key().as_ref(), &self.s.pki.ca_bundle)
                {
                    *write(&self.creds) = c;
                }
                let serial = out.certificate.serial_hex();
                tracing::info!(serial = %serial, not_after = out.certificate.not_after, reenroll = out.reenroll, "certificate issued");
                if renewing && out.previous_serial.is_some() {
                    self.emit(
                        "cert_renewed",
                        json!({"old_serial_hex": out.previous_serial, "new_serial_hex": serial, "not_after": out.certificate.not_after}),
                    );
                } else {
                    self.emit("enrolled", json!({"cert_serial_hex": serial, "not_after": out.certificate.not_after, "se_type": self.identity.se_type().as_str()}));
                }
                if was_connected {
                    self.reconnect.notify_one();
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "enrollment failed");
                let name = if renewing { "renew_failed" } else { "enroll_failed" };
                self.emit(name, json!({"http_status": e.http_status(), "reason": e.reason()}));
            }
        }
        if !was_connected && lock(&self.client).is_none() {
            let st = if read(&self.creds).operational_valid(self.clock.now_unix()).is_some() {
                AgentState::Offline
            } else {
                AgentState::Unprovisioned
            };
            self.set_state(st);
        }
        result
    }

    // -----------------------------------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------------------------------

    fn mqtt_tls(&self, creds: &Credentials) -> Result<Arc<rustls::ClientConfig>, (ConnectFailure, String)> {
        let now = self.clock.now_unix();
        let op = creds.operational_valid(now).ok_or((ConnectFailure::CertRejected, "no valid operational certificate".into()))?;
        let bundle = creds.bundle.as_ref().ok_or((ConnectFailure::TlsHandshake, "no trust bundle".into()))?;
        let mut cache = lock(&self.tls_cache);
        if let Some((serial, pins, cfg)) = cache.as_ref() {
            if *serial == op.kid && *pins == bundle.ca_pins {
                return Ok(cfg.clone());
            }
        }
        let verifier = PinnedVerifier::new(&creds.anchors, &bundle.ca_pins, tls::provider())
            .map_err(|e| (ConnectFailure::TlsHandshake, e.to_string()))?;
        let cfg = tls::client_config(
            Arc::new(verifier),
            Some(ClientIdentity { chain: vec![op.der.clone()], provider: self.identity.clone(), slot: KeySlot::Operational }),
            &[b"mqtt"],
        )
        .map_err(|e| (ConnectFailure::TlsHandshake, e.to_string()))?;
        *cache = Some((op.kid.clone(), bundle.ca_pins.clone(), cfg.clone()));
        Ok(cfg)
    }

    async fn connect_mqtt(
        &self,
    ) -> Result<(MqttClient, mpsc::Receiver<mqtt::Inbound>, mqtt::ConnectedInfo, String), (ConnectFailure, String)> {
        let creds = read(&self.creds).clone();
        let bundle = creds.bundle.clone().ok_or((ConnectFailure::TlsHandshake, "no trust bundle".to_string()))?;
        let host = self.s.mqtt.host.clone().unwrap_or(bundle.broker_host.clone());
        let port = self.s.mqtt.port.unwrap_or(bundle.broker_port);
        let cfg = self.mqtt_tls(&creds)?;
        let mut opts = MqttOptions::new(self.identity.device_id());
        opts.keep_alive = Duration::from_secs(self.s.mqtt.keep_alive_s.max(1));
        opts.connect_timeout = Duration::from_secs(self.s.mqtt.connect_timeout_s.max(1));
        match mqtt::connect(cfg, &host, port, &opts).await {
            Ok((c, i, info)) => Ok((c, i, info, format!("{host}:{port}"))),
            Err(MqttError::Connect(f, d)) => Err((f, d)),
            Err(e) => Err((ConnectFailure::Network, e.to_string())),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Uplink
    // -----------------------------------------------------------------------------------------

    /// Sign and publish (or buffer) an uplink message; returns its seq.
    async fn publish_uplink(self: &Arc<Self>, class: TopicClass, body: Body, nonce: Option<[u8; 16]>) -> Result<u64, AgentError> {
        let kid = {
            let creds = read(&self.creds);
            let op = creds.operational.as_ref().ok_or(AgentError::State("not provisioned"))?;
            Kid::Bytes(op.kid.clone())
        };
        let seq = self.seq.next()?;
        let msg = Message { seq, ts: self.clock.now_unix(), body, nonce };
        let signer = IdentitySigner { provider: self.identity.clone(), slot: KeySlot::Operational };
        let wire = envelope::encode(&msg, &signer, &kid)?;
        let topic = self.topic(class)?;
        let mut buffer = self.buffer.lock().await;
        let client = lock(&self.client).clone();
        if let (Some(client), true) = (client, buffer.is_empty()) {
            drop(buffer);
            match self.deliver(&client, &topic, wire.clone(), class == TopicClass::Telemetry).await {
                Ok(()) => return Ok(seq),
                Err(code) if code >= 0x80 && code != reason::UNSPECIFIED => {
                    // Broker refused it (ACL / quota): do not retry forever.
                    tracing::warn!(topic, reason_code = code, "uplink refused by broker");
                    return Ok(seq);
                }
                Err(_) => buffer = self.buffer.lock().await,
            }
        }
        buffer.push(Record { seq, topic, payload: wire })?;
        Ok(seq)
    }

    /// Publish one signed envelope with a fresh traceparent; `Err(reason)` if not acknowledged.
    async fn deliver(&self, client: &MqttClient, topic: &str, payload: Vec<u8>, is_telemetry: bool) -> Result<(), u8> {
        let trace = TraceContext::new();
        let props = Properties::new().with_user("traceparent", &trace.traceparent());
        match client.publish(topic, payload, 1, false, props, self.ack_timeout()).await {
            Ok(code) if code < 0x80 => {
                tracing::debug!(trace_id = %trace.trace_id, span_id = %trace.span_id, topic, "uplink acknowledged");
                if is_telemetry {
                    self.health_acked.notify_one();
                }
                Ok(())
            }
            Ok(code) => Err(code),
            Err(_) => Err(reason::UNSPECIFIED),
        }
    }

    async fn flush_buffer(&self, client: &MqttClient) -> bool {
        let (mut count, mut first, mut last) = (0u64, None, 0u64);
        loop {
            let mut buf = self.buffer.lock().await;
            let rec = match buf.peek() {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(e) => {
                    tracing::error!(error = %e, "offline buffer unreadable; dropping record");
                    let _ = buf.pop();
                    continue;
                }
            };
            let telemetry = rec.topic.ends_with("/telemetry");
            match self.deliver(client, &rec.topic, rec.payload.clone(), telemetry).await {
                Ok(()) => {}
                Err(code) if code >= 0x80 && code != reason::UNSPECIFIED => {}
                Err(_) => {
                    if count > 0 {
                        self.emit("buffer_flushed", json!({"count": count, "first_seq": first, "last_seq": last}));
                    }
                    return false;
                }
            }
            let _ = buf.pop();
            count += 1;
            first.get_or_insert(rec.seq);
            last = rec.seq;
        }
        if count > 0 {
            tracing::info!(count, "offline buffer flushed");
            self.emit("buffer_flushed", json!({"count": count, "first_seq": first, "last_seq": last}));
        }
        true
    }

    async fn send_one_telemetry(self: &Arc<Self>) -> Result<u64, AgentError> {
        let fw = {
            let rf = read(&self.running);
            FirmwareInfo { hash: rf.fw_hash, version: rf.version.clone() }
        };
        let now = self.clock.now_unix();
        let t = self.telemetry.lock().await.collect(&fw, now);
        self.publish_uplink(TopicClass::Telemetry, Body::Telemetry(t), None).await
    }

    async fn publish_ota_report(self: &Arc<Self>, r: &OtaReport, dut_error: Option<&str>) {
        let body = OtaStatus {
            campaign_id: r.campaign_id.clone(),
            state: r.state as u8,
            progress_pct: r.progress_pct.min(100),
            error: r.error.clone().filter(|e| !e.is_empty()).map(|e| e.chars().take(1024).collect()),
            fw_hash: r.fw_hash,
        };
        if let Err(e) = self.publish_uplink(TopicClass::OtaStatus, Body::OtaStatus(body), None).await {
            tracing::warn!(error = %e, "cannot publish OtaStatus");
        }
        self.emit(
            "ota_state",
            json!({"campaign_id": r.campaign_id, "state": r.state.name(), "error": dut_error.unwrap_or(""), "code": r.error}),
        );
    }

    // -----------------------------------------------------------------------------------------
    // Inbound
    // -----------------------------------------------------------------------------------------

    fn verify_downlink(&self, topic: &str, bytes: &[u8], class: TopicClass) -> Result<Message, WireError> {
        let tenant = self.identity.tenant_id().to_owned();
        let tenant_kid = ids::tenant_kid(&tenant)?;
        let key = read(&self.creds).bundle.as_ref().and_then(|b| b.tenant_cmd_pubkey).and_then(|k| PublicKey::ed25519_from_raw(&k).ok());
        let resolver = |kid: &Kid| match kid {
            Kid::Text(t) if *t == tenant_kid => key.clone(),
            _ => None,
        };
        let opts = DecodeOptions {
            now: self.clock.now_unix(),
            max_skew: Some(self.s.agent.max_skew_s),
            expected_direction: Some(Direction::Downlink),
            expected_tenant: Some(&tenant),
            expected_nonce: None,
            limits: DecodeLimits::default(),
        };
        // Verify everything but replay first, then record the seq only if the type matches the topic.
        let mut probe = crate::wire::envelope::InMemoryReplayStore::new();
        let verified = envelope::decode(bytes, &resolver, &mut probe, &opts)?;
        if verified.message.message_type() != class.message_type() {
            return Err(WireError::with(ErrorCode::EnvType, format!("type {} on topic {topic}", verified.message.message_type())));
        }
        let stream = envelope::replay_stream(&verified.sender_kid, Direction::Downlink, verified.message.message_type());
        if !lock(&self.replay).check_and_record(&stream, Direction::Downlink, verified.message.seq) {
            return Err(WireError::with(ErrorCode::EnvReplay, format!("seq {} not greater than last accepted", verified.message.seq)));
        }
        Ok(verified.message)
    }

    async fn handle_inbound(self: &Arc<Self>, p: &Publish) -> u8 {
        let parsed = match ids::parse_topic(&p.topic) {
            Ok(t)
                if t.device_id == self.identity.device_id()
                    && t.tenant_id == self.identity.tenant_id()
                    && t.class.direction() == Direction::Downlink =>
            {
                t
            }
            Ok(_) | Err(_) => {
                self.reject(&p.topic, &WireError::new(ErrorCode::TopicFormat, "not one of this device's downlink topics"));
                return reason::TOPIC_NAME_INVALID;
            }
        };
        let bytes = if parsed.class == TopicClass::Config {
            let recipient = IdentityRecipient { provider: self.identity.clone(), slot: KeySlot::Operational };
            match hpke::unwrap_config(&p.payload, &recipient, DecodeLimits::default()) {
                Ok(pt) => pt.to_vec(),
                Err(e) => {
                    self.reject(&p.topic, &e);
                    return reason::IMPLEMENTATION_SPECIFIC;
                }
            }
        } else {
            p.payload.clone()
        };
        let msg = match self.verify_downlink(&p.topic, &bytes, parsed.class) {
            Ok(m) => m,
            Err(e) => {
                self.reject(&p.topic, &e);
                return reason::IMPLEMENTATION_SPECIFIC;
            }
        };
        match msg.body {
            Body::Command(cmd) => self.on_command(cmd, msg.nonce).await,
            Body::ShadowDesired(d) => {
                let applied = lock(&self.shadow).apply_desired(&d);
                match applied {
                    Ok(Some((reported, effects))) => {
                        self.apply_effects(effects);
                        let _ = self.publish_uplink(TopicClass::ShadowReported, Body::ShadowReported(reported), None).await;
                    }
                    Ok(None) => tracing::info!(version = d.version, "stale desired state ignored"),
                    Err(e) => tracing::error!(error = %e, "cannot persist shadow"),
                }
            }
            Body::Config(c) => {
                let applied = lock(&self.config).apply(&c);
                match applied {
                    Ok(Some(effects)) => {
                        self.apply_effects(effects);
                        self.emit("config_applied", json!({"version": c.version}));
                    }
                    Ok(None) => tracing::info!(version = c.version, "stale config ignored"),
                    Err(e) => tracing::error!(error = %e, "cannot persist config"),
                }
            }
            Body::OtaNotify(n) => self.start_ota(n),
            _ => {}
        }
        reason::SUCCESS
    }

    async fn on_command(self: &Arc<Self>, cmd: crate::wire::envelope::Command, nonce: Option<[u8; 16]>) {
        let cached = lock(&self.idem).get(&cmd.idempotency_key).cloned();
        let (ack, effects, replayed): (CommandAck, Vec<Effect>, bool) = match cached {
            Some(a) => (a, Vec::new(), true),
            None => {
                let (a, e) = commands::execute(&cmd, self.clock.now_unix());
                if let Err(err) = lock(&self.idem).insert(&cmd.idempotency_key, &a) {
                    tracing::error!(error = %err, "cannot persist idempotency key");
                }
                (a, e, false)
            }
        };
        tracing::info!(cmd_id = %cmd.cmd_id, name = %cmd.name, status = ack.status, replayed, "command handled");
        if !replayed {
            self.emit("command_executed", json!({"cmd_id": cmd.cmd_id, "status": ack.status}));
        }
        if let Err(e) = self.publish_uplink(TopicClass::CmdAck, Body::CommandAck(ack), nonce).await {
            tracing::warn!(error = %e, "cannot publish CommandAck");
        }
        self.apply_effects(effects);
    }

    fn apply_effects(self: &Arc<Self>, effects: Vec<Effect>) {
        for e in effects {
            match e {
                Effect::TelemetryInterval(i) => {
                    self.interval_s.store(i, Ordering::Relaxed);
                    self.interval_changed.notify_one();
                }
                Effect::LogLevel(l) => {
                    crate::logging::set_level(&l);
                }
                Effect::Reboot(delay) => {
                    let sh = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                        sh.request_reboot(RebootReason::Requested);
                    });
                }
                Effect::SendTelemetry => {
                    let sh = self.clone();
                    tokio::spawn(async move {
                        let _ = sh.send_one_telemetry().await;
                    });
                }
                Effect::Renew => {
                    let sh = self.clone();
                    tokio::spawn(async move {
                        let _ = sh.enroll_now(false, true).await;
                    });
                }
            }
        }
    }

    fn start_ota(self: &Arc<Self>, notify: crate::wire::envelope::OtaNotify) {
        if self.ota_busy.swap(true, Ordering::SeqCst) {
            tracing::warn!(campaign = %notify.campaign_id, "an update is already in progress; notification ignored");
            return;
        }
        let sh = self.clone();
        tokio::spawn(async move {
            let creds = read(&sh.creds).clone();
            let anchors = match &sh.s.ota.download_ca_bundle {
                Some(p) => crate::persist::read_bounded(p, 1 << 20)
                    .ok()
                    .flatten()
                    .and_then(|b| crate::x509::pem_or_der_all(&b).ok())
                    .unwrap_or_default(),
                None => creds.anchors.clone(),
            };
            let download_tls = match ota::download::download_tls_config(&anchors) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "no download trust anchors");
                    sh.ota_busy.store(false, Ordering::SeqCst);
                    return;
                }
            };
            let ctx = OtaContext {
                settings: sh.s.ota.clone(),
                slots: sh.slots.clone(),
                boot: sh.boot.clone(),
                trusted_keys: creds.bundle.map(|b| b.fw_signing_pubkeys).unwrap_or_default(),
                running: read(&sh.running).clone(),
                download_tls,
                timeout: Duration::from_secs(sh.s.pki.timeout_s.max(1)),
            };
            let (tx, mut rx) = mpsc::unbounded_channel::<OtaReport>();
            let reporter_sh = sh.clone();
            let reporter = tokio::spawn(async move {
                while let Some(r) = rx.recv().await {
                    reporter_sh.publish_ota_report(&r, None).await;
                }
            });
            let report = move |r: OtaReport| {
                let _ = tx.send(r);
            };
            let result = ota::stage_update(&ctx, &notify, &report).await;
            drop(report);
            let _ = reporter.await;
            match result {
                Ok(staged) => {
                    tracing::info!(campaign = %notify.campaign_id, slot = staged.slot.name(), version = %staged.manifest.version, "update staged; rebooting");
                    sh.request_reboot(RebootReason::OtaApply);
                }
                Err(f) => {
                    tracing::warn!(campaign = %notify.campaign_id, code = %f.code, detail = %f.detail, "update rejected");
                    let r = OtaReport {
                        campaign_id: notify.campaign_id.clone(),
                        state: OtaState::Rejected,
                        progress_pct: 0,
                        error: Some(f.code.clone()),
                        fw_hash: None,
                    };
                    sh.publish_ota_report(&r, Some(f.dut_reason())).await;
                }
            }
            sh.ota_busy.store(false, Ordering::SeqCst);
        });
    }

    async fn run_session(self: &Arc<Self>, client: MqttClient, mut inbound: mpsc::Receiver<mqtt::Inbound>) -> mqtt::DisconnectInfo {
        // Subscribe to control changes first and force one evaluation, so a change that happens
        // while the session is being set up is never missed.
        let mut stop = self.stop.subscribe();
        let mut want = self.want.subscribe();
        let mut net = self.net_up.subscribe();
        stop.mark_changed();
        want.mark_changed();
        net.mark_changed();
        *lock(&self.client) = Some(client.clone());
        let filters: Vec<(String, u8)> = [TopicClass::ShadowDesired, TopicClass::CmdReq, TopicClass::OtaNotify, TopicClass::Config]
            .into_iter()
            .filter_map(|c| self.topic(c).ok())
            .map(|t| (t, 1))
            .collect();
        match client.subscribe(filters, self.ack_timeout()).await {
            Ok(codes) if codes.iter().any(|c| *c >= 0x80) => tracing::warn!(?codes, "some downlink subscriptions were refused"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "downlink subscription failed"),
        }
        self.flush_buffer(&client).await;
        if lock(&self.health).is_some() {
            let sh = self.clone();
            tokio::spawn(async move {
                let _ = sh.send_one_telemetry().await;
            });
        }
        let info = loop {
            tokio::select! {
                m = inbound.recv() => match m {
                    Some(m) => {
                        let code = self.handle_inbound(&m.publish).await;
                        m.ack(code).await;
                    }
                    None => break client.closed().await,
                },
                info = client.closed() => break info,
                _ = self.reconnect.notified() => {
                    client.disconnect().await;
                    break mqtt::DisconnectInfo { reason: "reconnect with renewed certificate".into(), reason_code: 0 };
                }
                _ = stop.changed() => if *stop.borrow() {
                    client.disconnect().await;
                    break mqtt::DisconnectInfo { reason: "shutdown".into(), reason_code: 0 };
                },
                _ = want.changed() => if !*want.borrow() {
                    client.disconnect().await;
                    break mqtt::DisconnectInfo { reason: "disconnect requested".into(), reason_code: 0 };
                },
                _ = net.changed() => if !*net.borrow() {
                    client.abort().await;
                    break mqtt::DisconnectInfo { reason: "network down".into(), reason_code: reason::UNSPECIFIED };
                },
            }
        };
        *lock(&self.client) = None;
        *lock(&self.broker) = None;
        info
    }
}

async fn wait_change(stop: &mut watch::Receiver<bool>, want: &mut watch::Receiver<bool>, net: &mut watch::Receiver<bool>, max: Duration) {
    tokio::select! {
        _ = stop.changed() => {}
        _ = want.changed() => {}
        _ = net.changed() => {}
        () = tokio::time::sleep(max) => {}
    }
}

async fn supervisor(sh: Arc<Shared>) {
    let mut backoff = Backoff::mqtt();
    let mut enroll_backoff = renewal::retry_backoff();
    let mut stop = sh.stop.subscribe();
    let mut want = sh.want.subscribe();
    let mut net = sh.net_up.subscribe();
    let scale = sh.s.mqtt.backoff_scale;
    loop {
        if *stop.borrow() {
            return;
        }
        let wanted = *want.borrow_and_update();
        let up = *net.borrow_and_update();
        if !wanted || !up {
            sh.set_state(AgentState::Offline);
            wait_change(&mut stop, &mut want, &mut net, Duration::from_secs(3600)).await;
            continue;
        }
        let now = sh.clock.now_unix();
        let creds = read(&sh.creds).clone();
        if creds.operational_valid(now).is_none() || creds.bundle.is_none() {
            if creds.current(now).is_none() {
                sh.set_state(AgentState::Unprovisioned);
                wait_change(&mut stop, &mut want, &mut net, Duration::from_secs(5)).await;
                continue;
            }
            let force_bootstrap = creds.operational_valid(now).is_none();
            if sh.enroll_now(force_bootstrap, false).await.is_err() {
                let d = enroll_backoff.next_delay().mul_f64(scale);
                wait_change(&mut stop, &mut want, &mut net, d).await;
            } else {
                enroll_backoff.reset();
            }
            continue;
        }
        sh.set_state(AgentState::Connecting);
        match sh.connect_mqtt().await {
            Ok((client, inbound, info, broker)) => {
                backoff.reset();
                *lock(&sh.broker) = Some(broker.clone());
                sh.set_state(AgentState::Connected);
                tracing::info!(broker = %broker, tls = %info.tls.version, resumed = info.tls.resumed, session_present = info.session_present, "connected");
                sh.emit(
                    "connected",
                    json!({"broker": broker, "tls_version": info.tls.version, "alpn": info.tls.alpn, "session_present": info.session_present, "resumed": info.tls.resumed}),
                );
                let d = sh.run_session(client, inbound).await;
                tracing::info!(reason = %d.reason, reason_code = d.reason_code, "disconnected");
                sh.emit("disconnected", json!({"reason": d.reason, "reason_code": d.reason_code}));
                sh.set_state(AgentState::Offline);
            }
            Err((failure, detail)) => {
                tracing::warn!(reason = failure.as_str(), detail = %detail, attempt = backoff.attempt(), "connect failed");
                sh.emit("connect_failed", json!({"reason": failure.as_str(), "detail": detail}));
                sh.set_state(AgentState::Backoff);
                let d = backoff.next_delay().mul_f64(scale);
                wait_change(&mut stop, &mut want, &mut net, d).await;
            }
        }
    }
}

async fn telemetry_task(sh: Arc<Shared>) {
    let mut stop = sh.stop.subscribe();
    loop {
        let interval = sh.interval_s.load(Ordering::Relaxed);
        let wait = if interval == 0 { Duration::from_secs(3600) } else { Duration::from_secs(interval) };
        tokio::select! {
            _ = stop.changed() => return,
            () = sh.interval_changed.notified() => continue,
            () = tokio::time::sleep(wait) => {}
        }
        if interval > 0 && read(&sh.creds).operational.is_some() {
            if let Err(e) = sh.send_one_telemetry().await {
                tracing::warn!(error = %e, "telemetry not sent");
            }
        }
    }
}

async fn renewal_task(sh: Arc<Shared>) {
    let mut stop = sh.stop.subscribe();
    let mut retry = renewal::retry_backoff();
    let scale = sh.s.mqtt.backoff_scale;
    loop {
        let now = sh.clock.now_unix();
        let op = read(&sh.creds).operational.clone();
        let mut wait = Duration::from_secs(1);
        if let Some(op) = op {
            let jitter = {
                let mut j = lock(&sh.renew_jitter);
                match j.as_ref() {
                    Some((serial, v)) if *serial == op.kid => *v,
                    _ => {
                        let v = rand::Rng::gen_range(&mut rand::thread_rng(), 0.0..1.0);
                        *j = Some((op.kid.clone(), v));
                        v
                    }
                }
            };
            let renew_at = renewal::renewal_time(op.not_before, op.not_after, jitter);
            let tick = Duration::from_secs((op.lifetime() / 20).clamp(1, 30));
            match renewal::decide(now, renew_at, op.not_after) {
                RenewalAction::WaitUntil(t) => wait = Duration::from_secs(t.saturating_sub(now)).min(tick),
                RenewalAction::Renew => {
                    if sh.enroll_now(false, true).await.is_ok() {
                        retry.reset();
                        continue;
                    }
                    wait = retry.next_delay().mul_f64(scale).max(Duration::from_millis(100));
                }
                RenewalAction::Bootstrap => {
                    // The supervisor re-enrolls with the bootstrap identity when it needs a session.
                    wait = tick;
                }
            }
        }
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

async fn health_task(sh: Arc<Shared>) {
    let deadline = match lock(&sh.health).as_ref() {
        Some(h) => h.deadline,
        None => return,
    };
    let mut stop = sh.stop.subscribe();
    tokio::select! {
        _ = stop.changed() => {}
        () = sh.health_acked.notified() => {
            let Some(h) = lock(&sh.health).take() else { return };
            let p = h.pending;
            if let Err(e) = sh.boot.mark_good() {
                tracing::error!(error = %e, "mark_good failed");
                return;
            }
            let _ = sh.slots.raise_anti_rollback(p.version_code);
            let _ = sh.slots.set_state(p.slot, "valid");
            let _ = sh.slots.set_pending_update(None);
            let fw_hash = read(&sh.running).fw_hash;
            tracing::info!(campaign = %p.campaign_id, slot = p.slot.name(), "update healthy");
            let r = OtaReport { campaign_id: p.campaign_id, state: OtaState::Success, progress_pct: 100, error: None, fw_hash: Some(fw_hash) };
            sh.publish_ota_report(&r, None).await;
        }
        () = tokio::time::sleep_until(deadline) => {
            tracing::error!("health gate missed (no MQTT session with telemetry PUBACK); rolling back");
            let _ = sh.boot.rollback();
            sh.request_reboot(RebootReason::Rollback);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for s in [
            AgentState::Unprovisioned,
            AgentState::Enrolling,
            AgentState::Connecting,
            AgentState::Connected,
            AgentState::Offline,
            AgentState::Backoff,
            AgentState::Rebooting,
        ] {
            assert!(!s.name().is_empty());
        }
        for r in [RebootReason::Requested, RebootReason::OtaApply, RebootReason::Rollback, RebootReason::Watchdog] {
            assert!(!r.name().is_empty());
        }
    }
}
