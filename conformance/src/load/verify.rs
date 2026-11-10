//! Cloud-side checks of the load test, standing in for the bridge's uplink verification:
//!
//! * every accepted Telemetry / CommandAck publish is verified (COSE_Sign1 ES256 with the key of
//!   the certificate the device presented to the broker, direction, timestamp, and the per-device
//!   replay stream: `seq` strictly increasing), sharded by device so per-device order is kept;
//! * downlink commands are tracked from injection to the verified CommandAck (cmd_id, nonce
//!   echo), which gives the command round trip.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose::Kid;
use ironmesh_agent::wire::envelope::{self, Body, DecodeOptions, InMemoryReplayStore, Message};
use ironmesh_agent::wire::error::ErrorCode;
use ironmesh_agent::wire::ids::{self, Direction, TopicClass};
use ironmesh_agent::wire::keys::PublicKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use tokio::sync::mpsc;

use super::stats::Recorder;
use crate::harness::broker::{Broker, Tapped};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A command waiting for its ack.
struct Pending {
    device: String,
    sent: Instant,
    message: Message,
}

/// Downlink command bookkeeping.
#[derive(Default)]
pub struct CmdTracker {
    pending: Mutex<HashMap<String, Pending>>,
    /// Injection (svc-registry publish, policy authz included) -> verified CommandAck accepted by
    /// the broker.
    pub rtt: Recorder,
    /// Commands signed and injected.
    pub sent: AtomicU64,
    /// Injected but no subscribed session (device offline).
    pub not_delivered: AtomicU64,
    /// Injection failed (policy denied the svc-registry publish or hook failure).
    pub inject_errors: AtomicU64,
    /// Acks that matched a pending command (cmd_id, device, nonce echo).
    pub acked: AtomicU64,
    /// Acks that did not match (unknown cmd_id, other device, nonce mismatch).
    pub ack_mismatch: AtomicU64,
    /// Ack status codes (0 ok, 1 rejected, 2 failed, 3 expired).
    pub ack_status: Mutex<BTreeMap<u8, u64>>,
}

impl CmdTracker {
    /// Remember an injected command.
    pub fn sent(&self, device: &str, cmd_id: &str, message: Message, sent: Instant) {
        self.sent.fetch_add(1, Ordering::Relaxed);
        lock(&self.pending).insert(cmd_id.to_owned(), Pending { device: device.to_owned(), sent, message });
    }

    /// Forget a command that could not be delivered.
    pub fn undeliverable(&self, cmd_id: &str, inject_error: bool) {
        lock(&self.pending).remove(cmd_id);
        if inject_error {
            self.inject_errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.not_delivered.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A verified CommandAck arrived.
    pub fn on_ack(&self, device: &str, ack: &Message, at: Instant) {
        let Body::CommandAck(a) = &ack.body else { return };
        let p = lock(&self.pending).remove(&a.cmd_id);
        match p {
            Some(p) if p.device == device && envelope::check_ack(&p.message, ack).is_ok() => {
                self.rtt.record(at.saturating_duration_since(p.sent));
                self.acked.fetch_add(1, Ordering::Relaxed);
                *lock(&self.ack_status).entry(a.status).or_default() += 1;
            }
            _ => {
                self.ack_mismatch.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Commands still waiting for an ack.
    #[must_use]
    pub fn unacked(&self) -> u64 {
        lock(&self.pending).len() as u64
    }
}

/// Verification results.
#[derive(Default)]
pub struct Verifier {
    /// Uplinks verified (signature, profile, timestamp, replay stream).
    pub verified: AtomicU64,
    /// Of which Telemetry.
    pub telemetry: AtomicU64,
    /// Of which CommandAck.
    pub acks: AtomicU64,
    /// Accepted publishes on other topics (not verified here).
    pub other: AtomicU64,
    /// Failures by wire error code.
    pub failures: Mutex<BTreeMap<String, u64>>,
    /// `ENV_REPLAY` rejections (seq not greater than the last accepted one).
    pub replay_rejections: AtomicU64,
    /// Messages queued for verification and not processed yet.
    pub backlog: AtomicI64,
    /// Highest backlog seen.
    pub peak_backlog: AtomicI64,
    /// Last verified uplink seq per device.
    pub last_seq: Mutex<HashMap<String, u64>>,
}

struct DeviceKeys {
    store: InMemoryReplayStore,
    keys: HashMap<Vec<u8>, PublicKey>,
}

fn refresh_keys(broker: &Broker, device: &str, keys: &mut HashMap<Vec<u8>, PublicKey>) {
    for der in broker.client_certs(device) {
        if let Ok(info) = ironmesh_agent::x509::parse_cert(&der) {
            if let Some(pk) = info.p256 {
                if let Ok(k) = PublicKey::p256_from_sec1(pk.to_sec1_point(false).as_bytes()) {
                    keys.insert(info.kid.clone(), k);
                }
            }
        }
    }
}

fn verify_one(v: &Verifier, cmds: &CmdTracker, broker: &Broker, devs: &mut HashMap<String, DeviceKeys>, t: &Tapped) {
    let class = match ids::parse_topic(&t.topic) {
        Ok(p) if p.device_id == t.client_id && matches!(p.class, TopicClass::Telemetry | TopicClass::CmdAck) => p.class,
        _ => {
            v.other.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let dev = devs.entry(t.client_id.clone()).or_insert_with(|| DeviceKeys { store: InMemoryReplayStore::new(), keys: HashMap::new() });
    let opts = DecodeOptions {
        now: crate::util::now_unix(),
        expected_direction: Some(Direction::Uplink),
        limits: DecodeLimits::default(),
        ..Default::default()
    };
    let mut result = None;
    for attempt in 0..2 {
        let keys = &dev.keys;
        let resolver = |kid: &Kid| match kid {
            Kid::Bytes(b) => keys.get(b).cloned(),
            Kid::Text(_) => None,
        };
        let r = envelope::decode(&t.payload, &resolver, &mut dev.store, &opts);
        match r {
            Err(e) if attempt == 0 && e.code() == ErrorCode::EnvUnknownKey => refresh_keys(broker, &t.client_id, &mut dev.keys),
            other => {
                result = Some(other);
                break;
            }
        }
    }
    match result {
        Some(Ok(ok)) => {
            if ok.message.message_type() != class.message_type() {
                *lock(&v.failures).entry("ENV_TYPE (type does not match topic)".into()).or_default() += 1;
                return;
            }
            v.verified.fetch_add(1, Ordering::Relaxed);
            {
                let mut ls = lock(&v.last_seq);
                let e = ls.entry(t.client_id.clone()).or_default();
                *e = (*e).max(ok.message.seq);
            }
            match class {
                TopicClass::Telemetry => {
                    v.telemetry.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    v.acks.fetch_add(1, Ordering::Relaxed);
                    cmds.on_ack(&t.client_id, &ok.message, t.at);
                }
            }
        }
        Some(Err(e)) => {
            if e.code() == ErrorCode::EnvReplay {
                v.replay_rejections.fetch_add(1, Ordering::Relaxed);
            }
            *lock(&v.failures).entry(e.code().as_str().to_owned()).or_default() += 1;
        }
        None => {}
    }
}

/// Start the verifier: returns the results, the sender to give the broker's tap and the task.
#[must_use]
pub fn spawn(
    broker: Broker,
    cmds: Arc<CmdTracker>,
    shards: usize,
) -> (Arc<Verifier>, mpsc::UnboundedSender<Tapped>, tokio::task::JoinHandle<()>) {
    let v = Arc::new(Verifier::default());
    let (tx, mut rx) = mpsc::unbounded_channel::<Tapped>();
    let mut shard_tx = Vec::new();
    let mut tasks = Vec::new();
    for _ in 0..shards.max(1) {
        let (stx, mut srx) = mpsc::unbounded_channel::<Tapped>();
        shard_tx.push(stx);
        let (v, cmds, broker) = (v.clone(), cmds.clone(), broker.clone());
        tasks.push(tokio::spawn(async move {
            let mut devs = HashMap::new();
            while let Some(t) = srx.recv().await {
                verify_one(&v, &cmds, &broker, &mut devs, &t);
                v.backlog.fetch_sub(1, Ordering::Relaxed);
            }
        }));
    }
    let vv = v.clone();
    let task = tokio::spawn(async move {
        while let Some(t) = rx.recv().await {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            t.client_id.hash(&mut h);
            let i = (h.finish() % shard_tx.len() as u64) as usize;
            let b = vv.backlog.fetch_add(1, Ordering::Relaxed) + 1;
            vv.peak_backlog.fetch_max(b, Ordering::Relaxed);
            let _ = shard_tx[i].send(t);
        }
        drop(shard_tx);
        for t in tasks {
            let _ = t.await;
        }
    });
    (v, tx, task)
}
