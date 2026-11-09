//! MQTT 5 broker double, faithful to `services/policy/deploy/emqx/emqx.conf` where it matters:
//!
//! * one mTLS listener: TLS 1.3 only, ALPN `mqtt`, client certificate mandatory and chained to the
//!   Device CA (`verify_peer`, `fail_if_no_peer_cert`), username = certificate CN;
//! * every CONNECT is authenticated by calling the **real** policy service `POST /emqx/authn`, every
//!   PUBLISH / SUBSCRIBE is authorized with `POST /emqx/authz` (bodies rendered like EMQX's
//!   templates), `authorization.deny_action = disconnect`, `max_qos_allowed = 1`;
//! * the EMQX management API `DELETE /api/v5/clients/{clientid}` (HTTP basic auth with the API
//!   key/secret) that the policy service uses to kick revoked sessions;
//! * sessions with `clean_start=false` survive reconnects (session present), retained messages,
//!   QoS 1 delivery of downlinks injected as `svc-registry` (also authorized by the policy).
//!
//! Fault injection: [`BrokerMode`] (rogue CA certificate, TLS 1.2 only), per-client CONNECT
//! refusal, per-client telemetry PUBACK suppression and a silent broker-side session drop.
//! Everything the broker sees is recorded as an [`Obs`] for the cases to assert on.
//!
//! Load mode ([`Broker::set_load_mode`]): the observation log is switched off (it would keep every
//! payload of a 10 000-device run) and the broker keeps only counters, hook round-trip timings
//! ([`BrokerStats`]) and an optional tap of accepted client publishes for the uplink verifier.
//! Subscriptions without wildcards are indexed by topic, so routing a publish does not scan every
//! session.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::delete;
use axum::Router;
use base64::Engine;
use ironmesh_agent::mqtt::codec::{self, prop, ConnAck, Disconnect, Packet, PropValue, Properties, PubAck, Publish, SubAck};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc};

use super::net::{self, ClientAuth, Versions};
use super::pki::{self, TestPki};
use crate::load::stats::Recorder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Broker-side counters and hook timings (atomics; hook timings only in load mode).
#[derive(Default)]
pub struct BrokerStats {
    /// TLS handshakes that completed.
    pub handshakes_ok: AtomicU64,
    /// TLS handshakes that failed (reasons in `handshake_errors`).
    pub handshakes_failed: AtomicU64,
    /// CONNECTs accepted (CONNACK 0).
    pub connects_ok: AtomicU64,
    /// CONNECTs refused (authn deny, hook failure or injected refusal).
    pub connects_denied: AtomicU64,
    /// Client PUBLISHes the policy allowed.
    pub publishes_accepted: AtomicU64,
    /// Of which on `.../telemetry`.
    pub telemetry_accepted: AtomicU64,
    /// Client PUBLISHes the policy denied.
    pub publishes_denied: AtomicU64,
    /// SUBSCRIBE filters granted.
    pub subscribes_granted: AtomicU64,
    /// SUBSCRIBE filters denied.
    pub subscribes_denied: AtomicU64,
    /// QoS 1 downlinks handed to sessions.
    pub downlinks_delivered: AtomicU64,
    /// PUBACKs received for downlinks.
    pub downlink_acks: AtomicU64,
    /// authn/authz hook calls that failed at the transport level (treated as deny: fail closed).
    pub hook_errors: AtomicU64,
    /// Sessions currently open.
    pub live_sessions: AtomicI64,
    /// Highest number of simultaneously open sessions.
    pub peak_sessions: AtomicI64,
    /// Session ends by cause.
    pub closes: Mutex<BTreeMap<String, u64>>,
    /// Handshake failures by error text.
    pub handshake_errors: Mutex<BTreeMap<String, u64>>,
    /// Hook transport errors by text.
    pub hook_error_texts: Mutex<BTreeMap<String, u64>>,
    /// `POST /emqx/authn` round trips seen by the broker (load mode only).
    pub authn_latency: Recorder,
    /// `POST /emqx/authz` round trips seen by the broker (load mode only).
    pub authz_latency: Recorder,
}

fn bump(m: &Mutex<BTreeMap<String, u64>>, key: String) {
    *lock(m).entry(key).or_default() += 1;
}

/// An accepted client PUBLISH handed to the tap (load-mode uplink verification).
#[derive(Debug, Clone)]
pub struct Tapped {
    /// When the broker accepted it (before the PUBACK was queued).
    pub at: Instant,
    /// Client id.
    pub client_id: String,
    /// Topic.
    pub topic: String,
    /// Payload.
    pub payload: Vec<u8>,
}

/// TLS identities of the broker listener.
pub struct BrokerCerts {
    /// The genuine broker certificate (chain to the pinned Services CA) and key.
    pub normal: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    /// Rogue CA impersonating the Services CA name.
    pub rogue: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    /// Rogue CA with its own name.
    pub rogue_distinct: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    /// Anchors for client certificates (Root + Device CA).
    pub client_anchors: Vec<Vec<u8>>,
    /// The `svc-registry` client certificate (Services CA) the downlink publisher connects with.
    pub service_client: Option<Vec<u8>>,
}

impl BrokerCerts {
    /// Everything from the hermetic PKI.
    #[must_use]
    pub fn hermetic(pki: &TestPki) -> Self {
        Self {
            normal: (pki.broker.chain(&pki.services), pki.broker.key()),
            rogue: (pki.rogue_broker.chain(&pki.rogue), pki.rogue_broker.key()),
            rogue_distinct: (pki.rogue_distinct_broker.chain(&pki.rogue_distinct), pki.rogue_distinct_broker.key()),
            client_anchors: vec![pki.root.der.clone(), pki.device.der.clone()],
            service_client: Some(pki.registry_client.der.clone()),
        }
    }
}
use super::policy::{AuthnDecision, AuthnRequest, AuthzRequest, ClientAttrs, PolicyClient};

/// The authn request EMQX renders for a CONNECT on the mTLS listener, exactly as the
/// `authentication.body` template of `services/policy/deploy/emqx/emqx.conf`: `username` = the
/// certificate CN (`peer_cert_as_username = cn`), `cert_subject` in RFC 4514 form, `cert_pem` = the
/// presented leaf certificate and `cert_serial` = its serial (`${client_attrs.cert_serial}`, set by
/// `mqtt.client_attrs_init` from the TLS peer certificate - never from client-controlled fields).
#[must_use]
pub fn emqx_authn_request(client_id: &str, peerhost: &str, leaf_der: &[u8], facts: &pki::CertFacts) -> AuthnRequest {
    let cn = facts.cn.clone().unwrap_or_default();
    AuthnRequest {
        clientid: client_id.to_owned(),
        username: cn.clone(),
        peerhost: peerhost.to_owned(),
        cert_common_name: cn,
        cert_subject: facts.subject.clone(),
        cert_pem: Some(crate::util::pem("CERTIFICATE", leaf_der)),
        cert_serial: Some(facts.serial_hex.clone()),
    }
}

/// What the TLS listener presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerMode {
    /// Services CA certificate, TLS 1.3 only (the contract broker).
    Normal,
    /// Certificate from an unpinned rogue CA that impersonates the Services CA's name (C-TLS-2).
    Rogue,
    /// Certificate from an unpinned rogue CA with its own name (C-TLS-2).
    RogueUnknownCa,
    /// TLS 1.2 only (C-TLS-3).
    Tls12Only,
}

/// What happens on an authz deny for PUBLISH (`authorization.deny_action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// Disconnect the client (the IronMesh EMQX configuration).
    Disconnect,
    /// PUBACK with 0x87.
    Ignore,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseCause {
    /// Client sent DISCONNECT.
    ClientDisconnect,
    /// Transport closed / error.
    Closed,
    /// Kicked through the management API.
    Kicked,
    /// Disconnected after an authz deny (`deny_action = disconnect`).
    DeniedPublish,
    /// Taken over by a new connection with the same client id.
    TakenOver,
    /// Dropped by the harness (network partition, broker side).
    Dropped,
    /// Protocol violation.
    Protocol(String),
}

/// One broker-side observation.
#[derive(Debug, Clone)]
pub enum ObsKind {
    /// TLS handshake result.
    Handshake {
        /// Succeeded.
        ok: bool,
        /// Error text when it failed.
        error: Option<String>,
        /// Negotiated version (`TLSv1.3`).
        version: Option<String>,
        /// Negotiated ALPN.
        alpn: Option<String>,
        /// Resumed (PSK / ticket).
        resumed: bool,
        /// Client certificate serial (hex).
        client_serial: Option<String>,
        /// Client certificate CN.
        client_cn: Option<String>,
        /// Mode of the listener.
        mode: BrokerMode,
    },
    /// CONNECT and its outcome.
    Connect {
        /// Client id.
        client_id: String,
        /// Clean start.
        clean_start: bool,
        /// Session expiry interval property.
        session_expiry: Option<u32>,
        /// Keep alive.
        keep_alive: u16,
        /// Receive maximum property.
        receive_maximum: Option<u32>,
        /// Certificate serial used.
        cert_serial: Option<String>,
        /// Policy authn allowed it.
        authn_allow: bool,
        /// CONNACK reason.
        reason_code: u8,
        /// Session present flag sent.
        session_present: bool,
    },
    /// PUBLISH from a client.
    Publish {
        /// Client id.
        client_id: String,
        /// Topic.
        topic: String,
        /// QoS.
        qos: u8,
        /// Retain.
        retain: bool,
        /// Payload.
        payload: Vec<u8>,
        /// Policy authz allowed it.
        allowed: bool,
    },
    /// SUBSCRIBE filter.
    Subscribe {
        /// Client id.
        client_id: String,
        /// Filter.
        filter: String,
        /// Granted.
        granted: bool,
    },
    /// The client acknowledged a downlink.
    DownlinkAck {
        /// Client id.
        client_id: String,
        /// Packet id.
        packet_id: u16,
        /// Reason code.
        reason_code: u8,
    },
    /// Downlink delivered by the harness.
    Delivered {
        /// Client id.
        client_id: String,
        /// Topic.
        topic: String,
        /// Packet id.
        packet_id: u16,
        /// Retained flag on delivery.
        retain: bool,
    },
    /// Session ended.
    Closed {
        /// Client id.
        client_id: String,
        /// Cause.
        cause: CloseCause,
    },
    /// Management API kick.
    Kick {
        /// Client id.
        client_id: String,
        /// A session was found and closed.
        found: bool,
    },
}

/// A timestamped observation.
#[derive(Debug, Clone)]
pub struct Obs {
    /// When.
    pub at: Instant,
    /// Connection number.
    pub conn: u64,
    /// What.
    pub kind: ObsKind,
}

impl Obs {
    /// The client id this observation is about.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        match &self.kind {
            ObsKind::Handshake { client_cn, .. } => client_cn.as_deref(),
            ObsKind::Connect { client_id, .. }
            | ObsKind::Publish { client_id, .. }
            | ObsKind::Subscribe { client_id, .. }
            | ObsKind::DownlinkAck { client_id, .. }
            | ObsKind::Delivered { client_id, .. }
            | ObsKind::Closed { client_id, .. }
            | ObsKind::Kick { client_id, .. } => Some(client_id),
        }
    }
}

struct Conn {
    id: u64,
    tx: mpsc::UnboundedSender<Packet>,
    kill: Arc<tokio::sync::Notify>,
    abort: Arc<std::sync::atomic::AtomicBool>,
    next_pid: u16,
    cert_serial: Option<String>,
}

#[derive(Default)]
struct Session {
    subs: Vec<String>,
}

#[derive(Default)]
struct BrokerState {
    conns: HashMap<String, Conn>,
    sessions: HashMap<String, Session>,
    retained: HashMap<String, Vec<u8>>,
    refuse: HashMap<String, u8>,
    drop_telemetry_acks: HashSet<String>,
    certs: HashMap<String, Vec<Vec<u8>>>,
    log: Vec<Obs>,
    /// Subscribers of wildcard-free filters, by filter (= topic).
    exact_subs: HashMap<String, HashSet<String>>,
    /// Clients whose session holds at least one wildcard filter.
    wildcard_clients: HashSet<String>,
}

fn has_wildcard(filter: &str) -> bool {
    filter.contains('+') || filter.contains('#')
}

impl BrokerState {
    /// Forget the subscription index entries of `client_id` (its session is being replaced).
    fn unindex(&mut self, client_id: &str) {
        if let Some(sess) = self.sessions.get(client_id) {
            for f in &sess.subs {
                if let Some(set) = self.exact_subs.get_mut(f) {
                    set.remove(client_id);
                    if set.is_empty() {
                        self.exact_subs.remove(f);
                    }
                }
            }
        }
        self.wildcard_clients.remove(client_id);
    }

    /// Clients whose session has a filter matching `topic` (each once).
    fn matching_sessions(&self, topic: &str) -> Vec<String> {
        let mut out: Vec<String> = self.exact_subs.get(topic).map(|c| c.iter().cloned().collect()).unwrap_or_default();
        for c in &self.wildcard_clients {
            if out.contains(c) {
                continue;
            }
            if self.sessions.get(c).is_some_and(|sess| sess.subs.iter().any(|f| has_wildcard(f) && topic_matches(f, topic))) {
                out.push(c.clone());
            }
        }
        out
    }
}

struct Inner {
    mode: Mutex<BrokerMode>,
    normal: Arc<rustls::ServerConfig>,
    rogue: Arc<rustls::ServerConfig>,
    rogue_distinct: Arc<rustls::ServerConfig>,
    tls12: Arc<rustls::ServerConfig>,
    policy: PolicyClient,
    deny_action: DenyAction,
    state: Mutex<BrokerState>,
    obs_tx: broadcast::Sender<Obs>,
    next_conn: Mutex<u64>,
    mgmt_auth: String,
    stats: Arc<BrokerStats>,
    load_mode: AtomicBool,
    tap: OnceLock<mpsc::UnboundedSender<Tapped>>,
    /// `svc-registry` client certificate and the session attributes its CONNECT was admitted with.
    service_cert: Option<Vec<u8>>,
    service_session: tokio::sync::Mutex<Option<ClientAttrs>>,
}

/// The running broker double.
#[derive(Clone)]
pub struct Broker {
    /// MQTT over TLS listener.
    pub addr: SocketAddr,
    /// Management API (plain HTTP).
    pub mgmt_addr: SocketAddr,
    /// Management API key.
    pub mgmt_key: String,
    /// Management API secret.
    pub mgmt_secret: String,
    inner: Arc<Inner>,
}

/// Lock helper that survives poisoning.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// MQTT topic filter matching (`+`, `#`).
#[must_use]
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    let f: Vec<&str> = filter.split('/').collect();
    let t: Vec<&str> = topic.split('/').collect();
    for (i, seg) in f.iter().enumerate() {
        match *seg {
            "#" => return i <= t.len(),
            "+" => {
                if i >= t.len() {
                    return false;
                }
            }
            s => {
                if t.get(i) != Some(&s) {
                    return false;
                }
            }
        }
    }
    f.len() == t.len()
}

async fn read_packet<S: tokio::io::AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>, timeout: Duration) -> Option<Packet> {
    let mut chunk = [0u8; 8192];
    loop {
        match codec::decode(buf, 1 << 20) {
            Ok(Some((p, n))) => {
                buf.drain(..n);
                return Some(p);
            }
            Ok(None) => {}
            Err(_) => return None,
        }
        let n = match tokio::time::timeout(timeout, s.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            _ => return None,
        };
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn props_connack() -> Properties {
    Properties::new()
        .with(prop::RECEIVE_MAXIMUM, PropValue::U16(32))
        .with(prop::MAXIMUM_QOS, PropValue::Byte(1))
        .with(prop::RETAIN_AVAILABLE, PropValue::Byte(1))
        .with(prop::MAXIMUM_PACKET_SIZE, PropValue::U32(64 * 1024))
}

impl Broker {
    /// Start the broker and its management API on `host` (random ports).
    ///
    /// # Errors
    /// Bind / TLS configuration failures.
    pub async fn start(host: &str, certs: BrokerCerts, policy: PolicyClient, deny_action: DenyAction) -> Result<Self> {
        let key = format!("conformance-{}", hex::encode(crate::util::random_bytes(4)));
        let secret = hex::encode(crate::util::random_bytes(16));
        Self::start_with_mgmt(host, 0, certs, policy, deny_action, key, secret).await
    }

    /// Start with a fixed management API port and credentials.
    ///
    /// # Errors
    /// Bind / TLS configuration failures.
    pub async fn start_with_mgmt(
        host: &str,
        mgmt_port: u16,
        certs: BrokerCerts,
        policy: PolicyClient,
        deny_action: DenyAction,
        mgmt_key: String,
        mgmt_secret: String,
    ) -> Result<Self> {
        let anchors: Vec<&[u8]> = certs.client_anchors.iter().map(Vec::as_slice).collect();
        let client_roots = net::roots(&anchors)?;
        let mk = |id: &(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), v: Versions| {
            net::server_config(id.0.clone(), id.1.clone_key(), ClientAuth::Required(client_roots.clone()), v, &[b"mqtt"])
        };
        let normal = mk(&certs.normal, Versions::Tls13Only)?;
        let rogue = mk(&certs.rogue, Versions::Tls13Only)?;
        let rogue_distinct = mk(&certs.rogue_distinct, Versions::Tls13Only)?;
        let tls12 = mk(&certs.normal, Versions::Tls12Only)?;
        let mgmt_auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{mgmt_key}:{mgmt_secret}")));
        let (obs_tx, _) = broadcast::channel(4096);
        let inner = Arc::new(Inner {
            mode: Mutex::new(BrokerMode::Normal),
            normal,
            rogue,
            rogue_distinct,
            tls12,
            policy,
            deny_action,
            state: Mutex::new(BrokerState::default()),
            obs_tx,
            next_conn: Mutex::new(0),
            mgmt_auth,
            stats: Arc::new(BrokerStats::default()),
            load_mode: AtomicBool::new(false),
            tap: OnceLock::new(),
            service_cert: certs.service_client.clone(),
            service_session: tokio::sync::Mutex::new(None),
        });
        let listener = net::bind(host, 0).await?;
        let addr = listener.local_addr()?;
        let mgmt_listener = net::bind(host, mgmt_port).await?;
        let mgmt_addr = mgmt_listener.local_addr()?;
        let router = Router::new().route("/api/v5/clients/{clientid}", delete(mgmt_kick)).with_state(inner.clone());
        net::serve_http(mgmt_listener, router);
        let acc_inner = inner.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else { return };
                tcp.set_nodelay(true).ok();
                let inner = acc_inner.clone();
                tokio::spawn(async move { handle_tcp(inner, tcp, peer).await });
            }
        });
        Ok(Self { addr, mgmt_addr, mgmt_key, mgmt_secret, inner })
    }

    /// Management API base URL (for `POLICY_EMQX_API_URL`).
    #[must_use]
    pub fn mgmt_url(&self) -> String {
        format!("http://{}", self.mgmt_addr)
    }

    /// Load mode: no observation log (counters and hook timings only). Cases that assert on
    /// observations must not run in this mode.
    pub fn set_load_mode(&self, on: bool) {
        self.inner.load_mode.store(on, Ordering::SeqCst);
    }

    /// Counters and hook timings.
    #[must_use]
    pub fn stats(&self) -> Arc<BrokerStats> {
        self.inner.stats.clone()
    }

    /// Receive every accepted client PUBLISH (set once; returns `false` if a tap was already set).
    pub fn set_tap(&self, tx: mpsc::UnboundedSender<Tapped>) -> bool {
        self.inner.tap.set(tx).is_ok()
    }

    /// Switch the listener mode (applies to new connections).
    pub fn set_mode(&self, mode: BrokerMode) {
        *lock(&self.inner.mode) = mode;
    }

    /// Refuse CONNECTs from `client_id` with `reason_code` (`None` lifts the refusal).
    pub fn refuse(&self, client_id: &str, reason_code: Option<u8>) {
        let mut s = lock(&self.inner.state);
        match reason_code {
            Some(c) => {
                s.refuse.insert(client_id.to_owned(), c);
            }
            None => {
                s.refuse.remove(client_id);
            }
        }
    }

    /// Withhold PUBACKs for telemetry of `client_id`.
    pub fn drop_telemetry_acks(&self, client_id: &str, on: bool) {
        let mut s = lock(&self.inner.state);
        if on {
            s.drop_telemetry_acks.insert(client_id.to_owned());
        } else {
            s.drop_telemetry_acks.remove(client_id);
        }
    }

    /// Whether `client_id` has a live session.
    #[must_use]
    pub fn is_connected(&self, client_id: &str) -> bool {
        lock(&self.inner.state).conns.contains_key(client_id)
    }

    /// Certificate serial of the live session of `client_id`.
    #[must_use]
    pub fn session_serial(&self, client_id: &str) -> Option<String> {
        lock(&self.inner.state).conns.get(client_id).and_then(|c| c.cert_serial.clone())
    }

    /// Drop the live session without a DISCONNECT (broker-side network partition).
    pub fn drop_session(&self, client_id: &str) -> bool {
        let conn = lock(&self.inner.state).conns.remove(client_id);
        match conn {
            Some(c) => {
                self.inner.record(c.id, ObsKind::Closed { client_id: client_id.to_owned(), cause: CloseCause::Dropped });
                c.abort.store(true, std::sync::atomic::Ordering::SeqCst);
                c.kill.notify_one();
                true
            }
            None => false,
        }
    }

    /// Client certificates the device presented (any session), DER.
    #[must_use]
    pub fn client_certs(&self, client_id: &str) -> Vec<Vec<u8>> {
        lock(&self.inner.state).certs.get(client_id).cloned().unwrap_or_default()
    }

    /// Every observation so far.
    #[must_use]
    pub fn observations(&self) -> Vec<Obs> {
        lock(&self.inner.state).log.clone()
    }

    /// Observations about `client_id` (handshakes are matched on the certificate CN).
    #[must_use]
    pub fn observations_for(&self, client_id: &str) -> Vec<Obs> {
        lock(&self.inner.state).log.iter().filter(|o| o.client_id() == Some(client_id)).cloned().collect()
    }

    /// Observations since `t`.
    #[must_use]
    pub fn observations_since(&self, t: Instant) -> Vec<Obs> {
        lock(&self.inner.state).log.iter().filter(|o| o.at >= t).cloned().collect()
    }

    /// Accepted publishes of `client_id` on topics ending in `suffix`.
    #[must_use]
    pub fn accepted_publishes(&self, client_id: &str, suffix: &str) -> Vec<(Instant, Vec<u8>)> {
        lock(&self.inner.state)
            .log
            .iter()
            .filter_map(|o| match &o.kind {
                ObsKind::Publish { client_id: c, topic, payload, allowed: true, .. } if c == client_id && topic.ends_with(suffix) => {
                    Some((o.at, payload.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Every accepted publish to exactly `topic` (any client).
    #[must_use]
    pub fn accepted_on_topic(&self, topic: &str) -> usize {
        lock(&self.inner.state)
            .log
            .iter()
            .filter(|o| matches!(&o.kind, ObsKind::Publish { topic: t, allowed: true, .. } if t == topic))
            .count()
    }

    /// Connected clients whose session subscribes to a filter matching `topic`.
    #[must_use]
    pub fn subscribers(&self, topic: &str) -> usize {
        let s = lock(&self.inner.state);
        s.matching_sessions(topic).iter().filter(|c| s.conns.contains_key(*c)).count()
    }

    /// Retained message on `topic`.
    #[must_use]
    pub fn retained(&self, topic: &str) -> Option<Vec<u8>> {
        lock(&self.inner.state).retained.get(topic).cloned()
    }

    /// Subscribe to the observation stream.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Obs> {
        self.inner.obs_tx.subscribe()
    }

    /// Wait (up to `timeout`) for an observation matching `pred` that happened at or after `since`.
    pub async fn wait_obs(&self, since: Instant, timeout: Duration, pred: impl Fn(&Obs) -> bool) -> Option<Obs> {
        let mut rx = self.subscribe();
        if let Some(o) = self.observations_since(since).into_iter().find(|o| pred(o)) {
            return Some(o);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(o)) if o.at >= since && pred(&o) => return Some(o),
                Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
                _ => return self.observations_since(since).into_iter().find(|o| pred(o)),
            }
        }
    }

    /// Publish a downlink as the registry service (`svc-registry`): authorized by the policy
    /// service like any other client publish, retained if asked, delivered (QoS 1) to every
    /// connected subscriber. Returns the packet ids used per delivered client.
    ///
    /// # Errors
    /// Policy denial or transport failures towards the policy.
    pub async fn inject(&self, topic: &str, payload: Vec<u8>, retain: bool) -> Result<Vec<(String, u16)>> {
        let attrs = self.service_session().await?;
        let allowed = self
            .inner
            .policy
            .authz(&AuthzRequest {
                clientid: SERVICE_CLIENT.into(),
                username: SERVICE_CLIENT.into(),
                peerhost: "127.0.0.1".into(),
                topic: topic.to_owned(),
                action: "publish",
                qos: 1,
                retain,
                attrs,
            })
            .await?;
        if !allowed {
            return Err(anyhow!("policy denied svc-registry publish to {topic} (retain={retain})"));
        }
        Ok(self.inner.route(topic, &payload, retain, true))
    }

    /// The `svc-registry` session: its CONNECT is authenticated once by the policy authn hook with
    /// the Services CA client certificate (`cert_pem` + `cert_serial`, issuer checked against
    /// `POLICY_SERVICES_CA_FILE`), like the registry's long-lived MQTT connection to EMQX; later
    /// publishes reuse the admitted session attributes.
    ///
    /// # Errors
    /// The policy refusing the service identity, or a hook failure.
    pub async fn service_session(&self) -> Result<ClientAttrs> {
        let mut s = self.inner.service_session.lock().await;
        if let Some(a) = s.as_ref() {
            return Ok(a.clone());
        }
        let attrs = match &self.inner.service_cert {
            Some(der) => {
                let d = self.replay_connect_authn(SERVICE_CLIENT, der, "127.0.0.1").await?;
                if !d.allow {
                    return Err(anyhow!("the policy authn hook refused the svc-registry CONNECT (Services CA client certificate)"));
                }
                d.attrs.unwrap_or_else(|| ClientAttrs { kind: "service".into(), ..ClientAttrs::default() })
            }
            None => ClientAttrs { tenant_id: String::new(), device_id: String::new(), kind: "service".into() },
        };
        *s = Some(attrs.clone());
        Ok(attrs)
    }

    /// Ask the policy authn hook what it decides for a CONNECT from `client_id` presenting the
    /// certificate `leaf_der` from `peerhost` - the request EMQX would send for that TLS session
    /// ([`emqx_authn_request`]). No session is opened.
    ///
    /// # Errors
    /// Unparsable certificate or a hook failure.
    pub async fn replay_connect_authn(&self, client_id: &str, leaf_der: &[u8], peerhost: &str) -> Result<AuthnDecision> {
        let facts = pki::cert_facts(leaf_der)?;
        self.inner.policy.authn(&emqx_authn_request(client_id, peerhost, leaf_der, &facts)).await
    }
}

/// Client id (= CN) of the registry's downlink publisher.
pub const SERVICE_CLIENT: &str = "svc-registry";

impl Inner {
    fn record(&self, conn: u64, kind: ObsKind) {
        if self.load_mode.load(Ordering::Relaxed) {
            return;
        }
        let o = Obs { at: Instant::now(), conn, kind };
        lock(&self.state).log.push(o.clone());
        let _ = self.obs_tx.send(o);
    }

    /// Route a message to subscribers (and the retained store). Returns deliveries.
    fn route(&self, topic: &str, payload: &[u8], retain: bool, from_cloud: bool) -> Vec<(String, u16)> {
        let mut delivered = Vec::new();
        let mut records = Vec::new();
        {
            let mut s = lock(&self.state);
            if retain {
                if payload.is_empty() {
                    s.retained.remove(topic);
                } else {
                    s.retained.insert(topic.to_owned(), payload.to_vec());
                }
            }
            let targets = s.matching_sessions(topic);
            for client in targets {
                if let Some(conn) = s.conns.get_mut(&client) {
                    conn.next_pid = conn.next_pid.wrapping_add(1).max(1);
                    let pid = conn.next_pid;
                    let p = Publish {
                        dup: false,
                        qos: 1,
                        retain: false,
                        topic: topic.to_owned(),
                        packet_id: Some(pid),
                        properties: Properties::new(),
                        payload: payload.to_vec(),
                    };
                    if conn.tx.send(Packet::Publish(p)).is_ok() {
                        delivered.push((client.clone(), pid));
                        records.push((conn.id, client.clone(), pid));
                    }
                }
            }
        }
        let _ = from_cloud;
        self.stats.downlinks_delivered.fetch_add(records.len() as u64, Ordering::Relaxed);
        for (cid, client, pid) in records {
            self.record(cid, ObsKind::Delivered { client_id: client, topic: topic.to_owned(), packet_id: pid, retain: false });
        }
        delivered
    }

    /// Account for one hook call; the decision, or `None` on a transport failure (deny).
    fn hook_done<T>(&self, hook: &str, started: Instant, r: Result<T>) -> Option<T> {
        if self.load_mode.load(Ordering::Relaxed) {
            let rec = if hook == "authn" { &self.stats.authn_latency } else { &self.stats.authz_latency };
            rec.record(started.elapsed());
        }
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                self.stats.hook_errors.fetch_add(1, Ordering::Relaxed);
                bump(&self.stats.hook_error_texts, format!("{hook}: {e:#}"));
                None
            }
        }
    }

    fn next_conn_id(&self) -> u64 {
        let mut n = lock(&self.next_conn);
        *n += 1;
        *n
    }
}

async fn mgmt_kick(State(inner): State<Arc<Inner>>, Path(client_id): Path<String>, h: HeaderMap) -> Response {
    if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(inner.mgmt_auth.as_str()) {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"code": "BAD_API_KEY_OR_SECRET"}))).into_response();
    }
    let conn = lock(&inner.state).conns.remove(&client_id);
    match conn {
        Some(c) => {
            let _ = c.tx.send(Packet::Disconnect(Disconnect { reason_code: 0x98, properties: Properties::new() }));
            c.kill.notify_one();
            inner.record(c.id, ObsKind::Kick { client_id: client_id.clone(), found: true });
            inner.record(c.id, ObsKind::Closed { client_id, cause: CloseCause::Kicked });
            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            inner.record(0, ObsKind::Kick { client_id, found: false });
            (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"code": "CLIENTID_NOT_FOUND"}))).into_response()
        }
    }
}

async fn handle_tcp(inner: Arc<Inner>, tcp: tokio::net::TcpStream, peer: SocketAddr) {
    let conn_id = inner.next_conn_id();
    let mode = *lock(&inner.mode);
    let cfg = match mode {
        BrokerMode::Normal => inner.normal.clone(),
        BrokerMode::Rogue => inner.rogue.clone(),
        BrokerMode::RogueUnknownCa => inner.rogue_distinct.clone(),
        BrokerMode::Tls12Only => inner.tls12.clone(),
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            inner.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
            bump(&inner.stats.handshake_errors, e.to_string());
            inner.record(
                conn_id,
                ObsKind::Handshake {
                    ok: false,
                    error: Some(e.to_string()),
                    version: None,
                    alpn: None,
                    resumed: false,
                    client_serial: None,
                    client_cn: None,
                    mode,
                },
            );
            return;
        }
        Err(_) => {
            inner.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
            bump(&inner.stats.handshake_errors, "handshake timeout".into());
            inner.record(
                conn_id,
                ObsKind::Handshake {
                    ok: false,
                    error: Some("handshake timeout".into()),
                    version: None,
                    alpn: None,
                    resumed: false,
                    client_serial: None,
                    client_cn: None,
                    mode,
                },
            );
            return;
        }
    };
    let (version, alpn, resumed, leaf) = {
        let c = tls.get_ref().1;
        (
            c.protocol_version().map(|v| match v {
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
                other => format!("{other:?}"),
            }),
            c.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned()),
            matches!(c.handshake_kind(), Some(rustls::HandshakeKind::Resumed)),
            c.peer_certificates().and_then(|p| p.first()).map(|c| c.to_vec()),
        )
    };
    inner.stats.handshakes_ok.fetch_add(1, Ordering::Relaxed);
    let facts = leaf.as_ref().and_then(|d| pki::cert_facts(d).ok());
    if let (Some(d), Some(cn)) = (&leaf, facts.as_ref().and_then(|f| f.cn.clone())) {
        let mut st = lock(&inner.state);
        let v = st.certs.entry(cn).or_default();
        if !v.contains(d) {
            v.push(d.clone());
        }
    }
    inner.record(
        conn_id,
        ObsKind::Handshake {
            ok: true,
            error: None,
            version,
            alpn,
            resumed,
            client_serial: facts.as_ref().map(|f| f.serial_hex.clone()),
            client_cn: facts.as_ref().and_then(|f| f.cn.clone()),
            mode,
        },
    );
    let (mut rd, mut wr) = tokio::io::split(tls);
    let mut buf = Vec::new();
    let Some(Packet::Connect(c)) = read_packet(&mut rd, &mut buf, Duration::from_secs(10)).await else { return };
    let client_id = c.client_id.clone();
    let cn = facts.as_ref().and_then(|f| f.cn.clone()).unwrap_or_default();
    let serial = facts.as_ref().map(|f| f.serial_hex.clone());
    let session_expiry = c.properties.get_u32(prop::SESSION_EXPIRY);
    let receive_maximum = c.properties.get_u32(prop::RECEIVE_MAXIMUM);
    let connect_obs = |allow: bool, rc: u8, sp: bool| ObsKind::Connect {
        client_id: client_id.clone(),
        clean_start: c.clean_start,
        session_expiry,
        keep_alive: c.keep_alive,
        receive_maximum,
        cert_serial: serial.clone(),
        authn_allow: allow,
        reason_code: rc,
        session_present: sp,
    };
    let refuse = lock(&inner.state).refuse.get(&client_id).copied();
    let reject = |code: u8| Packet::ConnAck(ConnAck { session_present: false, reason_code: code, properties: Properties::new() });
    if let Some(code) = refuse {
        inner.stats.connects_denied.fetch_add(1, Ordering::Relaxed);
        inner.record(conn_id, connect_obs(false, code, false));
        if let Ok(b) = reject(code).encode() {
            let _ = wr.write_all(&b).await;
        }
        let _ = wr.shutdown().await;
        return;
    }
    let decision = match (&facts, &leaf) {
        (Some(f), Some(der)) => {
            let t = Instant::now();
            let r = inner.policy.authn(&emqx_authn_request(&client_id, &peer.ip().to_string(), der, f)).await;
            inner.hook_done("authn", t, r)
        }
        _ => None,
    };
    let Some(decision) = decision.filter(|d| d.allow) else {
        inner.stats.connects_denied.fetch_add(1, Ordering::Relaxed);
        inner.record(conn_id, connect_obs(false, codec::reason::NOT_AUTHORIZED, false));
        if let Ok(b) = reject(codec::reason::NOT_AUTHORIZED).encode() {
            let _ = wr.write_all(&b).await;
        }
        let _ = wr.shutdown().await;
        return;
    };
    let attrs = decision.attrs.unwrap_or_default();
    let (tx, mut rx) = mpsc::unbounded_channel::<Packet>();
    let kill = Arc::new(tokio::sync::Notify::new());
    let abort = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (session_present, old) = {
        let mut s = lock(&inner.state);
        let present = !c.clean_start && s.sessions.contains_key(&client_id);
        if c.clean_start || !present {
            s.unindex(&client_id);
            s.sessions.insert(client_id.clone(), Session::default());
        }
        let old = s.conns.insert(
            client_id.clone(),
            Conn { id: conn_id, tx: tx.clone(), kill: kill.clone(), abort: abort.clone(), next_pid: 0, cert_serial: serial.clone() },
        );
        (present, old)
    };
    if let Some(old) = old {
        let _ = old.tx.send(Packet::Disconnect(Disconnect { reason_code: 0x8e, properties: Properties::new() }));
        old.kill.notify_one();
        inner.record(old.id, ObsKind::Closed { client_id: client_id.clone(), cause: CloseCause::TakenOver });
    }
    inner.stats.connects_ok.fetch_add(1, Ordering::Relaxed);
    let live = inner.stats.live_sessions.fetch_add(1, Ordering::Relaxed) + 1;
    inner.stats.peak_sessions.fetch_max(live, Ordering::Relaxed);
    inner.record(conn_id, connect_obs(true, 0, session_present));
    let ack = Packet::ConnAck(ConnAck { session_present, reason_code: 0, properties: props_connack() });
    match ack.encode() {
        Ok(b) if wr.write_all(&b).await.is_ok() => {}
        _ => {
            inner.stats.live_sessions.fetch_sub(1, Ordering::Relaxed);
            bump(&inner.stats.closes, "connack_write_failed".into());
            return;
        }
    }
    let writer = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            let disconnect = matches!(p, Packet::Disconnect(_));
            let Ok(bytes) = p.encode() else { break };
            if wr.write_all(&bytes).await.is_err() || disconnect {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    let keep_alive = Duration::from_secs(u64::from(c.keep_alive.max(1)) * 3 / 2 + 1);
    let mut cause = CloseCause::Closed;
    loop {
        let p = tokio::select! {
            p = read_packet(&mut rd, &mut buf, keep_alive) => match p { Some(p) => p, None => break },
            () = kill.notified() => break, // kicked, dropped or taken over
        };
        match p {
            Packet::Publish(p) => {
                if p.qos > 1 {
                    let _ = tx.send(Packet::Disconnect(Disconnect { reason_code: 0x9b, properties: Properties::new() }));
                    cause = CloseCause::Protocol("QoS 2 not supported".into());
                    break;
                }
                let t = Instant::now();
                let r = inner
                    .policy
                    .authz(&AuthzRequest {
                        clientid: client_id.clone(),
                        username: cn.clone(),
                        peerhost: peer.ip().to_string(),
                        topic: p.topic.clone(),
                        action: "publish",
                        qos: p.qos,
                        retain: p.retain,
                        attrs: attrs.clone(),
                    })
                    .await;
                let allowed = inner.hook_done("authz", t, r).unwrap_or(false);
                if allowed {
                    inner.stats.publishes_accepted.fetch_add(1, Ordering::Relaxed);
                    if p.topic.ends_with("/telemetry") {
                        inner.stats.telemetry_accepted.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(tap) = inner.tap.get() {
                        let _ = tap.send(Tapped {
                            at: Instant::now(),
                            client_id: client_id.clone(),
                            topic: p.topic.clone(),
                            payload: p.payload.clone(),
                        });
                    }
                } else {
                    inner.stats.publishes_denied.fetch_add(1, Ordering::Relaxed);
                }
                inner.record(
                    conn_id,
                    ObsKind::Publish {
                        client_id: client_id.clone(),
                        topic: p.topic.clone(),
                        qos: p.qos,
                        retain: p.retain,
                        payload: p.payload.clone(),
                        allowed,
                    },
                );
                if !allowed && inner.deny_action == DenyAction::Disconnect {
                    let _ = tx
                        .send(Packet::Disconnect(Disconnect { reason_code: codec::reason::NOT_AUTHORIZED, properties: Properties::new() }));
                    cause = CloseCause::DeniedPublish;
                    break;
                }
                if allowed {
                    inner.route(&p.topic, &p.payload, p.retain, false);
                }
                let suppress = allowed && p.topic.ends_with("/telemetry") && lock(&inner.state).drop_telemetry_acks.contains(&client_id);
                if let (Some(id), false) = (p.packet_id, suppress) {
                    let rc = if allowed { 0 } else { codec::reason::NOT_AUTHORIZED };
                    let _ = tx.send(Packet::PubAck(PubAck { packet_id: id, reason_code: rc, properties: Properties::new() }));
                }
            }
            Packet::Subscribe(s) => {
                let mut codes = Vec::new();
                let mut granted_filters = Vec::new();
                for (filter, opts) in &s.filters {
                    let qos = opts & 0x03;
                    let t = Instant::now();
                    let r = inner
                        .policy
                        .authz(&AuthzRequest {
                            clientid: client_id.clone(),
                            username: cn.clone(),
                            peerhost: peer.ip().to_string(),
                            topic: filter.clone(),
                            action: "subscribe",
                            qos: qos.min(1),
                            retain: false,
                            attrs: attrs.clone(),
                        })
                        .await;
                    let allowed = inner.hook_done("authz", t, r).unwrap_or(false);
                    if allowed {
                        inner.stats.subscribes_granted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        inner.stats.subscribes_denied.fetch_add(1, Ordering::Relaxed);
                    }
                    inner.record(conn_id, ObsKind::Subscribe { client_id: client_id.clone(), filter: filter.clone(), granted: allowed });
                    if allowed {
                        codes.push(qos.min(1));
                        granted_filters.push(filter.clone());
                    } else {
                        codes.push(codec::reason::NOT_AUTHORIZED);
                    }
                }
                let _ = tx.send(Packet::SubAck(SubAck { packet_id: s.packet_id, properties: Properties::new(), reason_codes: codes }));
                // Store the subscriptions, then deliver retained messages for them.
                let retained: Vec<(String, Vec<u8>)> = {
                    let mut st = lock(&inner.state);
                    let mut added = Vec::new();
                    if let Some(sess) = st.sessions.get_mut(&client_id) {
                        for f in &granted_filters {
                            if !sess.subs.contains(f) {
                                sess.subs.push(f.clone());
                                added.push(f.clone());
                            }
                        }
                    }
                    for f in added {
                        if has_wildcard(&f) {
                            st.wildcard_clients.insert(client_id.clone());
                        } else {
                            st.exact_subs.entry(f).or_default().insert(client_id.clone());
                        }
                    }
                    st.retained
                        .iter()
                        .filter(|(t, _)| granted_filters.iter().any(|f| topic_matches(f, t)))
                        .map(|(t, p)| (t.clone(), p.clone()))
                        .collect()
                };
                for (topic, payload) in retained {
                    let pid = {
                        let mut st = lock(&inner.state);
                        st.conns.get_mut(&client_id).map(|cc| {
                            cc.next_pid = cc.next_pid.wrapping_add(1).max(1);
                            cc.next_pid
                        })
                    };
                    if let Some(pid) = pid {
                        let _ = tx.send(Packet::Publish(Publish {
                            dup: false,
                            qos: 1,
                            retain: true,
                            topic: topic.clone(),
                            packet_id: Some(pid),
                            properties: Properties::new(),
                            payload,
                        }));
                        inner.record(conn_id, ObsKind::Delivered { client_id: client_id.clone(), topic, packet_id: pid, retain: true });
                    }
                }
            }
            Packet::PubAck(a) => {
                inner.stats.downlink_acks.fetch_add(1, Ordering::Relaxed);
                inner.record(
                    conn_id,
                    ObsKind::DownlinkAck { client_id: client_id.clone(), packet_id: a.packet_id, reason_code: a.reason_code },
                );
            }
            Packet::PingReq => {
                let _ = tx.send(Packet::PingResp);
            }
            Packet::Disconnect(_) => {
                cause = CloseCause::ClientDisconnect;
                break;
            }
            other => {
                cause = CloseCause::Protocol(format!("unexpected packet {other:?}"));
                break;
            }
        }
    }
    let removed = {
        let mut s = lock(&inner.state);
        if s.conns.get(&client_id).is_some_and(|cc| cc.id == conn_id) {
            s.conns.remove(&client_id);
            true
        } else {
            false
        }
    };
    inner.stats.live_sessions.fetch_sub(1, Ordering::Relaxed);
    let label = match &cause {
        CloseCause::ClientDisconnect => "client_disconnect".to_owned(),
        CloseCause::Closed if !removed => "kicked_or_taken_over".to_owned(),
        CloseCause::Closed => "transport_closed_or_keepalive".to_owned(),
        CloseCause::Kicked => "kicked".to_owned(),
        CloseCause::DeniedPublish => "denied_publish".to_owned(),
        CloseCause::TakenOver => "taken_over".to_owned(),
        CloseCause::Dropped => "dropped".to_owned(),
        CloseCause::Protocol(p) => format!("protocol: {p}"),
    };
    bump(&inner.stats.closes, label);
    if removed {
        inner.record(conn_id, ObsKind::Closed { client_id: client_id.clone(), cause });
    }
    drop(tx);
    if abort.load(std::sync::atomic::Ordering::SeqCst) {
        writer.abort();
    } else {
        let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert!(topic_matches("im/v1/t/d/cmd/req", "im/v1/t/d/cmd/req"));
        assert!(topic_matches("im/v1/#", "im/v1/t/d/cmd/req"));
        assert!(topic_matches("im/v1/+/d/telemetry", "im/v1/t/d/telemetry"));
        assert!(!topic_matches("im/v1/+/d/telemetry", "im/v1/t/e/telemetry"));
        assert!(!topic_matches("im/v1/t/d", "im/v1/t/d/telemetry"));
        assert!(topic_matches("#", "a/b"));
        assert!(topic_matches("a/#", "a"));
    }
}
