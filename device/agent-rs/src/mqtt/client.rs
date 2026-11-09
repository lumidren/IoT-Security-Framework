//! Asynchronous MQTT 5 client over a pinned TLS 1.3 stream.
//!
//! Session parameters follow `DESIGN_CONTRACT.md` §4: `clean_start = false`, session expiry
//! 7 days, receive maximum 32, keep-alive 60 s, client id = certificate CN. Outbound QoS 1
//! publishes respect the broker's receive maximum; inbound QoS 1 messages are delivered through a
//! bounded channel (capacity = our receive maximum) and acknowledged by the consumer *after* it
//! has processed them.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::codec::{
    self, prop, reason, CodecError, ConnAck, Connect, Disconnect, Packet, PropValue, Properties, PubAck, Publish, SubAck, Subscribe,
};
use crate::tls::{self, ConnectFailure, TlsInfo};

/// Client options.
#[derive(Debug, Clone)]
pub struct MqttOptions {
    /// Client identifier (= certificate CN).
    pub client_id: String,
    /// Keep alive.
    pub keep_alive: Duration,
    /// Session expiry interval (s).
    pub session_expiry_s: u32,
    /// Receive maximum we announce.
    pub receive_maximum: u16,
    /// Clean start.
    pub clean_start: bool,
    /// Maximum packet size we accept.
    pub max_packet_size: usize,
    /// Connect / handshake / CONNACK timeout.
    pub connect_timeout: Duration,
}

impl MqttOptions {
    /// Contract defaults.
    #[must_use]
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            keep_alive: Duration::from_secs(60),
            session_expiry_s: 7 * 24 * 3600,
            receive_maximum: 32,
            clean_start: false,
            max_packet_size: 256 * 1024,
            connect_timeout: Duration::from_secs(20),
        }
    }
}

/// Client-level error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MqttError {
    /// Could not connect.
    #[error("connect failed ({reason}): {1}", reason = .0.as_str())]
    Connect(ConnectFailure, String),
    /// The connection is closed.
    #[error("connection closed: {0}")]
    Closed(String),
    /// Timed out waiting for an acknowledgement.
    #[error("timed out waiting for the broker")]
    Timeout,
    /// Protocol error.
    #[error("protocol: {0}")]
    Protocol(String),
}

/// Result of CONNECT.
#[derive(Debug, Clone)]
pub struct ConnectedInfo {
    /// Session present flag.
    pub session_present: bool,
    /// TLS facts.
    pub tls: TlsInfo,
    /// Broker receive maximum.
    pub server_receive_maximum: u16,
    /// Broker maximum packet size, if announced.
    pub server_max_packet_size: Option<u32>,
}

/// Why the connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectInfo {
    /// Human-readable reason.
    pub reason: String,
    /// MQTT reason code (from DISCONNECT or local).
    pub reason_code: u8,
}

enum Cmd {
    Publish(Publish, Option<oneshot::Sender<u8>>),
    Subscribe(Vec<(String, u8)>, oneshot::Sender<Vec<u8>>),
    Ack(u16, u8),
    Disconnect(u8),
    Abort,
}

/// An inbound PUBLISH; QoS 1 messages must be acknowledged with [`Inbound::ack`].
#[derive(Debug)]
pub struct Inbound {
    /// The message.
    pub publish: Publish,
    ack: Option<(mpsc::Sender<Cmd>, u16)>,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cmd")
    }
}

impl Inbound {
    /// Acknowledge (PUBACK) with a reason code.
    pub async fn ack(mut self, reason_code: u8) {
        if let Some((tx, id)) = self.ack.take() {
            let _ = tx.send(Cmd::Ack(id, reason_code)).await;
        }
    }
}

/// Handle to a live MQTT session.
#[derive(Clone)]
pub struct MqttClient {
    tx: mpsc::Sender<Cmd>,
    closed: watch::Receiver<Option<DisconnectInfo>>,
}

impl MqttClient {
    /// Publish and (QoS 1) wait for the PUBACK reason code.
    ///
    /// # Errors
    /// [`MqttError::Closed`] or [`MqttError::Timeout`].
    pub async fn publish(
        &self,
        topic: &str,
        payload: Vec<u8>,
        qos: u8,
        retain: bool,
        properties: Properties,
        timeout: Duration,
    ) -> Result<u8, MqttError> {
        let publish = Publish { dup: false, qos, retain, topic: topic.to_owned(), packet_id: None, properties, payload };
        if qos == 0 {
            self.tx.send(Cmd::Publish(publish, None)).await.map_err(|_| self.closed_err())?;
            return Ok(reason::SUCCESS);
        }
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Publish(publish, Some(tx))).await.map_err(|_| self.closed_err())?;
        match tokio::time::timeout(timeout, rx).await {
            Err(_) => Err(MqttError::Timeout),
            Ok(Err(_)) => Err(self.closed_err()),
            Ok(Ok(code)) => Ok(code),
        }
    }

    /// Subscribe; returns one reason code per filter.
    ///
    /// # Errors
    /// [`MqttError::Closed`] or [`MqttError::Timeout`].
    pub async fn subscribe(&self, filters: Vec<(String, u8)>, timeout: Duration) -> Result<Vec<u8>, MqttError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Subscribe(filters, tx)).await.map_err(|_| self.closed_err())?;
        match tokio::time::timeout(timeout, rx).await {
            Err(_) => Err(MqttError::Timeout),
            Ok(Err(_)) => Err(self.closed_err()),
            Ok(Ok(codes)) => Ok(codes),
        }
    }

    /// Send DISCONNECT and close.
    pub async fn disconnect(&self) {
        let _ = self.tx.send(Cmd::Disconnect(reason::SUCCESS)).await;
    }

    /// Drop the connection without sending anything (simulated link loss).
    pub async fn abort(&self) {
        let _ = self.tx.send(Cmd::Abort).await;
    }

    /// Wait until the session ends.
    pub async fn closed(&self) -> DisconnectInfo {
        let mut rx = self.closed.clone();
        loop {
            if let Some(info) = rx.borrow().clone() {
                return info;
            }
            if rx.changed().await.is_err() {
                return rx
                    .borrow()
                    .clone()
                    .unwrap_or(DisconnectInfo { reason: "session task ended".into(), reason_code: reason::UNSPECIFIED });
            }
        }
    }

    /// Whether the session has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.borrow().is_some() || self.tx.is_closed()
    }

    fn closed_err(&self) -> MqttError {
        MqttError::Closed(self.closed.borrow().as_ref().map_or_else(|| "session ended".into(), |d| d.reason.clone()))
    }
}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>, max: usize) -> Result<Packet, MqttError> {
    let mut chunk = [0u8; 4096];
    loop {
        match codec::decode(buf, max) {
            Ok(Some((packet, n))) => {
                buf.drain(..n);
                return Ok(packet);
            }
            Ok(None) => {}
            Err(e) => return Err(MqttError::Protocol(e.to_string())),
        }
        let n = stream.read(&mut chunk).await.map_err(|e| MqttError::Closed(e.to_string()))?;
        if n == 0 {
            return Err(MqttError::Closed("connection closed by peer".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Connect over TLS, perform the MQTT handshake and spawn the session task.
///
/// # Errors
/// [`MqttError::Connect`] with a classified failure.
pub async fn connect(
    tls_config: Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    opts: &MqttOptions,
) -> Result<(MqttClient, mpsc::Receiver<Inbound>, ConnectedInfo), MqttError> {
    let (stream, tls_info) = tls::connect(tls_config, host, port, opts.connect_timeout).await.map_err(|(f, d)| MqttError::Connect(f, d))?;
    connect_on(stream, tls_info, opts).await
}

/// MQTT handshake on an established transport (used by [`connect`] and by tests).
///
/// # Errors
/// [`MqttError::Connect`].
pub async fn connect_on<S>(
    mut stream: S,
    tls_info: TlsInfo,
    opts: &MqttOptions,
) -> Result<(MqttClient, mpsc::Receiver<Inbound>, ConnectedInfo), MqttError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connect = Packet::Connect(Connect {
        clean_start: opts.clean_start,
        keep_alive: u16::try_from(opts.keep_alive.as_secs()).unwrap_or(u16::MAX),
        properties: Properties::new()
            .with(prop::SESSION_EXPIRY, PropValue::U32(opts.session_expiry_s))
            .with(prop::RECEIVE_MAXIMUM, PropValue::U16(opts.receive_maximum))
            .with(prop::MAXIMUM_PACKET_SIZE, PropValue::U32(u32::try_from(opts.max_packet_size).unwrap_or(u32::MAX))),
        client_id: opts.client_id.clone(),
        will: None,
        username: None,
        password: None,
    });
    let bytes = connect.encode().map_err(|e| MqttError::Connect(ConnectFailure::Network, e.to_string()))?;
    let io = |e: std::io::Error| MqttError::Connect(ConnectFailure::Network, e.to_string());
    tokio::time::timeout(opts.connect_timeout, stream.write_all(&bytes))
        .await
        .map_err(|_| MqttError::Connect(ConnectFailure::Timeout, "CONNECT write timed out".into()))?
        .map_err(io)?;
    let mut buf = Vec::new();
    let first = tokio::time::timeout(opts.connect_timeout, read_packet(&mut stream, &mut buf, opts.max_packet_size))
        .await
        .map_err(|_| MqttError::Connect(ConnectFailure::Timeout, "no CONNACK".into()))?;
    let ack: ConnAck = match first {
        Ok(Packet::ConnAck(a)) => a,
        Ok(_) => return Err(MqttError::Connect(ConnectFailure::Network, "expected CONNACK".into())),
        Err(MqttError::Closed(d)) => return Err(MqttError::Connect(ConnectFailure::CertRejected, d)),
        Err(e) => return Err(MqttError::Connect(ConnectFailure::Network, e.to_string())),
    };
    if ack.reason_code != reason::SUCCESS {
        let detail = format!("CONNACK reason 0x{:02x} {}", ack.reason_code, ack.properties.reason_string().unwrap_or(""));
        return Err(MqttError::Connect(ConnectFailure::NotAuthorized, detail));
    }
    let server_receive_maximum =
        ack.properties.get_u32(prop::RECEIVE_MAXIMUM).map_or(65535, |v| u16::try_from(v).unwrap_or(u16::MAX)).max(1);
    let keep_alive = ack.properties.get_u32(prop::SERVER_KEEP_ALIVE).map_or(opts.keep_alive, |s| Duration::from_secs(u64::from(s)));
    let info = ConnectedInfo {
        session_present: ack.session_present,
        tls: tls_info,
        server_receive_maximum,
        server_max_packet_size: ack.properties.get_u32(prop::MAXIMUM_PACKET_SIZE),
    };
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (in_tx, in_rx) = mpsc::channel(usize::from(opts.receive_maximum.max(1)));
    let (closed_tx, closed_rx) = watch::channel(None);
    let session = Session {
        buf,
        max_packet: opts.max_packet_size,
        keep_alive,
        receive_max: server_receive_maximum,
        next_id: 1,
        inflight: HashMap::new(),
        queued: VecDeque::new(),
        subs: HashMap::new(),
        cmd_tx: cmd_tx.clone(),
        in_tx,
    };
    tokio::spawn(async move {
        let info = session.run(stream, cmd_rx).await;
        let _ = closed_tx.send(Some(info));
    });
    Ok((MqttClient { tx: cmd_tx, closed: closed_rx }, in_rx, info))
}

struct Session {
    buf: Vec<u8>,
    max_packet: usize,
    keep_alive: Duration,
    receive_max: u16,
    next_id: u16,
    inflight: HashMap<u16, Option<oneshot::Sender<u8>>>,
    queued: VecDeque<(Publish, Option<oneshot::Sender<u8>>)>,
    subs: HashMap<u16, oneshot::Sender<Vec<u8>>>,
    cmd_tx: mpsc::Sender<Cmd>,
    in_tx: mpsc::Sender<Inbound>,
}

fn closed(reason: impl Into<String>, reason_code: u8) -> DisconnectInfo {
    DisconnectInfo { reason: reason.into(), reason_code }
}

impl Session {
    fn alloc_id(&mut self) -> u16 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if !self.inflight.contains_key(&id) && !self.subs.contains_key(&id) {
                return id;
            }
        }
    }

    async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W, p: &Packet) -> Result<(), DisconnectInfo> {
        let bytes = p.encode().map_err(|e| closed(e.to_string(), reason::PACKET_TOO_LARGE))?;
        w.write_all(&bytes).await.map_err(|e| closed(e.to_string(), reason::UNSPECIFIED))
    }

    async fn send_publish<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        mut p: Publish,
        reply: Option<oneshot::Sender<u8>>,
    ) -> Result<(), DisconnectInfo> {
        if p.qos > 0 {
            if self.inflight.len() >= usize::from(self.receive_max) {
                self.queued.push_back((p, reply));
                return Ok(());
            }
            let id = self.alloc_id();
            p.packet_id = Some(id);
            self.inflight.insert(id, reply);
        }
        self.write(w, &Packet::Publish(p)).await
    }

    async fn run<S: AsyncRead + AsyncWrite + Unpin>(mut self, stream: S, mut cmds: mpsc::Receiver<Cmd>) -> DisconnectInfo {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut last_rx = Instant::now();
        let mut last_tx = Instant::now();
        let mut chunk = vec![0u8; 8192];
        let tick = (self.keep_alive / 4).max(Duration::from_millis(50));
        let mut ticker = tokio::time::interval(tick);
        loop {
            // Drain any complete packets already buffered.
            loop {
                match codec::decode(&self.buf, self.max_packet) {
                    Ok(Some((packet, n))) => {
                        self.buf.drain(..n);
                        last_rx = Instant::now();
                        if let Err(info) = self.on_packet(&mut wr, packet).await {
                            return info;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let code = match e {
                            CodecError::TooLarge(_) => reason::PACKET_TOO_LARGE,
                            CodecError::Unsupported(_) => reason::PROTOCOL_ERROR,
                            CodecError::Malformed(_) => reason::MALFORMED,
                        };
                        let _ =
                            self.write(&mut wr, &Packet::Disconnect(Disconnect { reason_code: code, properties: Properties::new() })).await;
                        return closed(e.to_string(), code);
                    }
                }
            }
            tokio::select! {
                read = rd.read(&mut chunk) => match read {
                    Ok(0) => return closed("connection closed by broker", reason::UNSPECIFIED),
                    Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return closed(e.to_string(), reason::UNSPECIFIED),
                },
                cmd = cmds.recv() => {
                    let Some(cmd) = cmd else {
                        let _ = self.write(&mut wr, &Packet::Disconnect(Disconnect { reason_code: 0, properties: Properties::new() })).await;
                        return closed("client dropped", reason::SUCCESS);
                    };
                    last_tx = Instant::now();
                    let result = match cmd {
                        Cmd::Publish(p, reply) => self.send_publish(&mut wr, p, reply).await,
                        Cmd::Subscribe(filters, reply) => {
                            let id = self.alloc_id();
                            self.subs.insert(id, reply);
                            self.write(&mut wr, &Packet::Subscribe(Subscribe { packet_id: id, properties: Properties::new(), filters })).await
                        }
                        Cmd::Ack(id, code) => self.write(&mut wr, &Packet::PubAck(PubAck { packet_id: id, reason_code: code, properties: Properties::new() })).await,
                        Cmd::Abort => return closed("link down", reason::UNSPECIFIED),
                        Cmd::Disconnect(code) => {
                            let _ = self.write(&mut wr, &Packet::Disconnect(Disconnect { reason_code: code, properties: Properties::new() })).await;
                            let _ = wr.shutdown().await;
                            return closed("client disconnect", code);
                        }
                    };
                    if let Err(info) = result {
                        return info;
                    }
                },
                _ = ticker.tick() => {
                    if last_rx.elapsed() > self.keep_alive + self.keep_alive / 2 {
                        return closed("keep alive timeout", reason::KEEP_ALIVE_TIMEOUT);
                    }
                    if last_tx.elapsed() >= self.keep_alive / 2 {
                        last_tx = Instant::now();
                        if let Err(info) = self.write(&mut wr, &Packet::PingReq).await {
                            return info;
                        }
                    }
                }
            }
        }
    }

    async fn on_packet<W: AsyncWrite + Unpin>(&mut self, wr: &mut W, packet: Packet) -> Result<(), DisconnectInfo> {
        match packet {
            Packet::Publish(p) => {
                if p.qos > 1 {
                    return Err(closed("QoS 2 is not used by IronMesh", reason::PROTOCOL_ERROR));
                }
                let ack = p.packet_id.map(|id| (self.cmd_tx.clone(), id));
                if self.in_tx.send(Inbound { publish: p, ack }).await.is_err() {
                    return Err(closed("inbound consumer gone", reason::UNSPECIFIED));
                }
                Ok(())
            }
            Packet::PubAck(a) => {
                if let Some(reply) = self.inflight.remove(&a.packet_id) {
                    if let Some(r) = reply {
                        let _ = r.send(a.reason_code);
                    }
                    if let Some((p, reply)) = self.queued.pop_front() {
                        self.send_publish(wr, p, reply).await?;
                    }
                }
                Ok(())
            }
            Packet::SubAck(SubAck { packet_id, reason_codes, .. }) => {
                if let Some(reply) = self.subs.remove(&packet_id) {
                    let _ = reply.send(reason_codes);
                }
                Ok(())
            }
            Packet::PingResp => Ok(()),
            Packet::Disconnect(d) => Err(closed(
                format!("broker DISCONNECT 0x{:02x} {}", d.reason_code, d.properties.reason_string().unwrap_or("")),
                d.reason_code,
            )),
            other => {
                let _ = other;
                Err(closed("unexpected packet from broker", reason::PROTOCOL_ERROR))
            }
        }
    }
}

/// Exponential backoff with full jitter: `delay = random(0, min(cap, base * factor^attempt))`.
#[derive(Debug, Clone)]
pub struct Backoff {
    /// Base.
    pub base: Duration,
    /// Factor.
    pub factor: u32,
    /// Cap.
    pub cap: Duration,
    attempt: u32,
}

impl Backoff {
    /// Contract MQTT reconnect backoff (base 1 s, factor 2, cap 300 s).
    #[must_use]
    pub fn mqtt() -> Self {
        Self::new(Duration::from_secs(1), 2, Duration::from_secs(300))
    }

    /// Custom backoff.
    #[must_use]
    pub fn new(base: Duration, factor: u32, cap: Duration) -> Self {
        Self { base, factor, cap, attempt: 0 }
    }

    /// Upper bound of the next delay.
    #[must_use]
    pub fn ceiling(&self) -> Duration {
        let mult = u64::from(self.factor).saturating_pow(self.attempt.min(40));
        let ms = u64::try_from(self.base.as_millis()).unwrap_or(u64::MAX).saturating_mul(mult);
        Duration::from_millis(ms).min(self.cap)
    }

    /// Next delay (full jitter) and advance.
    pub fn next_delay(&mut self) -> Duration {
        use rand::Rng;
        let ceiling = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        let ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(rand::thread_rng().gen_range(0..=ms))
    }

    /// Reset after a successful connection.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Attempts so far.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_bounds() {
        let mut b = Backoff::mqtt();
        let ceilings: Vec<u64> = (0..12)
            .map(|_| {
                let c = b.ceiling().as_secs();
                let d = b.next_delay();
                assert!(d.as_secs() <= c);
                c
            })
            .collect();
        assert_eq!(&ceilings[..10], &[1, 2, 4, 8, 16, 32, 64, 128, 256, 300]);
        assert_eq!(b.attempt(), 12);
        b.reset();
        assert_eq!(b.ceiling(), Duration::from_secs(1));
    }

    async fn broker_side(mut s: tokio::io::DuplexStream, ack: ConnAck) -> tokio::io::DuplexStream {
        let mut buf = Vec::new();
        let p = read_packet(&mut s, &mut buf, 1 << 20).await.unwrap();
        assert!(matches!(p, Packet::Connect(_)));
        s.write_all(&Packet::ConnAck(ack).encode().unwrap()).await.unwrap();
        s
    }

    fn tls_info() -> TlsInfo {
        TlsInfo { version: "TLSv1.3".into(), alpn: Some("mqtt".into()), resumed: false }
    }

    #[tokio::test]
    async fn session_flow_over_duplex() {
        let (client_io, broker_io) = tokio::io::duplex(1 << 16);
        let ack =
            ConnAck { session_present: true, reason_code: 0, properties: Properties::new().with(prop::RECEIVE_MAXIMUM, PropValue::U16(1)) };
        let broker = tokio::spawn(broker_side(broker_io, ack));
        let mut opts = MqttOptions::new("dev-1");
        opts.keep_alive = Duration::from_millis(400);
        let (client, mut inbound, info) = connect_on(client_io, tls_info(), &opts).await.unwrap();
        assert!(info.session_present);
        assert_eq!(info.server_receive_maximum, 1);
        let mut b = broker.await.unwrap();
        // Two QoS1 publishes with receive maximum 1: the second is queued until the first PUBACK.
        let c2 = client.clone();
        let p1 = tokio::spawn(async move {
            c2.publish("t/1", vec![1], 1, false, Properties::new().with_user("traceparent", "x"), Duration::from_secs(5)).await
        });
        let c3 = client.clone();
        let p2 = tokio::spawn(async move { c3.publish("t/2", vec![2], 1, false, Properties::new(), Duration::from_secs(5)).await });
        let mut buf = Vec::new();
        let first = read_packet(&mut b, &mut buf, 1 << 20).await.unwrap();
        let Packet::Publish(first) = first else { panic!() };
        assert!(first.topic.starts_with("t/"));
        if first.topic == "t/1" {
            assert_eq!(first.properties.user("traceparent"), Some("x"));
        }
        b.write_all(
            &Packet::PubAck(PubAck { packet_id: first.packet_id.unwrap(), reason_code: 0, properties: Properties::new() })
                .encode()
                .unwrap(),
        )
        .await
        .unwrap();
        let second = read_packet(&mut b, &mut buf, 1 << 20).await.unwrap();
        let Packet::Publish(second) = second else { panic!() };
        b.write_all(
            &Packet::PubAck(PubAck { packet_id: second.packet_id.unwrap(), reason_code: 0x87, properties: Properties::new() })
                .encode()
                .unwrap(),
        )
        .await
        .unwrap();
        let mut codes = vec![p1.await.unwrap().unwrap(), p2.await.unwrap().unwrap()];
        codes.sort_unstable();
        assert_eq!(codes, vec![0, 0x87]);
        // QoS0 publish
        assert_eq!(client.publish("t/0", vec![], 0, false, Properties::new(), Duration::from_secs(1)).await.unwrap(), 0);
        let Packet::Publish(q0) = read_packet(&mut b, &mut buf, 1 << 20).await.unwrap() else { panic!() };
        assert_eq!(q0.qos, 0);
        // Subscribe
        let c4 = client.clone();
        let sub = tokio::spawn(async move { c4.subscribe(vec![("a/b".into(), 1)], Duration::from_secs(5)).await });
        let Packet::Subscribe(s) = read_packet(&mut b, &mut buf, 1 << 20).await.unwrap() else { panic!() };
        b.write_all(
            &Packet::SubAck(SubAck { packet_id: s.packet_id, properties: Properties::new(), reason_codes: vec![1] }).encode().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(sub.await.unwrap().unwrap(), vec![1]);
        // Inbound QoS1 + ack
        b.write_all(
            &Packet::Publish(Publish {
                dup: false,
                qos: 1,
                retain: false,
                topic: "a/b".into(),
                packet_id: Some(9),
                properties: Properties::new(),
                payload: vec![7],
            })
            .encode()
            .unwrap(),
        )
        .await
        .unwrap();
        let msg = inbound.recv().await.unwrap();
        assert_eq!(msg.publish.payload, vec![7]);
        msg.ack(0).await;
        let Packet::PubAck(a) = read_packet(&mut b, &mut buf, 1 << 20).await.unwrap() else { panic!() };
        assert_eq!(a.packet_id, 9);
        // Keep-alive ping is sent
        let p = tokio::time::timeout(Duration::from_secs(3), read_packet(&mut b, &mut buf, 1 << 20)).await.unwrap().unwrap();
        assert_eq!(p, Packet::PingReq);
        b.write_all(&Packet::PingResp.encode().unwrap()).await.unwrap();
        // Broker DISCONNECT ends the session
        b.write_all(&Packet::Disconnect(Disconnect { reason_code: 0x8e, properties: Properties::new() }).encode().unwrap()).await.unwrap();
        let info = client.closed().await;
        assert_eq!(info.reason_code, 0x8e);
        assert!(client.is_closed());
        assert!(matches!(
            client.publish("t", vec![], 1, false, Properties::new(), Duration::from_secs(1)).await,
            Err(MqttError::Closed(_))
        ));
    }

    #[tokio::test]
    async fn connack_refused_and_keepalive_timeout() {
        let (client_io, broker_io) = tokio::io::duplex(4096);
        let ack = ConnAck { session_present: false, reason_code: 0x87, properties: Properties::new() };
        let broker = tokio::spawn(broker_side(broker_io, ack));
        let r = connect_on(client_io, tls_info(), &MqttOptions::new("x")).await;
        assert!(matches!(r, Err(MqttError::Connect(ConnectFailure::NotAuthorized, _))));
        drop(broker.await.unwrap());

        let (client_io, broker_io) = tokio::io::duplex(4096);
        let broker =
            tokio::spawn(broker_side(broker_io, ConnAck { session_present: false, reason_code: 0, properties: Properties::new() }));
        let mut opts = MqttOptions::new("x");
        opts.keep_alive = Duration::from_millis(200);
        let (client, _inbound, _) = connect_on(client_io, tls_info(), &opts).await.unwrap();
        let _b = broker.await.unwrap(); // broker never answers PINGREQ
        let info = tokio::time::timeout(Duration::from_secs(5), client.closed()).await.unwrap();
        assert_eq!(info.reason_code, reason::KEEP_ALIVE_TIMEOUT);

        // Malformed packet from broker closes with MALFORMED.
        let (client_io, broker_io) = tokio::io::duplex(4096);
        let broker =
            tokio::spawn(broker_side(broker_io, ConnAck { session_present: false, reason_code: 0, properties: Properties::new() }));
        let (client, _inbound, _) = connect_on(client_io, tls_info(), &MqttOptions::new("x")).await.unwrap();
        let mut b = broker.await.unwrap();
        b.write_all(&[0x00, 0x00]).await.unwrap();
        assert_eq!(client.closed().await.reason_code, reason::MALFORMED);

        // Peer closes before CONNACK.
        let (client_io, broker_io) = tokio::io::duplex(4096);
        drop(broker_io);
        assert!(matches!(connect_on(client_io, tls_info(), &MqttOptions::new("x")).await, Err(MqttError::Connect(_, _))));
        let (client_io, mut broker_io) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = read_packet(&mut broker_io, &mut buf, 1 << 20).await;
            broker_io.write_all(&Packet::PingResp.encode().unwrap()).await.unwrap();
            broker_io
        });
        assert!(matches!(
            connect_on(client_io, tls_info(), &MqttOptions::new("x")).await,
            Err(MqttError::Connect(ConnectFailure::Network, _))
        ));
        drop(t.await.unwrap());
        let (client_io, broker_io) = tokio::io::duplex(4096);
        let broker =
            tokio::spawn(broker_side(broker_io, ConnAck { session_present: false, reason_code: 0, properties: Properties::new() }));
        let (client, _inbound, _) = connect_on(client_io, tls_info(), &MqttOptions::new("x")).await.unwrap();
        let _b = broker.await.unwrap();
        client.disconnect().await;
        assert_eq!(client.closed().await.reason_code, 0);
        assert!(MqttError::Timeout.to_string().contains("timed out"));
    }
}
