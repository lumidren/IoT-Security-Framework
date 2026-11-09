//! Virtual fleet simulator: N software-keyed devices in one tokio process, each with its own
//! identity directory, staggered enrollment, realistic per-device telemetry baselines and
//! optional misbehaving devices (auth-failure bursts, beaconing, topic violations, firmware-hash
//! change) for the anomaly-detection demo and the 10 000-device load test.
//!
//! Per-device state is deliberately small: keys + certificate metadata, one rustls client
//! config, the MQTT session (8 KiB read buffer) and a 16-byte PRNG; no per-device threads.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::enroll::{self, Credentials, EnrollRequest};
use crate::identity::software::{SecretSource, SoftwareIdentity};
use crate::identity::{IdentitySigner, KeySlot, SharedIdentity};
use crate::logging::TraceContext;
use crate::mqtt::codec::Properties;
use crate::mqtt::{self, MqttOptions};
use crate::settings::Settings;
use crate::telemetry::FirmwareInfo;
use crate::tls::{self, ClientIdentity, PinnedVerifier};
use crate::wire::cose::Kid;
use crate::wire::envelope::{self, Body, Message, Telemetry};
use crate::wire::ids::{self, TopicClass};

/// Misbehaviour injected into a simulated device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anomaly {
    /// Bursts of failed logins.
    AuthBurst,
    /// High-frequency fixed-period traffic with large uploads.
    Beaconing,
    /// Publishes to another device's topic.
    TopicViolation,
    /// Firmware hash changes without an OTA campaign.
    FwHashChange,
}

impl Anomaly {
    /// Anomaly for the k-th misbehaving device (round robin).
    #[must_use]
    pub fn nth(k: usize) -> Anomaly {
        [Anomaly::AuthBurst, Anomaly::Beaconing, Anomaly::TopicViolation, Anomaly::FwHashChange][k % 4]
    }
}

/// Tiny deterministic PRNG (xorshift64*), 8 bytes of state per device.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seeded generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    /// Next u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Per-device telemetry model.
#[derive(Debug, Clone)]
pub struct Model {
    rng: Rng,
    cpu: f32,
    mem: f32,
    temp: f32,
    rx: u64,
    tx: u64,
    uptime: u64,
    tick: u64,
    /// Injected anomaly.
    pub anomaly: Option<Anomaly>,
    fw: [u8; 32],
}

fn round2(v: f64) -> f64 {
    // Quarter steps are exactly representable as half/single floats (compact CBOR).
    (v * 4.0).round() / 4.0
}

impl Model {
    /// Model for device `index`.
    #[must_use]
    pub fn new(index: u64, anomaly: Option<Anomaly>, fw: [u8; 32]) -> Self {
        let mut rng = Rng::new(index + 1);
        let cpu = 5.0 + 35.0 * rng.unit() as f32;
        let mem = 20.0 + 50.0 * rng.unit() as f32;
        let temp = 35.0 + 20.0 * rng.unit() as f32;
        Self { rng, cpu, mem, temp, rx: 0, tx: 0, uptime: (index % 86_400) * 7, tick: 0, anomaly, fw }
    }

    /// Next sample after `elapsed_s` seconds.
    pub fn sample(&mut self, elapsed_s: u64, version: &str) -> Telemetry {
        self.tick += 1;
        self.uptime += elapsed_s;
        let n = |r: &mut Rng, s: f64| (r.unit() - 0.5) * 2.0 * s;
        let cpu = (f64::from(self.cpu) + n(&mut self.rng, 4.0)).clamp(0.0, 100.0);
        let mem = (f64::from(self.mem) + n(&mut self.rng, 1.5)).clamp(0.0, 100.0);
        let temp = f64::from(self.temp) + n(&mut self.rng, 0.8) + cpu / 50.0;
        let rx_rate = 2_000 + self.rng.next_u64() % 3_000;
        let mut tx_rate = 1_000 + self.rng.next_u64() % 1_500;
        let mut auth_failures = u64::from(self.rng.next_u64() % 200 == 0);
        match self.anomaly {
            Some(Anomaly::AuthBurst) if self.tick % 5 == 0 => auth_failures = 40 + self.rng.next_u64() % 60,
            Some(Anomaly::Beaconing) => tx_rate *= 50,
            Some(Anomaly::FwHashChange) if self.tick == 10 => self.fw[0] ^= 0xff,
            _ => {}
        }
        self.rx += rx_rate * elapsed_s.max(1);
        self.tx += tx_rate * elapsed_s.max(1);
        Telemetry {
            cpu_pct: round2(cpu),
            mem_pct: round2(mem),
            net_rx_bytes: self.rx,
            net_tx_bytes: self.tx,
            temp_c: round2(temp),
            uptime_s: self.uptime,
            auth_failures,
            fw_hash: self.fw,
            fw_version: version.to_owned(),
            proc_count: Some(80 + self.rng.next_u64() % 40),
            top_procs: Some(vec!["ironmesh-agent".into(), "systemd".into(), "sshd".into()]),
            rssi: None,
            free_heap: None,
            lat: None,
            lon: None,
        }
    }

    /// Telemetry period for this device.
    #[must_use]
    pub fn period(&self, base: Duration) -> Duration {
        if self.anomaly == Some(Anomaly::Beaconing) {
            Duration::from_secs(1)
        } else {
            base
        }
    }
}

/// Fleet index written by `provision`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetIndex {
    /// Tenant.
    pub tenant_id: String,
    /// Device ids (directory names).
    pub devices: Vec<String>,
}

/// Device id for index `i` under a 12-hex-digit fleet prefix.
#[must_use]
pub fn device_id(prefix: u64, i: u64) -> String {
    format!("dev-{:08x}{:08x}", prefix & 0xffff_ffff, i & 0xffff_ffff)
}

/// Create `count` device identities (software keys, bootstrap key) and their CSRs.
///
/// Each device gets `<out>/<device_id>/` with `identity.json`, encrypted keys, a 0600 machine
/// secret and `bootstrap.csr.pem`; sign the CSRs with the Factory CA (`pkictl issue-bootstrap
/// --csr`) and drop `bootstrap.crt` into the same directory.
///
/// # Errors
/// I/O or identity errors.
pub fn provision(out: &Path, count: u64, tenant_id: &str, prefix: u64) -> Result<FleetIndex, String> {
    crate::persist::ensure_private_dir(out).map_err(|e| e.to_string())?;
    let mut devices = Vec::new();
    for i in 0..count {
        let id = device_id(prefix, i);
        let dir = out.join(&id);
        let ident =
            SoftwareIdentity::create(&dir, &id, tenant_id, &SecretSource::File(dir.join("machine-secret"))).map_err(|e| e.to_string())?;
        let pk = crate::identity::IdentityProvider::generate_bootstrap_key(&ident).map_err(|e| e.to_string())?;
        let sign = |d: &[u8; 32]| crate::identity::IdentityProvider::sign(&ident, KeySlot::Bootstrap, d).map_err(|e| e.to_string());
        let csr = crate::x509::build_csr(&id, tenant_id, &pk, &sign).map_err(|e| e.to_string())?;
        crate::persist::write_atomic(&dir.join("bootstrap.csr.pem"), crate::x509::to_pem("CERTIFICATE REQUEST", &csr).as_bytes())
            .map_err(|e| e.to_string())?;
        devices.push(id);
    }
    let index = FleetIndex { tenant_id: tenant_id.to_owned(), devices };
    crate::persist::write_json(&out.join("fleet.json"), &index).map_err(|e| e.to_string())?;
    Ok(index)
}

/// Shared fleet counters.
#[derive(Debug, Default)]
pub struct Stats {
    /// Devices enrolled.
    pub enrolled: AtomicU64,
    /// Devices connected now.
    pub connected: AtomicU64,
    /// Telemetry messages acknowledged.
    pub published: AtomicU64,
    /// Failures (enroll / connect / publish).
    pub errors: AtomicU64,
}

/// Run one simulated device until `stop`.
pub async fn run_device(
    settings: Arc<Settings>,
    dir: PathBuf,
    index: u64,
    anomaly: Option<Anomaly>,
    stats: Arc<Stats>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let fail = |stats: &Stats, what: &str, e: &dyn std::fmt::Display| {
        stats.errors.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(device = index, what, error = %e, "fleet device error");
    };
    let identity: SharedIdentity = match SoftwareIdentity::open(&dir, &SecretSource::File(dir.join("machine-secret"))) {
        Ok(i) => Arc::new(i),
        Err(e) => return fail(&stats, "identity", &e),
    };
    let fw_hash: [u8; 32] =
        sha2::Digest::finalize(sha2::Digest::chain_update(sha2::Sha256::default(), settings.agent.fw_version.as_bytes())).into();
    let mut model = Model::new(index, anomaly, fw_hash);
    let mut seq = crate::seq::SeqCounter::open(&dir.join("seq.json"), 100).ok();
    let mut backoff = mqtt::Backoff::mqtt();
    loop {
        if *stop.borrow() {
            return;
        }
        let now = crate::seq::Clock::new().now_unix();
        let mut creds = match Credentials::load(&dir, &identity, settings.bundle_key().as_ref(), &settings.pki.ca_bundle) {
            Ok(c) => c,
            Err(e) => return fail(&stats, "credentials", &e),
        };
        if creds.operational_valid(now).is_none() || creds.bundle.is_none() {
            let pins = creds.bundle.as_ref().map(|b| b.ca_pins.clone()).unwrap_or_else(|| settings.est_pins());
            let s = seq.as_mut().and_then(|c| c.next().ok()).unwrap_or(1);
            let req = EnrollRequest {
                identity: &identity,
                creds: &creds,
                dir: dir.clone(),
                est_host: &settings.pki.est_host,
                est_port: settings.pki.est_port,
                pins,
                bundle_key: settings.bundle_key(),
                fw: FirmwareInfo { hash: fw_hash, version: settings.agent.fw_version.clone() },
                seq: s,
                now,
                timeout: Duration::from_secs(settings.pki.timeout_s),
                force_bootstrap: creds.operational_valid(now).is_none(),
            };
            match enroll::enroll(req).await {
                Ok(_) => {
                    stats.enrolled.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(e) => {
                    fail(&stats, "enroll", &e);
                    tokio::time::sleep(backoff.next_delay().mul_f64(settings.mqtt.backoff_scale).max(Duration::from_secs(1))).await;
                    continue;
                }
            }
        }
        let (Some(op), Some(bundle)) = (creds.operational.take(), creds.bundle.take()) else { continue };
        let Ok(verifier) = PinnedVerifier::new(&creds.anchors, &bundle.ca_pins, tls::provider()) else {
            return fail(&stats, "pins", &"no pins");
        };
        let cfg = match tls::client_config(
            Arc::new(verifier),
            Some(ClientIdentity { chain: vec![op.der.clone()], provider: identity.clone(), slot: KeySlot::Operational }),
            &[b"mqtt"],
        ) {
            Ok(c) => c,
            Err(e) => return fail(&stats, "tls", &e),
        };
        let host = settings.mqtt.host.clone().unwrap_or(bundle.broker_host.clone());
        let port = settings.mqtt.port.unwrap_or(bundle.broker_port);
        let mut opts = MqttOptions::new(identity.device_id());
        opts.max_packet_size = 64 * 1024;
        opts.receive_maximum = 8;
        let (client, mut inbound, _) = match mqtt::connect(cfg, &host, port, &opts).await {
            Ok(c) => c,
            Err(e) => {
                fail(&stats, "connect", &e);
                tokio::time::sleep(backoff.next_delay().mul_f64(settings.mqtt.backoff_scale)).await;
                continue;
            }
        };
        backoff.reset();
        stats.connected.fetch_add(1, Ordering::Relaxed);
        let kid = Kid::Bytes(op.kid.clone());
        let signer = IdentitySigner { provider: identity.clone(), slot: KeySlot::Operational };
        let Ok(topic) = ids::build_topic(identity.tenant_id(), identity.device_id(), TopicClass::Telemetry) else { return };
        let period = model.period(Duration::from_secs(settings.telemetry.interval_s.max(1)));
        // Desynchronise devices so the broker does not see thundering herds.
        let phase = Duration::from_millis(index * 7919 % u64::try_from(period.as_millis()).unwrap_or(1000).max(1));
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + phase, period);
        loop {
            tokio::select! {
                _ = stop.changed() => {
                    client.disconnect().await;
                    stats.connected.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                m = inbound.recv() => match m {
                    Some(m) => m.ack(0).await,
                    None => break,
                },
                _ = ticker.tick() => {
                    if op.not_after <= crate::seq::Clock::new().now_unix() + op.lifetime() / 2 {
                        client.disconnect().await;
                        break; // re-enroll at half lifetime
                    }
                    let Some(s) = seq.as_mut().and_then(|c| c.next().ok()) else { break };
                    let msg = Message { seq: s, ts: crate::seq::Clock::new().now_unix(), body: Body::Telemetry(model.sample(period.as_secs(), &settings.agent.fw_version)), nonce: None };
                    let Ok(wire) = envelope::encode(&msg, &signer, &kid) else { continue };
                    let props = Properties::new().with_user("traceparent", &TraceContext::new().traceparent());
                    match client.publish(&topic, wire, 1, false, props, Duration::from_secs(30)).await {
                        Ok(c) if c < 0x80 => { stats.published.fetch_add(1, Ordering::Relaxed); }
                        Ok(_) => { stats.errors.fetch_add(1, Ordering::Relaxed); }
                        Err(_) => break,
                    }
                    if model.anomaly == Some(Anomaly::TopicViolation) && model.tick % 3 == 0 {
                        let other = ids::build_topic(identity.tenant_id(), &device_id(0xdead_beef, index), TopicClass::Telemetry).unwrap_or_default();
                        let _ = client.publish(&other, vec![0xa0], 1, false, Properties::new(), Duration::from_secs(10)).await;
                    }
                }
            }
        }
        stats.connected.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Offline benchmark result.
#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    /// Devices simulated.
    pub devices: u64,
    /// Signed telemetry envelopes produced.
    pub messages: u64,
    /// Resident memory before (bytes).
    pub rss_before: u64,
    /// Resident memory after (bytes).
    pub rss_after: u64,
    /// `(rss_after - rss_before) / devices`.
    pub bytes_per_device: u64,
}

fn rss() -> u64 {
    let mut sys = sysinfo::System::new();
    let pid = sysinfo::get_current_pid().ok();
    if let Some(pid) = pid {
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        sys.process(pid).map_or(0, sysinfo::Process::memory)
    } else {
        0
    }
}

/// Network-free footprint benchmark: `devices` identities with keys, telemetry models, offline
/// buffers and sequence counters, each producing `rounds` signed telemetry envelopes.
pub async fn bench(devices: u64, rounds: u64) -> BenchReport {
    struct Dev {
        identity: SharedIdentity,
        model: Model,
        buffer: crate::buffer::RingBuffer,
        seq: u64,
    }
    let before = rss();
    let tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";
    let mut fleet: Vec<Dev> = (0..devices)
        .map(|i| {
            let id = SoftwareIdentity::ephemeral(&device_id(0x000f_1ee7, i), tenant);
            let _ = crate::identity::IdentityProvider::generate_bootstrap_key(&id);
            let _ = crate::identity::IdentityProvider::generate_operational_key(&id)
                .and_then(|_| crate::identity::IdentityProvider::commit_pending(&id));
            Dev {
                identity: Arc::new(id),
                model: Model::new(i, (i % 50 == 0).then(|| Anomaly::nth(i as usize)), [0; 32]),
                buffer: crate::buffer::RingBuffer::in_memory(32),
                seq: 1,
            }
        })
        .collect();
    let mut messages = 0;
    for _ in 0..rounds {
        for d in &mut fleet {
            let msg = Message { seq: d.seq, ts: 1_767_225_600, body: Body::Telemetry(d.model.sample(30, "1.0.0")), nonce: None };
            d.seq += 1;
            let signer = IdentitySigner { provider: d.identity.clone(), slot: KeySlot::Operational };
            if let Ok(w) = envelope::encode(&msg, &signer, &Kid::Bytes(vec![1, 2, 3])) {
                let _ = d.buffer.push(crate::buffer::Record { seq: msg.seq, topic: String::new(), payload: w });
                messages += 1;
            }
        }
        tokio::task::yield_now().await;
    }
    let after = rss();
    let report = BenchReport {
        devices,
        messages,
        rss_before: before,
        rss_after: after,
        bytes_per_device: after.saturating_sub(before) / devices.max(1),
    };
    drop(fleet);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_and_ids() {
        let mut m = Model::new(3, None, [0; 32]);
        let t = m.sample(30, "1.0.0");
        assert!((0.0..=100.0).contains(&t.cpu_pct));
        let msg = Message { seq: 1, ts: 1, body: Body::Telemetry(t), nonce: None };
        envelope::encode_payload(&msg).unwrap();
        let mut a = Model::new(1, Some(Anomaly::AuthBurst), [0; 32]);
        let bursts: u64 = (0..10).map(|_| a.sample(30, "1.0.0").auth_failures).sum();
        assert!(bursts >= 80);
        let mut f = Model::new(1, Some(Anomaly::FwHashChange), [0; 32]);
        let hashes: Vec<[u8; 32]> = (0..12).map(|_| f.sample(1, "1.0.0").fw_hash).collect();
        assert_ne!(hashes[0], hashes[11]);
        assert_eq!(Model::new(1, Some(Anomaly::Beaconing), [0; 32]).period(Duration::from_secs(30)), Duration::from_secs(1));
        assert!(ids::is_device_id(&device_id(0xabc, 5)));
        assert_eq!(Anomaly::nth(6), Anomaly::TopicViolation);
        let mut r = Rng::new(0);
        assert!((0.0..1.0).contains(&r.unit()));
    }

    #[test]
    fn provisioning_writes_csrs() {
        let dir = tempfile::tempdir().unwrap();
        let idx = provision(dir.path(), 3, "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", 0x1234).unwrap();
        assert_eq!(idx.devices.len(), 3);
        for d in &idx.devices {
            assert!(dir.path().join(d).join("bootstrap.csr.pem").exists());
        }
    }

    #[tokio::test]
    async fn bench_runs() {
        let r = bench(20, 2).await;
        assert_eq!(r.messages, 40);
    }
}
