//! `ironmesh-conformance load`: drive N simulated devices through the real protocol path that
//! runs on one machine, and measure it.
//!
//! ```text
//! orchestrator process (this one)                 fleet process (load-fleet)       policy process
//! ├─ hermetic cloud: test PKI, EST double,       ├─ N agent-rs device stacks      REAL policy service
//! │  registry double, MQTT 5 broker double ◄─────┤  (EST + attestation, mTLS +    (EMQX authn/authz
//! │  (TLS 1.3 + mTLS) ── authn/authz hooks ──────┼──pinning, COSE telemetry,  ───► hooks, Rego,
//! ├─ uplink verifier (COSE + replay per device)  │  command verify + ack)          revocation cache)
//! ├─ command injector (tenant-signed ping)       └─ stdin/stdout control lines
//! └─ sampler: sysinfo CPU/RSS of all three processes every --sample-s, policy /metrics before/after
//! ```
//!
//! Phases: provisioning (factory: software identities, bootstrap certificates from the Factory
//! CA, manufacture records), ramp (devices start at `--rate` per second in stages with holds),
//! sustain (`--sustain-s` seconds of telemetry every `--interval-s`, plus `--cmd-fraction` of the
//! devices receiving one downlink command each), stop and verification. Results go to
//! `loadtest/results/<timestamp>[-label]/{summary.json,timeseries.csv,report.md}`.

pub mod fleet;
pub mod report;
pub mod sampler;
pub mod stats;
pub mod verify;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ironmesh_agent::wire::envelope::Body;
use ironmesh_agent::wire::ids::TopicClass;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::harness::downlink::{command_body, nonce16};
use crate::harness::{pki, Cloud, CloudOptions};
use crate::util;
use fleet::{DeviceEntry, ErrorClass, FleetResult, FleetSpec, FleetStatus};
use sampler::{Environment, ProcSample, Sampler};
use stats::{SeriesDelta, Summary};
use verify::CmdTracker;

/// Product of the manufacture records.
pub const PRODUCT: &str = "gateway-rpi";

/// Command-line options of `load`.
#[derive(clap::Args, Debug, Clone, Serialize)]
pub struct LoadArgs {
    /// Simulated devices.
    #[arg(long, default_value_t = 10_000)]
    pub devices: usize,
    /// Device starts per second during the ramp (each start = EST enrollment + MQTT connect).
    #[arg(long, default_value_t = 200.0)]
    pub rate: f64,
    /// Ramp stages, cumulative % of the devices; the ramp pauses `--stage-hold-s` after each.
    #[arg(long, value_delimiter = ',', default_value = "25,50,75,100")]
    pub stages: Vec<u32>,
    /// Pause after each ramp stage (s).
    #[arg(long, default_value_t = 15)]
    pub stage_hold_s: u64,
    /// Telemetry interval per device (s).
    #[arg(long, default_value_t = 10)]
    pub interval_s: u64,
    /// Sustained window after the ramp (s).
    #[arg(long, default_value_t = 600)]
    pub sustain_s: u64,
    /// Longest wait after the ramp schedule for stragglers to connect before the sustain starts (s).
    #[arg(long, default_value_t = 60)]
    pub ramp_grace_s: u64,
    /// Fraction of the devices that receive one downlink command during the sustained window.
    #[arg(long, default_value_t = 0.05)]
    pub cmd_fraction: f64,
    /// Resource / status sampling period (s).
    #[arg(long, default_value_t = 5)]
    pub sample_s: u64,
    /// Abort when fleet + harness + policy RSS exceeds this (MiB). Default: 70 % of RAM.
    #[arg(long)]
    pub rss_cap_mb: Option<u64>,
    /// Abort when the host's available memory drops below this (MiB).
    #[arg(long, default_value_t = 768)]
    pub min_available_mb: u64,
    /// Persistent connections from the broker double to the policy hooks.
    #[arg(long, default_value_t = 64)]
    pub hook_pool: usize,
    /// Publish -> PUBACK timeout (s).
    #[arg(long, default_value_t = 30)]
    pub publish_timeout_s: u64,
    /// Reconnect / re-enroll backoff scale (1.0 = contract backoff: 1 s base, 300 s cap, full jitter).
    #[arg(long, default_value_t = 1.0)]
    pub backoff_scale: f64,
    /// Tokio worker threads of the fleet process (0: one per logical CPU).
    #[arg(long, default_value_t = 0)]
    pub fleet_threads: usize,
    /// Uplink verifier shards.
    #[arg(long, default_value_t = 4)]
    pub verify_shards: usize,
    /// Policy service binary (default conformance/target/bin/policy).
    #[arg(long)]
    pub policy_bin: Option<PathBuf>,
    /// Results root (default loadtest/results).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Suffix of the results directory name.
    #[arg(long)]
    pub label: Option<String>,
    /// Keep the provisioned device directories (conformance/target/load/<run>/fleet).
    #[arg(long)]
    pub keep_fleet: bool,
}

/// One row of `timeseries.csv`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Row {
    /// Seconds since the fleet process was ready.
    pub t_s: f64,
    /// `ramp`, `sustain`.
    pub phase: String,
    /// Device tasks started.
    pub started: u64,
    /// Devices enrolled.
    pub enrolled: u64,
    /// Devices with a live session (device side).
    pub connected: u64,
    /// Devices that connected at least once.
    pub ever_connected: u64,
    /// Sessions open on the broker.
    pub broker_sessions: i64,
    /// First connections per second in this interval.
    pub connects_per_s: f64,
    /// Telemetry publishes accepted by the broker (policy-authorized) per second.
    pub telemetry_accepted_per_s: f64,
    /// Telemetry PUBACKs received by devices per second.
    pub device_acked_per_s: f64,
    /// Publish -> PUBACK in this interval.
    pub publish: Summary,
    /// authz hook round trip in this interval.
    pub authz: Summary,
    /// authn hook round trip in this interval.
    pub authn: Summary,
    /// Classified device-side errors so far.
    pub errors_total: u64,
    /// PUBACK timeouts so far.
    pub publish_timeouts: u64,
    /// Fleet process.
    pub fleet: ProcSample,
    /// Harness process (broker + EST doubles, verifier).
    pub harness: ProcSample,
    /// Policy service.
    pub policy: ProcSample,
    /// Sum of the three RSS values.
    pub total_rss_mb: f64,
    /// Host available memory.
    pub host_available_mb: f64,
    /// Uplinks waiting for verification.
    pub verifier_backlog: i64,
}

/// CPU / RSS statistics of one process over a set of rows.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcStats {
    /// Mean CPU, % of one logical CPU.
    pub cpu_mean_pct: f64,
    /// Max CPU, % of one logical CPU.
    pub cpu_max_pct: f64,
    /// Mean RSS (MiB).
    pub rss_mean_mb: f64,
    /// Max RSS (MiB).
    pub rss_max_mb: f64,
}

impl ProcStats {
    fn of(rows: &[&Row], f: impl Fn(&Row) -> ProcSample) -> Self {
        let cpu: Vec<f64> = rows.iter().map(|r| f(r).cpu_pct).collect();
        let rss: Vec<f64> = rows.iter().map(|r| f(r).rss_mb).collect();
        let (cpu_mean_pct, cpu_max_pct) = stats::mean_max(&cpu);
        let (rss_mean_mb, rss_max_mb) = stats::mean_max(&rss);
        Self { cpu_mean_pct, cpu_max_pct, rss_mean_mb, rss_max_mb }
    }
}

/// How the run went.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Outcome {
    /// Ramp and sustain completed without an abort.
    pub completed: bool,
    /// Why the run was stopped early.
    pub abort_reason: Option<String>,
    /// Factory provisioning (s).
    pub provision_s: f64,
    /// Ramp (fleet ready -> sustain start), s.
    pub ramp_s: f64,
    /// Sustained window actually run (s).
    pub sustain_s: f64,
}

/// Device counts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeviceCounts {
    /// Requested.
    pub requested: usize,
    /// Provisioned (identity + bootstrap certificate + manufacture record).
    pub provisioned: usize,
    /// Device tasks started.
    pub started: u64,
    /// Enrolled (operational certificate via EST + attestation).
    pub enrolled: u64,
    /// Connected at least once (CONNACK + SUBACK).
    pub ever_connected: u64,
    /// Broker sessions open at the end of the sustained window.
    pub connected_end_of_sustain: i64,
    /// Device-side live sessions when `stop` arrived.
    pub connected_at_stop: u64,
    /// Never connected.
    pub never_connected: u64,
    /// Highest simultaneous broker sessions.
    pub broker_peak_sessions: i64,
}

/// Rates.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Throughput {
    /// Configured device start rate (/s).
    pub target_start_rate: f64,
    /// First connections per second over the ramp's active seconds (holds excluded).
    pub achieved_connect_rate: f64,
    /// First to last first-connection (s).
    pub first_connect_span_s: f64,
    /// Broker-accepted telemetry, whole run.
    pub telemetry_accepted_total: u64,
    /// Broker-accepted telemetry during the sustained window.
    pub telemetry_accepted_sustain: u64,
    /// ... per second.
    pub sustain_telemetry_per_s: f64,
    /// Offered rate if every device connected at the end of the sustain publishes on schedule.
    pub expected_telemetry_per_s: f64,
    /// Telemetry PUBACKs received by devices, whole run.
    pub device_acked_total: u64,
}

/// Latency summaries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Latencies {
    /// Telemetry publish -> PUBACK during the sustained window (device side).
    pub publish_sustain: Summary,
    /// ... during the ramp.
    pub publish_ramp: Summary,
    /// ... whole run.
    pub publish_all: Summary,
    /// TCP + TLS 1.3 mTLS + CONNACK (device side).
    pub connect: Summary,
    /// Full EST enrollment: nonce, key generation, CSR, attestation, simpleenroll, cacerts.
    pub enroll: Summary,
    /// Command injection -> verified CommandAck accepted by the broker.
    pub command_rtt: Summary,
    /// Broker -> policy `POST /emqx/authn` round trip.
    pub authn_hook: Summary,
    /// Broker -> policy `POST /emqx/authz` round trip.
    pub authz_hook: Summary,
    /// Part of the hook round trips spent waiting for a free pool connection.
    pub hook_pool_wait: Summary,
}

/// Downlink commands.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Commands {
    /// Signed and injected.
    pub sent: u64,
    /// No subscribed session at injection time.
    pub not_delivered: u64,
    /// Injection failed.
    pub inject_errors: u64,
    /// Verified acks matching a command.
    pub acked: u64,
    /// Still pending at the end.
    pub unacked: u64,
    /// Non-matching acks.
    pub ack_mismatch: u64,
    /// Ack status codes.
    pub ack_status: BTreeMap<u8, u64>,
    /// Commands executed on devices (device side).
    pub executed_on_devices: u64,
    /// Downlinks rejected by devices.
    pub rejected_by_devices: u64,
}

/// Policy service figures from `/metrics` (before/after deltas).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyFigures {
    /// authn allow decisions.
    pub authn_allow: f64,
    /// authn deny decisions.
    pub authn_deny: f64,
    /// authz allow decisions.
    pub authz_allow: f64,
    /// authz deny decisions.
    pub authz_deny: f64,
    /// Decision cache hits.
    pub authz_cache_hit: f64,
    /// Decision cache misses.
    pub authz_cache_miss: f64,
    /// Registry lookups.
    pub registry_lookups: f64,
    /// CPU seconds used by the policy process during the run.
    pub process_cpu_seconds: f64,
    /// Every changed `ironmesh_*` / `process_*` / `go_*` series.
    pub deltas: Vec<SeriesDelta>,
    /// The policy service exports no hook latency histogram.
    pub latency_note: String,
}

/// Errors from every vantage point.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Errors {
    /// Device side, by class.
    pub fleet: BTreeMap<String, ErrorClass>,
    /// Broker TLS handshake failures.
    pub broker_handshake: BTreeMap<String, u64>,
    /// Broker hook transport errors.
    pub broker_hook: BTreeMap<String, u64>,
    /// Broker session ends by cause.
    pub broker_closes: BTreeMap<String, u64>,
    /// CONNECTs refused.
    pub connects_denied: u64,
    /// PUBLISHes denied by authz.
    pub publishes_denied: u64,
    /// SUBSCRIBE filters denied.
    pub subscribes_denied: u64,
    /// EST attempts by HTTP status.
    pub est_status: BTreeMap<u16, u64>,
    /// Uplink verification failures by wire error code.
    pub verifier: BTreeMap<String, u64>,
}

/// End-to-end checks.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Verification {
    /// Uplinks verified.
    pub uplinks_verified: u64,
    /// Telemetry verified.
    pub telemetry_verified: u64,
    /// CommandAcks verified.
    pub acks_verified: u64,
    /// Replay rejections.
    pub replay_rejections: u64,
    /// Devices with at least one PUBACKed uplink.
    pub devices_with_acked_uplinks: u64,
    /// ... whose last PUBACKed seq equals the last seq the verifier accepted.
    pub last_seq_matched: u64,
    /// ... where they differ.
    pub last_seq_mismatched: u64,
    /// A few mismatches.
    pub mismatch_examples: Vec<String>,
    /// Highest verifier backlog.
    pub verifier_peak_backlog: i64,
    /// Every device's last seq accepted and no replay rejection.
    pub passed: bool,
}

/// Resource figures.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Resources {
    /// Fleet process during the sustained window.
    pub fleet_sustain: ProcStats,
    /// Harness process during the sustained window.
    pub harness_sustain: ProcStats,
    /// Policy process during the sustained window.
    pub policy_sustain: ProcStats,
    /// Fleet process, whole run.
    pub fleet_all: ProcStats,
    /// Harness process, whole run.
    pub harness_all: ProcStats,
    /// Policy process, whole run.
    pub policy_all: ProcStats,
    /// Highest combined RSS (MiB).
    pub peak_total_rss_mb: f64,
    /// Lowest host available memory (MiB).
    pub min_host_available_mb: f64,
    /// Fleet RSS / connected device at the end of the sustain (KiB).
    pub fleet_rss_per_device_kib: f64,
    /// Harness RSS / broker session at the end of the sustain (KiB).
    pub harness_rss_per_session_kib: f64,
    /// Abort threshold for the combined RSS (MiB).
    pub rss_cap_mb: f64,
    /// Abort threshold for host available memory (MiB).
    pub min_available_floor_mb: f64,
    /// Hook pool size and connections opened.
    pub hook_pool: (usize, u64),
}

/// `summary.json`.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    /// Results directory name.
    pub run: String,
    /// Start (RFC 3339 UTC).
    pub started_at: String,
    /// Command line.
    pub command: String,
    /// Machine and toolchain.
    pub environment: Environment,
    /// Options.
    pub config: LoadArgs,
    /// Outcome.
    pub outcome: Outcome,
    /// Devices.
    pub devices: DeviceCounts,
    /// Rates.
    pub throughput: Throughput,
    /// Latencies.
    pub latency: Latencies,
    /// Commands.
    pub commands: Commands,
    /// Policy service.
    pub policy: PolicyFigures,
    /// Errors.
    pub errors: Errors,
    /// End-to-end checks.
    pub verification: Verification,
    /// Resources.
    pub resources: Resources,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ramp,
    Sustain,
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

fn run_name(label: Option<&str>) -> String {
    let now = time::OffsetDateTime::now_utc();
    let base =
        format!("{:04}{:02}{:02}-{:02}{:02}{:02}", now.year(), u8::from(now.month()), now.day(), now.hour(), now.minute(), now.second());
    match label {
        Some(l) if !l.is_empty() => {
            format!("{base}-{}", l.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).collect::<String>())
        }
        _ => base,
    }
}

/// Factory provisioning: identities + CSRs in parallel chunks ([`ironmesh_agent::fleet::provision`]),
/// then bootstrap certificates from the Factory CA and manufacture records in the registry.
async fn provision(cloud: &Cloud, root: &Path, n: usize) -> Result<Vec<DeviceEntry>> {
    let chunks = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get).clamp(1, 16).min(n.max(1));
    let per = n.div_ceil(chunks);
    let mut handles = Vec::new();
    for k in 0..chunks {
        let start = k * per;
        if start >= n {
            break;
        }
        let count = per.min(n - start);
        let dir = root.join(format!("chunk-{k:02}"));
        let tenant = cloud.tenant_id.clone();
        let prefix = 0x10ad_0000_u64 + k as u64;
        handles.push(tokio::task::spawn_blocking(move || {
            ironmesh_agent::fleet::provision(&dir, count as u64, &tenant, prefix).map(|idx| (dir, idx)).map_err(|e| anyhow!(e))
        }));
    }
    let mut out = Vec::with_capacity(n);
    for h in handles {
        let (dir, idx) = h.await??;
        out.extend(idx.devices.into_iter().map(|id| DeviceEntry { dir: dir.join(&id), id }));
    }
    // Interleave the chunks so consecutive starts do not hit the same directory.
    out.sort_by_key(|d| {
        let n: u64 = u64::from_str_radix(&d.id[d.id.len() - 8..], 16).unwrap_or(0);
        (n, d.id.clone())
    });
    for (i, d) in out.iter().enumerate() {
        let csr_pem = std::fs::read(d.dir.join("bootstrap.csr.pem")).with_context(|| format!("{}: bootstrap CSR", d.id))?;
        let csr = util::pem_block(&csr_pem, "CERTIFICATE REQUEST").ok_or_else(|| anyhow!("{}: no CSR PEM", d.id))?;
        let der = cloud.issue_bootstrap(&d.id, &csr).await?;
        let serial = pki::cert_facts(&der)?.serial_hex;
        std::fs::write(d.dir.join("bootstrap.crt"), util::pem("CERTIFICATE", &der))?;
        cloud.register_device(&d.id, "software", &serial, PRODUCT).await?;
        if (i + 1) % 2000 == 0 {
            eprintln!("[load] factory: {} / {n} bootstrap certificates issued", i + 1);
        }
    }
    Ok(out)
}

struct FleetIo {
    stdin: tokio::process::ChildStdin,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
}

impl FleetIo {
    async fn send(&mut self, line: &str) -> Result<()> {
        self.stdin.write_all(format!("{line}\n").as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn next_json(&mut self, timeout: Duration, key: &str) -> Option<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.recv()).await.ok()??;
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if v.get(key).is_some() {
                    return Some(v);
                }
            }
        }
    }

    async fn status(&mut self) -> Option<FleetStatus> {
        self.send("tick").await.ok()?;
        self.next_json(Duration::from_secs(10), "t_ms").await.and_then(|v| serde_json::from_value(v).ok())
    }
}

fn spawn_commands(
    cloud: Arc<Cloud>,
    cmds: Arc<CmdTracker>,
    ids: Vec<String>,
    count: usize,
    window: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if count == 0 || ids.is_empty() {
            return;
        }
        let Ok(h) = cloud.hermetic("load commands") else { return };
        let start = tokio::time::Instant::now() + Duration::from_secs(5);
        let spacing = window.saturating_sub(Duration::from_secs(15)).max(Duration::from_secs(1)).as_secs_f64() / count as f64;
        for k in 0..count {
            tokio::time::sleep_until(start + Duration::from_secs_f64(spacing * k as f64)).await;
            let idx = (k * ids.len() / count + k % 7) % ids.len();
            let device = &ids[idx];
            let Ok(d) = cloud.signer.sign(command_body("ping", &util::uuid4(), 120), Some(nonce16())) else { continue };
            let Body::Command(c) = &d.message.body else { continue };
            let cmd_id = c.cmd_id.clone();
            let Ok(topic) = cloud.topic(device, TopicClass::CmdReq) else { continue };
            cmds.sent(device, &cmd_id, d.message.clone(), Instant::now());
            match h.broker.inject(&topic, d.wire, false).await {
                Ok(v) if v.is_empty() => cmds.undeliverable(&cmd_id, false),
                Ok(_) => {}
                Err(_) => cmds.undeliverable(&cmd_id, true),
            }
        }
    })
}

/// Run the load test; returns the results directory and whether it passed (completed, every
/// device's last seq accepted, no replay rejection).
///
/// # Errors
/// Start-up failures (policy binary, provisioning, fleet process).
#[allow(clippy::too_many_lines)]
pub async fn run(a: LoadArgs, policy_bin: PathBuf, go: PathBuf) -> Result<(PathBuf, bool)> {
    crate::install_crypto();
    let repo = util::repo_root();
    let env = Environment::collect(&repo, &go);
    let name = run_name(a.label.as_deref());
    let results = a.out.clone().unwrap_or_else(|| repo.join("loadtest").join("results")).join(&name);
    let run_dir = repo.join("conformance").join("target").join("load").join(&name);
    std::fs::create_dir_all(&results)?;
    std::fs::create_dir_all(&run_dir)?;
    let started_at = rfc3339_now();
    let command = std::iter::once("ironmesh-conformance".to_string()).chain(std::env::args().skip(1)).collect::<Vec<_>>().join(" ");
    let rss_cap_mb = a.rss_cap_mb.map_or(env.ram_total_mb * 0.7, |v| v as f64);
    let n = a.devices;
    eprintln!(
        "[load] {name}: {n} devices, start rate {}/s, stages {:?} (+{} s holds), telemetry every {} s, sustain {} s; \
         RAM {:.0} MiB ({:.0} available), RSS cap {:.0} MiB, available floor {} MiB",
        a.rate,
        a.stages,
        a.stage_hold_s,
        a.interval_s,
        a.sustain_s,
        env.ram_total_mb,
        env.ram_available_at_start_mb,
        rss_cap_mb,
        a.min_available_mb
    );
    if env.ram_available_at_start_mb < a.min_available_mb as f64 {
        bail!("only {:.0} MiB available, below the --min-available-mb floor of {}", env.ram_available_at_start_mb, a.min_available_mb);
    }
    let tenant = util::uuid4();
    let cloud = Cloud::start_hermetic(&CloudOptions {
        bind_host: "127.0.0.1".into(),
        advertise_host: "127.0.0.1".into(),
        policy_bin,
        real_pki: None,
        pki_dir: None,
        est_port: 0,
        run_dir: run_dir.clone(),
        repo_root: repo.clone(),
        tenant_id: tenant.clone(),
        // Production values (the conformance suite shortens the registry cache and logs at debug).
        policy_env: vec![("POLICY_LOG_LEVEL".into(), "info".into()), ("POLICY_REGISTRY_CACHE_TTL".into(), "30s".into())],
        hook_pool: Some(a.hook_pool),
    })
    .await
    .context("start the hermetic cloud")?;
    let cloud = Arc::new(cloud);
    let h = cloud.hermetic("load")?;
    let broker = h.broker.clone();
    broker.set_load_mode(true);
    let bstats = broker.stats();
    let cmds = Arc::new(CmdTracker::default());
    let (verifier, tap_tx, verifier_task) = verify::spawn(broker.clone(), cmds.clone(), a.verify_shards);
    broker.set_tap(tap_tx);

    // Factory.
    let t_prov = Instant::now();
    let fleet_root = run_dir.join("fleet");
    let devices = provision(&cloud, &fleet_root, n).await.context("provision the fleet")?;
    let provision_s = t_prov.elapsed().as_secs_f64();
    eprintln!("[load] factory: {} devices provisioned in {provision_s:.1} s", devices.len());
    let ep = cloud.endpoints();
    let anchors_file = fleet_root.join("ca-bundle.pem");
    std::fs::write(&anchors_file, &ep.anchors_pem)?;
    let schedule = stats::ramp_schedule(devices.len(), a.rate, &a.stages, a.stage_hold_s * 1000);
    let ramp_sched = Duration::from_millis(schedule.last().copied().unwrap_or(0));
    let ids: Vec<String> = devices.iter().map(|d| d.id.clone()).collect();
    let spec = FleetSpec {
        devices: devices.clone(),
        schedule_ms: schedule,
        anchors_file,
        est_host: ep.est_host.clone(),
        est_port: ep.est_port,
        est_pins_hex: ep.est_pins_hex.clone(),
        bundle_pubkey_hex: ep.bundle_pubkey_hex.clone(),
        interval_s: a.interval_s,
        publish_timeout_s: a.publish_timeout_s,
        connect_timeout_s: 20,
        est_timeout_s: 30,
        backoff_scale: a.backoff_scale,
        fw_version: "1.0.0".into(),
        result_file: run_dir.join("fleet-result.json"),
        worker_threads: a.fleet_threads,
    };
    let spec_path = run_dir.join("fleet-spec.json");
    std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
    let metrics_before = h.policy_client.metrics_text().await.unwrap_or_default();
    let policy_pid = h.policy.lock().await.pid();

    // Fleet process.
    let exe = std::env::current_exe()?;
    let fleet_log = std::fs::File::create(run_dir.join("fleet.log"))?;
    let mut child = tokio::process::Command::new(exe)
        .arg("load-fleet")
        .arg("--spec")
        .arg(&spec_path)
        .env("RUST_LOG", "warn")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::from(fleet_log))
        .kill_on_drop(true)
        .spawn()
        .context("spawn the fleet process")?;
    let stdin = child.stdin.take().ok_or_else(|| anyhow!("fleet stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("fleet stdout"))?;
    let (line_tx, line_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if line_tx.send(l).is_err() {
                break;
            }
        }
    });
    let mut io = FleetIo { stdin, lines: line_rx };
    io.next_json(Duration::from_secs(60), "ready").await.ok_or_else(|| anyhow!("the fleet process did not start; see fleet.log"))?;
    let t0 = Instant::now();
    let mut sampler = Sampler::new(&[child.id(), Some(std::process::id()), policy_pid]);
    eprintln!("[load] fleet process {} ready; ramp schedule {:.0} s", child.id().unwrap_or(0), ramp_sched.as_secs_f64());

    let mut phase = Phase::Ramp;
    let mut abort: Option<String> = None;
    let mut rows: Vec<Row> = Vec::new();
    let mut last = FleetStatus::default();
    let mut prev_t = t0;
    let mut prev_tele = bstats.telemetry_accepted.load(Ordering::Relaxed);
    let mut prev_ok = 0u64;
    let mut prev_ever = 0u64;
    let mut ramp_s = 0.0;
    let mut sustain_start: Option<(Instant, u64)> = None;
    let mut sustain_end: Option<(Instant, u64, i64)> = None;
    let mut cmd_task = None;
    let mut next_sample = t0 + Duration::from_secs(a.sample_s.max(1));
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    loop {
        ticker.tick().await;
        if let Ok(Some(st)) = child.try_wait() {
            abort = Some(format!("the fleet process exited early ({st}); see fleet.log"));
            break;
        }
        let now = Instant::now();
        if now >= next_sample {
            next_sample += Duration::from_secs(a.sample_s.max(1));
            let st = io.status().await;
            let (procs, host) = sampler.sample();
            let now = Instant::now();
            let dt = now.duration_since(prev_t).as_secs_f64();
            let tele = bstats.telemetry_accepted.load(Ordering::Relaxed);
            let s = st.clone().unwrap_or_else(|| last.clone());
            let row = Row {
                t_s: now.duration_since(t0).as_secs_f64(),
                phase: if phase == Phase::Ramp { "ramp".into() } else { "sustain".into() },
                started: s.started,
                enrolled: s.enrolled,
                connected: s.connected,
                ever_connected: s.ever_connected,
                broker_sessions: bstats.live_sessions.load(Ordering::Relaxed),
                connects_per_s: stats::rate(s.ever_connected.saturating_sub(prev_ever), dt),
                telemetry_accepted_per_s: stats::rate(tele.saturating_sub(prev_tele), dt),
                device_acked_per_s: stats::rate(s.published_ok.saturating_sub(prev_ok), dt),
                publish: s.publish_window.clone(),
                authz: bstats.authz_latency.take_window(),
                authn: bstats.authn_latency.take_window(),
                errors_total: s.errors_total,
                publish_timeouts: s.publish_timeouts,
                fleet: procs.first().copied().unwrap_or_default(),
                harness: procs.get(1).copied().unwrap_or_default(),
                policy: procs.get(2).copied().unwrap_or_default(),
                total_rss_mb: procs.iter().map(|p| p.rss_mb).sum(),
                host_available_mb: host.available_mb,
                verifier_backlog: verifier.backlog.load(Ordering::Relaxed),
            };
            eprintln!(
                "[load] t={:>5.0}s {:7} started {:>5} enrolled {:>5} connected {:>5} | tele {:>6.0}/s pub p50/p99 {:>6.1}/{:>7.1} ms | \
                 authz p99 {:>6.1} ms | err {:>4} | RSS fleet {:>5.0} harness {:>5.0} policy {:>4.0} MiB | CPU {:>4.0}/{:>4.0}/{:>4.0} % | avail {:>5.0} MiB",
                row.t_s,
                row.phase,
                row.started,
                row.enrolled,
                row.connected,
                row.telemetry_accepted_per_s,
                row.publish.p50_ms,
                row.publish.p99_ms,
                row.authz.p99_ms,
                row.errors_total,
                row.fleet.rss_mb,
                row.harness.rss_mb,
                row.policy.rss_mb,
                row.fleet.cpu_pct,
                row.harness.cpu_pct,
                row.policy.cpu_pct,
                row.host_available_mb
            );
            if row.total_rss_mb > rss_cap_mb {
                abort = Some(format!(
                    "combined RSS {:.0} MiB exceeded the cap of {rss_cap_mb:.0} MiB (fleet {:.0}, harness {:.0}, policy {:.0})",
                    row.total_rss_mb, row.fleet.rss_mb, row.harness.rss_mb, row.policy.rss_mb
                ));
            } else if host.available_mb < a.min_available_mb as f64 {
                abort = Some(format!(
                    "host available memory {:.0} MiB fell below the floor of {} MiB (combined RSS {:.0} MiB: fleet {:.0}, harness {:.0}, policy {:.0})",
                    host.available_mb, a.min_available_mb, row.total_rss_mb, row.fleet.rss_mb, row.harness.rss_mb, row.policy.rss_mb
                ));
            }
            prev_t = now;
            prev_tele = tele;
            prev_ok = s.published_ok;
            prev_ever = s.ever_connected;
            if let Some(st) = st {
                last = st;
            }
            rows.push(row);
            if abort.is_some() {
                break;
            }
        }
        let el = t0.elapsed();
        match phase {
            Phase::Ramp => {
                let all_in = last.ever_connected >= n as u64;
                if el >= ramp_sched && (all_in || el >= ramp_sched + Duration::from_secs(a.ramp_grace_s)) {
                    phase = Phase::Sustain;
                    ramp_s = el.as_secs_f64();
                    let _ = io.send("phase sustain").await;
                    sustain_start = Some((Instant::now(), bstats.telemetry_accepted.load(Ordering::Relaxed)));
                    let count = (a.cmd_fraction * n as f64).round() as usize;
                    cmd_task = Some(spawn_commands(cloud.clone(), cmds.clone(), ids.clone(), count, Duration::from_secs(a.sustain_s)));
                    eprintln!(
                        "[load] ramp done after {ramp_s:.0} s ({} of {n} connected at least once); sustaining for {} s",
                        last.ever_connected, a.sustain_s
                    );
                }
            }
            Phase::Sustain => {
                if sustain_start.is_some_and(|(s, _)| s.elapsed() >= Duration::from_secs(a.sustain_s)) {
                    break;
                }
            }
        }
    }
    let end_snapshot = (Instant::now(), bstats.telemetry_accepted.load(Ordering::Relaxed), bstats.live_sessions.load(Ordering::Relaxed));
    if sustain_start.is_some() {
        sustain_end = Some(end_snapshot);
    }
    if let Some(r) = &abort {
        eprintln!("[load] ABORT: {r}");
    }
    if let Some(t) = cmd_task.take() {
        t.abort();
    }

    // Stop and collect.
    let _ = io.send("stop").await;
    let done = io.next_json(Duration::from_secs(120), "done").await.is_some();
    let _ = tokio::time::timeout(Duration::from_secs(30), child.wait()).await;
    let _ = child.start_kill();
    let fleet: FleetResult = if done {
        serde_json::from_slice(&std::fs::read(&spec.result_file)?).context("fleet result")?
    } else {
        eprintln!("[load] the fleet process did not finish cleanly; device-side totals are from the last status");
        FleetResult { status: last.clone(), ..FleetResult::default() }
    };
    let drain = Instant::now();
    while verifier.backlog.load(Ordering::Relaxed) > 0 && drain.elapsed() < Duration::from_secs(120) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Give in-flight acks a moment, then stop counting commands.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let metrics_after = h.policy_client.metrics_text().await.unwrap_or_default();
    std::fs::write(run_dir.join("policy-metrics-before.txt"), &metrics_before)?;
    std::fs::write(run_dir.join("policy-metrics-after.txt"), &metrics_after)?;

    // Verification: every device's last PUBACKed seq was accepted by the verifier.
    let last_seq = verifier.last_seq.lock().map(|m| m.clone()).unwrap_or_default();
    let mut ver = Verification {
        uplinks_verified: verifier.verified.load(Ordering::Relaxed),
        telemetry_verified: verifier.telemetry.load(Ordering::Relaxed),
        acks_verified: verifier.acks.load(Ordering::Relaxed),
        replay_rejections: verifier.replay_rejections.load(Ordering::Relaxed),
        verifier_peak_backlog: verifier.peak_backlog.load(Ordering::Relaxed),
        ..Verification::default()
    };
    for d in &fleet.devices {
        if d.last_acked_seq == 0 {
            continue;
        }
        ver.devices_with_acked_uplinks += 1;
        let v = last_seq.get(&d.id).copied().unwrap_or(0);
        if v == d.last_acked_seq {
            ver.last_seq_matched += 1;
        } else {
            ver.last_seq_mismatched += 1;
            if ver.mismatch_examples.len() < 10 {
                ver.mismatch_examples.push(format!("{}: device last PUBACKed seq {}, verifier last accepted {v}", d.id, d.last_acked_seq));
            }
        }
    }
    ver.passed = ver.devices_with_acked_uplinks > 0 && ver.last_seq_mismatched == 0 && ver.replay_rejections == 0 && done;

    let deltas = stats::prometheus_deltas(&metrics_before, &metrics_after, &["ironmesh_", "process_", "go_goroutines", "go_memstats_heap"]);
    let policy = PolicyFigures {
        authn_allow: stats::delta_sum(&deltas, "ironmesh_authn_decisions_total", "result=\"allow\""),
        authn_deny: stats::delta_sum(&deltas, "ironmesh_authn_decisions_total", "result=\"deny\""),
        authz_allow: stats::delta_sum(&deltas, "ironmesh_authz_decisions_total", "result=\"allow\""),
        authz_deny: stats::delta_sum(&deltas, "ironmesh_authz_decisions_total", "result=\"deny\""),
        authz_cache_hit: stats::delta_sum(&deltas, "ironmesh_authz_cache_total", "outcome=\"hit\""),
        authz_cache_miss: stats::delta_sum(&deltas, "ironmesh_authz_cache_total", "outcome=\"miss\""),
        registry_lookups: stats::delta_sum(&deltas, "ironmesh_registry_lookups_total", ""),
        process_cpu_seconds: stats::delta_sum(&deltas, "process_cpu_seconds_total", ""),
        latency_note: "services/policy exports decision counters but no authn/authz latency histogram; hook latency is the \
                       broker-side HTTP round trip (what EMQX would observe)"
            .into(),
        deltas: deltas.into_iter().filter(|d| d.delta != 0.0).collect(),
    };

    let sustain_rows: Vec<&Row> = rows.iter().filter(|r| r.phase == "sustain").collect();
    let all_rows: Vec<&Row> = rows.iter().collect();
    let (sustain_secs, sustain_tele) = match (sustain_start, sustain_end) {
        (Some((s, t0v)), Some((e, t1v, _))) => (e.duration_since(s).as_secs_f64(), t1v.saturating_sub(t0v)),
        _ => (0.0, 0),
    };
    let connected_end = sustain_end.map_or(end_snapshot.2, |(_, _, c)| c);
    let firsts: Vec<u64> = fleet.devices.iter().map(|d| d.first_connect_ms).filter(|v| *v > 0).collect();
    let span_s = match (firsts.iter().min(), firsts.iter().max()) {
        (Some(a0), Some(b0)) => (b0 - a0) as f64 / 1000.0,
        _ => 0.0,
    };
    let holds_in_span = a.stages.iter().filter(|p| **p > 0 && **p < 100).count() as f64 * a.stage_hold_s as f64;
    let last_sustain = sustain_rows.last().copied().or(rows.last());
    let resources = Resources {
        fleet_sustain: ProcStats::of(&sustain_rows, |r| r.fleet),
        harness_sustain: ProcStats::of(&sustain_rows, |r| r.harness),
        policy_sustain: ProcStats::of(&sustain_rows, |r| r.policy),
        fleet_all: ProcStats::of(&all_rows, |r| r.fleet),
        harness_all: ProcStats::of(&all_rows, |r| r.harness),
        policy_all: ProcStats::of(&all_rows, |r| r.policy),
        peak_total_rss_mb: rows.iter().map(|r| r.total_rss_mb).fold(0.0, f64::max),
        min_host_available_mb: rows.iter().map(|r| r.host_available_mb).fold(f64::MAX, f64::min).min(env.ram_available_at_start_mb),
        fleet_rss_per_device_kib: last_sustain.map_or(0.0, |r| {
            if r.connected > 0 {
                r.fleet.rss_mb * 1024.0 / r.connected as f64
            } else {
                0.0
            }
        }),
        harness_rss_per_session_kib: last_sustain.map_or(0.0, |r| {
            if r.broker_sessions > 0 {
                r.harness.rss_mb * 1024.0 / r.broker_sessions as f64
            } else {
                0.0
            }
        }),
        rss_cap_mb,
        min_available_floor_mb: a.min_available_mb as f64,
        hook_pool: h.policy_client.hooks.as_ref().map_or((0, 0), |p| (p.max(), p.opened())),
    };
    let lock_map = |m: &std::sync::Mutex<BTreeMap<String, u64>>| m.lock().map(|g| g.clone()).unwrap_or_default();
    let est_status = match &h.authority {
        crate::harness::Authority::Builtin(est) => est.status_counts(),
        crate::harness::Authority::Real(_) => BTreeMap::new(),
    };
    let summary = RunSummary {
        run: name.clone(),
        started_at,
        command,
        environment: env,
        config: a.clone(),
        outcome: Outcome {
            completed: abort.is_none() && sustain_end.is_some(),
            abort_reason: abort.clone(),
            provision_s,
            ramp_s,
            sustain_s: sustain_secs,
        },
        devices: DeviceCounts {
            requested: n,
            provisioned: devices.len(),
            started: fleet.status.started,
            enrolled: fleet.status.enrolled,
            ever_connected: fleet.status.ever_connected,
            connected_end_of_sustain: connected_end,
            connected_at_stop: fleet.connected_at_stop,
            never_connected: (devices.len() as u64).saturating_sub(fleet.status.ever_connected),
            broker_peak_sessions: bstats.peak_sessions.load(Ordering::Relaxed),
        },
        throughput: Throughput {
            target_start_rate: a.rate,
            achieved_connect_rate: if span_s > holds_in_span {
                firsts.len().saturating_sub(1) as f64 / (span_s - holds_in_span)
            } else {
                0.0
            },
            first_connect_span_s: span_s,
            telemetry_accepted_total: bstats.telemetry_accepted.load(Ordering::Relaxed),
            telemetry_accepted_sustain: sustain_tele,
            sustain_telemetry_per_s: stats::rate(sustain_tele, sustain_secs),
            expected_telemetry_per_s: connected_end.max(0) as f64 / a.interval_s.max(1) as f64,
            device_acked_total: fleet.status.published_ok,
        },
        latency: Latencies {
            publish_sustain: fleet.publish_latency_sustain.clone(),
            publish_ramp: fleet.publish_latency_ramp.clone(),
            publish_all: fleet.publish_latency_all.clone(),
            connect: fleet.connect_latency.clone(),
            enroll: fleet.enroll_latency.clone(),
            command_rtt: cmds.rtt.summary(),
            authn_hook: bstats.authn_latency.summary(),
            authz_hook: bstats.authz_latency.summary(),
            hook_pool_wait: h.policy_client.hooks.as_ref().map(|p| p.permit_wait.summary()).unwrap_or_default(),
        },
        commands: Commands {
            sent: cmds.sent.load(Ordering::Relaxed),
            not_delivered: cmds.not_delivered.load(Ordering::Relaxed),
            inject_errors: cmds.inject_errors.load(Ordering::Relaxed),
            acked: cmds.acked.load(Ordering::Relaxed),
            unacked: cmds.unacked(),
            ack_mismatch: cmds.ack_mismatch.load(Ordering::Relaxed),
            ack_status: cmds.ack_status.lock().map(|g| g.clone()).unwrap_or_default(),
            executed_on_devices: fleet.status.cmds_executed,
            rejected_by_devices: fleet.status.downlink_rejected,
        },
        policy,
        errors: Errors {
            fleet: fleet.errors.clone(),
            broker_handshake: lock_map(&bstats.handshake_errors),
            broker_hook: lock_map(&bstats.hook_error_texts),
            broker_closes: lock_map(&bstats.closes),
            connects_denied: bstats.connects_denied.load(Ordering::Relaxed),
            publishes_denied: bstats.publishes_denied.load(Ordering::Relaxed),
            subscribes_denied: bstats.subscribes_denied.load(Ordering::Relaxed),
            est_status,
            verifier: lock_map(&verifier.failures),
        },
        verification: ver,
        resources,
    };
    std::fs::write(results.join("summary.json"), serde_json::to_string_pretty(&summary)?)?;
    std::fs::write(results.join("timeseries.csv"), report::csv(&rows))?;
    std::fs::write(results.join("report.md"), report::render(&summary, &rows))?;
    let passed = summary.outcome.completed && summary.verification.passed;
    eprintln!(
        "[load] {}: {} of {n} devices connected, {:.0} telemetry/s sustained, publish p50/p95/p99/max {} ms, verification {}; results in {}",
        if passed { "PASS" } else { "NOT PASSED" },
        summary.devices.ever_connected,
        summary.throughput.sustain_telemetry_per_s,
        summary.latency.publish_sustain.short(),
        if summary.verification.passed { "passed" } else { "FAILED" },
        results.display()
    );
    drop(verifier_task);
    cloud.shutdown().await;
    if !a.keep_fleet {
        let _ = std::fs::remove_dir_all(&fleet_root);
    }
    Ok((results, passed))
}
