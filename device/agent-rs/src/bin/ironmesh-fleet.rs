//! `ironmesh-fleet`: virtual fleet simulator.
//!
//! ```text
//! ironmesh-fleet provision --out fleet/ --count 500 --tenant <uuid>   identities + bootstrap CSRs
//! ironmesh-fleet run --dir fleet/ --config fleet.toml [--anomalous 5] [--stagger-ms 20]
//! ironmesh-fleet bench --count 10000 --rounds 3                        memory footprint (no network)
//! ```
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ironmesh_agent::fleet::{self, Anomaly, FleetIndex, Stats};
use ironmesh_agent::settings::Settings;

#[derive(Parser)]
#[command(name = "ironmesh-fleet", version, about = "IronMesh virtual fleet simulator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create device identities and bootstrap CSRs.
    Provision {
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
        /// Number of devices.
        #[arg(long, default_value_t = 500)]
        count: u64,
        /// Tenant id.
        #[arg(long)]
        tenant: String,
        /// Device id prefix (hex, 8 digits).
        #[arg(long, default_value = "f1ee7000")]
        prefix: String,
    },
    /// Run the fleet against an IronMesh stack.
    Run {
        /// Fleet directory created by `provision`.
        #[arg(long)]
        dir: PathBuf,
        /// Shared agent configuration (pki, mqtt, telemetry interval).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Only run the first N devices.
        #[arg(long)]
        count: Option<usize>,
        /// Number of misbehaving devices.
        #[arg(long, default_value_t = 0)]
        anomalous: usize,
        /// Delay between device starts (staggered enrollment).
        #[arg(long, default_value_t = 20)]
        stagger_ms: u64,
        /// Stop after this many seconds (0 = run until Ctrl-C).
        #[arg(long, default_value_t = 0)]
        duration_s: u64,
    },
    /// Measure per-device memory without a network.
    Bench {
        /// Devices.
        #[arg(long, default_value_t = 10_000)]
        count: u64,
        /// Telemetry rounds.
        #[arg(long, default_value_t = 3)]
        rounds: u64,
    },
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("ironmesh-fleet: {msg}");
    ExitCode::from(1)
}

async fn run(dir: PathBuf, config: Option<PathBuf>, count: Option<usize>, anomalous: usize, stagger_ms: u64, duration_s: u64) -> ExitCode {
    let settings = match Settings::load(config.as_deref()) {
        Ok(s) => Arc::new(s),
        Err(e) => return fail(e),
    };
    let index: FleetIndex = match ironmesh_agent::persist::read_json(&dir.join("fleet.json")) {
        Ok(Some(i)) => i,
        Ok(None) => return fail("fleet.json missing; run `ironmesh-fleet provision` first"),
        Err(e) => return fail(e),
    };
    let devices: Vec<String> = index.devices.into_iter().take(count.unwrap_or(usize::MAX)).collect();
    let n = devices.len();
    let stats = Arc::new(Stats::default());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::with_capacity(n);
    // Spread the misbehaving devices over the fleet.
    let stride = n.checked_div(anomalous).map_or(usize::MAX, |s| s.max(1));
    for (i, id) in devices.iter().enumerate() {
        let anomaly = (anomalous > 0 && i % stride == 0 && i / stride < anomalous).then(|| Anomaly::nth(i / stride));
        if let Some(a) = anomaly {
            tracing::info!(device = %id, anomaly = ?a, "misbehaving device");
        }
        tasks.push(tokio::spawn(fleet::run_device(settings.clone(), dir.join(id), i as u64, anomaly, stats.clone(), stop_rx.clone())));
        tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
    }
    let report = {
        let stats = stats.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                tracing::info!(
                    devices = n,
                    enrolled = stats.enrolled.load(Ordering::Relaxed),
                    connected = stats.connected.load(Ordering::Relaxed),
                    published = stats.published.load(Ordering::Relaxed),
                    errors = stats.errors.load(Ordering::Relaxed),
                    "fleet status"
                );
            }
        })
    };
    if duration_s > 0 {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(duration_s)) => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    } else {
        let _ = tokio::signal::ctrl_c().await;
    }
    let _ = stop_tx.send(true);
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }
    report.abort();
    println!(
        "{}",
        serde_json::json!({
            "devices": n,
            "enrolled": stats.enrolled.load(Ordering::Relaxed),
            "published": stats.published.load(Ordering::Relaxed),
            "errors": stats.errors.load(Ordering::Relaxed),
        })
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    ironmesh_agent::logging::init(&std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()), "ironmesh-fleet");
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    match cli.cmd {
        Cmd::Provision { out, count, tenant, prefix } => {
            if !ironmesh_agent::wire::ids::is_tenant_id(&tenant) {
                return fail("tenant must be a lower-case UUIDv4");
            }
            let Ok(prefix) = u64::from_str_radix(&prefix, 16) else { return fail("prefix must be hex") };
            match fleet::provision(&out, count, &tenant, prefix) {
                Ok(idx) => {
                    println!(
                        "{} identities in {}; sign each bootstrap.csr.pem with the Factory CA and save it as bootstrap.crt",
                        idx.devices.len(),
                        out.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }
        Cmd::Run { dir, config, count, anomalous, stagger_ms, duration_s } => {
            rt.block_on(run(dir, config, count, anomalous, stagger_ms, duration_s))
        }
        Cmd::Bench { count, rounds } => {
            let r = rt.block_on(fleet::bench(count, rounds));
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            ExitCode::SUCCESS
        }
    }
}
