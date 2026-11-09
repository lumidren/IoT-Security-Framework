//! `ironmesh-agent`: the IronMesh Linux device agent.
//!
//! ```text
//! ironmesh-agent [--config FILE]                       run the service (systemd)
//! ironmesh-agent --factory --device-id D --tenant-id T  create the identity, print the bootstrap CSR
//! ironmesh-agent --install-bootstrap bootstrap.crt      install the factory-issued bootstrap cert
//! ironmesh-agent --boot-status                          print A/B slot state (JSON)
//! ironmesh-agent --rollback                             abandon a pending slot (ironmesh-rollback.service)
//! ironmesh-agent --dut                                  conformance control channel (feature dut-control)
//! ```
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use ironmesh_agent::agent::{Agent, RebootReason};
use ironmesh_agent::app;
use ironmesh_agent::enroll::Credentials;
use ironmesh_agent::identity::KeySlot;
use ironmesh_agent::seq::Clock;
use ironmesh_agent::settings::Settings;
use ironmesh_agent::{logging, x509};
use tokio::sync::broadcast;

#[derive(Parser, Debug)]
#[command(name = "ironmesh-agent", version, about = "IronMesh Linux device agent")]
struct Cli {
    /// TOML configuration file (environment overrides: IRONMESH_<SECTION>_<KEY>).
    #[arg(long, short, env = "IRONMESH_CONFIG")]
    config: Option<PathBuf>,
    /// Factory mode: create the identity and print the bootstrap CSR.
    #[arg(long)]
    factory: bool,
    /// Device id minted by the Registry (factory mode).
    #[arg(long, requires = "factory")]
    device_id: Option<String>,
    /// Tenant id (factory mode).
    #[arg(long, requires = "factory")]
    tenant_id: Option<String>,
    /// Force the software backend in factory mode.
    #[arg(long, requires = "factory")]
    software: bool,
    /// Install the factory-issued bootstrap certificate (PEM or DER).
    #[arg(long)]
    install_bootstrap: Option<PathBuf>,
    /// Print the A/B boot state and exit.
    #[arg(long)]
    boot_status: bool,
    /// Abandon the pending slot (systemd OnFailure hook) and exit.
    #[arg(long)]
    rollback: bool,
    /// Serve the DUT control protocol on stdin/stdout (test builds only).
    #[arg(long)]
    dut: bool,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("ironmesh-agent: {msg}");
    ExitCode::from(1)
}

fn factory(settings: &Settings, cli: &Cli) -> ExitCode {
    let (Some(device), Some(tenant)) = (&cli.device_id, &cli.tenant_id) else {
        return fail("--factory requires --device-id and --tenant-id");
    };
    if !ironmesh_agent::wire::ids::is_device_id(device) || !ironmesh_agent::wire::ids::is_tenant_id(tenant) {
        return fail("device id must be dev-<16 hex> and tenant id a lower-case UUIDv4");
    }
    let mut s = settings.clone();
    if cli.software {
        s.identity.backend = ironmesh_agent::settings::Backend::Software;
    }
    let identity = match app::create_identity(&s, device, tenant) {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    if identity.has_key(KeySlot::Bootstrap) {
        return fail("a bootstrap key already exists; refusing to overwrite it");
    }
    let pk = match identity.generate_bootstrap_key() {
        Ok(pk) => pk,
        Err(e) => return fail(e),
    };
    let id2 = identity.clone();
    let sign = move |d: &[u8; 32]| id2.sign(KeySlot::Bootstrap, d).map_err(|e| e.to_string());
    match x509::build_csr(device, tenant, &pk, &sign) {
        Ok(csr) => {
            print!("{}", x509::to_pem("CERTIFICATE REQUEST", &csr));
            eprintln!("bootstrap key generated in the {:?} backend (assurance {:?})", s.identity.backend, identity.assurance());
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn boot_status(settings: &Settings) -> ExitCode {
    let boot = app::boot_control(settings);
    match (boot.state(), ironmesh_agent::ota::slots::SlotStore::open(&settings.ota.slots_dir)) {
        (Ok(state), Ok(slots)) => {
            let out = serde_json::json!({
                "active": state.active.name(),
                "pending": state.pending.map(|p| p.name()),
                "boot_count": state.boot_count,
                "anti_rollback_version_code": slots.anti_rollback(),
                "slots": {
                    "a": slots.meta(ironmesh_agent::ota::boot::Slot::A),
                    "b": slots.meta(ironmesh_agent::ota::boot::Slot::B),
                },
                "pending_update": slots.pending_update(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            ExitCode::SUCCESS
        }
        (Err(e), _) => fail(e),
        (_, Err(e)) => fail(e),
    }
}

async fn run_service(settings: Settings) -> ExitCode {
    let identity = match app::open_identity(&settings) {
        Ok(i) => i,
        Err(e) => return fail(format!("identity: {e}")),
    };
    if let Err(e) = ironmesh_agent::identity::self_test(identity.as_ref(), KeySlot::Bootstrap)
        .or_else(|_| ironmesh_agent::identity::self_test(identity.as_ref(), KeySlot::Operational))
    {
        return fail(format!("identity self-test failed: {e}"));
    }
    let (events, _) = broadcast::channel(256);
    let opts = app::agent_options(&settings, identity, Arc::new(Clock::new()), events, None, true, true, false);
    let (agent, mut reboots) = match Agent::start(opts).await {
        Ok(a) => a,
        Err(e) => return fail(e),
    };
    let reason = tokio::select! {
        r = reboots.recv() => r,
        _ = shutdown_signal() => None,
    };
    agent.shutdown().await;
    if let Some(reason) = reason {
        tracing::info!(reason = reason.name(), "restart requested");
        if matches!(reason, RebootReason::Requested | RebootReason::OtaApply | RebootReason::Rollback)
            && !settings.ota.reboot_command.is_empty()
        {
            let mut cmd = std::process::Command::new(&settings.ota.reboot_command[0]);
            cmd.args(&settings.ota.reboot_command[1..]);
            if let Err(e) = cmd.status() {
                tracing::error!(error = %e, "reboot command failed; exiting so systemd restarts the agent");
            }
        }
    }
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(feature = "dut-control")]
async fn run_dut(settings: Settings) -> ExitCode {
    let factory: ironmesh_agent::dut::OptionsFactory = Arc::new({
        let clock = Arc::new(Clock::new());
        move |events, reason, want, net| {
            let identity = app::open_identity(&settings).map_err(|e| e.to_string())?;
            Ok(app::agent_options(&settings, identity, clock.clone(), events, reason, want, net, true))
        }
    });
    match ironmesh_agent::dut::run_stdio(factory).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

#[cfg(not(feature = "dut-control"))]
async fn run_dut(_settings: Settings) -> ExitCode {
    eprintln!("ironmesh-agent: the DUT control channel is not compiled into this build (cargo feature `dut-control`); refusing --dut");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.dut && !cfg!(feature = "dut-control") {
        eprintln!("ironmesh-agent: the DUT control channel is not compiled into this build (cargo feature `dut-control`); refusing --dut");
        return ExitCode::from(2);
    }
    let settings = match Settings::load(cli.config.as_deref()) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    logging::init(&settings.agent.log_level, "ironmesh-agent");
    if cli.factory {
        return factory(&settings, &cli);
    }
    if let Some(cert) = &cli.install_bootstrap {
        let identity = match app::open_identity(&settings) {
            Ok(i) => i,
            Err(e) => return fail(e),
        };
        let bytes = match std::fs::read(cert) {
            Ok(b) => b,
            Err(e) => return fail(e),
        };
        return match Credentials::install_bootstrap(&settings.identity.dir, &identity, &bytes) {
            Ok(info) => {
                println!("bootstrap certificate installed: serial {} not_after {}", info.serial_hex(), info.not_after);
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        };
    }
    if cli.boot_status {
        return boot_status(&settings);
    }
    if cli.rollback {
        return match app::boot_control(&settings).rollback() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        };
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    if cli.dut {
        return runtime.block_on(run_dut(settings));
    }
    runtime.block_on(run_service(settings))
}
