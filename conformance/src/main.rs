//! `ironmesh-conformance`: run the device conformance suite against one firmware target.
//!
//! ```text
//! ironmesh-conformance run --target agent-rs|esp32-host|esp32-hil [--cases C-OTA-*] [--junit out.xml] [--report out.md]
//!                          [--policy-bin path] [--pki-bin path] [--stack <url> [--stack-config file]]
//! ironmesh-conformance summary [--results-dir conformance/results]
//! ironmesh-conformance list
//! ironmesh-conformance build
//! ```
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ironmesh_conformance::cases::{self, RunOptions, Verdict};
use ironmesh_conformance::dut::agent_rs::AgentRsLauncher;
use ironmesh_conformance::dut::esp32_hil::Esp32HilLauncher;
use ironmesh_conformance::dut::esp32_host::Esp32HostLauncher;
use ironmesh_conformance::dut::{exe, Launcher, Target};
use ironmesh_conformance::harness::stack::{Stack, StackConfig};
use ironmesh_conformance::harness::{Backend, Cloud, CloudOptions};
use ironmesh_conformance::report::{self, junit, markdown, summary, RunReport, StoredResult};
use ironmesh_conformance::util;

#[derive(Parser)]
#[command(name = "ironmesh-conformance", version, about = "IronMesh device conformance suite (conformance/DUT_PROTOCOL.md)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the suite against one target.
    Run(Box<RunArgs>),
    /// Regenerate results/SUMMARY.md from every results/<target>/results.json.
    Summary {
        /// Results directory.
        #[arg(long)]
        results_dir: Option<PathBuf>,
    },
    /// List the cases.
    List,
    /// Build the policy service and the DUT binaries into conformance/target.
    Build,
    /// Write a persistent harness PKI (CAs, keys, bundle key) for provisioning HIL boards.
    ExportPki {
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(clap::Args)]
struct RunArgs {
    /// Target: agent-rs, esp32-host or esp32-hil.
    #[arg(long)]
    target: String,
    /// Case selection (comma-separated, wildcards: `C-OTA-*`). Default: all.
    #[arg(long, value_delimiter = ',')]
    cases: Vec<String>,
    /// JUnit XML output (default results/<target>/junit.xml).
    #[arg(long)]
    junit: Option<PathBuf>,
    /// Markdown report (default results/<target>/report.md).
    #[arg(long)]
    report: Option<PathBuf>,
    /// Results directory root (default conformance/results).
    #[arg(long)]
    results_dir: Option<PathBuf>,
    /// Policy service binary (default: conformance/target/bin/policy, built with `go build` if missing).
    #[arg(long)]
    policy_bin: Option<PathBuf>,
    /// Use the real PKI service binary as the enrollment authority (see README).
    #[arg(long)]
    pki_bin: Option<PathBuf>,
    /// pkictl binary for the real-PKI key ceremony (default: next to the policy binary).
    #[arg(long)]
    pkictl_bin: Option<PathBuf>,
    /// agent-rs DUT binary (built with --features dut-control).
    #[arg(long)]
    agent_bin: Option<PathBuf>,
    /// agent-rs release binary (C-HOOK-1).
    #[arg(long)]
    agent_release_bin: Option<PathBuf>,
    /// esp32-host shim binary (im-dut-shim).
    #[arg(long)]
    shim_bin: Option<PathBuf>,
    /// esp32-hil configuration (TOML).
    #[arg(long)]
    hil_config: Option<PathBuf>,
    /// Run against a real stack (docker-compose / EMQX) at this URL instead of the hermetic cloud.
    #[arg(long)]
    stack: Option<String>,
    /// Credentials and endpoints of the real stack (TOML).
    #[arg(long)]
    stack_config: Option<PathBuf>,
    /// C-REV-1 iterations.
    #[arg(long, default_value_t = 20)]
    rev_iterations: usize,
    /// Do not build missing binaries.
    #[arg(long)]
    no_build: bool,
    /// Bind address of the hermetic cloud.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    /// Address devices use to reach the hermetic cloud.
    #[arg(long, default_value = "127.0.0.1")]
    advertise_host: String,
}

struct Paths {
    repo: PathBuf,
    conformance: PathBuf,
}

impl Paths {
    fn new() -> Self {
        let repo = util::repo_root();
        Self { conformance: repo.join("conformance"), repo }
    }
    fn policy(&self) -> PathBuf {
        self.conformance.join("target").join("bin").join(exe("policy"))
    }
    fn pki(&self) -> PathBuf {
        self.conformance.join("target").join("bin").join(exe("pki"))
    }
    fn pkictl(&self) -> PathBuf {
        self.conformance.join("target").join("bin").join(exe("pkictl"))
    }
    fn agent_dut(&self) -> PathBuf {
        self.conformance.join("target").join("duts").join("agent-rs-dut").join("debug").join(exe("ironmesh-agent"))
    }
    fn agent_release(&self) -> PathBuf {
        self.conformance.join("target").join("duts").join("agent-rs-release").join("release").join(exe("ironmesh-agent"))
    }
    fn shim(&self) -> PathBuf {
        self.conformance.join("target").join("duts").join("esp32-host").join("debug").join(exe("im-dut-shim"))
    }
}

fn go_binary() -> PathBuf {
    let win = PathBuf::from(r"C:\Program Files\Go\bin\go.exe");
    if cfg!(windows) && win.is_file() {
        win
    } else {
        PathBuf::from("go")
    }
}

fn run_cmd(cmd: &mut std::process::Command, what: &str) -> Result<()> {
    eprintln!("[build] {what}");
    let st = cmd.status().with_context(|| format!("run {what}"))?;
    if !st.success() {
        bail!("{what} failed ({st})");
    }
    Ok(())
}

fn build_go(p: &Paths, pkg: &str, out: &Path) -> Result<()> {
    std::fs::create_dir_all(out.parent().unwrap_or(Path::new(".")))?;
    run_cmd(
        std::process::Command::new(go_binary()).current_dir(&p.repo).env("CGO_ENABLED", "0").arg("build").arg("-o").arg(out).arg(pkg),
        &format!("go build {pkg}"),
    )
}

fn build_cargo(manifest: &Path, target_dir: &Path, extra: &[&str]) -> Result<()> {
    let mut c = std::process::Command::new("cargo");
    c.arg("build").arg("--locked").arg("--manifest-path").arg(manifest).arg("--target-dir").arg(target_dir).args(extra);
    run_cmd(&mut c, &format!("cargo build {} {}", manifest.display(), extra.join(" ")))
}

fn build_all(p: &Paths, policy: bool, pki: bool, agent: bool, release: bool, shim: bool) -> Result<()> {
    let duts = p.conformance.join("target").join("duts");
    if policy {
        build_go(p, "./services/policy/cmd/policy", &p.policy())?;
    }
    if pki {
        build_go(p, "./services/pki/cmd/pki", &p.pki())?;
        build_go(p, "./services/pki/cmd/pkictl", &p.pkictl())?;
    }
    if agent {
        build_cargo(
            &p.repo.join("device/agent-rs/Cargo.toml"),
            &duts.join("agent-rs-dut"),
            &["--features", "dut-control", "--bin", "ironmesh-agent"],
        )?;
    }
    if release {
        build_cargo(&p.repo.join("device/agent-rs/Cargo.toml"), &duts.join("agent-rs-release"), &["--release", "--bin", "ironmesh-agent"])?;
    }
    if shim {
        build_cargo(
            &p.repo.join("device/esp32/host/Cargo.toml"),
            &duts.join("esp32-host"),
            &["-p", "im-dut-shim", "--bin", "im-dut-shim"],
        )?;
    }
    Ok(())
}

fn sha_prefix(path: &Path) -> String {
    use sha2::Digest;
    std::fs::read(path).map(|b| hex::encode(&sha2::Sha256::digest(&b)[..8])).unwrap_or_else(|_| "?".into())
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

fn host_description() -> String {
    let name = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "host".into());
    format!("{name} ({} {})", std::env::consts::OS, std::env::consts::ARCH)
}

async fn run(a: RunArgs) -> Result<bool> {
    ironmesh_conformance::install_crypto();
    let p = Paths::new();
    let target = Target::parse(&a.target).ok_or_else(|| anyhow!("unknown target {:?} (agent-rs, esp32-host, esp32-hil)", a.target))?;
    let policy_bin = a.policy_bin.clone().unwrap_or_else(|| p.policy());
    let agent_bin = a.agent_bin.clone().unwrap_or_else(|| p.agent_dut());
    let release_bin = a.agent_release_bin.clone().unwrap_or_else(|| p.agent_release());
    let shim_bin = a.shim_bin.clone().unwrap_or_else(|| p.shim());
    if !a.no_build {
        build_all(
            &p,
            a.stack.is_none() && !policy_bin.is_file() && a.policy_bin.is_none(),
            a.pki_bin.as_ref().is_some_and(|b| *b == p.pki() && (!b.is_file() || !p.pkictl().is_file())),
            target == Target::AgentRs && !agent_bin.is_file() && a.agent_bin.is_none(),
            target == Target::AgentRs && !release_bin.is_file() && a.agent_release_bin.is_none(),
            target == Target::Esp32Host && !shim_bin.is_file() && a.shim_bin.is_none(),
        )?;
    }
    let results_root = a.results_dir.clone().unwrap_or_else(|| p.conformance.join("results"));
    let results = results_root.join(target.name());
    std::fs::create_dir_all(&results)?;
    let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let run_dir = p.conformance.join("target").join("runs").join(format!("{}-{stamp}", target.name()));
    std::fs::create_dir_all(&run_dir)?;
    let tenant = util::uuid4();
    let started_at = rfc3339_now();
    let t0 = Instant::now();
    let mut environment = vec![("tenant_id".to_string(), tenant.clone()), ("run_dir".to_string(), run_dir.display().to_string())];

    let hil = match (target, &a.hil_config) {
        (Target::Esp32Hil, Some(f)) => Some(Esp32HilLauncher::from_file(f)?.config),
        (Target::Esp32Hil, None) => bail!("--target esp32-hil requires --hil-config"),
        _ => None,
    };
    let advertise_host = hil.as_ref().map_or_else(|| a.advertise_host.clone(), |h| h.advertise_host.clone());
    let bind_host = if hil.is_some() && a.bind == "127.0.0.1" { "0.0.0.0".to_string() } else { a.bind.clone() };
    let cloud = match &a.stack {
        Some(url) => {
            let mut cfg = StackConfig::load(url, a.stack_config.as_deref())?;
            if cfg.tenant_id.is_empty() {
                cfg.tenant_id = tenant.clone();
            }
            let stack = Stack::new(cfg)?;
            let mut keys = ironmesh_conformance::harness::keys::HarnessKeys::load(&p.repo);
            if let Some(k) = stack.tenant_key() {
                keys.tenant = k;
            }
            if let Some(k) = stack.fw_key() {
                keys.firmware = k;
            }
            let tenant_id = stack.cfg.tenant_id.clone();
            environment.push(("stack".into(), url.clone()));
            Cloud::new(tenant_id, keys, Backend::Stack(Box::new(stack)), run_dir.clone())
        }
        None => {
            environment.push(("policy_service".into(), format!("{} (sha256 {})", policy_bin.display(), sha_prefix(&policy_bin))));
            Cloud::start_hermetic(&CloudOptions {
                bind_host: bind_host.clone(),
                advertise_host: advertise_host.clone(),
                policy_bin: policy_bin.clone(),
                real_pki: a.pki_bin.clone().map(|b| (b, a.pkictl_bin.clone().unwrap_or_else(|| p.pkictl()))),
                pki_dir: hil.as_ref().map(|h| h.pki_dir.clone()),
                est_port: hil.as_ref().map_or(0, |h| h.est_port),
                run_dir: run_dir.clone(),
                repo_root: p.repo.clone(),
                tenant_id: tenant.clone(),
            })
            .await?
        }
    };
    environment.push(("signing_keys".into(), cloud.keys.source.clone()));
    let launcher = match target {
        Target::AgentRs => {
            environment.push(("dut_binary".into(), format!("{} (sha256 {})", agent_bin.display(), sha_prefix(&agent_bin))));
            environment.push(("release_binary".into(), format!("{} (sha256 {})", release_bin.display(), sha_prefix(&release_bin))));
            Launcher::AgentRs(AgentRsLauncher { binary: agent_bin, release_binary: Some(release_bin) })
        }
        Target::Esp32Host => {
            environment
                .push(("dut_binary".into(), format!("{} (sha256 {}), real-network mode", shim_bin.display(), sha_prefix(&shim_bin))));
            Launcher::Esp32Host(Esp32HostLauncher { binary: shim_bin })
        }
        Target::Esp32Hil => {
            let cfg = a.hil_config.as_deref().ok_or_else(|| anyhow!("--target esp32-hil requires --hil-config"))?;
            environment.push(("hil_config".into(), cfg.display().to_string()));
            Launcher::Esp32Hil(Esp32HilLauncher::from_file(cfg)?)
        }
    };
    if let Some(pki) = &a.pki_bin {
        environment
            .push(("pki_service".into(), format!("{} (sha256 {}): real PKI is the enrollment authority", pki.display(), sha_prefix(pki))));
    }
    let profile = launcher.profile();
    environment.push(("product".into(), profile.product.clone()));
    environment.push(("reconnect_backoff_clock_scale".into(), profile.backoff_scale.to_string()));
    environment.push(("ota_health_timeout_s".into(), profile.health_timeout_s.to_string()));
    let cloud = Arc::new(cloud);
    let launcher = Arc::new(launcher);
    let defs: Vec<_> = cases::all()
        .into_iter()
        .filter(|d| a.cases.is_empty() || a.cases.iter().any(|pat| util::wildcard_match(pat.trim(), d.id)))
        .collect();
    if defs.is_empty() {
        bail!("no case matches {:?}", a.cases);
    }
    eprintln!("[run] target {} ({} cases), cloud {}, run dir {}", target.name(), defs.len(), cloud.mode(), run_dir.display());
    let mut out = Vec::new();
    for d in &defs {
        eprint!("[run] {} {} ... ", d.id, d.title);
        let r = cases::run_case(d, cloud.clone(), launcher.clone(), RunOptions { rev_iterations: a.rev_iterations }).await;
        eprintln!(
            "{} ({:.1} s){}",
            r.verdict.label(),
            r.seconds,
            if r.reason.is_empty() { String::new() } else { format!(": {}", r.reason) }
        );
        out.push(r);
        if let Err(e) = cloud.check_alive().await {
            eprintln!("[run] cloud failure: {e:#}");
            break;
        }
    }
    cloud.shutdown().await;
    let report = RunReport {
        target: target.name().into(),
        mode: cloud.mode().into(),
        started_at,
        seconds: t0.elapsed().as_secs_f64(),
        git_commit: format!("{}{}", report::git_commit(&p.repo), if report::git_dirty(&p.repo) { " (working tree modified)" } else { "" }),
        host: host_description(),
        environment,
        results: out.iter().map(StoredResult::from).collect(),
    };
    let junit_path = a.junit.clone().unwrap_or_else(|| results.join("junit.xml"));
    let report_path = a.report.clone().unwrap_or_else(|| results.join("report.md"));
    std::fs::write(&junit_path, junit::render(&report))?;
    std::fs::write(&report_path, markdown::render(&report))?;
    std::fs::write(results.join("results.json"), serde_json::to_string_pretty(&report)?)?;
    write_summary(&results_root, &p.repo)?;
    let (pa, fa, na, er) = report.counts();
    eprintln!("[run] {pa} passed, {fa} failed, {na} n/a, {er} errors; JUnit {}; report {}", junit_path.display(), report_path.display());
    Ok(out.iter().all(|r| matches!(r.verdict, Verdict::Passed | Verdict::NotApplicable)))
}

fn write_summary(results_root: &Path, repo: &Path) -> Result<()> {
    // Real-PKI runs live in results/real-pki/<target>; the summary is always written one level up.
    let root = if results_root.file_name().is_some_and(|n| n == "real-pki") {
        results_root.parent().unwrap_or(results_root)
    } else {
        results_root
    };
    let runs = summary::load_all(root)?;
    let interop = summary::load_all(&root.join("real-pki")).unwrap_or_default();
    if runs.is_empty() && interop.is_empty() {
        return Ok(());
    }
    let s = summary::render(&runs, &interop, &rfc3339_now(), &report::git_commit(repo));
    let results_root = root;
    std::fs::write(results_root.join("SUMMARY.md"), s)?;
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ironmesh-conformance: {e}");
            return ExitCode::from(2);
        }
    };
    let p = Paths::new();
    let result = match cli.cmd {
        Cmd::Run(a) => runtime.block_on(run(*a)).map(|ok| if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }),
        Cmd::Summary { results_dir } => {
            write_summary(&results_dir.unwrap_or_else(|| p.conformance.join("results")), &p.repo).map(|()| ExitCode::SUCCESS)
        }
        Cmd::List => {
            for d in cases::all() {
                println!("{:9} {}\n          pass: {}", d.id, d.title, d.criterion);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Build => build_all(&p, true, true, true, true, true).map(|()| ExitCode::SUCCESS),
        Cmd::ExportPki { out } => ironmesh_conformance::harness::pki::TestPki::generate(&[]).and_then(|pki| pki.save(&out)).map(|()| {
            eprintln!("harness PKI written to {} (anchors.pem, est-pin.hex, bundle.pub.hex, factory-ca.*)", out.display());
            ExitCode::SUCCESS
        }),
    };
    match result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ironmesh-conformance: {e:#}");
            ExitCode::from(2)
        }
    }
}
