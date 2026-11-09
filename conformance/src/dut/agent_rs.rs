//! `agent-rs` launcher: the Linux agent built with the `dut-control` feature, provisioned the way
//! the factory does it (`--factory` creates the identity and prints the bootstrap CSR, the harness
//! Factory CA signs it, `--install-bootstrap` installs it) and then started with `--dut` against a
//! generated configuration that points at the cloud.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

use super::{device_dir, scrub_env, Dut, DutLink, LaunchOptions, Resumption, Target, TargetProfile};
use crate::harness::{ota, Cloud};
use crate::util;

/// Product of the generated configuration.
pub const PRODUCT: &str = "gateway-rpi";
/// Factory firmware version code.
pub const FACTORY_VERSION_CODE: u64 = 100;
/// Default reconnect backoff scale ("clock scaling" of DUT_PROTOCOL C-TLS-5).
pub const BACKOFF_SCALE: f64 = 0.02;
/// Health deadline configured for update boots (production: 120 s).
pub const HEALTH_TIMEOUT_S: u64 = 15;

/// Launcher.
pub struct AgentRsLauncher {
    /// `ironmesh-agent` built with `--features dut-control`.
    pub binary: PathBuf,
    /// `ironmesh-agent` release build (no `dut-control`), for C-HOOK-1.
    pub release_binary: Option<PathBuf>,
}

/// The factory image the harness installs as the running firmware (`telemetry.fw_image`).
#[must_use]
pub fn factory_image() -> Vec<u8> {
    ota::firmware_image(0x00a9_e175, 48 * 1024)
}

impl AgentRsLauncher {
    /// Profile.
    #[must_use]
    pub fn profile(&self, backoff_scale: Option<f64>) -> TargetProfile {
        TargetProfile {
            target: Target::AgentRs,
            product: PRODUCT.into(),
            set_clock: true,
            resumption: Resumption::Resumed,
            backoff_scale: backoff_scale.unwrap_or(BACKOFF_SCALE),
            health_timeout_s: HEALTH_TIMEOUT_S,
            benign_command: "ping".into(),
            factory_image: Some(factory_image()),
            release_binary: self.release_binary.clone(),
        }
    }

    fn config(&self, dir: &std::path::Path, cloud: &Cloud, scale: f64) -> Result<String> {
        let ep = cloud.endpoints();
        let p = |s: &str| dir.join(s).to_string_lossy().replace('\\', "/");
        let mut root = toml::Table::new();
        let mut t = |name: &str, entries: Vec<(&str, toml::Value)>| {
            let mut tab = toml::Table::new();
            for (k, v) in entries {
                tab.insert(k.into(), v);
            }
            root.insert(name.into(), toml::Value::Table(tab));
        };
        use toml::Value as V;
        t(
            "identity",
            vec![
                ("dir", V::String(p("identity"))),
                ("backend", V::String("software".into())),
                ("machine_secret", V::String(p("identity/machine-secret"))),
                ("ak_cert", V::String(p("identity/ak.crt"))),
            ],
        );
        t(
            "pki",
            vec![
                ("est_host", V::String(ep.est_host.clone())),
                ("est_port", V::Integer(i64::from(ep.est_port))),
                ("ca_bundle", V::String(p("ca-bundle.pem"))),
                ("est_pins", V::Array(ep.est_pins_hex.iter().cloned().map(V::String).collect())),
                ("bundle_pubkey", V::String(ep.bundle_pubkey_hex.clone())),
                ("timeout_s", V::Integer(10)),
            ],
        );
        t(
            "mqtt",
            vec![
                ("keep_alive_s", V::Integer(60)),
                ("connect_timeout_s", V::Integer(10)),
                ("ack_timeout_s", V::Integer(5)),
                ("backoff_scale", V::Float(scale)),
            ],
        );
        t(
            "telemetry",
            vec![("interval_s", V::Integer(0)), ("auth_log", V::String(p("auth.log"))), ("fw_image", V::String(p("factory-image.bin")))],
        );
        // T-60 download allowlist: artifacts only from the cloud's artifact host (`ota.base_url` and
        // an explicit `ota.allowed_hosts`; an empty list would mean "the EST and base_url hosts").
        let mut ota = vec![
            ("slots_dir", V::String(p("slots"))),
            ("boot_control", V::String("file".into())),
            ("product", V::String(PRODUCT.into())),
            ("health_timeout_s", V::Integer(HEALTH_TIMEOUT_S as i64)),
            ("max_boot_attempts", V::Integer(3)),
            ("reboot_command", V::Array(Vec::new())),
        ];
        if let Some(base) = cloud.artifact_base_url() {
            ota.push(("base_url", V::String(base)));
        }
        if let Some(host) = cloud.artifact_host() {
            ota.push(("allowed_hosts", V::Array(vec![V::String(host)])));
        }
        t("ota", ota);
        t(
            "agent",
            vec![
                ("state_dir", V::String(p("state"))),
                ("log_level", V::String("info".into())),
                ("fw_version", V::String("1.0.0".into())),
                ("fw_version_code", V::Integer(FACTORY_VERSION_CODE as i64)),
                ("max_skew_s", V::Integer(300)),
            ],
        );
        Ok(toml::to_string(&root)?)
    }

    /// Provision and start.
    ///
    /// # Errors
    /// Missing binary, factory failures, start failures.
    pub async fn launch(&self, cloud: &Cloud, opts: &LaunchOptions) -> Result<Dut> {
        if !self.binary.is_file() {
            bail!("agent-rs DUT binary {} not found (cargo build --features dut-control)", self.binary.display());
        }
        let device_id = util::new_device_id();
        let dir = device_dir(cloud, &opts.label, &device_id);
        std::fs::create_dir_all(&dir)?;
        let scale = opts.backoff_scale.unwrap_or(BACKOFF_SCALE);
        let cfg = dir.join("agent.toml");
        std::fs::write(&cfg, self.config(&dir, cloud, scale)?)?;
        std::fs::write(dir.join("ca-bundle.pem"), cloud.endpoints().anchors_pem)?;
        std::fs::write(dir.join("factory-image.bin"), factory_image())?;
        std::fs::write(dir.join("auth.log"), b"")?;
        // Factory station: identity + bootstrap CSR (the key never leaves the identity backend).
        let mut c = Command::new(&self.binary);
        scrub_env(&mut c);
        let out = c
            .arg("--config")
            .arg(&cfg)
            .args(["--factory", "--software", "--device-id", &device_id, "--tenant-id", &cloud.tenant_id])
            .output()
            .await
            .context("ironmesh-agent --factory")?;
        if !out.status.success() {
            bail!("ironmesh-agent --factory failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        let csr = util::pem_block(&out.stdout, "CERTIFICATE REQUEST").ok_or_else(|| anyhow!("--factory printed no CSR"))?;
        let boot = cloud.issue_bootstrap(&device_id, &csr).await?;
        let serial = crate::harness::pki::cert_facts(&boot)?.serial_hex;
        cloud.register_device(&device_id, "software", &serial, PRODUCT).await?;
        let boot_pem = dir.join("bootstrap.pem");
        std::fs::write(&boot_pem, util::pem("CERTIFICATE", &boot))?;
        let mut c = Command::new(&self.binary);
        scrub_env(&mut c);
        let out = c.arg("--config").arg(&cfg).arg("--install-bootstrap").arg(&boot_pem).output().await.context("--install-bootstrap")?;
        if !out.status.success() {
            bail!("ironmesh-agent --install-bootstrap failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        // Start the DUT.
        let log = std::fs::File::create(dir.join("agent.log"))?;
        let mut c = Command::new(&self.binary);
        scrub_env(&mut c);
        c.arg("--config").arg(&cfg).arg("--dut").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::from(log)).kill_on_drop(true);
        let mut child = c.spawn().context("spawn ironmesh-agent --dut")?;
        let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        let link = DutLink::spawn(stdout, stdin, None);
        let mut profile = self.profile(Some(scale));
        profile.factory_image = Some(factory_image());
        let dut = Dut::attach(link, profile, dir, serial, Some(child)).await?;
        if dut.info.device_id != device_id {
            bail!("hello reports device {} but {device_id} was provisioned", dut.info.device_id);
        }
        Ok(dut)
    }
}
