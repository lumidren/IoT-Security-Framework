//! `esp32-host` launcher: the ESP32 protocol core (`components/im_core`, every protocol decision in
//! C) behind `device/esp32/host/dut-shim` in **real-network mode** (`--est HOST:PORT`): rustls
//! TLS 1.3 + EST + MQTT bytes over real sockets to the harness, instead of the shim's in-process
//! simulated cloud. The harness plays the factory: it generates the bootstrap key (the shim's
//! stand-in for ATECC slot 0), has the Factory CA certify it and passes both to the shim.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

use super::{device_dir, harness_bootstrap_key, Dut, DutLink, LaunchOptions, Resumption, Target, TargetProfile};
use crate::harness::Cloud;
use crate::util;

/// Product compiled into the shim.
pub const PRODUCT: &str = "sensor-esp32";

/// Launcher.
pub struct Esp32HostLauncher {
    /// `im-dut-shim` binary.
    pub binary: PathBuf,
}

/// The shim's factory image (`DeviceConfig::sim().firmware`, 64 KiB). Cases verify its hash against
/// `ota_slots` before using it as a delta base.
#[must_use]
pub fn factory_image() -> Vec<u8> {
    (0..64 * 1024u32).map(|i| i.wrapping_mul(2_654_435_761) as u8).collect()
}

impl Esp32HostLauncher {
    /// Profile.
    #[must_use]
    pub fn profile(&self) -> TargetProfile {
        TargetProfile {
            target: Target::Esp32Host,
            product: PRODUCT.into(),
            set_clock: true,
            resumption: Resumption::TicketOffered,
            // No clock scaling: the C core's backoff runs on the real monotonic clock.
            backoff_scale: 1.0,
            // IM_OTA_HEALTH_TIMEOUT_MS (im_ota.h).
            health_timeout_s: 120,
            benign_command: "noop".into(),
            factory_image: Some(factory_image()),
            release_binary: None,
        }
    }

    /// Provision and start.
    ///
    /// # Errors
    /// Missing binary, provisioning or start failures.
    pub async fn launch(&self, cloud: &Cloud, opts: &LaunchOptions) -> Result<Dut> {
        if !self.binary.is_file() {
            bail!("esp32-host DUT binary {} not found (cargo build -p im-dut-shim in device/esp32/host)", self.binary.display());
        }
        let device_id = util::new_device_id();
        let dir = device_dir(cloud, &opts.label, &device_id);
        std::fs::create_dir_all(&dir)?;
        let ep = cloud.endpoints();
        let (sk, csr) = harness_bootstrap_key(&device_id, &cloud.tenant_id)?;
        let boot = cloud.issue_bootstrap(&device_id, &csr).await?;
        let serial = crate::harness::pki::cert_facts(&boot)?.serial_hex;
        cloud.register_device(&device_id, "software", &serial, PRODUCT).await?;
        std::fs::write(dir.join("ca.pem"), &ep.anchors_pem)?;
        std::fs::write(dir.join("bootstrap.pem"), util::pem("CERTIFICATE", &boot))?;
        std::fs::write(dir.join("bootstrap.key.hex"), hex::encode(sk.to_bytes()))?;
        let log = std::fs::File::create(dir.join("shim.log"))?;
        let mut c = Command::new(&self.binary);
        super::scrub_env(&mut c);
        c.arg("--est")
            .arg(format!("{}:{}", ep.est_host, ep.est_port))
            .arg("--ca")
            .arg(dir.join("ca.pem"))
            .arg("--bootstrap-cert")
            .arg(dir.join("bootstrap.pem"))
            .arg("--bootstrap-key")
            .arg(dir.join("bootstrap.key.hex"))
            .args(["--device-id", &device_id, "--tenant-id", &cloud.tenant_id, "--bundle-pubkey", &ep.bundle_pubkey_hex])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .kill_on_drop(true);
        let mut child = c.spawn().context("spawn im-dut-shim")?;
        let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        let link = DutLink::spawn(stdout, stdin, None);
        let dut = Dut::attach(link, self.profile(), dir, serial, Some(child)).await?;
        if dut.info.device_id != device_id {
            bail!("hello reports device {} but {device_id} was provisioned", dut.info.device_id);
        }
        Ok(dut)
    }
}
