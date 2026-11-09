//! Devices under test. [`Dut`] is the one handle every case uses; the launchers know how to
//! provision and start each target:
//!
//! | Target       | Launcher                     | Transport                                  |
//! |--------------|------------------------------|--------------------------------------------|
//! | `agent-rs`   | [`agent_rs::AgentRsLauncher`] | stdin/stdout of `ironmesh-agent --dut`     |
//! | `esp32-host` | [`esp32_host::Esp32HostLauncher`] | stdin/stdout of `im-dut-shim` (real-network mode) |
//! | `esp32-hil`  | [`esp32_hil::Esp32HilLauncher`] | serial port, `@@IM ` framing              |

pub mod agent_rs;
pub mod esp32_hil;
pub mod esp32_host;
pub mod link;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

pub use link::{DutError, DutLink, Event};

use crate::harness::Cloud;

/// Firmware targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Linux agent.
    AgentRs,
    /// ESP32 protocol core on the host.
    Esp32Host,
    /// ESP32 hardware in the loop.
    Esp32Hil,
}

impl Target {
    /// CLI / report name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Target::AgentRs => "agent-rs",
            Target::Esp32Host => "esp32-host",
            Target::Esp32Hil => "esp32-hil",
        }
    }

    /// Parse a CLI name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "agent-rs" => Some(Target::AgentRs),
            "esp32-host" => Some(Target::Esp32Host),
            "esp32-hil" => Some(Target::Esp32Hil),
            _ => None,
        }
    }

    /// Whether this target is an ESP32 build of the C core.
    #[must_use]
    pub const fn is_esp32(self) -> bool {
        matches!(self, Target::Esp32Host | Target::Esp32Hil)
    }
}

/// How a target reports TLS session resumption (C-TLS-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resumption {
    /// The DUT's `connected.resumed` must be true and the broker must see a resumed handshake.
    Resumed,
    /// ESP32 semantics: the device offers the session ticket it received; the broker-side
    /// resumed handshake is the criterion and the DUT flag is informational.
    TicketOffered,
}

/// What the suite needs to know about a target beyond the protocol.
#[derive(Debug, Clone)]
pub struct TargetProfile {
    /// Target.
    pub target: Target,
    /// Product name in manifests (`MF_PRODUCT`).
    pub product: String,
    /// `set_clock` is available (host targets).
    pub set_clock: bool,
    /// C-TLS-4 semantics.
    pub resumption: Resumption,
    /// Reconnect backoff time scale (1.0 = real time; agent-rs `mqtt.backoff_scale`).
    pub backoff_scale: f64,
    /// OTA health-check deadline after an update boot (s).
    pub health_timeout_s: u64,
    /// A command the target executes without side effects (C-RPL-*).
    pub benign_command: String,
    /// The factory image of a fresh device, when the harness knows its bytes (C-OTA-7 base).
    pub factory_image: Option<Vec<u8>>,
    /// The release build of this target can be checked for the absence of the control channel.
    pub release_binary: Option<PathBuf>,
}

/// `hello` result.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Target name reported.
    pub target: String,
    /// Firmware version.
    pub fw_version: String,
    /// Firmware version code.
    pub fw_version_code: u64,
    /// Secure element type.
    pub se_type: String,
    /// Device id.
    pub device_id: String,
    /// Tenant id.
    pub tenant_id: String,
}

/// A running device under test.
pub struct Dut {
    /// Protocol link.
    pub link: DutLink,
    /// `hello`.
    pub info: DeviceInfo,
    /// Target profile.
    pub profile: TargetProfile,
    /// Working directory of this device (config, keys, logs).
    pub dir: PathBuf,
    /// Bootstrap certificate serial (hex).
    pub bootstrap_serial_hex: String,
    process: tokio::sync::Mutex<Option<tokio::process::Child>>,
}

/// Default response timeout (the protocol requires answers within 5 s; late answers are still
/// accepted and recorded as slow).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(12);

impl Dut {
    /// Wrap a started link: runs `hello` and checks the protocol version.
    ///
    /// # Errors
    /// No / invalid `hello`.
    pub async fn attach(
        link: DutLink,
        profile: TargetProfile,
        dir: PathBuf,
        bootstrap_serial_hex: String,
        process: Option<tokio::process::Child>,
    ) -> Result<Self> {
        let h = link.call("hello", json!({}), Duration::from_secs(30)).await?;
        if h["protocol_version"] != 1 {
            bail!("DUT speaks protocol_version {} (expected 1)", h["protocol_version"]);
        }
        let s = |k: &str| h[k].as_str().unwrap_or_default().to_owned();
        let info = DeviceInfo {
            target: s("target"),
            fw_version: s("fw_version"),
            fw_version_code: h["fw_version_code"].as_u64().unwrap_or(0),
            se_type: s("se_type"),
            device_id: s("device_id"),
            tenant_id: s("tenant_id"),
        };
        Ok(Self { link, info, profile, dir, bootstrap_serial_hex, process: tokio::sync::Mutex::new(process) })
    }

    /// Device id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.info.device_id
    }

    /// Call an operation; protocol errors are returned as [`DutError`].
    ///
    /// # Errors
    /// [`DutError`].
    pub async fn call(&self, op: &str, args: Value) -> Result<Value, DutError> {
        self.link.call(op, args, CALL_TIMEOUT).await
    }

    /// Call an operation that must succeed.
    ///
    /// # Errors
    /// Any failure.
    pub async fn ok(&self, op: &str, args: Value) -> Result<Value> {
        self.call(op, args).await.map_err(|e| anyhow!("{e}"))
    }

    /// `status`.
    ///
    /// # Errors
    /// Any failure.
    pub async fn status(&self) -> Result<Value> {
        self.ok("status", json!({})).await
    }

    /// Event position.
    #[must_use]
    pub fn mark(&self) -> usize {
        self.link.mark()
    }

    /// Wait for an event (or fail with a descriptive error).
    ///
    /// # Errors
    /// Timeout.
    pub async fn expect_event(&self, from: usize, name: &str, timeout: Duration) -> Result<Event> {
        self.link.wait_event(from, name, timeout, |_| true).await.ok_or_else(|| {
            let seen: Vec<String> = self.link.events_since(from).iter().map(|e| format!("{}{}", e.name, e.data)).collect();
            anyhow!("no `{name}` event within {timeout:?}; events seen: [{}]", seen.join(", "))
        })
    }

    /// Wait for the first of several events.
    ///
    /// # Errors
    /// Timeout.
    pub async fn expect_any(&self, from: usize, names: &[&str], timeout: Duration) -> Result<Event> {
        self.link.wait_any(from, names, timeout, |_| true).await.ok_or_else(|| {
            let seen: Vec<String> = self.link.events_since(from).iter().map(|e| format!("{}{}", e.name, e.data)).collect();
            anyhow!("none of {names:?} within {timeout:?}; events seen: [{}]", seen.join(", "))
        })
    }

    /// `enroll` and wait for `enrolled`.
    ///
    /// # Errors
    /// `enroll_failed` or timeout.
    pub async fn enroll(&self) -> Result<Event> {
        let m = self.mark();
        self.ok("enroll", json!({})).await?;
        let e = self.expect_any(m, &["enrolled", "enroll_failed"], Duration::from_secs(30)).await?;
        if e.name != "enrolled" {
            bail!("enrollment failed: {}", e.data);
        }
        Ok(e)
    }

    /// `connect` and wait for `connected`.
    ///
    /// # Errors
    /// `connect_failed` or timeout.
    pub async fn connect(&self) -> Result<Event> {
        let m = self.mark();
        self.ok("connect", json!({})).await?;
        let e = self.expect_any(m, &["connected", "connect_failed"], Duration::from_secs(30)).await?;
        if e.name != "connected" {
            bail!("connect failed: {}", e.data);
        }
        Ok(e)
    }

    /// Enroll and connect.
    ///
    /// # Errors
    /// Either step failing.
    pub async fn online(&self) -> Result<(Event, Event)> {
        let e = self.enroll().await?;
        let c = self.connect().await?;
        Ok((e, c))
    }

    /// The operational certificate serial from `status`.
    ///
    /// # Errors
    /// Not provisioned.
    pub async fn cert_serial(&self) -> Result<String> {
        self.status().await?["cert_serial_hex"].as_str().map(str::to_owned).ok_or_else(|| anyhow!("status has no cert_serial_hex"))
    }

    /// Wait until `status.state` equals `state`.
    ///
    /// # Errors
    /// Timeout.
    pub async fn wait_state(&self, state: &str, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let s = self.status().await?;
            if s["state"] == state {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                bail!("state is {} (wanted {state}) after {timeout:?}", s["state"]);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Stop the DUT and save the transcript.
    pub async fn shutdown(&self) {
        self.link.save_transcript(&self.dir.join("dut-transcript.log"));
        if let Some(mut c) = self.process.lock().await.take() {
            let _ = c.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
        }
    }
}

/// Per-launch options.
#[derive(Debug, Clone, Default)]
pub struct LaunchOptions {
    /// Label for the working directory (case id).
    pub label: String,
    /// Override the reconnect backoff time scale (agent-rs only).
    pub backoff_scale: Option<f64>,
}

/// The launcher of the selected target.
pub enum Launcher {
    /// agent-rs.
    AgentRs(agent_rs::AgentRsLauncher),
    /// esp32-host.
    Esp32Host(esp32_host::Esp32HostLauncher),
    /// esp32-hil.
    Esp32Hil(esp32_hil::Esp32HilLauncher),
}

impl Launcher {
    /// Target.
    #[must_use]
    pub fn target(&self) -> Target {
        match self {
            Launcher::AgentRs(_) => Target::AgentRs,
            Launcher::Esp32Host(_) => Target::Esp32Host,
            Launcher::Esp32Hil(_) => Target::Esp32Hil,
        }
    }

    /// Static profile (before launch).
    #[must_use]
    pub fn profile(&self) -> TargetProfile {
        match self {
            Launcher::AgentRs(l) => l.profile(None),
            Launcher::Esp32Host(l) => l.profile(),
            Launcher::Esp32Hil(l) => l.profile(),
        }
    }

    /// Provision (factory) and start a fresh device.
    ///
    /// # Errors
    /// Provisioning or start failures.
    pub async fn launch(&self, cloud: &Cloud, opts: &LaunchOptions) -> Result<Dut> {
        match self {
            Launcher::AgentRs(l) => l.launch(cloud, opts).await,
            Launcher::Esp32Host(l) => l.launch(cloud, opts).await,
            Launcher::Esp32Hil(l) => l.launch(cloud, opts).await,
        }
    }
}

/// `<run_dir>/devices/<label>-<device>`.
#[must_use]
pub fn device_dir(cloud: &Cloud, label: &str, device_id: &str) -> PathBuf {
    let safe: String = label.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    cloud.run_dir.join("devices").join(format!("{safe}-{device_id}"))
}

/// Generate a P-256 key and a bootstrap CSR for it (the factory station for targets whose key is
/// created by the harness, e.g. the esp32-host shim's simulated secure element).
///
/// # Errors
/// rcgen failures.
pub fn harness_bootstrap_key(device_id: &str, tenant_id: &str) -> Result<(p256::SecretKey, Vec<u8>)> {
    use p256::pkcs8::EncodePrivateKey;
    let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let der = sk.to_pkcs8_der().map_err(|e| anyhow!("{e}"))?;
    let kp = rcgen::KeyPair::try_from(der.as_bytes()).map_err(|e| anyhow!("{e}"))?;
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(rcgen::DnType::CommonName, device_id);
    p.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, tenant_id);
    p.distinguished_name.push(rcgen::DnType::OrganizationName, "IronMesh");
    let csr = p.serialize_request(&kp)?;
    Ok((sk, csr.der().to_vec()))
}

/// Remove `IRONMESH_*` variables so a developer's environment cannot change a DUT's config.
pub fn scrub_env(cmd: &mut tokio::process::Command) {
    for (k, _) in std::env::vars() {
        if k.starts_with("IRONMESH_") {
            cmd.env_remove(k);
        }
    }
}

/// Find a built binary: explicit path, else the first existing candidate.
#[must_use]
pub fn find_binary(explicit: Option<&Path>, candidates: &[PathBuf]) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    candidates.iter().find(|p| p.is_file()).cloned()
}

/// Platform executable name.
#[must_use]
pub fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}
