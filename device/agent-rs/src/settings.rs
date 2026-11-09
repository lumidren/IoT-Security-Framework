//! Agent configuration: a TOML file plus `IRONMESH_<SECTION>_<KEY>` environment overrides
//! (e.g. `IRONMESH_PKI_EST_HOST=pki.example.com`); `IRONMESH_PQ_REQUIRED=1` forces ML-DSA-65
//! verification of firmware manifests.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Identity backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Encrypted file (+ optional keyring); lower assurance.
    #[default]
    Software,
    /// TPM 2.0 (feature `tpm`).
    Tpm,
    /// OP-TEE (feature `optee`).
    Optee,
}

/// `[identity]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentitySettings {
    /// Identity directory (`identity.json`, keys, certificates).
    pub dir: PathBuf,
    /// Backend.
    pub backend: Backend,
    /// Machine secret for the software backend (0600).
    pub machine_secret: PathBuf,
    /// Also mix in a secret from the OS keyring (feature `keyring`).
    pub use_keyring: bool,
    /// TPM TCTI.
    pub tpm_tcti: Option<String>,
    /// TPM persistent primary handle.
    pub tpm_primary_handle: u32,
    /// AK certificate path.
    pub ak_cert: PathBuf,
}

impl Default for IdentitySettings {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/ironmesh/identity"),
            backend: Backend::Software,
            machine_secret: PathBuf::from("/var/lib/ironmesh/identity/machine-secret"),
            use_keyring: false,
            tpm_tcti: None,
            tpm_primary_handle: 0x8100_0101,
            ak_cert: PathBuf::from("/var/lib/ironmesh/ak.crt"),
        }
    }
}

/// `[pki]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PkiSettings {
    /// EST host.
    pub est_host: String,
    /// EST port.
    pub est_port: u16,
    /// Factory trust anchors (PEM: root + Services CA).
    pub ca_bundle: PathBuf,
    /// Factory SPKI pins (hex SHA-256) for the EST server before a bundle is received.
    pub est_pins: Vec<String>,
    /// PKI bundle public key (hex Ed25519), baked in at the factory.
    pub bundle_pubkey: String,
    /// Request timeout (s).
    pub timeout_s: u64,
}

impl Default for PkiSettings {
    fn default() -> Self {
        Self {
            est_host: "pki.ironmesh.local".into(),
            est_port: 8443,
            ca_bundle: PathBuf::from("/etc/ironmesh/ca-bundle.pem"),
            est_pins: Vec::new(),
            bundle_pubkey: String::new(),
            timeout_s: 30,
        }
    }
}

/// `[mqtt]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MqttSettings {
    /// Override the bundle's broker host (lab use).
    pub host: Option<String>,
    /// Override the bundle's broker port.
    pub port: Option<u16>,
    /// Keep-alive (s).
    pub keep_alive_s: u64,
    /// Connect timeout (s).
    pub connect_timeout_s: u64,
    /// Publish acknowledgement timeout (s).
    pub ack_timeout_s: u64,
    /// Multiply reconnect backoff delays (tests / clock scaling).
    pub backoff_scale: f64,
}

impl Default for MqttSettings {
    fn default() -> Self {
        Self { host: None, port: None, keep_alive_s: 60, connect_timeout_s: 20, ack_timeout_s: 30, backoff_scale: 1.0 }
    }
}

/// `[telemetry]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetrySettings {
    /// Interval (s); 0 disables periodic telemetry.
    pub interval_s: u64,
    /// `auth.log` path (falls back to `journalctl`).
    pub auth_log: PathBuf,
    /// Firmware image used for `fw_hash` when no A/B slot is active (default: the agent binary).
    pub fw_image: Option<PathBuf>,
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        Self { interval_s: 30, auth_log: PathBuf::from("/var/log/auth.log"), fw_image: None }
    }
}

/// `[ota]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OtaSettings {
    /// Slot directory (`a/`, `b/`, `state.json`).
    pub slots_dir: PathBuf,
    /// `file` or `fw_setenv`.
    pub boot_control: String,
    /// Product name for `MF_PRODUCT`.
    pub product: String,
    /// Require ML-DSA-65 (also `IRONMESH_PQ_REQUIRED`).
    pub pq_required: bool,
    /// Health deadline after an update boot (s).
    pub health_timeout_s: u64,
    /// Boot attempts before the bootloader rolls back.
    pub max_boot_attempts: u32,
    /// Artifact download hosts allowed (T-60). Empty (the default) means the hosts of the
    /// configured EST endpoint (`pki.est_host`) and OTA base URL (`ota.base_url`), never "any
    /// host"; see [`Settings::download_allowlist`].
    pub allowed_hosts: Vec<String>,
    /// OTA service / artifact base URL (`https://host[:port]/...`); its host is allowlisted for
    /// artifact downloads when `allowed_hosts` is empty.
    pub base_url: Option<String>,
    /// Trust anchors for artifact downloads (PEM). Defaults to the PKI CA bundle.
    pub download_ca_bundle: Option<PathBuf>,
    /// Maximum image size (bytes).
    pub max_image_size: u64,
    /// Command run to reboot the device (`reboot` command / OTA apply) outside DUT mode.
    pub reboot_command: Vec<String>,
}

impl Default for OtaSettings {
    fn default() -> Self {
        Self {
            slots_dir: PathBuf::from("/var/lib/ironmesh/slots"),
            boot_control: "file".into(),
            product: "gateway-rpi".into(),
            pq_required: false,
            health_timeout_s: 120,
            max_boot_attempts: 3,
            allowed_hosts: Vec::new(),
            base_url: None,
            download_ca_bundle: None,
            max_image_size: 1 << 30,
            reboot_command: vec!["systemctl".into(), "reboot".into()],
        }
    }
}

/// `[agent]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentSettings {
    /// State directory (seq, replay store, buffer, shadow, config, idempotency).
    pub state_dir: PathBuf,
    /// Offline buffer capacity (messages).
    pub buffer_capacity: usize,
    /// Sequence reservation block (1 = persist every message).
    pub seq_block: u64,
    /// Log filter.
    pub log_level: String,
    /// Firmware version reported when no slot metadata exists.
    pub fw_version: String,
    /// Firmware version code when no slot metadata exists.
    pub fw_version_code: u64,
    /// Maximum inbound timestamp skew (s).
    pub max_skew_s: u64,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("/var/lib/ironmesh/state"),
            buffer_capacity: 10_000,
            seq_block: 1,
            log_level: "info".into(),
            fw_version: env!("CARGO_PKG_VERSION").into(),
            fw_version_code: 0,
            max_skew_s: 300,
        }
    }
}

/// Complete configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// `[identity]`
    pub identity: IdentitySettings,
    /// `[pki]`
    pub pki: PkiSettings,
    /// `[mqtt]`
    pub mqtt: MqttSettings,
    /// `[telemetry]`
    pub telemetry: TelemetrySettings,
    /// `[ota]`
    pub ota: OtaSettings,
    /// `[agent]`
    pub agent: AgentSettings,
}

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// I/O.
    #[error("config I/O: {0}")]
    Io(#[from] std::io::Error),
    /// TOML.
    #[error("config: {0}")]
    Parse(String),
    /// Semantic.
    #[error("config: {0}")]
    Invalid(String),
}

const SECTIONS: [&str; 6] = ["identity", "pki", "mqtt", "telemetry", "ota", "agent"];

fn env_value(raw: &str) -> toml::Value {
    // Accept TOML literals (numbers, booleans, arrays); fall back to a plain string.
    match format!("v = {raw}").parse::<toml::Table>() {
        Ok(mut t) => t.remove("v").unwrap_or_else(|| toml::Value::String(raw.into())),
        Err(_) => toml::Value::String(raw.into()),
    }
}

impl Settings {
    /// Parse TOML text and apply overrides from `env`.
    ///
    /// # Errors
    /// [`SettingsError`].
    pub fn from_toml_with_env(text: &str, env: impl IntoIterator<Item = (String, String)>) -> Result<Self, SettingsError> {
        let mut root: toml::Table = text.parse().map_err(|e: toml::de::Error| SettingsError::Parse(e.to_string()))?;
        let mut pq_required = None;
        for (k, v) in env {
            if k == "IRONMESH_PQ_REQUIRED" {
                pq_required = Some(matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
                continue;
            }
            let Some(rest) = k.strip_prefix("IRONMESH_") else { continue };
            let rest = rest.to_ascii_lowercase();
            let Some(section) = SECTIONS.iter().find(|s| rest.starts_with(&format!("{s}_"))) else { continue };
            let key = &rest[section.len() + 1..];
            let table = root.entry((*section).to_owned()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let toml::Value::Table(t) = table {
                t.insert(key.to_owned(), env_value(&v));
            }
        }
        let mut s: Settings = toml::Value::Table(root).try_into().map_err(|e: toml::de::Error| SettingsError::Parse(e.to_string()))?;
        if let Some(pq) = pq_required {
            s.ota.pq_required = pq;
        }
        s.validate()?;
        Ok(s)
    }

    /// Load from a file (missing file = defaults) with the process environment.
    ///
    /// # Errors
    /// [`SettingsError`].
    pub fn load(path: Option<&Path>) -> Result<Self, SettingsError> {
        let text = match path {
            Some(p) => std::fs::read_to_string(p)?,
            None => String::new(),
        };
        Self::from_toml_with_env(&text, std::env::vars())
    }

    /// Check invariants.
    ///
    /// # Errors
    /// [`SettingsError::Invalid`].
    pub fn validate(&self) -> Result<(), SettingsError> {
        if !self.pki.bundle_pubkey.is_empty() {
            let raw = hex::decode(&self.pki.bundle_pubkey).map_err(|_| SettingsError::Invalid("pki.bundle_pubkey must be hex".into()))?;
            if raw.len() != 32 {
                return Err(SettingsError::Invalid("pki.bundle_pubkey must be a 32-byte Ed25519 key".into()));
            }
        }
        for pin in &self.pki.est_pins {
            if hex::decode(pin).map(|p| p.len()) != Ok(32) {
                return Err(SettingsError::Invalid("pki.est_pins entries must be hex SHA-256 digests".into()));
            }
        }
        if self.agent.buffer_capacity == 0 || self.agent.buffer_capacity > 1_000_000 {
            return Err(SettingsError::Invalid("agent.buffer_capacity must be 1..1000000".into()));
        }
        if !(0.0..=1000.0).contains(&self.mqtt.backoff_scale) {
            return Err(SettingsError::Invalid("mqtt.backoff_scale must be 0..1000".into()));
        }
        if !matches!(self.ota.boot_control.as_str(), "file" | "fw_setenv") {
            return Err(SettingsError::Invalid("ota.boot_control must be file or fw_setenv".into()));
        }
        if let Some(u) = &self.ota.base_url {
            crate::ota::download::parse_https_url(u).map_err(|e| SettingsError::Invalid(format!("ota.base_url: {e}")))?;
        }
        if self
            .ota
            .allowed_hosts
            .iter()
            .any(|h| h.trim().is_empty() || h.contains(['/', '@', '*']) || (h.contains(':') && h.parse::<std::net::Ipv6Addr>().is_err()))
        {
            return Err(SettingsError::Invalid("ota.allowed_hosts entries must be bare host names (no scheme, port or wildcard)".into()));
        }
        Ok(())
    }

    /// Hosts OTA artifacts may be downloaded from (T-60): `ota.allowed_hosts` when set,
    /// otherwise the hosts of the configured EST endpoint and OTA base URL. Lower-cased; never
    /// "any host".
    #[must_use]
    pub fn download_allowlist(&self) -> Vec<String> {
        let mut hosts: Vec<String> = if self.ota.allowed_hosts.is_empty() {
            let base = self.ota.base_url.as_deref().and_then(|u| crate::ota::download::parse_https_url(u).ok()).map(|u| u.host);
            std::iter::once(self.pki.est_host.trim_start_matches('[').trim_end_matches(']').to_owned()).chain(base).collect()
        } else {
            self.ota.allowed_hosts.clone()
        };
        for h in &mut hosts {
            *h = h.trim().to_ascii_lowercase();
        }
        hosts.retain(|h| !h.is_empty());
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// The baked-in bundle key.
    #[must_use]
    pub fn bundle_key(&self) -> Option<[u8; 32]> {
        hex::decode(&self.pki.bundle_pubkey).ok().and_then(|b| b.try_into().ok())
    }

    /// Factory EST pins.
    #[must_use]
    pub fn est_pins(&self) -> Vec<[u8; 32]> {
        self.pki.est_pins.iter().filter_map(|p| hex::decode(p).ok()).filter_map(|b| b.try_into().ok()).collect()
    }

    /// Point every path below one root directory (tests, fleet simulator, DUT runs).
    pub fn rebase(&mut self, root: &Path) {
        self.identity.dir = root.join("identity");
        self.identity.machine_secret = root.join("identity").join("machine-secret");
        self.identity.ak_cert = root.join("identity").join("ak.crt");
        self.agent.state_dir = root.join("state");
        self.ota.slots_dir = root.join("slots");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_and_env_overrides() {
        let text = r#"
            [pki]
            est_host = "file-host"
            [mqtt]
            keep_alive_s = 30
        "#;
        let env = vec![
            ("IRONMESH_PKI_EST_HOST".to_string(), "env-host".to_string()),
            ("IRONMESH_MQTT_PORT".to_string(), "18883".to_string()),
            ("IRONMESH_OTA_ALLOWED_HOSTS".to_string(), r#"["a", "b"]"#.to_string()),
            ("IRONMESH_PQ_REQUIRED".to_string(), "1".to_string()),
            ("IRONMESH_UNKNOWNSECTION_X".to_string(), "1".to_string()),
            ("PATH".to_string(), "x".to_string()),
        ];
        let s = Settings::from_toml_with_env(text, env).unwrap();
        assert_eq!(s.pki.est_host, "env-host");
        assert_eq!(s.mqtt.port, Some(18883));
        assert_eq!(s.mqtt.keep_alive_s, 30);
        assert_eq!(s.ota.allowed_hosts, vec!["a".to_string(), "b".to_string()]);
        assert!(s.ota.pq_required);
        assert_eq!(s.agent.buffer_capacity, 10_000);
        assert!(Settings::from_toml_with_env("[pki]\nnope = 1", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[pki]\nbundle_pubkey = \"zz\"", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[pki]\nbundle_pubkey = \"00\"", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[pki]\nest_pins = [\"00\"]", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[agent]\nbuffer_capacity = 0", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[ota]\nboot_control = \"x\"", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[mqtt]\nbackoff_scale = -1.0", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[ota]\nbase_url = \"http://ota\"", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[ota]\nallowed_hosts = [\"*\"]", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("[ota]\nallowed_hosts = [\"https://ota\"]", Vec::new()).is_err());
        assert!(Settings::from_toml_with_env("not toml [", Vec::new()).is_err());
        let ok = Settings::from_toml_with_env(
            &format!("[pki]\nbundle_pubkey = \"{}\"\nest_pins = [\"{}\"]", "11".repeat(32), "22".repeat(32)),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(ok.bundle_key(), Some([0x11; 32]));
        assert_eq!(ok.est_pins(), vec![[0x22; 32]]);
        let mut r = Settings::default();
        r.rebase(Path::new("/tmp/x"));
        assert!(r.agent.state_dir.ends_with("state"));
        assert!(Settings::load(None).is_ok() || std::env::vars().any(|(k, _)| k.starts_with("IRONMESH_")));
    }

    #[test]
    fn download_allowlist_defaults_to_configured_endpoints() {
        let mut s = Settings::default();
        assert_eq!(s.download_allowlist(), vec!["pki.ironmesh.local".to_string()], "empty list is not 'any host'");
        s.pki.est_host = "PKI.Example".into();
        s.ota.base_url = Some("https://ota.example:8443/artifacts".into());
        assert_eq!(s.download_allowlist(), vec!["ota.example".to_string(), "pki.example".to_string()]);
        s.ota.allowed_hosts = vec!["Cdn.Example".into()];
        assert_eq!(s.download_allowlist(), vec!["cdn.example".to_string()], "an explicit list is authoritative");
        let t = Settings::from_toml_with_env("[pki]\nest_host = \"pki\"\n[ota]\nbase_url = \"https://ota/x\"", Vec::new()).unwrap();
        assert_eq!(t.download_allowlist(), vec!["ota".to_string(), "pki".to_string()]);
    }
}
