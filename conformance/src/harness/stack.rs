//! `--stack` backend: the same cases against a real deployment (docker-compose / Helm with EMQX,
//! the PKI, policy and registry services), for the CI integration job. It is compiled and its
//! configuration is unit-tested here, but it is only *exercised* in CI (no Docker on the
//! development host).
//!
//! What it maps to:
//!
//! | Cloud operation      | Real stack                                                                  |
//! |----------------------|-----------------------------------------------------------------------------|
//! | bootstrap issuance   | `pkictl issue-bootstrap --dir <ca_dir> --tenant --device --csr` (factory)   |
//! | manufacture record   | registry `POST /v1/devices` (factory API key)                               |
//! | quarantine           | registry `POST /v1/devices/{id}/quarantine` (operator API key)               |
//! | revoke               | PKI `POST /v1/certificates/{serial}/revoke` (mTLS, Services CA client cert)   |
//! | certificate lookup   | PKI `GET /v1/certificates/{serial}`                                          |
//! | downlinks            | MQTT publish as `svc-registry` to EMQX, signed with the configured tenant key |
//! | artifacts            | written to a directory served by the stack's object store / static server     |
//!
//! Broker-side fault injection (rogue CA, TLS 1.2, refusals, PUBACK suppression) and broker-side
//! observation are not possible against EMQX, so the cases that need them report
//! `not_applicable` in this mode.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::json;

use super::net::{self, http_request};
use super::{unsupported, DeviceEndpoints};

/// `--stack-config` file (TOML). Every secret can also come from the environment
/// (`IRONMESH_STACK_<FIELD>` upper-case).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct StackConfig {
    /// Host devices and the harness use (from `--stack <url>`).
    pub host: String,
    /// EST / PKI management port (contract §7: 8443).
    pub pki_port: u16,
    /// Registry base URL (default `http://<host>:8000`).
    pub registry_url: String,
    /// Registry API key (`imk_...`, role factory+operator) for `/v1/devices`.
    pub registry_token: String,
    /// MQTT port (8883).
    pub mqtt_port: u16,
    /// Root + Services CA PEM (factory trust anchors of the devices).
    pub anchors_pem: PathBuf,
    /// PKI bundle public key (hex), i.e. `bundle.pub.pem` raw key.
    pub bundle_pubkey_hex: String,
    /// `pkictl` binary and CA directory (passphrase in `PKI_FILE_KMS_PASSPHRASE`).
    pub pkictl: PathBuf,
    /// `PKI_CA_DIR` written by the key ceremony.
    pub pki_ca_dir: PathBuf,
    /// Services CA client certificate allowed on the PKI management API (e.g. `svc-registry`).
    pub svc_cert: PathBuf,
    /// Its key.
    pub svc_key: PathBuf,
    /// Tenant id provisioned in the stack.
    pub tenant_id: String,
    /// Tenant command key seed (hex) when the stack runs with a test tenant key; enables the
    /// downlink cases (C-RPL-*, C-OTA-*, C-CFG-1).
    pub tenant_key_seed_hex: String,
    /// Firmware signing key seed (hex) trusted by the stack's bundle; enables C-OTA-*.
    pub fw_key_seed_hex: String,
    /// Directory served at `artifact_base_url` (OTA artifacts).
    pub artifact_dir: PathBuf,
    /// Base URL of `artifact_dir`.
    pub artifact_base_url: String,
}

impl StackConfig {
    /// Load: `--stack <url>` gives the host, the optional TOML gives the rest, the environment
    /// overrides secrets.
    ///
    /// # Errors
    /// Unreadable / invalid file or URL.
    pub fn load(url: &str, file: Option<&Path>) -> Result<Self> {
        let mut c: StackConfig = match file {
            Some(f) => toml::from_str(&std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?)?,
            None => StackConfig::default(),
        };
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let host = rest.split(['/', ':']).next().unwrap_or("").to_owned();
        if host.is_empty() {
            bail!("--stack expects a URL such as https://ironmesh.local");
        }
        c.host = host;
        if c.pki_port == 0 {
            c.pki_port = 8443;
        }
        if c.mqtt_port == 0 {
            c.mqtt_port = 8883;
        }
        if c.registry_url.is_empty() {
            c.registry_url = format!("http://{}:8000", c.host);
        }
        for (field, var) in [
            (&mut c.registry_token, "IRONMESH_STACK_REGISTRY_TOKEN"),
            (&mut c.tenant_key_seed_hex, "IRONMESH_STACK_TENANT_KEY_SEED_HEX"),
            (&mut c.fw_key_seed_hex, "IRONMESH_STACK_FW_KEY_SEED_HEX"),
            (&mut c.bundle_pubkey_hex, "IRONMESH_STACK_BUNDLE_PUBKEY_HEX"),
            (&mut c.tenant_id, "IRONMESH_STACK_TENANT_ID"),
        ] {
            if let Ok(v) = std::env::var(var) {
                *field = v;
            }
        }
        Ok(c)
    }
}

/// A connected stack backend.
pub struct Stack {
    /// Configuration.
    pub cfg: StackConfig,
    anchors: Vec<Vec<u8>>,
    mgmt_tls: Arc<rustls::ClientConfig>,
    mqtt_tls: Arc<rustls::ClientConfig>,
    has_tenant_key: bool,
}

fn read_pem_certs(path: &Path) -> Result<Vec<Vec<u8>>> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ironmesh_agent::x509::pem_or_der_all(&data).map_err(|e| anyhow!("{}: {e}", path.display()))
}

fn read_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    rustls::pki_types::PrivateKeyDer::from_pem_slice(&data).map_err(|e| anyhow!("{}: {e}", path.display()))
}

impl Stack {
    /// Build from configuration (reads certificates; no network yet).
    ///
    /// # Errors
    /// Missing files.
    pub fn new(cfg: StackConfig) -> Result<Self> {
        let anchors = read_pem_certs(&cfg.anchors_pem)?;
        let anchor_refs: Vec<&[u8]> = anchors.iter().map(Vec::as_slice).collect();
        let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            read_pem_certs(&cfg.svc_cert)?.into_iter().map(rustls::pki_types::CertificateDer::from).collect();
        let key = read_key(&cfg.svc_key)?;
        let mgmt_tls = net::client_config(&anchor_refs, Some((chain.clone(), key.clone_key())), &[])?;
        let mqtt_tls = net::client_config(&anchor_refs, Some((chain, key)), &[b"mqtt"])?;
        let has_tenant_key = cfg.tenant_key_seed_hex.len() == 64;
        Ok(Self { cfg, anchors, mgmt_tls, mqtt_tls, has_tenant_key })
    }

    /// Tenant signing key seed, if configured.
    #[must_use]
    pub fn tenant_key(&self) -> Option<ed25519_dalek::SigningKey> {
        hex::decode(&self.cfg.tenant_key_seed_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|s: [u8; 32]| ed25519_dalek::SigningKey::from_bytes(&s))
    }

    /// Firmware signing key seed, if configured.
    #[must_use]
    pub fn fw_key(&self) -> Option<ed25519_dalek::SigningKey> {
        hex::decode(&self.cfg.fw_key_seed_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|s: [u8; 32]| ed25519_dalek::SigningKey::from_bytes(&s))
    }

    /// Whether downlinks can be signed.
    #[must_use]
    pub fn has_tenant_key(&self) -> bool {
        self.has_tenant_key
    }

    /// Device endpoints.
    #[must_use]
    pub fn endpoints(&self) -> DeviceEndpoints {
        let anchors_pem: String = self.anchors.iter().map(|d| crate::util::pem("CERTIFICATE", d)).collect();
        // The Services CA is the anchor that is not self-signed.
        let pins = self
            .anchors
            .iter()
            .filter_map(|d| super::pki::cert_facts(d).ok())
            .filter(|f| f.subject != f.issuer)
            .map(|f| hex::encode(f.spki_sha256))
            .collect();
        DeviceEndpoints {
            est_host: self.cfg.host.clone(),
            est_port: self.cfg.pki_port,
            anchors_pem,
            est_pins_hex: pins,
            bundle_pubkey_hex: self.cfg.bundle_pubkey_hex.clone(),
        }
    }

    fn pki(&self, path: &str) -> String {
        format!("https://{}:{}{path}", self.cfg.host, self.cfg.pki_port)
    }

    /// `pkictl issue-bootstrap --csr`.
    ///
    /// # Errors
    /// pkictl failure.
    pub async fn issue_bootstrap(&self, device_id: &str, tenant_id: &str, csr_der: &[u8]) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir()?;
        let csr = dir.path().join("device.csr");
        std::fs::write(&csr, crate::util::pem("CERTIFICATE REQUEST", csr_der))?;
        let out = tokio::process::Command::new(&self.cfg.pkictl)
            .args(["issue-bootstrap", "--dir"])
            .arg(&self.cfg.pki_ca_dir)
            .args(["--tenant", tenant_id, "--device", device_id, "--csr"])
            .arg(&csr)
            .output()
            .await
            .context("run pkictl issue-bootstrap")?;
        if !out.status.success() {
            bail!("pkictl issue-bootstrap failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        let cert = self.cfg.pki_ca_dir.join("devices").join(format!("{device_id}.crt"));
        read_pem_certs(&cert)?.into_iter().next().ok_or_else(|| anyhow!("{} holds no certificate", cert.display()))
    }

    async fn registry(&self, method: &str, path: &str, body: serde_json::Value) -> Result<net::HttpResponse> {
        let headers =
            vec![("content-type", "application/json".to_string()), ("authorization", format!("Bearer {}", self.cfg.registry_token))];
        let tls = net::client_config(&self.anchors.iter().map(Vec::as_slice).collect::<Vec<_>>(), None, &[])?;
        http_request(
            method,
            &format!("{}{path}", self.cfg.registry_url),
            &headers,
            serde_json::to_vec(&body)?,
            Some(tls),
            Duration::from_secs(10),
        )
        .await
    }

    /// Registry `POST /v1/devices`.
    ///
    /// # Errors
    /// Non-201 answers.
    pub async fn register_device(&self, device_id: &str, se_type: &str, bootstrap_serial_hex: &str, product: &str) -> Result<()> {
        let r = self
            .registry(
                "POST",
                "/v1/devices",
                json!({"id": device_id, "product": product, "hw_revision": "conformance", "se_type": se_type, "bootstrap_serial_hex": bootstrap_serial_hex}),
            )
            .await?;
        if r.status != 201 && r.status != 200 {
            bail!("registry POST /v1/devices answered {}: {}", r.status, r.text());
        }
        Ok(())
    }

    /// Registry `POST /v1/devices/{id}/quarantine`.
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn quarantine(&self, device_id: &str) -> Result<()> {
        let r = self.registry("POST", &format!("/v1/devices/{device_id}/quarantine"), json!({"reason": "conformance C-ENR-2"})).await?;
        if !(200..300).contains(&r.status) {
            bail!("registry quarantine answered {}: {}", r.status, r.text());
        }
        Ok(())
    }

    /// PKI `POST /v1/certificates/{serial}/revoke`.
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn revoke(&self, serial_hex: &str) -> Result<()> {
        let r = http_request(
            "POST",
            &self.pki(&format!("/v1/certificates/{serial_hex}/revoke")),
            &[("content-type", "application/json".to_string())],
            serde_json::to_vec(&json!({"reason": "keyCompromise"}))?,
            Some(self.mgmt_tls.clone()),
            Duration::from_secs(15),
        )
        .await?;
        if !(200..300).contains(&r.status) {
            bail!("PKI revoke answered {}: {}", r.status, r.text());
        }
        Ok(())
    }

    /// PKI `GET /v1/certificates/{serial}` (PEM field).
    ///
    /// # Errors
    /// Non-200 answers.
    pub async fn certificate(&self, serial_hex: &str) -> Result<Vec<u8>> {
        let r = http_request(
            "GET",
            &self.pki(&format!("/v1/certificates/{serial_hex}")),
            &[],
            Vec::new(),
            Some(self.mgmt_tls.clone()),
            Duration::from_secs(10),
        )
        .await?;
        if r.status != 200 {
            bail!("PKI certificate lookup answered {}", r.status);
        }
        let v = r.json()?;
        let pem = v["pem"].as_str().or_else(|| v["certificate"]["pem"].as_str()).ok_or_else(|| anyhow!("no pem in the PKI answer"))?;
        ironmesh_agent::x509::pem_or_der_first(pem.as_bytes()).map_err(|e| anyhow!("{e}"))
    }

    /// Publish as `svc-registry`.
    ///
    /// # Errors
    /// MQTT failures.
    pub async fn inject(&self, topic: &str, payload: Vec<u8>, retain: bool) -> Result<usize> {
        use ironmesh_agent::mqtt::{self, MqttOptions};
        let opts = MqttOptions::new("svc-registry");
        let (client, _inbound, _info) = mqtt::connect(self.mqtt_tls.clone(), &self.cfg.host, self.cfg.mqtt_port, &opts)
            .await
            .map_err(|e| anyhow!("svc-registry connect: {e}"))?;
        let rc = client
            .publish(topic, payload, 1, retain, ironmesh_agent::mqtt::codec::Properties::new(), Duration::from_secs(10))
            .await
            .map_err(|e| anyhow!("publish: {e}"))?;
        client.disconnect().await;
        if rc >= 0x80 {
            bail!("EMQX refused the svc-registry publish (reason 0x{rc:02x})");
        }
        Ok(1)
    }

    /// Write an artifact to the served directory.
    ///
    /// # Errors
    /// [`super::Unsupported`] when no artifact directory is configured.
    pub fn host_artifact(&self, bytes: Vec<u8>) -> Result<String> {
        if self.cfg.artifact_base_url.is_empty() || self.cfg.artifact_dir.as_os_str().is_empty() {
            return Err(unsupported("OTA artifacts need artifact_dir + artifact_base_url in the --stack-config file"));
        }
        let name = format!("{}.bin", hex::encode(crate::util::random_bytes(8)));
        std::fs::write(self.cfg.artifact_dir.join(&name), bytes)?;
        Ok(format!("{}/{name}", self.cfg.artifact_base_url.trim_end_matches('/')))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_from_url() {
        let c = StackConfig::load("https://ironmesh.local/", None).unwrap();
        assert_eq!(c.host, "ironmesh.local");
        assert_eq!(c.pki_port, 8443);
        assert_eq!(c.mqtt_port, 8883);
        assert_eq!(c.registry_url, "http://ironmesh.local:8000");
        let c = StackConfig::load("mqtt.example:8883", None).unwrap();
        assert_eq!(c.host, "mqtt.example");
        assert!(StackConfig::load("https://", None).is_err());
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("s.toml");
        std::fs::write(&f, "pki_port = 9443\nregistry_url = \"https://r:8000\"\n").unwrap();
        let c = StackConfig::load("https://h", Some(&f)).unwrap();
        assert_eq!((c.pki_port, c.registry_url.as_str()), (9443, "https://r:8000"));
        std::fs::write(&f, "nope = 1\n").unwrap();
        assert!(StackConfig::load("https://h", Some(&f)).is_err());
    }
}
