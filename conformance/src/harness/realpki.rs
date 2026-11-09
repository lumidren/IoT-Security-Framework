//! The **real** PKI service (`services/pki`, `--pki-bin`) as the enrollment authority: a key
//! ceremony with the real `pkictl` (file KMS, in a throw-away directory), the `pki` binary with the
//! in-memory store, EST on its TLS 1.3 mTLS listener, the CRL on its plain listener, the
//! management API, and its revocation publisher pointed at the real policy service. Revocations
//! then traverse the production code end to end: `POST /v1/certificates/{serial}/revoke` -> PKI
//! store + outbox + CRL + OCSP -> signed push (`device_deny` as the PKI decides) -> policy -> kick.
//!
//! Callers of the management API authenticate the way the services do:
//!
//! * operator calls (revoke, certificate lookups) carry an ES256 JWT `aud=pki`;
//! * registry calls (tenant command key, enrollment policy, revoke-all, device release) present the
//!   `svc-registry` Services CA client certificate from the ceremony (`pkictl issue-server`) **and**
//!   a JWT with `iss = sub = registry`;
//! * OTA calls (tenant firmware keys) present `svc-ota` and a JWT with `iss = sub = ota`.
//!
//! Every token is minted for one request (fresh `jti`, 60 s lifetime): the PKI accepts each `jti`
//! once (`PKI_MGMT_JWT_SINGLE_USE`).
//!
//! The tenant policy (command key, firmware keys, `allow_software_keys`) is provisioned through
//! `PUT /v1/tenants/{t}/command-key` / `firmware-keys` / `enrollment` before any device enrolls,
//! so the PKI's trust bundles carry the harness's tenant command key and firmware key and the
//! downlink / OTA cases apply. `PKI_SUPERSEDE_GRACE` is shortened to [`SUPERSEDE_GRACE`] so the
//! PKI's own supersede-on-renewal revocation happens within a case. Remaining limit:
//! `PKI_OPERATIONAL_CERT_TTL` is bounded to 168h-720h, so C-ROT-2 cannot use short-lived
//! certificates.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value};
use tokio::process::{Child, Command};

use super::jwt::ServiceJwt;
use super::net::{self, http_request};
use super::policy::free_port;

/// `PKI_SUPERSEDE_GRACE` of the harness's PKI (production default: 1 h).
pub const SUPERSEDE_GRACE: Duration = Duration::from_secs(5);

/// A certificate chain and its PKCS#8 key.
#[derive(Clone)]
pub struct Identity {
    /// Chain (leaf first).
    pub chain: Vec<Vec<u8>>,
    /// PKCS#8 DER key.
    pub key: Vec<u8>,
}

impl Identity {
    /// As rustls types.
    #[must_use]
    pub fn rustls(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            self.chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.clone())),
        )
    }

    /// The leaf certificate.
    #[must_use]
    pub fn leaf(&self) -> Vec<u8> {
        self.chain.first().cloned().unwrap_or_default()
    }
}

/// Material produced by the ceremony.
pub struct Material {
    /// `PKI_CA_DIR`.
    pub dir: PathBuf,
    /// File-KMS passphrase.
    pub passphrase: String,
    /// Root CA DER.
    pub root: Vec<u8>,
    /// Factory CA DER.
    pub factory: Vec<u8>,
    /// Device CA DER.
    pub device: Vec<u8>,
    /// Services CA DER.
    pub services: Vec<u8>,
    /// Bundle public key.
    pub bundle_pubkey: [u8; 32],
    /// Broker certificate (`pkictl issue-server --cn mqtt`).
    pub broker: Identity,
    /// OTA artifact server certificate (`pkictl issue-server --cn ota`).
    pub artifacts: Identity,
    /// `svc-registry` client certificate (`pkictl issue-server --cn svc-registry`).
    pub registry_client: Identity,
    /// `svc-ota` client certificate (`pkictl issue-server --cn svc-ota`).
    pub ota_client: Identity,
    /// Services CA subject CN (the rogue CA impersonates it).
    pub services_cn: String,
}

fn certs(path: &Path) -> Result<Vec<Vec<u8>>> {
    ironmesh_agent::x509::pem_or_der_all(&std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .map_err(|e| anyhow!("{}: {e}", path.display()))
}

fn first(path: &Path) -> Result<Vec<u8>> {
    certs(path)?.into_iter().next().ok_or_else(|| anyhow!("{} holds no certificate", path.display()))
}

async fn pkictl(bin: &Path, passphrase: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .env("PKI_FILE_KMS_PASSPHRASE", passphrase)
        .args(args)
        .output()
        .await
        .with_context(|| format!("run pkictl {}", args[0]))?;
    if !out.status.success() {
        bail!("pkictl {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
    }
    Ok(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

async fn issue_server(bin: &Path, passphrase: &str, dir: &Path, cn: &str, sans: &str) -> Result<Identity> {
    let d = dir.to_string_lossy().to_string();
    pkictl(bin, passphrase, &["issue-server", "--dir", &d, "--cn", cn, "--san", sans]).await?;
    let key_pem = std::fs::read(dir.join("services").join(format!("{cn}.key.pem")))?;
    let key = crate::util::pem_block(&key_pem, "PRIVATE KEY").ok_or_else(|| anyhow!("{cn}.key.pem is not PKCS#8"))?;
    Ok(Identity { chain: certs(&dir.join("services").join(format!("{cn}.crt")))?, key })
}

/// Run the key ceremony with the real `pkictl`.
///
/// # Errors
/// pkictl failures.
pub async fn ceremony(bin: &Path, dir: &Path, sans: &[String]) -> Result<Material> {
    let passphrase = hex::encode(crate::util::random_bytes(16));
    std::fs::create_dir_all(dir)?;
    let d = dir.to_string_lossy().to_string();
    pkictl(bin, &passphrase, &["init-root", "--dir", &d]).await?;
    let root_key = dir.join("root-ca.key.json").to_string_lossy().to_string();
    for kind in ["factory", "device", "services"] {
        pkictl(bin, &passphrase, &["init-intermediate", "--dir", &d, "--kind", kind, "--root-key", &root_key]).await?;
    }
    pkictl(bin, &passphrase, &["init-bundle-key", "--dir", &d]).await?;
    let all = sans.join(",");
    let broker = issue_server(bin, &passphrase, dir, "mqtt", &all).await?;
    let artifacts = issue_server(bin, &passphrase, dir, "ota", &all).await?;
    let registry_client = issue_server(bin, &passphrase, dir, "svc-registry", "registry").await?;
    let ota_client = issue_server(bin, &passphrase, dir, "svc-ota", "ota").await?;
    let pem = std::fs::read_to_string(dir.join("bundle.pub.pem"))?;
    let spki = crate::util::pem_block(pem.as_bytes(), "PUBLIC KEY").ok_or_else(|| anyhow!("bundle.pub.pem is not a PUBLIC KEY"))?;
    let bundle_pubkey: [u8; 32] =
        spki.get(spki.len().saturating_sub(32)..).and_then(|k| k.try_into().ok()).ok_or_else(|| anyhow!("bundle key"))?;
    let services = first(&dir.join("services-ca.crt"))?;
    let services_cn = super::pki::cert_facts(&services)?.cn.unwrap_or_default();
    Ok(Material {
        root: first(&dir.join("root-ca.crt"))?,
        factory: first(&dir.join("factory-ca.crt"))?,
        device: first(&dir.join("device-ca.crt"))?,
        services,
        bundle_pubkey,
        broker,
        artifacts,
        registry_client,
        ota_client,
        services_cn,
        dir: dir.to_path_buf(),
        passphrase,
    })
}

impl Material {
    /// Broker TLS identity.
    #[must_use]
    pub fn broker_identity(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        self.broker.rustls()
    }
}

/// Where the PKI pushes to / looks up.
pub struct Wiring {
    /// Listen host.
    pub host: String,
    /// SANs of the PKI's self-issued listener certificate.
    pub sans: Vec<String>,
    /// Policy service base URL.
    pub policy_url: String,
    /// Policy bearer token.
    pub policy_token: String,
    /// Policy HMAC key.
    pub policy_hmac: String,
    /// Registry double.
    pub registry_url: String,
    /// Registry token.
    pub registry_token: String,
    /// Broker host for the bundle.
    pub broker_host: String,
    /// Broker port for the bundle.
    pub broker_port: u16,
    /// Log file.
    pub log_file: PathBuf,
}

/// Who calls the management API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// An operator tool: ES256 JWT only (`sub = svc-conformance`).
    Operator,
    /// The registry: `svc-registry` client certificate + JWT `iss = sub = registry`.
    Registry,
    /// The OTA service: `svc-ota` client certificate + JWT `iss = sub = ota`.
    Ota,
}

/// The running PKI service.
pub struct RealPki {
    child: Child,
    /// Material.
    pub material: Material,
    /// EST / management (mTLS listener) port.
    pub mtls_port: u16,
    /// CRL / health (plain listener) port.
    pub plain_port: u16,
    /// Host.
    pub host: String,
    pkictl: PathBuf,
    operator: ServiceJwt,
    registry: ServiceJwt,
    ota: ServiceJwt,
    tls: Arc<rustls::ClientConfig>,
    registry_tls: Arc<rustls::ClientConfig>,
    ota_tls: Arc<rustls::ClientConfig>,
}

impl RealPki {
    /// Spawn `pki` and wait for `/readyz`.
    ///
    /// # Errors
    /// Spawn failure or not ready within 30 s.
    pub async fn spawn(bin: &Path, pkictl: &Path, material: Material, w: &Wiring) -> Result<Self> {
        let (m, p) = (free_port(&w.host)?, free_port(&w.host)?);
        Self::spawn_on(bin, pkictl, material, w, m, p).await
    }

    /// Spawn on reserved ports (mTLS, plain).
    ///
    /// # Errors
    /// Spawn failure or not ready within 30 s.
    pub async fn spawn_on(bin: &Path, pkictl: &Path, material: Material, w: &Wiring, mtls_port: u16, plain_port: u16) -> Result<Self> {
        if !bin.is_file() {
            bail!("PKI binary {} not found (go build ./services/pki/cmd/pki)", bin.display());
        }
        let operator = ServiceJwt::random("svc-conformance", "svc-conformance");
        let registry = ServiceJwt::random("registry", "registry");
        let ota = ServiceJwt::random("ota", "ota");
        let jwt_file = material.dir.join("mgmt-jwt.pub.pem");
        std::fs::write(&jwt_file, format!("{}{}{}", operator.public_pem()?, registry.public_pem()?, ota.public_pem()?))?;
        let log = std::fs::OpenOptions::new().create(true).append(true).open(&w.log_file)?;
        let log2 = log.try_clone()?;
        let mut cmd = Command::new(bin);
        cmd.env("PKI_ENV", "test")
            .env("PKI_LISTEN_MTLS", format!("{}:{mtls_port}", w.host))
            .env("PKI_LISTEN_PLAIN", format!("{}:{plain_port}", w.host))
            .env("PKI_KMS", "file")
            .env("PKI_FILE_KMS_PASSPHRASE", &material.passphrase)
            .env("PKI_CA_DIR", &material.dir)
            .env("PKI_SERVER_SANS", w.sans.join(","))
            .env("PKI_POLICY_URL", &w.policy_url)
            .env("PKI_POLICY_TOKEN", &w.policy_token)
            .env("PKI_POLICY_HMAC_KEY", &w.policy_hmac)
            .env("PKI_REGISTRY_URL", &w.registry_url)
            .env("PKI_REGISTRY_TOKEN", &w.registry_token)
            .env("PKI_MGMT_JWT_PUBLIC_KEY_FILE", &jwt_file)
            .env("PKI_MGMT_JWT_SINGLE_USE", "true")
            .env("PKI_SUPERSEDE_GRACE", format!("{}s", SUPERSEDE_GRACE.as_secs()))
            .env("PKI_DEFAULT_ALLOW_SOFTWARE_KEYS", "true")
            .env("PKI_BROKER_HOST", &w.broker_host)
            .env("PKI_BROKER_PORT", w.broker_port.to_string())
            .env("PKI_LOG_LEVEL", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .kill_on_drop(true);
        let child = cmd.spawn().with_context(|| format!("spawn {}", bin.display()))?;
        let tls = net::client_config(&[&material.root], None, &[])?;
        let registry_tls = net::client_config(&[&material.root], Some(material.registry_client.rustls()), &[])?;
        let ota_tls = net::client_config(&[&material.root], Some(material.ota_client.rustls()), &[])?;
        let mut me = Self {
            child,
            material,
            mtls_port,
            plain_port,
            host: w.host.clone(),
            pkictl: pkictl.to_path_buf(),
            operator,
            registry,
            ota,
            tls,
            registry_tls,
            ota_tls,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Some(st)) = me.child.try_wait() {
                bail!("the PKI service exited during start-up ({st}); see {}", w.log_file.display());
            }
            let url = format!("http://{}:{plain_port}/readyz", w.host);
            if http_request("GET", &url, &[], Vec::new(), None, Duration::from_secs(1)).await.is_ok_and(|r| r.status == 200) {
                return Ok(me);
            }
            if tokio::time::Instant::now() > deadline {
                let _ = me.child.start_kill();
                bail!("the PKI service was not ready within 30 s; see {}", w.log_file.display());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// CRL distribution point on the plain listener.
    #[must_use]
    pub fn crl_url(&self) -> String {
        format!("http://{}:{}/crl/device-ca.crl", self.host, self.plain_port)
    }

    /// A fresh single-use ES256 service JWT (`aud=pki`) for `caller`.
    ///
    /// # Errors
    /// Signing failures.
    pub fn jwt(&self, caller: Caller) -> Result<String> {
        match caller {
            Caller::Operator => &self.operator,
            Caller::Registry => &self.registry,
            Caller::Ota => &self.ota,
        }
        .mint("pki", &[])
    }

    async fn call(&self, caller: Caller, method: &str, path: &str, body: Option<Value>) -> Result<net::HttpResponse> {
        let url = format!("https://{}:{}{path}", self.host, self.mtls_port);
        // One token per request: the PKI remembers every jti it accepted.
        let mut headers = vec![("authorization", format!("Bearer {}", self.jwt(caller)?))];
        let data = match body {
            Some(b) => {
                headers.push(("content-type", "application/json".into()));
                serde_json::to_vec(&b)?
            }
            None => Vec::new(),
        };
        let tls = match caller {
            Caller::Operator => self.tls.clone(),
            Caller::Registry => self.registry_tls.clone(),
            Caller::Ota => self.ota_tls.clone(),
        };
        http_request(method, &url, &headers, data, Some(tls), Duration::from_secs(15)).await
    }

    async fn mgmt(&self, caller: Caller, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let r = self.call(caller, method, path, body).await?;
        if !(200..300).contains(&r.status) {
            bail!("PKI {method} {path} ({caller:?}) answered {}: {}", r.status, r.text());
        }
        if r.body.is_empty() {
            return Ok(Value::Null);
        }
        r.json()
    }

    /// `POST /v1/certificates/{serial}/revoke` with `reason` (the PKI then pushes a serial-scoped
    /// event, `device_deny=false`, to the policy service).
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn revoke(&self, serial_hex: &str, reason: &str) -> Result<Value> {
        self.mgmt(Caller::Operator, "POST", &format!("/v1/certificates/{serial_hex}/revoke"), Some(json!({ "reason": reason }))).await
    }

    /// `POST /v1/devices/{id}/revoke-all` as the registry (quarantine; `device_deny=true` events).
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn revoke_all(&self, device_id: &str, reason: &str) -> Result<Value> {
        self.mgmt(Caller::Registry, "POST", &format!("/v1/devices/{device_id}/revoke-all"), Some(json!({ "reason": reason }))).await
    }

    /// `POST /v1/devices/{id}/release` as the registry (`device_release` event).
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn release(&self, device_id: &str, tenant_id: &str, note: &str) -> Result<Value> {
        self.mgmt(
            Caller::Registry,
            "POST",
            &format!("/v1/devices/{device_id}/release"),
            Some(json!({"tenant_id": tenant_id, "note": note})),
        )
        .await
    }

    /// Provision the tenant policy the way the owning services do: the command key and the
    /// enrollment policy as `svc-registry`, the firmware keys as `svc-ota`. Returns the stored
    /// policy (`GET /v1/tenants/{t}/policy`).
    ///
    /// # Errors
    /// Any non-2xx answer.
    pub async fn provision_tenant(&self, tenant_id: &str, command_key: &[u8; 32], firmware_keys: &[Vec<u8>]) -> Result<Value> {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let t = format!("/v1/tenants/{tenant_id}");
        self.mgmt(Caller::Registry, "PUT", &format!("{t}/command-key"), Some(json!({ "public_key_b64": b64(command_key) }))).await?;
        self.mgmt(Caller::Registry, "PUT", &format!("{t}/enrollment"), Some(json!({ "allow_software_keys": true }))).await?;
        let fw: Vec<String> = firmware_keys.iter().map(|k| b64(k)).collect();
        self.mgmt(Caller::Ota, "PUT", &format!("{t}/firmware-keys"), Some(json!({ "public_keys_b64": fw }))).await?;
        let pol = self.mgmt(Caller::Registry, "GET", &format!("{t}/policy"), None).await?;
        if pol["command_key_b64"].as_str() != Some(b64(command_key).as_str()) {
            bail!("the PKI did not store the tenant command key: {pol}");
        }
        Ok(pol)
    }

    /// Field ownership and JWT single use, checked against the running PKI: `svc-ota` may not set
    /// the command key (403), and a token presented twice is refused the second time (401).
    /// Returns `(ota_writes_command_key_status, first_use_status, replay_status)`.
    ///
    /// # Errors
    /// Transport failures.
    pub async fn probe_authorization(&self, tenant_id: &str) -> Result<(u16, u16, u16)> {
        let path = format!("/v1/tenants/{tenant_id}/command-key");
        let body = json!({ "public_key_b64": base64::engine::general_purpose::STANDARD.encode([7u8; 32]) });
        let wrong_owner = self.call(Caller::Ota, "PUT", &path, Some(body)).await?.status;
        let url = format!("https://{}:{}/v1/tenants/{tenant_id}/policy", self.host, self.mtls_port);
        let token = self.jwt(Caller::Operator)?;
        let headers = [("authorization", format!("Bearer {token}"))];
        let first = http_request("GET", &url, &headers, Vec::new(), Some(self.tls.clone()), Duration::from_secs(15)).await?.status;
        let replay = http_request("GET", &url, &headers, Vec::new(), Some(self.tls.clone()), Duration::from_secs(15)).await?.status;
        Ok((wrong_owner, first, replay))
    }

    /// `GET /v1/certificates/{serial}` (the record: `status`, `revocation_reason`, ...).
    ///
    /// # Errors
    /// Unknown serial.
    pub async fn certificate_record(&self, serial_hex: &str) -> Result<Value> {
        self.mgmt(Caller::Operator, "GET", &format!("/v1/certificates/{serial_hex}"), None).await
    }

    /// `GET /v1/certificates/{serial}` (DER of `certificate_pem`).
    ///
    /// # Errors
    /// Unknown serial.
    pub async fn certificate(&self, serial_hex: &str) -> Result<Vec<u8>> {
        let v = self.certificate_record(serial_hex).await?;
        let pem = v["certificate_pem"].as_str().ok_or_else(|| anyhow!("no certificate_pem for {serial_hex}"))?;
        ironmesh_agent::x509::pem_or_der_first(pem.as_bytes()).map_err(|e| anyhow!("{e}"))
    }

    /// `GET /v1/devices/{id}/certificates`.
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn device_certificates(&self, device_id: &str) -> Result<Value> {
        self.mgmt(Caller::Operator, "GET", &format!("/v1/devices/{device_id}/certificates"), None).await
    }

    /// `pkictl issue-bootstrap --csr` (the factory station).
    ///
    /// # Errors
    /// pkictl failures.
    pub async fn issue_bootstrap(&self, device_id: &str, tenant_id: &str, csr_der: &[u8]) -> Result<Vec<u8>> {
        let csr = self.material.dir.join(format!("{device_id}.csr"));
        std::fs::write(&csr, crate::util::pem("CERTIFICATE REQUEST", csr_der))?;
        let d = self.material.dir.to_string_lossy().to_string();
        let c = csr.to_string_lossy().to_string();
        pkictl(
            &self.pkictl,
            &self.material.passphrase,
            &["issue-bootstrap", "--dir", &d, "--tenant", tenant_id, "--device", device_id, "--csr", &c],
        )
        .await?;
        first(&self.material.dir.join("devices").join(format!("{device_id}.crt")))
    }

    /// Stop the process.
    pub async fn stop(&mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }

    /// Whether the process is running.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}
