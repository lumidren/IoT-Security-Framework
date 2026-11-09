//! The **real** PKI service (`services/pki`, `--pki-bin`) as the enrollment authority: a key
//! ceremony with the real `pkictl` (file KMS, in a throw-away directory), the `pki` binary with the
//! in-memory store, EST on its mTLS listener, the CRL on its plain listener, the management API
//! authenticated with an ES256 service JWT (`aud=pki`), and its revocation publisher pointed at
//! the real policy service. Revocations then traverse the production code end to end:
//! `POST /v1/certificates/{serial}/revoke` -> PKI store + CRL + OCSP -> signed push -> policy ->
//! kick.
//!
//! Limits of this mode (why it is an additional profile and not the default): with the in-memory
//! store there is no way to provision a tenant policy, so the PKI issues trust bundles with an
//! empty `tenant_cmd_pubkey` and no `fw_signing_pubkeys` (devices then reject every downlink and
//! update, as the contract requires), and `PKI_OPERATIONAL_CERT_TTL` is bounded to 168h-720h (no
//! short-lived certificates for C-ROT-2).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value};
use tokio::process::{Child, Command};

use super::net::{self, http_request};
use super::policy::free_port;

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
    /// Broker certificate chain (issued by `pkictl issue-server`).
    pub broker_chain: Vec<Vec<u8>>,
    /// Broker key (PKCS#8 DER).
    pub broker_key: Vec<u8>,
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
    pkictl(bin, &passphrase, &["issue-server", "--dir", &d, "--cn", "mqtt", "--san", &sans.join(",")]).await?;
    let pem = std::fs::read_to_string(dir.join("bundle.pub.pem"))?;
    let spki = crate::util::pem_block(pem.as_bytes(), "PUBLIC KEY").ok_or_else(|| anyhow!("bundle.pub.pem is not a PUBLIC KEY"))?;
    let bundle_pubkey: [u8; 32] =
        spki.get(spki.len().saturating_sub(32)..).and_then(|k| k.try_into().ok()).ok_or_else(|| anyhow!("bundle key"))?;
    let key_pem = std::fs::read(dir.join("services").join("mqtt.key.pem"))?;
    let broker_key = crate::util::pem_block(&key_pem, "PRIVATE KEY").ok_or_else(|| anyhow!("mqtt.key.pem is not PKCS#8"))?;
    let services = first(&dir.join("services-ca.crt"))?;
    let services_cn = super::pki::cert_facts(&services)?.cn.unwrap_or_default();
    Ok(Material {
        root: first(&dir.join("root-ca.crt"))?,
        factory: first(&dir.join("factory-ca.crt"))?,
        device: first(&dir.join("device-ca.crt"))?,
        services,
        bundle_pubkey,
        broker_chain: certs(&dir.join("services").join("mqtt.crt"))?,
        broker_key,
        services_cn,
        dir: dir.to_path_buf(),
        passphrase,
    })
}

impl Material {
    /// Broker TLS identity.
    #[must_use]
    pub fn broker_identity(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            self.broker_chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(self.broker_key.clone())),
        )
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
    jwt_key: p256::ecdsa::SigningKey,
    tls: Arc<rustls::ClientConfig>,
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
        let jwt_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        use p256::pkcs8::EncodePublicKey;
        let jwt_pub = jwt_key.verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF).map_err(|e| anyhow!("{e}"))?;
        let jwt_file = material.dir.join("mgmt-jwt.pub.pem");
        std::fs::write(&jwt_file, jwt_pub)?;
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
        let mut me = Self { child, material, mtls_port, plain_port, host: w.host.clone(), pkictl: pkictl.to_path_buf(), jwt_key, tls };
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

    /// A 5-minute ES256 service JWT with `aud=pki` (contract §7).
    ///
    /// # Errors
    /// Signing failures.
    pub fn jwt(&self) -> Result<String> {
        use p256::ecdsa::signature::Signer;
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let now = crate::util::now_unix();
        let header = b64(json!({"alg": "ES256", "typ": "JWT"}).to_string().as_bytes());
        let claims =
            b64(json!({"iss": "svc-conformance", "sub": "svc-conformance", "aud": "pki", "iat": now, "nbf": now - 5, "exp": now + 300})
                .to_string()
                .as_bytes());
        let input = format!("{header}.{claims}");
        let sig: p256::ecdsa::Signature = self.jwt_key.try_sign(input.as_bytes()).map_err(|e| anyhow!("{e}"))?;
        Ok(format!("{input}.{}", b64(&sig.to_bytes())))
    }

    async fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let url = format!("https://{}:{}{path}", self.host, self.mtls_port);
        let mut headers = vec![("authorization", format!("Bearer {}", self.jwt()?))];
        let data = match body {
            Some(b) => {
                headers.push(("content-type", "application/json".into()));
                serde_json::to_vec(&b)?
            }
            None => Vec::new(),
        };
        let r = http_request(method, &url, &headers, data, Some(self.tls.clone()), Duration::from_secs(15)).await?;
        if !(200..300).contains(&r.status) {
            bail!("PKI {method} {path} answered {}: {}", r.status, r.text());
        }
        r.json()
    }

    /// `POST /v1/certificates/{serial}/revoke` (the PKI then pushes to the policy service).
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn revoke(&self, serial_hex: &str) -> Result<Value> {
        self.mgmt("POST", &format!("/v1/certificates/{serial_hex}/revoke"), Some(json!({"reason": "keyCompromise"}))).await
    }

    /// `GET /v1/certificates/{serial}` (DER of `certificate_pem`).
    ///
    /// # Errors
    /// Unknown serial.
    pub async fn certificate(&self, serial_hex: &str) -> Result<Vec<u8>> {
        let v = self.mgmt("GET", &format!("/v1/certificates/{serial_hex}"), None).await?;
        let pem = v["certificate_pem"].as_str().ok_or_else(|| anyhow!("no certificate_pem for {serial_hex}"))?;
        ironmesh_agent::x509::pem_or_der_first(pem.as_bytes()).map_err(|e| anyhow!("{e}"))
    }

    /// `GET /v1/devices/{id}/certificates`.
    ///
    /// # Errors
    /// Non-2xx answers.
    pub async fn device_certificates(&self, device_id: &str) -> Result<Value> {
        self.mgmt("GET", &format!("/v1/devices/{device_id}/certificates"), None).await
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
