//! The **real** policy service (`services/policy`), run as a subprocess, and the two clients the
//! harness needs to talk to it the way production does:
//!
//! * [`PolicyClient::authn`] / [`PolicyClient::authz`]: the EMQX HTTP authn/authz backends, with
//!   the request bodies rendered exactly like `services/policy/deploy/emqx/emqx.conf` templates
//!   them (strings for `qos`/`retain`, nested and flat `client_attrs`, the hook token header).
//! * [`PolicyClient::publish_revocation`]: the PKI revocation push of
//!   `services/pki/internal/revocation/publisher.go` (JSON event, `Authorization: Bearer`,
//!   `X-IronMesh-Signature: sha256=<hex HMAC-SHA256(body)>`, `X-IronMesh-Event-ID`).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

use super::net::{http_request, HookPool, HttpResponse};

/// HTTP headers of a request.
pub type Headers = Vec<(&'static str, String)>;

/// HMAC-SHA256 (RFC 2104).
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

/// `X-IronMesh-Signature` value for `body` (same as `revocation.Sign` in the PKI).
#[must_use]
pub fn revocation_signature(key: &[u8], body: &[u8]) -> String {
    format!("sha256={}", hex::encode(hmac_sha256(key, body)))
}

/// The PKI → policy revocation event (field order as the Go struct).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEvent {
    /// Unique event id.
    pub event_id: String,
    /// Serial (lower-case hex).
    pub serial: String,
    /// Device id.
    pub device_id: String,
    /// Tenant id.
    pub tenant_id: String,
    /// RFC 5280 reason name.
    pub reason: String,
    /// RFC 3339 timestamp.
    pub revoked_at: String,
}

/// Session attributes returned by authn (EMQX `client_attrs`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAttrs {
    /// Tenant.
    #[serde(default)]
    pub tenant_id: String,
    /// Device.
    #[serde(default)]
    pub device_id: String,
    /// `device` or `service`.
    #[serde(default)]
    pub kind: String,
}

/// The authn request EMQX sends.
#[derive(Debug, Clone, Serialize)]
pub struct AuthnRequest {
    /// MQTT client id.
    pub clientid: String,
    /// Username (EMQX `peer_cert_as_username = cn`).
    pub username: String,
    /// Peer IP.
    pub peerhost: String,
    /// Certificate CN.
    pub cert_common_name: String,
    /// Certificate subject (RFC 4514).
    pub cert_subject: String,
    /// Certificate PEM (EMQX >= 5.8 template `${cert_pem}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
}

/// The authn decision.
#[derive(Debug, Clone)]
pub struct AuthnDecision {
    /// `result == "allow"`.
    pub allow: bool,
    /// Attributes for the session.
    pub attrs: Option<ClientAttrs>,
    /// Session expiry bound to the certificate (Unix s).
    pub expire_at: Option<i64>,
}

/// Inputs of an authz decision.
#[derive(Debug, Clone)]
pub struct AuthzRequest {
    /// Client id.
    pub clientid: String,
    /// Username.
    pub username: String,
    /// Peer IP.
    pub peerhost: String,
    /// Topic or filter.
    pub topic: String,
    /// `publish` / `subscribe`.
    pub action: &'static str,
    /// QoS.
    pub qos: u8,
    /// Retain flag.
    pub retain: bool,
    /// Session attributes from authn.
    pub attrs: ClientAttrs,
}

/// Client of a running policy service.
#[derive(Clone)]
pub struct PolicyClient {
    /// Base URL (`http://127.0.0.1:port`).
    pub base: String,
    /// `X-IronMesh-Hook-Token`.
    pub hook_token: Option<String>,
    /// PKI bearer token.
    pub pki_token: String,
    /// PKI HMAC key.
    pub pki_hmac: Vec<u8>,
    /// Persistent connection pool for the authn/authz hooks (`None`: one connection per call).
    pub hooks: Option<Arc<HookPool>>,
}

const TIMEOUT: Duration = Duration::from_secs(5);

impl PolicyClient {
    /// The same client with a persistent hook connection pool of `max` connections (load tests).
    ///
    /// # Errors
    /// Invalid base URL.
    pub fn with_hook_pool(mut self, max: usize) -> Result<Self> {
        self.hooks = Some(Arc::new(HookPool::new(&self.base, max)?));
        Ok(self)
    }

    async fn hook_post(&self, path: &str, body: Vec<u8>) -> Result<HttpResponse> {
        match &self.hooks {
            Some(pool) => pool.post(path, &self.hook_headers(), body, TIMEOUT).await,
            None => http_request("POST", &format!("{}{path}", self.base), &self.hook_headers(), body, None, TIMEOUT).await,
        }
    }

    /// The raw `/metrics` exposition text.
    ///
    /// # Errors
    /// Transport failure.
    pub async fn metrics_text(&self) -> Result<String> {
        Ok(http_request("GET", &format!("{}/metrics", self.base), &[], Vec::new(), None, TIMEOUT).await?.text())
    }

    fn hook_headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![("content-type", "application/json".to_string())];
        if let Some(t) = &self.hook_token {
            h.push(("x-ironmesh-hook-token", t.clone()));
        }
        h
    }

    /// `POST /emqx/authn`.
    ///
    /// # Errors
    /// Transport or a non-200 answer.
    pub async fn authn(&self, req: &AuthnRequest) -> Result<AuthnDecision> {
        let body = serde_json::to_vec(req)?;
        let r = self.hook_post("/emqx/authn", body).await?;
        if r.status != 200 {
            bail!("authn hook answered {}: {}", r.status, r.text());
        }
        let v = r.json()?;
        Ok(AuthnDecision {
            allow: v["result"] == "allow",
            attrs: v.get("client_attrs").and_then(|a| serde_json::from_value(a.clone()).ok()),
            expire_at: v.get("expire_at").and_then(Value::as_i64),
        })
    }

    /// `POST /emqx/authz`, rendered like the EMQX HTTP authorizer template.
    ///
    /// # Errors
    /// Transport or a non-200 answer.
    pub async fn authz(&self, req: &AuthzRequest) -> Result<bool> {
        let body = json!({
            "clientid": req.clientid,
            "username": req.username,
            "peerhost": req.peerhost,
            "topic": req.topic,
            "action": req.action,
            "qos": req.qos.to_string(),
            "retain": req.retain.to_string(),
            "client_attrs": {"tenant_id": req.attrs.tenant_id, "device_id": req.attrs.device_id, "kind": req.attrs.kind},
            "tenant_id": req.attrs.tenant_id,
            "device_id": req.attrs.device_id,
            "kind": req.attrs.kind,
        });
        let r = self.hook_post("/emqx/authz", serde_json::to_vec(&body)?).await?;
        if r.status != 200 {
            bail!("authz hook answered {}: {}", r.status, r.text());
        }
        Ok(r.json()?["result"] == "allow")
    }

    /// The exact request the PKI publisher sends; returned separately so unit tests can check it.
    ///
    /// # Errors
    /// JSON encoding.
    pub fn revocation_request(&self, ev: &RevocationEvent) -> Result<(Headers, Vec<u8>)> {
        let body = serde_json::to_vec(ev)?;
        let headers = vec![
            ("content-type", "application/json".to_string()),
            ("x-ironmesh-signature", revocation_signature(&self.pki_hmac, &body)),
            ("x-ironmesh-event-id", ev.event_id.clone()),
            ("authorization", format!("Bearer {}", self.pki_token)),
        ];
        Ok((headers, body))
    }

    /// `POST /internal/v1/revocations` (expects `202`).
    ///
    /// # Errors
    /// Transport failure or a non-2xx answer.
    pub async fn publish_revocation(&self, ev: &RevocationEvent) -> Result<HttpResponse> {
        let (headers, body) = self.revocation_request(ev)?;
        let r = http_request("POST", &format!("{}/internal/v1/revocations", self.base), &headers, body, None, TIMEOUT).await?;
        if !(200..300).contains(&r.status) {
            bail!("policy rejected the revocation event with {}: {}", r.status, r.text());
        }
        Ok(r)
    }

    /// Read a counter / histogram sample from `/metrics` (sum of every series of `name` whose
    /// label set contains `label_filter`).
    ///
    /// # Errors
    /// Transport failure.
    pub async fn metric(&self, name: &str, label_filter: &str) -> Result<f64> {
        let r = http_request("GET", &format!("{}/metrics", self.base), &[], Vec::new(), None, TIMEOUT).await?;
        Ok(parse_metric(&r.text(), name, label_filter))
    }
}

/// Sum the samples of `name` (exact metric name, any labels containing `label_filter`).
#[must_use]
pub fn parse_metric(text: &str, name: &str, label_filter: &str) -> f64 {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (series, value) = l.rsplit_once(' ')?;
            let (metric, labels) = match series.find('{') {
                Some(i) => (&series[..i], &series[i..]),
                None => (series, ""),
            };
            (metric == name && labels.contains(label_filter)).then(|| value.parse::<f64>().ok()).flatten()
        })
        .sum()
}

/// Settings for spawning the policy service.
pub struct PolicySpawn {
    /// Policy binary.
    pub binary: PathBuf,
    /// Listen host.
    pub host: String,
    /// Fake EMQX management API base URL (the broker double).
    pub emqx_api_url: String,
    /// API key / secret for the management API.
    pub emqx_key: String,
    /// API secret.
    pub emqx_secret: String,
    /// Registry double base URL and token.
    pub registry_url: String,
    /// Registry token.
    pub registry_token: String,
    /// CRL URL and Device CA PEM file.
    pub crl_url: String,
    /// Device CA certificate file (CRL signature verification).
    pub crl_issuer_file: PathBuf,
    /// State directory.
    pub state_dir: PathBuf,
    /// Log file (stdout + stderr of the process).
    pub log_file: PathBuf,
    /// Extra environment, applied after the defaults (load tests: production cache TTL, log level).
    pub extra_env: Vec<(String, String)>,
}

/// A running policy service.
pub struct PolicyService {
    child: Child,
    /// Client.
    pub client: PolicyClient,
    /// Log file.
    pub log_file: PathBuf,
}

/// A free TCP port on `host` (bind to 0 and release).
///
/// # Errors
/// Bind failure.
pub fn free_port(host: &str) -> Result<u16> {
    let l = std::net::TcpListener::bind((host, 0))?;
    Ok(l.local_addr()?.port())
}

impl PolicyService {
    /// Spawn and wait for `/readyz`.
    ///
    /// # Errors
    /// Spawn failure or not ready within 30 s.
    pub async fn spawn(s: PolicySpawn) -> Result<Self> {
        if !s.binary.is_file() {
            bail!(
                "policy binary {} not found (build it with `go build ./services/policy/cmd/policy` or pass --policy-bin)",
                s.binary.display()
            );
        }
        std::fs::create_dir_all(&s.state_dir)?;
        let port = free_port(&s.host)?;
        let hook_token = hex::encode(crate::util::random_bytes(16));
        let pki_token = hex::encode(crate::util::random_bytes(16));
        let pki_hmac = hex::encode(crate::util::random_bytes(32));
        let log = std::fs::OpenOptions::new().create(true).append(true).open(&s.log_file)?;
        let log2 = log.try_clone()?;
        let mut cmd = Command::new(&s.binary);
        cmd.env_clear();
        for k in ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "PATH", "HOME", "USERPROFILE"] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        cmd.env("POLICY_LISTEN", format!("{}:{port}", s.host))
            .env("POLICY_EMQX_API_URL", &s.emqx_api_url)
            .env("POLICY_EMQX_API_KEY", &s.emqx_key)
            .env("POLICY_EMQX_API_SECRET", &s.emqx_secret)
            .env("POLICY_PKI_CRL_URL", &s.crl_url)
            .env("POLICY_CRL_ISSUER_CERT_FILE", &s.crl_issuer_file)
            .env("POLICY_CRL_POLL_INTERVAL", "5s")
            .env("POLICY_PKI_HMAC_SECRET", &pki_hmac)
            .env("POLICY_PKI_TOKEN", &pki_token)
            .env("POLICY_REGISTRY_URL", &s.registry_url)
            .env("POLICY_REGISTRY_TOKEN", &s.registry_token)
            // Lifecycle answers are cached for 30 s in production; the suite flips lifecycle
            // states (quarantine) between steps, so it shortens the cache. Revocations do not
            // depend on it: they go through the revocation cache, which is updated synchronously.
            .env("POLICY_REGISTRY_CACHE_TTL", "1s")
            .env("POLICY_STATE_DIR", &s.state_dir)
            .env("POLICY_HOOK_TOKEN", &hook_token)
            .env("POLICY_LOG_LEVEL", "debug")
            .envs(s.extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .kill_on_drop(true);
        let child = cmd.spawn().with_context(|| format!("spawn {}", s.binary.display()))?;
        let client = PolicyClient {
            base: format!("http://{}:{port}", s.host),
            hook_token: Some(hook_token),
            pki_token,
            pki_hmac: pki_hmac.into_bytes(),
            hooks: None,
        };
        let mut svc = Self { child, client, log_file: s.log_file };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Some(status)) = svc.child.try_wait() {
                bail!("policy service exited during start-up ({status}); see {}", svc.log_file.display());
            }
            if let Ok(r) = http_request("GET", &format!("{}/readyz", svc.client.base), &[], Vec::new(), None, Duration::from_secs(1)).await
            {
                if r.status == 200 {
                    return Ok(svc);
                }
            }
            if tokio::time::Instant::now() > deadline {
                svc.stop().await;
                bail!("policy service not ready within 30 s; see {}", svc.log_file.display());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Stop the process.
    pub async fn stop(&mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }

    /// Process id.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Whether the process is still running.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Lines of the policy log mentioning `needle` (for evidence).
#[must_use]
pub fn log_lines(path: &Path, needle: &str, max: usize) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines().filter(|l| l.contains(needle)).rev().take(max).map(str::to_owned).collect::<Vec<_>>().into_iter().rev().collect()
        })
        .unwrap_or_default()
}

/// Shared handle.
pub type SharedPolicy = Arc<tokio::sync::Mutex<PolicyService>>;

/// RFC 3339 UTC timestamp with nanoseconds (Go `time.Time` JSON form).
///
/// # Errors
/// Never in practice.
pub fn rfc3339_now() -> Result<String> {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex::encode(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // Long keys are hashed first (RFC 4231 test case 6).
        let mac = hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(hex::encode(mac), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    #[test]
    fn revocation_request_is_signed_like_the_pki_publisher() {
        let c =
            PolicyClient { base: "http://x".into(), hook_token: None, pki_token: "tok".into(), pki_hmac: b"secret".to_vec(), hooks: None };
        let ev = RevocationEvent {
            event_id: "e1".into(),
            serial: "0a1b".into(),
            device_id: "dev-0011223344556677".into(),
            tenant_id: "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11".into(),
            reason: "keyCompromise".into(),
            revoked_at: "2026-01-01T00:00:00Z".into(),
        };
        let (h, body) = c.revocation_request(&ev).unwrap();
        // Field order of the Go struct.
        assert!(String::from_utf8_lossy(&body).starts_with("{\"event_id\":\"e1\",\"serial\":\"0a1b\",\"device_id\""));
        let sig = h.iter().find(|(k, _)| *k == "x-ironmesh-signature").unwrap().1.clone();
        assert_eq!(sig, revocation_signature(b"secret", &body));
        assert!(sig.starts_with("sha256=") && sig.len() == 7 + 64);
        assert!(h.iter().any(|(k, v)| *k == "authorization" && v == "Bearer tok"));
        assert!(h.iter().any(|(k, v)| *k == "x-ironmesh-event-id" && v == "e1"));
    }

    #[test]
    fn metrics_parsing() {
        let text = "# HELP x\nironmesh_kick_total{result=\"ok\"} 3\nironmesh_kick_total{result=\"error\"} 1\nironmesh_revocation_latency_seconds_sum 0.25\n";
        assert_eq!(parse_metric(text, "ironmesh_kick_total", "result=\"ok\""), 3.0);
        assert_eq!(parse_metric(text, "ironmesh_kick_total", ""), 4.0);
        assert_eq!(parse_metric(text, "ironmesh_revocation_latency_seconds_sum", ""), 0.25);
        assert_eq!(parse_metric(text, "missing", ""), 0.0);
    }
}
