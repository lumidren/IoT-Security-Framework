//! The **real** policy service (`services/policy`), run as a subprocess, and the two clients the
//! harness needs to talk to it the way production does:
//!
//! * [`PolicyClient::authn`] / [`PolicyClient::authz`]: the EMQX HTTP authn/authz backends, with
//!   the request bodies rendered exactly like `services/policy/deploy/emqx/emqx.conf` templates
//!   them (strings for `qos`/`retain`, nested and flat `client_attrs`, the hook token header).
//! * [`PolicyClient::publish_revocation`] / [`PolicyClient::publish_release`]: the PKI event push
//!   of `services/pki/internal/revocation/publisher.go` (revocation body with `device_deny`, or the
//!   `device_release` body; `Authorization: Bearer`, `X-IronMesh-Signature: sha256=<hex
//!   HMAC-SHA256(body)>`, `X-IronMesh-Event-ID`).
//! * [`PolicyClient::revocations`]: the management API (`GET /v1/revocations`) with an ES256
//!   service JWT minted per request (`aud=policy`, single-use `jti`).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

use super::jwt::ServiceJwt;
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

/// The PKI → policy revocation event (field order of the Go `revocationWire` struct).
///
/// `device_deny` is what the PKI publisher sends: `true` for revoke-all (registry quarantine /
/// decommission), `false` for single-certificate revocations (operator revoke of one serial,
/// supersede on renewal). The policy service deny-lists the device id for `device_deny` or the
/// reasons `keyCompromise` / `cessationOfOperation`, and only the serial otherwise.
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
    /// Device-level deny (revoke-all).
    pub device_deny: bool,
}

/// The PKI → policy `device_release` event (field order of the Go `releaseWire` struct).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseEvent {
    /// Unique event id.
    pub event_id: String,
    /// Always `device_release`.
    pub event: String,
    /// Device id.
    pub device_id: String,
    /// Tenant id.
    pub tenant_id: String,
    /// RFC 3339 timestamp.
    pub released_at: String,
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
    /// Certificate PEM (template `cert_pem = "${cert_pem}"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    /// Certificate serial, hex (template `cert_serial = "${client_attrs.cert_serial}"`, set by
    /// `mqtt.client_attrs_init` from the TLS peer certificate only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_serial: Option<String>,
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
    /// Service identity for the management API (`POLICY_JWT_PUBLIC_KEY_PEM` holds its key).
    pub mgmt_jwt: Option<Arc<ServiceJwt>>,
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
        self.event_request(&ev.event_id, ev)
    }

    /// The exact `device_release` request the PKI publisher sends.
    ///
    /// # Errors
    /// JSON encoding.
    pub fn release_request(&self, ev: &ReleaseEvent) -> Result<(Headers, Vec<u8>)> {
        self.event_request(&ev.event_id, ev)
    }

    fn event_request<T: Serialize>(&self, event_id: &str, ev: &T) -> Result<(Headers, Vec<u8>)> {
        let body = serde_json::to_vec(ev)?;
        let headers = vec![
            ("content-type", "application/json".to_string()),
            ("x-ironmesh-signature", revocation_signature(&self.pki_hmac, &body)),
            ("x-ironmesh-event-id", event_id.to_owned()),
            ("authorization", format!("Bearer {}", self.pki_token)),
        ];
        Ok((headers, body))
    }

    async fn publish_event(&self, (headers, body): (Headers, Vec<u8>), what: &str) -> Result<HttpResponse> {
        let r = http_request("POST", &format!("{}/internal/v1/revocations", self.base), &headers, body, None, TIMEOUT).await?;
        if !(200..300).contains(&r.status) {
            bail!("policy rejected the {what} event with {}: {}", r.status, r.text());
        }
        Ok(r)
    }

    /// `POST /internal/v1/revocations` with a revocation (expects `202`).
    ///
    /// # Errors
    /// Transport failure or a non-2xx answer.
    pub async fn publish_revocation(&self, ev: &RevocationEvent) -> Result<HttpResponse> {
        self.publish_event(self.revocation_request(ev)?, "revocation").await
    }

    /// `POST /internal/v1/revocations` with a `device_release` event (expects `202`).
    ///
    /// # Errors
    /// Transport failure or a non-2xx answer.
    pub async fn publish_release(&self, ev: &ReleaseEvent) -> Result<HttpResponse> {
        self.publish_event(self.release_request(ev)?, "device_release").await
    }

    /// `GET /v1/revocations` (every page), each request with a freshly minted single-use service
    /// JWT (`aud=policy`, `role=viewer`).
    ///
    /// # Errors
    /// No management identity, transport failure or a non-200 answer.
    pub async fn revocations(&self) -> Result<Vec<Value>> {
        let jwt = self.mgmt_jwt.as_ref().ok_or_else(|| anyhow!("the policy management API is not configured"))?;
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let path = match &cursor {
                Some(c) => format!("/v1/revocations?limit=100&cursor={c}"),
                None => "/v1/revocations?limit=100".to_string(),
            };
            let token = jwt.mint("policy", &[("role", json!("viewer"))])?;
            let headers = [("authorization", format!("Bearer {token}"))];
            let r = http_request("GET", &format!("{}{path}", self.base), &headers, Vec::new(), None, TIMEOUT).await?;
            if r.status != 200 {
                bail!("policy GET {path} answered {}: {}", r.status, r.text());
            }
            let v = r.json()?;
            out.extend(v["items"].as_array().cloned().unwrap_or_default());
            match v["next_cursor"].as_str() {
                Some(c) if !c.is_empty() => cursor = Some(c.to_owned()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Send `GET /v1/revocations` twice with the **same** token; returns both statuses. A
    /// single-use deployment answers `200` then `401`.
    ///
    /// # Errors
    /// No management identity or transport failure.
    pub async fn replay_mgmt_token(&self) -> Result<(u16, u16)> {
        let jwt = self.mgmt_jwt.as_ref().ok_or_else(|| anyhow!("the policy management API is not configured"))?;
        let token = jwt.mint("policy", &[("role", json!("viewer"))])?;
        let headers = [("authorization", format!("Bearer {token}"))];
        let url = format!("{}/v1/revocations?limit=1", self.base);
        let a = http_request("GET", &url, &headers, Vec::new(), None, TIMEOUT).await?.status;
        let b = http_request("GET", &url, &headers, Vec::new(), None, TIMEOUT).await?.status;
        Ok((a, b))
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
    /// Device CA certificate file (CRL signature verification and `POLICY_DEVICE_CA_FILE`: the
    /// issuer every device `cert_pem` must chain to).
    pub crl_issuer_file: PathBuf,
    /// Services CA certificate file (`POLICY_SERVICES_CA_FILE`: issuer of `svc-*` client certificates).
    pub services_ca_file: Option<PathBuf>,
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
        // The harness's management identity (what the console or an operator tool would hold).
        let mgmt_jwt = Arc::new(ServiceJwt::random("svc-conformance", "svc-conformance"));
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
            .env("POLICY_DEVICE_CA_FILE", &s.crl_issuer_file)
            // The default, stated explicitly: a CONNECT without cert_pem / cert_serial is denied.
            .env("POLICY_REQUIRE_CERT_SERIAL", "true")
            .env("POLICY_JWT_PUBLIC_KEY_PEM", mgmt_jwt.public_pem()?)
            .env("POLICY_JWT_SINGLE_USE", "true")
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
            .envs(s.services_ca_file.iter().map(|f| ("POLICY_SERVICES_CA_FILE", f.as_os_str())))
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
            mgmt_jwt: Some(mgmt_jwt),
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
        let c = PolicyClient {
            base: "http://x".into(),
            hook_token: None,
            pki_token: "tok".into(),
            pki_hmac: b"secret".to_vec(),
            hooks: None,
            mgmt_jwt: None,
        };
        let ev = RevocationEvent {
            event_id: "e1".into(),
            serial: "0a1b".into(),
            device_id: "dev-0011223344556677".into(),
            tenant_id: "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11".into(),
            reason: "keyCompromise".into(),
            revoked_at: "2026-01-01T00:00:00Z".into(),
            device_deny: false,
        };
        let (h, body) = c.revocation_request(&ev).unwrap();
        // Field order of the Go revocationWire struct; device_deny always present; no `event` member.
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(text.starts_with("{\"event_id\":\"e1\",\"serial\":\"0a1b\",\"device_id\""));
        assert!(text.ends_with(",\"revoked_at\":\"2026-01-01T00:00:00Z\",\"device_deny\":false}"), "{text}");
        assert!(!text.contains("\"event\""));
        let rel = ReleaseEvent {
            event_id: "e2".into(),
            event: "device_release".into(),
            device_id: "dev-0011223344556677".into(),
            tenant_id: "t".into(),
            released_at: "2026-01-01T00:00:01Z".into(),
        };
        let (h2, body2) = c.release_request(&rel).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&body2),
            "{\"event_id\":\"e2\",\"event\":\"device_release\",\"device_id\":\"dev-0011223344556677\",\"tenant_id\":\"t\",\"released_at\":\"2026-01-01T00:00:01Z\"}"
        );
        assert!(h2.iter().any(|(k, v)| *k == "x-ironmesh-signature" && *v == revocation_signature(b"secret", &body2)));
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

/// Cost of the CONNECT certificate checks in the real policy service, isolated from load:
/// sequential `POST /emqx/authn` over one keep-alive connection, the same device and the same
/// cached registry answer, (a) with `cert_pem` + `cert_serial` and the hardened defaults and (b)
/// with neither and `POLICY_REQUIRE_CERT_SERIAL=false` (the pre-hardening behaviour).
///
/// `cargo test --release -- --ignored authn_certificate_check_cost --nocapture` (needs
/// `conformance/target/bin/policy`).
#[cfg(test)]
mod cost {
    use super::*;
    use crate::harness::pki::{cert_facts, DeviceCertSpec, TestPki};
    use crate::harness::registry::{DeviceRecord, FakeRegistry, ACTIVE};

    async fn measure(with_cert: bool, n: usize) -> Vec<f64> {
        let dir = tempfile::tempdir().unwrap();
        let pki = TestPki::generate(&[]).unwrap();
        let reg = FakeRegistry::start("127.0.0.1", "tok".into()).await.unwrap();
        let ca = dir.path().join("device-ca.pem");
        std::fs::write(&ca, crate::util::pem("CERTIFICATE", &pki.device.der)).unwrap();
        let svc_ca = dir.path().join("services-ca.pem");
        std::fs::write(&svc_ca, crate::util::pem("CERTIFICATE", &pki.services.der)).unwrap();
        let mut extra = vec![("POLICY_LOG_LEVEL".to_string(), "warn".to_string()), ("POLICY_REGISTRY_CACHE_TTL".into(), "30s".into())];
        if !with_cert {
            extra.push(("POLICY_REQUIRE_CERT_SERIAL".into(), "false".into()));
        }
        let mut svc = PolicyService::spawn(PolicySpawn {
            binary: crate::util::repo_root().join("conformance/target/bin").join(crate::dut::exe("policy")),
            host: "127.0.0.1".into(),
            emqx_api_url: "http://127.0.0.1:9".into(),
            emqx_key: "k".into(),
            emqx_secret: "s".into(),
            registry_url: reg.url(),
            registry_token: "tok".into(),
            crl_url: format!("{}/crl/device-ca.crl", reg.url()),
            crl_issuer_file: ca,
            services_ca_file: Some(svc_ca),
            state_dir: dir.path().join("state"),
            log_file: dir.path().join("policy.log"),
            extra_env: extra,
        })
        .await
        .unwrap();
        let client = svc.client.clone().with_hook_pool(1).unwrap();
        let tenant = crate::util::uuid4();
        let id = crate::util::new_device_id();
        let key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        use p256::pkcs8::EncodePublicKey;
        let spki = key.public_key().to_public_key_der().unwrap();
        let spec =
            DeviceCertSpec { device_id: id.clone(), tenant_id: tenant.clone(), bootstrap: false, software: true, lifetime_s: 86_400 };
        let der = pki.issue_device_cert(&spec, spki.as_bytes()).unwrap();
        reg.register(&id, DeviceRecord { tenant_id: tenant, state: ACTIVE.into(), ..DeviceRecord::default() });
        let mut req = crate::harness::broker::emqx_authn_request(&id, "127.0.0.1", &der, &cert_facts(&der).unwrap());
        if !with_cert {
            req.cert_pem = None;
            req.cert_serial = None;
        }
        let mut out = Vec::with_capacity(n);
        for i in 0..n + 200 {
            let t = std::time::Instant::now();
            assert!(client.authn(&req).await.unwrap().allow);
            if i >= 200 {
                out.push(t.elapsed().as_secs_f64() * 1000.0);
            }
        }
        svc.stop().await;
        out
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs the policy binary; a measurement, not a check"]
    async fn authn_certificate_check_cost() {
        crate::install_crypto();
        let n = 5000;
        for round in 0..2 {
            for with in [false, true] {
                let v = measure(with, n).await;
                let p = |q| crate::util::percentile(&v, q).unwrap_or(f64::NAN);
                let mean = v.iter().sum::<f64>() / v.len() as f64;
                println!(
                    "round {round} cert checks {:5}: n={n} mean {mean:.3} ms p50 {:.3} p95 {:.3} p99 {:.3} max {:.3}",
                    with,
                    p(50.0),
                    p(95.0),
                    p(99.0),
                    v.iter().copied().fold(0.0, f64::max)
                );
            }
        }
    }
}
