//! Registry double: the internal endpoints of `docs/API_CONTRACT.md` §1.12 the real policy service
//! and the real PKI call (lifecycle, PKI device lookup, assurance, `enrolled`), the admin release
//! of §1.2 (`POST /v1/devices/{id}/release`), plus the PKI plain-listener CRL distribution point
//! the policy service polls as its fallback revocation path.
//!
//! `enrolled` behaves like `services/registry` (`devices.enrolled`): the body is validated
//! (`serial_hex`, `not_before`, `not_after`, `se_type`, `assurance_level`, optional `fw_version` /
//! `fw_hash_hex`), `404` for an unknown device, `409` unless the device is `manufactured`,
//! `provisioned` or `active`; otherwise the certificate is recorded and the device becomes
//! `active` (`200` with the device). `release` answers `409` unless the device is `quarantined`
//! and makes it `active`; the PKI side effect of a release (`POST /v1/devices/{id}/release`,
//! which pushes the `device_release` event to the policy service) is performed by
//! [`super::Cloud::release_device`], the harness's registry orchestration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::net;

/// Lifecycle states (contract §7).
pub const MANUFACTURED: &str = "manufactured";
/// Lifecycle state.
pub const ACTIVE: &str = "active";
/// Lifecycle state.
pub const QUARANTINED: &str = "quarantined";

/// Lifecycle states that permit (re)enrollment (`ENROLLABLE` in `services/registry`).
pub const ENROLLABLE: [&str; 3] = [MANUFACTURED, "provisioned", ACTIVE];

/// A certificate recorded by `enrolled`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    /// Serial (lower-case hex, normalised).
    pub serial_hex: String,
    /// notBefore (RFC 3339 as sent).
    pub not_before: String,
    /// notAfter (RFC 3339 as sent).
    pub not_after: String,
}

/// A device record (manufacture record + lifecycle).
#[derive(Debug, Clone, Default)]
pub struct DeviceRecord {
    /// Tenant.
    pub tenant_id: String,
    /// Lifecycle state.
    pub state: String,
    /// Secure element type from the manufacture record.
    pub se_type: String,
    /// Bootstrap serial (lower-case hex).
    pub bootstrap_serial_hex: String,
    /// Assurance level recorded at enrollment.
    pub assurance_level: Option<String>,
    /// Product.
    pub product: String,
    /// Certificates recorded by `enrolled` (latest last).
    pub certificates: Vec<CertRecord>,
}

/// Why a registry operation was refused (HTTP status + detail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub u16, pub String);

/// The body of `POST /internal/v1/devices/{id}/enrolled` (API_CONTRACT §1.12).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Enrolled {
    /// Serial of the issued certificate (hex, `:` allowed).
    pub serial_hex: String,
    /// notBefore (RFC 3339).
    pub not_before: String,
    /// notAfter (RFC 3339).
    pub not_after: String,
    /// Attested secure element type.
    pub se_type: String,
    /// `hardware` | `software`.
    pub assurance_level: String,
    /// Firmware version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fw_version: Option<String>,
    /// Firmware hash (64 lower-case hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fw_hash_hex: Option<String>,
}

fn rfc3339(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
}

impl Enrolled {
    /// The registry's input validation (`EnrolledInput`): `422` detail on failure.
    ///
    /// # Errors
    /// The first invalid field.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let serial_ok = (1..=64).contains(&self.serial_hex.len()) && self.serial_hex.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
        if !serial_ok {
            return Err("serial_hex: must match ^[0-9a-fA-F:]{1,64}$".into());
        }
        if !rfc3339(&self.not_before) || !rfc3339(&self.not_after) {
            return Err("not_before / not_after: must be RFC 3339 date-times".into());
        }
        if !matches!(self.se_type.as_str(), "atecc608" | "tpm2" | "optee" | "software") {
            return Err(format!("se_type: unknown value {:?}", self.se_type));
        }
        if !matches!(self.assurance_level.as_str(), "hardware" | "software") {
            return Err(format!("assurance_level: unknown value {:?}", self.assurance_level));
        }
        if let Some(h) = &self.fw_hash_hex {
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
                return Err("fw_hash_hex: must be 64 lower-case hex digits".into());
            }
        }
        Ok(())
    }
}

fn normalize_serial(s: &str) -> String {
    let t = s.to_ascii_lowercase().replace(':', "");
    let t = t.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.to_owned()
    }
}

fn device_json(id: &str, r: &DeviceRecord) -> serde_json::Value {
    let cert = r.certificates.last();
    json!({
        "id": id, "tenant_id": r.tenant_id, "product": r.product, "state": r.state,
        "assurance_level": r.assurance_level, "se_type": r.se_type,
        "bootstrap_serial_hex": r.bootstrap_serial_hex,
        "cert": cert.map(|c| json!({"serial_hex": c.serial_hex, "not_after": c.not_after})),
        "certificates": r.certificates.iter().map(|c| json!({"serial_hex": c.serial_hex, "not_before": c.not_before, "not_after": c.not_after})).collect::<Vec<_>>(),
    })
}

fn apply_enrolled(
    devices: &Mutex<HashMap<String, DeviceRecord>>,
    id: &str,
    e: &Enrolled,
) -> std::result::Result<serde_json::Value, Refused> {
    e.validate().map_err(|d| Refused(422, d))?;
    let mut d = devices.lock().map_err(|_| Refused(503, "registry state unavailable".into()))?;
    let r = d.get_mut(id).ok_or_else(|| Refused(404, format!("device {id} not found")))?;
    if !ENROLLABLE.contains(&r.state.as_str()) {
        return Err(Refused(409, format!("device is {}; enrollment is not permitted", r.state)));
    }
    let serial = normalize_serial(&e.serial_hex);
    r.certificates.retain(|c| c.serial_hex != serial);
    r.certificates.push(CertRecord { serial_hex: serial, not_before: e.not_before.clone(), not_after: e.not_after.clone() });
    r.assurance_level = Some(e.assurance_level.clone());
    r.state = ACTIVE.into();
    Ok(device_json(id, r))
}

fn apply_release(devices: &Mutex<HashMap<String, DeviceRecord>>, id: &str) -> std::result::Result<serde_json::Value, Refused> {
    let mut d = devices.lock().map_err(|_| Refused(503, "registry state unavailable".into()))?;
    let r = d.get_mut(id).ok_or_else(|| Refused(404, format!("device {id} not found")))?;
    if r.state != QUARANTINED {
        return Err(Refused(409, format!("device is {}; only a quarantined device can be released", r.state)));
    }
    r.state = ACTIVE.into();
    Ok(device_json(id, r))
}

fn refused(r: Refused) -> Response {
    let status = StatusCode::from_u16(r.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, [("content-type", "application/problem+json")], json!({"status": r.0, "detail": r.1}).to_string()).into_response()
}

#[derive(Clone)]
struct Ctx {
    token: String,
    devices: Arc<Mutex<HashMap<String, DeviceRecord>>>,
    lookups: Arc<Mutex<Vec<String>>>,
    crl: Arc<Mutex<Vec<u8>>>,
}

/// The running registry double.
pub struct FakeRegistry {
    /// Listen address.
    pub addr: SocketAddr,
    /// Bearer token callers must present.
    pub token: String,
    devices: Arc<Mutex<HashMap<String, DeviceRecord>>>,
    lookups: Arc<Mutex<Vec<String>>>,
    crl: Arc<Mutex<Vec<u8>>>,
}

fn authorized(ctx: &Ctx, h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|v| v == format!("Bearer {}", ctx.token))
}

async fn lifecycle(State(ctx): State<Ctx>, Path(id): Path<String>, h: HeaderMap) -> Response {
    if !authorized(&ctx, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Ok(mut l) = ctx.lookups.lock() {
        l.push(id.clone());
    }
    let rec = ctx.devices.lock().ok().and_then(|d| d.get(&id).cloned());
    match rec {
        Some(r) => axum::Json(json!({
            "device_id": id, "tenant_id": r.tenant_id, "state": r.state,
            "assurance_level": r.assurance_level, "product": r.product,
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn tenant_device(State(ctx): State<Ctx>, Path((tenant, id)): Path<(String, String)>, h: HeaderMap) -> Response {
    if !authorized(&ctx, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let rec = ctx.devices.lock().ok().and_then(|d| d.get(&id).cloned()).filter(|r| r.tenant_id == tenant);
    match rec {
        Some(r) => axum::Json(json!({
            "device_id": id, "tenant_id": r.tenant_id, "state": r.state, "assurance_level": r.assurance_level,
            "se_type": r.se_type, "bootstrap_serial": r.bootstrap_serial_hex,
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn assurance(State(ctx): State<Ctx>, Path((_tenant, id)): Path<(String, String)>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if !authorized(&ctx, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let level = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["assurance_level"].as_str().map(str::to_owned));
    if let Ok(mut d) = ctx.devices.lock() {
        if let Some(r) = d.get_mut(&id) {
            r.assurance_level = level;
            if r.state == MANUFACTURED {
                r.state = ACTIVE.into();
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn enrolled(State(ctx): State<Ctx>, Path(id): Path<String>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if !authorized(&ctx, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let e: Enrolled = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(err) => return refused(Refused(422, format!("invalid body: {err}"))),
    };
    match apply_enrolled(&ctx.devices, &id, &e) {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => refused(r),
    }
}

async fn release(State(ctx): State<Ctx>, Path(id): Path<String>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if !authorized(&ctx, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !body.is_empty() && serde_json::from_slice::<serde_json::Value>(&body).map(|v| !v.is_object()).unwrap_or(true) {
        return refused(Refused(422, "body must be a JSON object {note}".into()));
    }
    match apply_release(&ctx.devices, &id) {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => refused(r),
    }
}

async fn crl(State(ctx): State<Ctx>, h: HeaderMap) -> Response {
    let der = ctx.crl.lock().map(|c| c.clone()).unwrap_or_default();
    if der.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let etag = format!("\"{}\"", hex::encode(&Sha256::digest(&der)[..8]));
    if h.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        return (StatusCode::NOT_MODIFIED, [("etag", etag)]).into_response();
    }
    (StatusCode::OK, [("content-type", "application/pkix-crl".to_string()), ("etag", etag)], der).into_response()
}

impl FakeRegistry {
    /// Start on `host:0`.
    ///
    /// # Errors
    /// Bind failure.
    pub async fn start(host: &str, token: String) -> Result<Self> {
        let devices = Arc::new(Mutex::new(HashMap::new()));
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let crl_store = Arc::new(Mutex::new(Vec::new()));
        let ctx = Ctx { token: token.clone(), devices: devices.clone(), lookups: lookups.clone(), crl: crl_store.clone() };
        let router = Router::new()
            .route("/internal/v1/devices/{id}/lifecycle", get(lifecycle))
            .route("/internal/v1/tenants/{tenant}/devices/{id}", get(tenant_device))
            .route("/internal/v1/tenants/{tenant}/devices/{id}/assurance", post(assurance))
            .route("/internal/v1/devices/{id}/enrolled", post(enrolled))
            .route("/v1/devices/{id}/release", post(release))
            .route("/crl/device-ca.crl", get(crl))
            .with_state(ctx);
        let listener = net::bind(host, 0).await?;
        let addr = listener.local_addr()?;
        net::serve_http(listener, router);
        Ok(Self { addr, token, devices, lookups, crl: crl_store })
    }

    /// Base URL.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Register a device at manufacture time (state `manufactured`).
    pub fn register(&self, device_id: &str, rec: DeviceRecord) {
        if let Ok(mut d) = self.devices.lock() {
            d.insert(device_id.to_owned(), rec);
        }
    }

    /// Record an issued certificate exactly like `POST /internal/v1/devices/{id}/enrolled` (the
    /// in-process EST server calls this; the real PKI calls the HTTP route).
    ///
    /// # Errors
    /// The refusal the route would answer.
    pub fn record_enrollment(&self, device_id: &str, e: &Enrolled) -> std::result::Result<serde_json::Value, Refused> {
        apply_enrolled(&self.devices, device_id, e)
    }

    /// Change the lifecycle state.
    pub fn set_state(&self, device_id: &str, state: &str) {
        if let Ok(mut d) = self.devices.lock() {
            if let Some(r) = d.get_mut(device_id) {
                r.state = state.to_owned();
            }
        }
    }

    /// The record of a device.
    #[must_use]
    pub fn get(&self, device_id: &str) -> Option<DeviceRecord> {
        self.devices.lock().ok().and_then(|d| d.get(device_id).cloned())
    }

    /// How many lifecycle lookups the policy service made for `device_id`.
    #[must_use]
    pub fn lookups(&self, device_id: &str) -> usize {
        self.lookups.lock().map(|l| l.iter().filter(|d| *d == device_id).count()).unwrap_or(0)
    }

    /// Publish a new CRL.
    pub fn set_crl(&self, der: Vec<u8>) {
        if let Ok(mut c) = self.crl.lock() {
            *c = der;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrolled_body(serial: &str) -> Enrolled {
        Enrolled {
            serial_hex: serial.into(),
            not_before: "2026-11-10T00:00:00Z".into(),
            not_after: "2026-11-24T00:00:00Z".into(),
            se_type: "software".into(),
            assurance_level: "software".into(),
            fw_version: None,
            fw_hash_hex: None,
        }
    }

    #[tokio::test]
    async fn enrolled_and_release_follow_the_contract() {
        let reg = FakeRegistry::start("127.0.0.1", "tok".into()).await.unwrap();
        let rec = DeviceRecord { tenant_id: "t".into(), state: MANUFACTURED.into(), se_type: "software".into(), ..DeviceRecord::default() };
        reg.register("dev-0011223344556677", rec);
        let auth = [("authorization", "Bearer tok".to_string()), ("content-type", "application/json".to_string())];
        let post = |path: String, body: Vec<u8>| {
            let url = format!("{}{path}", reg.url());
            let auth = auth.clone();
            async move { net::http_request("POST", &url, &auth, body, None, std::time::Duration::from_secs(5)).await.unwrap() }
        };
        let path = "/internal/v1/devices/dev-0011223344556677/enrolled".to_string();
        // Invalid body -> 422; unknown device -> 404; unauthenticated -> 401.
        assert_eq!(post(path.clone(), br#"{"serial_hex":"xyz"}"#.to_vec()).await.status, 422);
        let ok = serde_json::to_vec(&enrolled_body("0A:1B")).unwrap();
        assert_eq!(post("/internal/v1/devices/dev-ffffffffffffffff/enrolled".into(), ok.clone()).await.status, 404);
        let r = net::http_request("POST", &format!("{}{path}", reg.url()), &[], ok.clone(), None, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(r.status, 401);
        // Recorded: manufactured -> active, serial normalised.
        let r = post(path.clone(), ok.clone()).await;
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(r.json().unwrap()["cert"]["serial_hex"], "a1b");
        assert_eq!(reg.get("dev-0011223344556677").unwrap().state, ACTIVE);
        // Release of a device that is not quarantined -> 409.
        let rel = "/v1/devices/dev-0011223344556677/release".to_string();
        assert_eq!(post(rel.clone(), br#"{"note":"x"}"#.to_vec()).await.status, 409);
        // Quarantined: enrollment refused (409), release -> active, enrollment accepted again.
        reg.set_state("dev-0011223344556677", QUARANTINED);
        assert_eq!(post(path.clone(), ok.clone()).await.status, 409);
        let r = post(rel, br#"{"note":"cleared"}"#.to_vec()).await;
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(r.json().unwrap()["state"], ACTIVE);
        assert_eq!(post(path, serde_json::to_vec(&enrolled_body("0c")).unwrap()).await.status, 200);
        assert_eq!(reg.get("dev-0011223344556677").unwrap().certificates.len(), 2);
    }
}
