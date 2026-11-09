//! Registry double: the internal lifecycle endpoints the real policy service (and the real PKI)
//! call, plus the PKI plain-listener CRL distribution point the policy service polls as its
//! fallback revocation path.

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

/// A device record (manufacture record + lifecycle).
#[derive(Debug, Clone)]
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

async fn enrolled(State(ctx): State<Ctx>, Path(id): Path<String>, h: HeaderMap) -> Response {
    if !authorized(&ctx, &h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Ok(mut d) = ctx.devices.lock() {
        if let Some(r) = d.get_mut(&id) {
            r.state = ACTIVE.into();
        }
    }
    StatusCode::NO_CONTENT.into_response()
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
