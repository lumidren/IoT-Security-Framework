//! EST server (RFC 7030) with the IronMesh attestation extension (contract §3), mirroring the
//! checks of `services/pki/internal/est/handler.go`:
//!
//! 1. TLS client certificate: Factory CA for `simpleenroll`, Device CA for `simplereenroll`,
//!    valid now and not revoked.
//! 2. CSR: valid signature, CN = device id and OU = tenant of the client certificate, ECDSA
//!    P-256, a **fresh** key (not the identity key and never certified before), SAN URI matches.
//! 3. `X-IronMesh-Attestation`: nonce known, unused, unexpired and issued to this device
//!    (single use); envelope verified with the TLS client key (`verify_attestation`, kid = client
//!    serial, csr_hash binding).
//! 4. Tenant policy (`software` allowed) and the manufacture record (`se_type`, bootstrap serial).
//! 5. Lifecycle state from the registry in `manufactured | provisioned | active`, else 403.
//! 6. Issue (profile of contract §2, lifetime per device for C-ROT-2), return the certs-only
//!    PKCS#7 and the signed `X-IronMesh-Bundle`.
//!
//! Every attempt is recorded as an [`EnrollRecord`] so the cases can verify what the DUT sent.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::Engine;
use ironmesh_agent::est::bundle::{sign_bundle, TrustBundle};
use ironmesh_agent::est::pkcs7;
use ironmesh_agent::wire::attestation::{verify_attestation, VerifyAttestation};
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose::{self, Kid};
use ironmesh_agent::wire::envelope::{self, Body};
use ironmesh_agent::wire::keys::PublicKey;
use ironmesh_agent::wire::ErrorCode;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::net::{self, ClientAuth, PeerCert, Versions};
use super::pki::{self, DeviceCertSpec, TestPki};
use super::registry::FakeRegistry;
use crate::util;

/// Nonce lifetime (contract §3).
pub const NONCE_TTL: Duration = Duration::from_secs(120);
/// Default operational lifetime (contract §2: 14 d).
pub const DEFAULT_LIFETIME_S: u64 = 14 * 86_400;

/// What the attestation said.
#[derive(Debug, Clone)]
pub struct AttestationFacts {
    /// kid (hex) of the attestation envelope.
    pub kid_hex: String,
    /// Envelope seq.
    pub seq: u64,
    /// Envelope ts.
    pub ts: u64,
    /// se_type.
    pub se_type: String,
    /// fw_version.
    pub fw_version: String,
    /// fw_hash (hex).
    pub fw_hash_hex: String,
    /// The signature verified with the TLS client key.
    pub signature_ok: bool,
}

/// One enrollment attempt.
#[derive(Debug, Clone)]
pub struct EnrollRecord {
    /// When.
    pub at: Instant,
    /// Device id (client certificate CN).
    pub device_id: String,
    /// `simplereenroll`.
    pub reenroll: bool,
    /// Client certificate serial (hex).
    pub client_serial_hex: String,
    /// SHA-256 SPKI of the client certificate.
    pub client_spki_sha256: [u8; 32],
    /// CSR CN.
    pub csr_cn: Option<String>,
    /// CSR OUs.
    pub csr_ous: Vec<String>,
    /// SHA-256 SPKI of the CSR key.
    pub csr_spki_sha256: Option<[u8; 32]>,
    /// The CSR key had never been certified for this device.
    pub csr_key_fresh: bool,
    /// Attestation details.
    pub attestation: Option<AttestationFacts>,
    /// HTTP status returned.
    pub status: u16,
    /// Error text (non-200).
    pub error: Option<String>,
    /// Issued certificate.
    pub issued_der: Option<Vec<u8>>,
    /// Issued serial (hex).
    pub issued_serial_hex: Option<String>,
}

struct NonceEntry {
    device_id: String,
    expires: Instant,
}

#[derive(Default)]
struct EstState {
    nonces: HashMap<Vec<u8>, NonceEntry>,
    nonces_issued: usize,
    records: Vec<EnrollRecord>,
    certified: HashMap<String, Vec<[u8; 32]>>,
    lifetimes: HashMap<String, u64>,
    revoked: Vec<String>,
    issued: HashMap<String, Vec<u8>>,
}

/// Bundle content.
#[derive(Clone)]
pub struct BundleSpec {
    /// Tenant command key.
    pub tenant_cmd_pubkey: [u8; 32],
    /// Firmware signing keys.
    pub fw_signing_pubkeys: Vec<Vec<u8>>,
    /// Broker host.
    pub broker_host: String,
    /// Broker port.
    pub broker_port: u16,
}

#[derive(Clone)]
struct Ctx {
    pki: Arc<TestPki>,
    registry: Arc<FakeRegistry>,
    tenant_id: String,
    allow_software_keys: bool,
    bundle: BundleSpec,
    state: Arc<Mutex<EstState>>,
}

/// The running EST server.
pub struct EstServer {
    /// Listen address.
    pub addr: SocketAddr,
    state: Arc<Mutex<EstState>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn pkcs7_response(certs: &[Vec<u8>]) -> Response {
    let body = b64().encode(pkcs7::encode_certs_only(certs));
    (
        StatusCode::OK,
        [
            ("content-type", "application/pkcs7-mime; smime-type=certs-only"),
            ("content-transfer-encoding", "base64"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}

/// Which CA issued a client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Issuer {
    Factory,
    Device,
}

struct Client {
    der: Vec<u8>,
    facts: pki::CertFacts,
    issuer: Issuer,
    device_id: String,
}

fn identify(ctx: &Ctx, peer: &PeerCert) -> Result<Client, (StatusCode, String)> {
    let der = peer.0.clone().ok_or((StatusCode::UNAUTHORIZED, "a TLS client certificate is required".to_string()))?;
    let facts = pki::cert_facts(&der).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let issuer = if pki::issued_by(&der, &ctx.pki.factory) {
        Issuer::Factory
    } else if pki::issued_by(&der, &ctx.pki.device) {
        Issuer::Device
    } else {
        return Err((StatusCode::UNAUTHORIZED, "client certificate is not issued by the Factory or Device CA".into()));
    };
    let now = util::now_unix();
    if now < facts.not_before || now > facts.not_after {
        return Err((StatusCode::UNAUTHORIZED, "client certificate is not valid now".into()));
    }
    if lock(&ctx.state).revoked.contains(&facts.serial_hex) {
        return Err((StatusCode::UNAUTHORIZED, "client certificate is revoked".into()));
    }
    let device_id = facts.cn.clone().filter(|c| ironmesh_agent::wire::ids::is_device_id(c));
    let Some(device_id) = device_id else {
        return Err((StatusCode::FORBIDDEN, "client certificate CN is not a device id".into()));
    };
    let want_ou = match issuer {
        Issuer::Factory => format!("bootstrap:{}", ctx.tenant_id),
        Issuer::Device => ctx.tenant_id.clone(),
    };
    if !facts.ous.contains(&want_ou) {
        return Err((StatusCode::FORBIDDEN, "client certificate OU does not name this tenant".into()));
    }
    Ok(Client { der, facts, issuer, device_id })
}

async fn cacerts(State(ctx): State<Ctx>) -> Response {
    let p = &ctx.pki;
    pkcs7_response(&[p.root.der.clone(), p.factory.der.clone(), p.device.der.clone(), p.services.der.clone()])
}

async fn csrattrs() -> Response {
    // CsrAttrs ::= SEQUENCE OF AttrOrOID: ecPublicKey, prime256v1, ecdsa-with-SHA256.
    let der = hex::decode("301d06072a8648ce3d020106082a8648ce3d03010706082a8648ce3d040302").unwrap_or_default();
    (StatusCode::OK, [("content-type", "application/csrattrs"), ("content-transfer-encoding", "base64")], b64().encode(der)).into_response()
}

async fn nonce(State(ctx): State<Ctx>, Extension(peer): Extension<PeerCert>) -> Response {
    let client = match identify(&ctx, &peer) {
        Ok(c) => c,
        Err((s, m)) => return (s, m).into_response(),
    };
    let n = util::random_bytes(32);
    {
        let mut st = lock(&ctx.state);
        st.nonces.insert(n.clone(), NonceEntry { device_id: client.device_id.clone(), expires: Instant::now() + NONCE_TTL });
        st.nonces_issued += 1;
    }
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(NONCE_TTL.as_secs() as i64);
    let expires = expires.format(&time::format_description::well_known::Rfc3339).unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "application/json"), ("cache-control", "no-store")],
        json!({"nonce": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n), "expires_at": expires}).to_string(),
    )
        .into_response()
}

fn csr_signature_ok(csr: &[u8]) -> bool {
    use x509_parser::prelude::FromDer;
    x509_parser::certification_request::X509CertificationRequest::from_der(csr).is_ok_and(|(_, r)| r.verify_signature().is_ok())
}

fn csr_san_uris(csr: &[u8]) -> Vec<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::FromDer;
    let mut out = Vec::new();
    if let Ok((_, r)) = x509_parser::certification_request::X509CertificationRequest::from_der(csr) {
        if let Some(exts) = r.requested_extensions() {
            for e in exts {
                if let ParsedExtension::SubjectAlternativeName(san) = e {
                    for n in &san.general_names {
                        if let GeneralName::URI(u) = n {
                            out.push((*u).to_owned());
                        }
                    }
                }
            }
        }
    }
    out
}

fn att_status(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::AttCsrHash | ErrorCode::AttType | ErrorCode::AttEvidence => StatusCode::BAD_REQUEST,
        ErrorCode::AttSeType => StatusCode::FORBIDDEN,
        _ => StatusCode::UNAUTHORIZED,
    }
}

fn enroll_impl(
    ctx: &Ctx,
    peer: &PeerCert,
    headers: &HeaderMap,
    body: &[u8],
    reenroll: bool,
    rec: &mut EnrollRecord,
) -> Result<Response, (StatusCode, String)> {
    let client = identify(ctx, peer)?;
    rec.device_id = client.device_id.clone();
    rec.client_serial_hex = client.facts.serial_hex.clone();
    rec.client_spki_sha256 = client.facts.spki_sha256;
    match (reenroll, client.issuer) {
        (true, Issuer::Factory) => {
            return Err((
                StatusCode::FORBIDDEN,
                "simplereenroll requires the current operational certificate issued by the Device CA".into(),
            ))
        }
        (false, Issuer::Device) => {
            return Err((StatusCode::FORBIDDEN, "simpleenroll requires a bootstrap certificate issued by the Factory CA".into()))
        }
        _ => {}
    }
    let ct = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.to_ascii_lowercase().starts_with("application/pkcs10") {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/pkcs10".into()));
    }
    // 2. CSR
    let csr = ironmesh_agent::est::decode_b64_body(body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "request body is not valid base64".to_string()))?;
    if !csr_signature_ok(&csr) {
        return Err((StatusCode::BAD_REQUEST, "malformed PKCS#10 request or invalid CSR signature".into()));
    }
    let (cn, ous, csr_pk) = ironmesh_agent::x509::inspect_csr(&csr).map_err(|e| (StatusCode::BAD_REQUEST, format!("CSR: {e}")))?;
    rec.csr_cn = cn.clone();
    rec.csr_ous = ous.clone();
    use p256::pkcs8::EncodePublicKey;
    let csr_spki = csr_pk.to_public_key_der().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let csr_pin: [u8; 32] = Sha256::digest(csr_spki.as_bytes()).into();
    rec.csr_spki_sha256 = Some(csr_pin);
    if cn.as_deref() != Some(client.device_id.as_str()) {
        return Err((StatusCode::FORBIDDEN, "CSR subject CN does not match the client certificate device id".into()));
    }
    if ous != vec![ctx.tenant_id.clone()] {
        return Err((StatusCode::FORBIDDEN, "CSR subject OU must be the tenant id of the client certificate".into()));
    }
    if csr_pin == client.facts.spki_sha256 {
        return Err((StatusCode::BAD_REQUEST, "CSR must use a freshly generated key, not the current identity key".into()));
    }
    let fresh = !lock(&ctx.state).certified.get(&client.device_id).is_some_and(|v| v.contains(&csr_pin));
    rec.csr_key_fresh = fresh;
    if !fresh {
        return Err((StatusCode::BAD_REQUEST, "CSR public key was already certified for this device; generate a fresh key".into()));
    }
    let urn = ironmesh_agent::x509::device_urn(&ctx.tenant_id, &client.device_id);
    if csr_san_uris(&csr).iter().any(|u| *u != urn) {
        return Err((StatusCode::FORBIDDEN, "CSR SAN URI does not match the device identity".into()));
    }
    // 3. Attestation
    let att_b64 =
        headers.get("x-ironmesh-attestation").ok_or((StatusCode::UNAUTHORIZED, "X-IronMesh-Attestation header is required".to_string()))?;
    let att =
        b64().decode(att_b64.as_bytes()).map_err(|_| (StatusCode::BAD_REQUEST, "attestation header is not valid base64".to_string()))?;
    let signed = cose::sign1_decode(&att, DecodeLimits::default()).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let msg = envelope::decode_payload(&signed.payload, DecodeLimits::default()).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let Body::Attestation(a) = &msg.body else { return Err((StatusCode::BAD_REQUEST, "attestation must be a type-10 envelope".into())) };
    let kid_hex = match &signed.kid {
        Kid::Bytes(b) => hex::encode(b),
        Kid::Text(t) => t.clone(),
    };
    rec.attestation = Some(AttestationFacts {
        kid_hex,
        seq: msg.seq,
        ts: msg.ts,
        se_type: a.se_type.as_str().into(),
        fw_version: a.fw_version.clone(),
        fw_hash_hex: hex::encode(a.fw_hash),
        signature_ok: false,
    });
    {
        let mut st = lock(&ctx.state);
        match st.nonces.remove(a.nonce.as_slice()) {
            None => return Err((StatusCode::UNAUTHORIZED, "nonce is unknown or has already been used".into())),
            Some(n) if n.expires < Instant::now() => return Err((StatusCode::UNAUTHORIZED, "nonce has expired".into())),
            Some(n) if n.device_id != client.device_id => {
                return Err((StatusCode::UNAUTHORIZED, "nonce was issued to a different device".into()))
            }
            Some(_) => {}
        }
    }
    let client_info = ironmesh_agent::x509::parse_cert(&client.der).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let client_pk = client_info.p256.ok_or((StatusCode::UNAUTHORIZED, "client key must be P-256".to_string()))?;
    let pk = PublicKey::P256(p256::ecdsa::VerifyingKey::from(client_pk));
    verify_attestation(
        &att,
        &VerifyAttestation {
            identity_public_key: &pk,
            expected_nonce: &a.nonce,
            csr_der: &csr,
            now: util::now_unix(),
            expected_kid: Some(&client.facts.serial),
            allowed_se_types: None,
        },
    )
    .map_err(|e| (att_status(e.code()), format!("attestation: {} ({})", e.code().as_str(), e.detail())))?;
    if let Some(f) = rec.attestation.as_mut() {
        f.signature_ok = true;
    }
    // 4. Tenant policy + manufacture record
    if a.se_type.as_str() == "software" && !ctx.allow_software_keys {
        return Err((StatusCode::FORBIDDEN, "tenant policy does not allow software keys".into()));
    }
    let record = ctx.registry.get(&client.device_id).ok_or((StatusCode::FORBIDDEN, "device is not registered".to_string()))?;
    if record.tenant_id != ctx.tenant_id {
        return Err((StatusCode::FORBIDDEN, "device belongs to a different tenant".into()));
    }
    if !record.se_type.is_empty() && record.se_type != a.se_type.as_str() {
        return Err((
            StatusCode::FORBIDDEN,
            format!("attested se_type {:?} does not match the manufacture record ({:?})", a.se_type.as_str(), record.se_type),
        ));
    }
    if client.issuer == Issuer::Factory && !record.bootstrap_serial_hex.is_empty() && record.bootstrap_serial_hex != client.facts.serial_hex
    {
        return Err((StatusCode::FORBIDDEN, "bootstrap certificate serial does not match the manufacture record".into()));
    }
    // 5. Lifecycle
    if !matches!(record.state.as_str(), "manufactured" | "provisioned" | "active") {
        return Err((StatusCode::FORBIDDEN, format!("device lifecycle state {:?} does not permit enrollment", record.state)));
    }
    // 6. Issue
    let lifetime = lock(&ctx.state).lifetimes.get(&client.device_id).copied().unwrap_or(DEFAULT_LIFETIME_S);
    let spec = DeviceCertSpec {
        device_id: client.device_id.clone(),
        tenant_id: ctx.tenant_id.clone(),
        bootstrap: false,
        software: a.se_type.as_str() == "software",
        lifetime_s: lifetime,
    };
    let der = ctx.pki.issue_device_cert(&spec, csr_spki.as_bytes()).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let facts = pki::cert_facts(&der).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let bundle = sign_bundle(
        &TrustBundle {
            tenant_cmd_pubkey: Some(ctx.bundle.tenant_cmd_pubkey),
            fw_signing_pubkeys: ctx.bundle.fw_signing_pubkeys.clone(),
            broker_host: ctx.bundle.broker_host.clone(),
            broker_port: ctx.bundle.broker_port,
            ca_pins: ctx.pki.bundle_pins(),
        },
        &ctx.pki.bundle_key,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    {
        let mut st = lock(&ctx.state);
        let e = st.certified.entry(client.device_id.clone()).or_default();
        e.push(client.facts.spki_sha256);
        e.push(csr_pin);
        st.issued.insert(facts.serial_hex.clone(), der.clone());
    }
    // The PKI's synchronous `POST /internal/v1/devices/{id}/enrolled` (API_CONTRACT §1.12); a
    // refusal fails the enrollment with 503 like the real PKI (which also revokes the certificate).
    let ts = |t: u64| {
        time::OffsetDateTime::from_unix_timestamp(t as i64)
            .ok()
            .and_then(|d| d.format(&time::format_description::well_known::Rfc3339).ok())
            .unwrap_or_default()
    };
    let enrolled = super::registry::Enrolled {
        serial_hex: facts.serial_hex.clone(),
        not_before: ts(facts.not_before),
        not_after: ts(facts.not_after),
        se_type: a.se_type.as_str().to_owned(),
        assurance_level: if a.se_type.as_str() == "software" { "software" } else { "hardware" }.into(),
        fw_version: None,
        fw_hash_hex: None,
    };
    if let Err(r) = ctx.registry.record_enrollment(&client.device_id, &enrolled) {
        lock(&ctx.state).revoked.push(facts.serial_hex.clone());
        return Err((StatusCode::SERVICE_UNAVAILABLE, format!("the registry could not record the enrollment ({}: {})", r.0, r.1)));
    }
    rec.issued_der = Some(der.clone());
    rec.issued_serial_hex = Some(facts.serial_hex);
    let mut resp = pkcs7_response(&[der]);
    if let Ok(v) = b64().encode(bundle).parse() {
        resp.headers_mut().insert("x-ironmesh-bundle", v);
    }
    Ok(resp)
}

async fn enroll_route(ctx: Ctx, peer: PeerCert, headers: HeaderMap, body: axum::body::Bytes, reenroll: bool) -> Response {
    let mut rec = EnrollRecord {
        at: Instant::now(),
        device_id: String::new(),
        reenroll,
        client_serial_hex: String::new(),
        client_spki_sha256: [0; 32],
        csr_cn: None,
        csr_ous: Vec::new(),
        csr_spki_sha256: None,
        csr_key_fresh: false,
        attestation: None,
        status: 200,
        error: None,
        issued_der: None,
        issued_serial_hex: None,
    };
    let r = enroll_impl(&ctx, &peer, &headers, &body, reenroll, &mut rec);
    let resp = match r {
        Ok(resp) => resp,
        Err((s, m)) => {
            rec.status = s.as_u16();
            rec.error = Some(m.clone());
            (s, [("content-type", "text/plain; charset=utf-8")], m).into_response()
        }
    };
    lock(&ctx.state).records.push(rec);
    resp
}

async fn simpleenroll(
    State(ctx): State<Ctx>,
    Extension(peer): Extension<PeerCert>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    enroll_route(ctx, peer, headers, body, false).await
}

async fn simplereenroll(
    State(ctx): State<Ctx>,
    Extension(peer): Extension<PeerCert>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    enroll_route(ctx, peer, headers, body, true).await
}

impl EstServer {
    /// Start on `host:0`.
    ///
    /// # Errors
    /// Bind or TLS configuration failure.
    pub async fn start(
        host: &str,
        port: u16,
        pki: Arc<TestPki>,
        registry: Arc<FakeRegistry>,
        tenant_id: String,
        bundle: BundleSpec,
    ) -> Result<Self> {
        let state = Arc::new(Mutex::new(EstState::default()));
        let ctx = Ctx { pki: pki.clone(), registry, tenant_id, allow_software_keys: true, bundle, state: state.clone() };
        let router = Router::new()
            .route("/.well-known/est/cacerts", get(cacerts))
            .route("/.well-known/est/csrattrs", get(csrattrs))
            .route("/.well-known/est/ironmesh/nonce", get(nonce))
            .route("/.well-known/est/simpleenroll", post(simpleenroll))
            .route("/.well-known/est/simplereenroll", post(simplereenroll))
            .with_state(ctx);
        let client_roots = net::roots(&[&pki.root.der, &pki.factory.der, &pki.device.der])?;
        let cfg = net::server_config(pki.est.chain(&pki.services), pki.est.key(), ClientAuth::Optional(client_roots), Versions::Both, &[])?;
        let listener = net::bind(host, port).await?;
        let addr = listener.local_addr()?;
        net::serve_https(listener, cfg, router);
        Ok(Self { addr, state })
    }

    /// Operational lifetime for one device (C-ROT-2 short-lived certificates).
    pub fn set_lifetime(&self, device_id: &str, seconds: u64) {
        lock(&self.state).lifetimes.insert(device_id.to_owned(), seconds);
    }

    /// Mark a serial revoked (the EST server refuses it as a client certificate).
    pub fn revoke(&self, serial_hex: &str) {
        lock(&self.state).revoked.push(serial_hex.to_owned());
    }

    /// Whether `serial_hex` was revoked.
    #[must_use]
    pub fn is_revoked(&self, serial_hex: &str) -> bool {
        lock(&self.state).revoked.iter().any(|s| s == serial_hex)
    }

    /// Enrollment attempts of a device.
    #[must_use]
    pub fn records(&self, device_id: &str) -> Vec<EnrollRecord> {
        lock(&self.state).records.iter().filter(|r| r.device_id == device_id).cloned().collect()
    }

    /// Enrollment attempts by HTTP status (all devices).
    #[must_use]
    pub fn status_counts(&self) -> std::collections::BTreeMap<u16, u64> {
        let mut m = std::collections::BTreeMap::new();
        for r in &lock(&self.state).records {
            *m.entry(r.status).or_insert(0) += 1;
        }
        m
    }

    /// Certificate issued with `serial_hex`.
    #[must_use]
    pub fn issued(&self, serial_hex: &str) -> Option<Vec<u8>> {
        lock(&self.state).issued.get(serial_hex).cloned()
    }

    /// Nonces issued so far (all devices).
    #[must_use]
    pub fn nonces_issued(&self) -> usize {
        lock(&self.state).nonces_issued
    }
}
