//! In-test IronMesh backend doubles: a test PKI (rcgen), an EST server (axum over rustls with
//! mandatory client auth and the attestation extension), an HTTPS artifact store with `Range`
//! support, and a minimal MQTT 5 broker (rustls, ACLs per the contract topic table, message
//! injection, optional TLS 1.2-only mode).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};

use ironmesh_agent::agent::{Agent, AgentEvent, AgentOptions, RebootReason};
use ironmesh_agent::app;
use ironmesh_agent::enroll::Credentials;
use ironmesh_agent::est::bundle::{sign_bundle, TrustBundle};
use ironmesh_agent::est::pkcs7;
use ironmesh_agent::identity::software::{SecretSource, SoftwareIdentity};
use ironmesh_agent::identity::{IdentityProvider, KeySlot, SharedIdentity};
use ironmesh_agent::mqtt::codec::{self, ConnAck, Packet, PropValue, Properties, PubAck, Publish, SubAck};
use ironmesh_agent::seq::Clock;
use ironmesh_agent::settings::Settings;
use ironmesh_agent::wire::attestation::{verify_attestation, VerifyAttestation};
use ironmesh_agent::wire::cbor::DecodeLimits;
use ironmesh_agent::wire::cose::{self, Kid};
use ironmesh_agent::wire::envelope::{self, Body, Message};
use ironmesh_agent::wire::ids::{self, TopicClass};
use ironmesh_agent::wire::keys::PublicKey;
use ironmesh_agent::x509;

pub const TENANT: &str = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";
pub const DEVICE: &str = "dev-8f3a1c2b9d4e5f60";

pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------------------------
// PKI
// ---------------------------------------------------------------------------------------------

pub struct Ca {
    pub params: CertificateParams,
    pub key: KeyPair,
    pub der: Vec<u8>,
}

impl Ca {
    pub fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key)
    }

    pub fn pin(&self) -> [u8; 32] {
        x509::parse_cert(&self.der).unwrap().spki_sha256
    }
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.distinguished_name.push(DnType::OrganizationName, "IronMesh");
    p.distinguished_name.push(DnType::CommonName, cn);
    p
}

fn self_signed_ca(cn: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(cn);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    Ca { params, key, der }
}

fn sub_ca(cn: &str, parent: &Ca) -> Ca {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(cn);
    let der = params.signed_by(&key, &parent.issuer()).unwrap().der().to_vec();
    Ca { params, key, der }
}

pub struct Leaf {
    pub der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl Leaf {
    pub fn chain(&self, ca: &Ca) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.der.clone()), CertificateDer::from(ca.der.clone())]
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }
}

fn server_leaf(ca: &Ca, host: &str) -> Leaf {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![host.to_owned(), "127.0.0.1".to_owned()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, host);
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let der = p.signed_by(&key, &ca.issuer()).unwrap().der().to_vec();
    Leaf { der, key_der: key.serialize_der() }
}

pub struct TestPki {
    pub root: Ca,
    pub services: Ca,
    pub device: Ca,
    pub factory: Ca,
    pub rogue: Ca,
    pub broker: Leaf,
    pub est: Leaf,
    pub artifacts: Leaf,
    pub rogue_broker: Leaf,
    pub bundle_key: ed25519_dalek::SigningKey,
    pub tenant_key: ed25519_dalek::SigningKey,
    pub fw_key: ed25519_dalek::SigningKey,
    pub untrusted_fw_key: ed25519_dalek::SigningKey,
}

impl TestPki {
    pub fn new() -> Self {
        install_crypto();
        let root = self_signed_ca("IronMesh Test Root CA");
        let services = sub_ca("IronMesh Test Services CA", &root);
        let device = sub_ca("IronMesh Test Device CA", &root);
        let factory = sub_ca("IronMesh Test Factory CA", &root);
        let rogue = self_signed_ca("IronMesh Test Services CA");
        Self {
            broker: server_leaf(&services, "localhost"),
            est: server_leaf(&services, "localhost"),
            artifacts: server_leaf(&services, "localhost"),
            rogue_broker: server_leaf(&rogue, "localhost"),
            root,
            services,
            device,
            factory,
            rogue,
            bundle_key: ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
            tenant_key: ed25519_dalek::SigningKey::from_bytes(&[12; 32]),
            fw_key: ed25519_dalek::SigningKey::from_bytes(&[13; 32]),
            untrusted_fw_key: ed25519_dalek::SigningKey::from_bytes(&[14; 32]),
        }
    }

    /// Root + Services CA (the factory trust anchors).
    pub fn anchors_pem(&self) -> String {
        [self.root.der.as_slice(), self.services.der.as_slice()].iter().map(|d| x509::to_pem("CERTIFICATE", d)).collect()
    }

    pub fn bootstrap_cert(&self, public_key: &p256::PublicKey) -> Vec<u8> {
        self.bootstrap_cert_for(DEVICE, public_key)
    }

    pub fn bootstrap_cert_for(&self, device: &str, public_key: &p256::PublicKey) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        let spki = rcgen::SubjectPublicKeyInfo::from_der(public_key.to_public_key_der().unwrap().as_bytes()).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, device);
        p.distinguished_name.push(DnType::OrganizationalUnitName, format!("bootstrap:{TENANT}"));
        p.distinguished_name.push(DnType::OrganizationName, "IronMesh");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.serial_number = Some(SerialNumber::from_slice(&rand_bytes(16)));
        p.signed_by(&spki, &self.factory.issuer()).unwrap().der().to_vec()
    }
}

pub fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v[0] &= 0x7f;
    v[0] |= 0x01;
    v
}

fn roots(cas: &[&Ca]) -> Arc<rustls::RootCertStore> {
    let mut r = rustls::RootCertStore::empty();
    for c in cas {
        r.add(CertificateDer::from(c.der.clone())).unwrap();
    }
    Arc::new(r)
}

fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: Option<Arc<rustls::RootCertStore>>,
    tls12_only: bool,
    alpn: &[&[u8]],
) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls12_only { &[&rustls::version::TLS12] } else { &[&rustls::version::TLS13, &rustls::version::TLS12] };
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).unwrap();
    let builder = match client_roots {
        Some(r) => {
            builder.with_client_cert_verifier(rustls::server::WebPkiClientVerifier::builder_with_provider(r, provider).build().unwrap())
        }
        None => builder.with_no_client_auth(),
    };
    let mut cfg = builder.with_single_cert(chain, key).unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

// ---------------------------------------------------------------------------------------------
// HTTPS servers (EST + artifacts)
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct PeerCert(Option<Vec<u8>>);

async fn serve_https(cfg: Arc<rustls::ServerConfig>, router: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let peer = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec());
                let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(PeerCert(peer.clone()));
                    tower::ServiceExt::oneshot(router.clone(), req)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
            });
        }
    });
    addr
}

#[derive(Default)]
pub struct EstState {
    pub nonces: HashSet<Vec<u8>>,
    pub enrollments: Vec<(bool, String, String)>, // (reenroll, se_type, serial)
    pub refuse_status: Option<u16>,
    pub lifetime_s: u64,
    pub bundle: Vec<u8>,
    pub cacerts: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct EstCtx {
    pki: Arc<TestPki>,
    state: Arc<Mutex<EstState>>,
}

pub struct EstServer {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<EstState>>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

async fn est_cacerts(State(ctx): State<EstCtx>) -> Response {
    let certs = ctx.state.lock().unwrap().cacerts.clone();
    let body = b64().encode(pkcs7::encode_certs_only(&certs));
    ([("content-type", "application/pkcs7-mime; smime-type=certs-only"), ("content-transfer-encoding", "base64")], body).into_response()
}

async fn est_nonce(State(ctx): State<EstCtx>, Extension(peer): Extension<PeerCert>) -> Response {
    if peer.0.is_none() {
        return (StatusCode::UNAUTHORIZED, "client certificate required").into_response();
    }
    let n = rand_bytes(32);
    ctx.state.lock().unwrap().nonces.insert(n.clone());
    let body =
        serde_json::json!({"nonce": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n), "expires_at": "2099-01-01T00:00:00Z"});
    ([("content-type", "application/json")], body.to_string()).into_response()
}

fn enroll_impl(ctx: &EstCtx, peer: &PeerCert, headers: &HeaderMap, body: &[u8], reenroll: bool) -> Result<Response, (StatusCode, String)> {
    let bad = |s: StatusCode, m: &str| (s, m.to_owned());
    if let Some(code) = ctx.state.lock().unwrap().refuse_status {
        return Err(bad(StatusCode::from_u16(code).unwrap(), "device lifecycle state \"quarantined\" does not permit enrollment"));
    }
    let peer_der = peer.0.clone().ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "no client cert"))?;
    let peer_info = x509::parse_cert(&peer_der).map_err(|e| bad(StatusCode::UNAUTHORIZED, &e.to_string()))?;
    let expected_issuer = if reenroll { &ctx.pki.device } else { &ctx.pki.factory };
    if peer_info.issuer_der != x509::parse_cert(&expected_issuer.der).unwrap().subject_der {
        return Err(bad(StatusCode::FORBIDDEN, "wrong issuer for this operation"));
    }
    let att_b64 = headers.get("x-ironmesh-attestation").ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "attestation required"))?;
    let att = b64().decode(att_b64.as_bytes()).map_err(|_| bad(StatusCode::BAD_REQUEST, "attestation base64"))?;
    let csr = ironmesh_agent::est::decode_b64_body(body).map_err(|_| bad(StatusCode::BAD_REQUEST, "csr base64"))?;
    // Find the nonce (unverified) and consume it.
    let signed = cose::sign1_decode(&att, DecodeLimits::default()).map_err(|e| bad(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let msg =
        envelope::decode_payload(&signed.payload, DecodeLimits::default()).map_err(|e| bad(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let Body::Attestation(a) = &msg.body else { return Err(bad(StatusCode::BAD_REQUEST, "not an attestation")) };
    if !ctx.state.lock().unwrap().nonces.remove(a.nonce.as_slice()) {
        return Err(bad(StatusCode::UNAUTHORIZED, "nonce is unknown or has already been used"));
    }
    let pk = PublicKey::P256(p256::ecdsa::VerifyingKey::from(peer_info.p256.unwrap()));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    verify_attestation(
        &att,
        &VerifyAttestation {
            identity_public_key: &pk,
            expected_nonce: &a.nonce,
            csr_der: &csr,
            now,
            expected_kid: Some(&peer_info.kid),
            allowed_se_types: None,
        },
    )
    .map_err(|e| bad(StatusCode::FORBIDDEN, &e.to_string()))?;
    let (cn, ou, csr_pk) = x509::inspect_csr(&csr).map_err(|e| bad(StatusCode::BAD_REQUEST, &e.to_string()))?;
    if cn.as_deref() != peer_info.subject_cn.as_deref() || ou != vec![TENANT.to_string()] {
        return Err(bad(StatusCode::FORBIDDEN, "CSR subject mismatch"));
    }
    if Some(csr_pk) == peer_info.p256 {
        return Err(bad(StatusCode::BAD_REQUEST, "CSR must use a fresh key"));
    }
    let mut params =
        rcgen::CertificateSigningRequestParams::from_der(&csr.clone().into()).map_err(|e| bad(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let lifetime = ctx.state.lock().unwrap().lifetime_s;
    let nb = time::OffsetDateTime::now_utc() - time::Duration::seconds(5);
    params.params.not_before = nb;
    params.params.not_after = nb + time::Duration::seconds(lifetime as i64);
    params.params.serial_number = Some(SerialNumber::from_slice(&rand_bytes(16)));
    params.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.params.distinguished_name = rcgen::DistinguishedName::new();
    let device = cn.clone().unwrap_or_default();
    params.params.distinguished_name.push(DnType::CommonName, device.clone());
    params.params.distinguished_name.push(DnType::OrganizationalUnitName, TENANT);
    params.params.distinguished_name.push(DnType::OrganizationName, "IronMesh");
    params.params.subject_alt_names = vec![SanType::URI(x509::device_urn(TENANT, &device).try_into().unwrap())];
    let cert = params.signed_by(&ctx.pki.device.issuer()).map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let der = cert.der().to_vec();
    let serial = x509::parse_cert(&der).unwrap().serial_hex();
    let bundle = {
        let mut st = ctx.state.lock().unwrap();
        st.enrollments.push((reenroll, a.se_type.as_str().into(), serial));
        st.bundle.clone()
    };
    let body = b64().encode(pkcs7::encode_certs_only(&[der]));
    let mut resp = ([("content-type", "application/pkcs7-mime; smime-type=certs-only"), ("content-transfer-encoding", "base64")], body)
        .into_response();
    resp.headers_mut().insert("x-ironmesh-bundle", b64().encode(bundle).parse().unwrap());
    Ok(resp)
}

async fn est_enroll(
    State(ctx): State<EstCtx>,
    Extension(peer): Extension<PeerCert>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    enroll_impl(&ctx, &peer, &headers, &body, false).unwrap_or_else(|e| e.into_response())
}

async fn est_reenroll(
    State(ctx): State<EstCtx>,
    Extension(peer): Extension<PeerCert>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    enroll_impl(&ctx, &peer, &headers, &body, true).unwrap_or_else(|e| e.into_response())
}

impl EstServer {
    pub async fn start(pki: Arc<TestPki>, bundle: TrustBundle, lifetime_s: u64) -> Self {
        let state = Arc::new(Mutex::new(EstState {
            lifetime_s,
            bundle: sign_bundle(&bundle, &pki.bundle_key).unwrap(),
            cacerts: vec![pki.root.der.clone(), pki.services.der.clone(), pki.device.der.clone(), pki.factory.der.clone()],
            ..Default::default()
        }));
        let ctx = EstCtx { pki: pki.clone(), state: state.clone() };
        let router = Router::new()
            .route("/.well-known/est/cacerts", get(est_cacerts))
            .route("/.well-known/est/ironmesh/nonce", get(est_nonce))
            .route("/.well-known/est/simpleenroll", post(est_enroll))
            .route("/.well-known/est/simplereenroll", post(est_reenroll))
            .with_state(ctx);
        let cfg =
            server_config(pki.est.chain(&pki.services), pki.est.key(), Some(roots(&[&pki.root, &pki.factory, &pki.device])), false, &[]);
        let addr = serve_https(cfg, router).await;
        Self { addr, state }
    }
}

#[derive(Clone, Default)]
pub struct Artifacts(pub Arc<Mutex<HashMap<String, Vec<u8>>>>);

async fn artifact(State(store): State<Artifacts>, AxPath(name): AxPath<String>, headers: HeaderMap) -> Response {
    let Some(data) = store.0.lock().unwrap().get(&name).cloned() else { return StatusCode::NOT_FOUND.into_response() };
    if let Some(r) = headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
        .and_then(|v| v.strip_suffix('-'))
        .and_then(|v| v.parse::<usize>().ok())
    {
        let start = r.min(data.len());
        return (StatusCode::PARTIAL_CONTENT, data[start..].to_vec()).into_response();
    }
    (StatusCode::OK, data).into_response()
}

pub async fn start_artifacts(pki: &TestPki) -> (SocketAddr, Artifacts) {
    let store = Artifacts::default();
    let router = Router::new().route("/fw/{name}", get(artifact)).with_state(store.clone());
    let cfg = server_config(pki.artifacts.chain(&pki.services), pki.artifacts.key(), None, false, &[]);
    (serve_https(cfg, router).await, store)
}

// ---------------------------------------------------------------------------------------------
// MQTT broker double
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
pub struct BrokerState {
    pub connects: Vec<(String, bool)>,
    pub publishes: Vec<Publish>,
    pub denied: Vec<String>,
    pub subscriptions: HashMap<String, Vec<String>>,
    pub conns: HashMap<String, mpsc::UnboundedSender<Packet>>,
    pub acks: Vec<(u16, u8)>,
    pub sessions: HashSet<String>,
    pub drop_telemetry_acks: bool,
    pub handshakes: usize,
}

pub struct Broker {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<BrokerState>>,
    pub published: broadcast::Sender<Publish>,
}

async fn read_packet<S: tokio::io::AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<Packet> {
    let mut chunk = [0u8; 4096];
    loop {
        match codec::decode(buf, 1 << 20) {
            Ok(Some((p, n))) => {
                buf.drain(..n);
                return Some(p);
            }
            Ok(None) => {}
            Err(_) => return None,
        }
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn may_publish(topic: &str, device: &str, retain: bool) -> bool {
    matches!(ids::parse_topic(topic), Ok(t) if t.device_id == device && t.class.direction() == ids::Direction::Uplink && (!retain || t.class.retained_allowed()))
}

fn may_subscribe(filter: &str, device: &str) -> bool {
    matches!(ids::parse_topic(filter), Ok(t) if t.device_id == device && t.class.direction() == ids::Direction::Downlink)
}

impl Broker {
    pub async fn start(pki: &TestPki, rogue: bool, tls12_only: bool) -> Self {
        let (leaf, ca) = if rogue { (&pki.rogue_broker, &pki.rogue) } else { (&pki.broker, &pki.services) };
        let cfg = server_config(leaf.chain(ca), leaf.key(), Some(roots(&[&pki.root, &pki.device])), tls12_only, &[b"mqtt"]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(BrokerState::default()));
        let (published, _) = broadcast::channel(1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
        let st = state.clone();
        let pubs = published.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let st = st.clone();
                let pubs = pubs.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    st.lock().unwrap().handshakes += 1;
                    let cn = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .and_then(|c| x509::parse_cert(c).ok())
                        .and_then(|i| i.subject_cn);
                    handle_conn(tls, cn, st, pubs).await;
                });
            }
        });
        Self { addr, state, published }
    }

    /// Send a QoS 1 PUBLISH to a connected client.
    pub fn inject(&self, client_id: &str, topic: &str, payload: Vec<u8>, retain: bool) -> bool {
        let tx = self.state.lock().unwrap().conns.get(client_id).cloned();
        tx.is_some_and(|tx| {
            tx.send(Packet::Publish(Publish {
                dup: false,
                qos: 1,
                retain,
                topic: topic.into(),
                packet_id: Some(rand::random::<u16>().max(1)),
                properties: Properties::new(),
                payload,
            }))
            .is_ok()
        })
    }

    pub fn kick(&self, client_id: &str) {
        if let Some(tx) = self.state.lock().unwrap().conns.get(client_id) {
            let _ = tx.send(Packet::Disconnect(codec::Disconnect { reason_code: 0x8e, properties: Properties::new() }));
        }
    }

    pub fn published_on(&self, suffix: &str) -> Vec<Publish> {
        self.state.lock().unwrap().publishes.iter().filter(|p| p.topic.ends_with(suffix)).cloned().collect()
    }
}

async fn handle_conn(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    cn: Option<String>,
    st: Arc<Mutex<BrokerState>>,
    pubs: broadcast::Sender<Publish>,
) {
    let (mut rd, mut wr) = tokio::io::split(tls);
    let mut buf = Vec::new();
    let Some(Packet::Connect(c)) = read_packet(&mut rd, &mut buf).await else { return };
    let client_id = c.client_id.clone();
    if cn.as_deref() != Some(client_id.as_str()) {
        let _ = wr
            .write_all(
                &Packet::ConnAck(ConnAck { session_present: false, reason_code: 0x85, properties: Properties::new() }).encode().unwrap(),
            )
            .await;
        return;
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<Packet>();
    let session_present = {
        let mut s = st.lock().unwrap();
        s.connects.push((client_id.clone(), c.clean_start));
        let present = !c.clean_start && s.sessions.contains(&client_id);
        s.sessions.insert(client_id.clone());
        s.conns.insert(client_id.clone(), tx.clone());
        present
    };
    let ack =
        ConnAck { session_present, reason_code: 0, properties: Properties::new().with(codec::prop::RECEIVE_MAXIMUM, PropValue::U16(32)) };
    if wr.write_all(&Packet::ConnAck(ack).encode().unwrap()).await.is_err() {
        return;
    }
    let writer = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            let disconnect = matches!(p, Packet::Disconnect(_));
            if wr.write_all(&p.encode().unwrap()).await.is_err() || disconnect {
                let _ = wr.shutdown().await;
                break;
            }
        }
    });
    while let Some(p) = read_packet(&mut rd, &mut buf).await {
        match p {
            Packet::Publish(p) => {
                let allowed = may_publish(&p.topic, &client_id, p.retain);
                let drop_ack = st.lock().unwrap().drop_telemetry_acks && p.topic.ends_with("/telemetry");
                if allowed {
                    st.lock().unwrap().publishes.push(p.clone());
                    let _ = pubs.send(p.clone());
                } else {
                    st.lock().unwrap().denied.push(p.topic.clone());
                }
                if let (Some(id), false) = (p.packet_id, drop_ack && allowed) {
                    let _ = tx.send(Packet::PubAck(PubAck {
                        packet_id: id,
                        reason_code: if allowed { 0 } else { 0x87 },
                        properties: Properties::new(),
                    }));
                }
            }
            Packet::Subscribe(s) => {
                let codes = s
                    .filters
                    .iter()
                    .map(|(f, _)| {
                        if may_subscribe(f, &client_id) {
                            st.lock().unwrap().subscriptions.entry(client_id.clone()).or_default().push(f.clone());
                            1
                        } else {
                            0x87
                        }
                    })
                    .collect();
                let _ = tx.send(Packet::SubAck(SubAck { packet_id: s.packet_id, properties: Properties::new(), reason_codes: codes }));
            }
            Packet::PubAck(a) => st.lock().unwrap().acks.push((a.packet_id, a.reason_code)),
            Packet::PingReq => {
                let _ = tx.send(Packet::PingResp);
            }
            Packet::Disconnect(_) => break,
            _ => break,
        }
    }
    {
        let mut s = st.lock().unwrap();
        if s.conns.get(&client_id).is_some_and(|c| c.same_channel(&tx)) {
            s.conns.remove(&client_id);
        }
    }
    drop(tx);
    writer.abort();
}

// ---------------------------------------------------------------------------------------------
// Device under test
// ---------------------------------------------------------------------------------------------

pub struct Env {
    pub pki: Arc<TestPki>,
    pub est: EstServer,
    pub broker: Broker,
    pub artifacts: (SocketAddr, Artifacts),
    pub dir: tempfile::TempDir,
    pub settings: Settings,
    pub events: broadcast::Sender<AgentEvent>,
    pub clock: Arc<Clock>,
}

pub fn bundle_for(pki: &TestPki, broker: SocketAddr) -> TrustBundle {
    TrustBundle {
        tenant_cmd_pubkey: Some(pki.tenant_key.verifying_key().to_bytes()),
        fw_signing_pubkeys: vec![pki.fw_key.verifying_key().to_bytes().to_vec()],
        broker_host: "127.0.0.1".into(),
        broker_port: broker.port(),
        ca_pins: vec![pki.services.pin()],
    }
}

impl Env {
    pub async fn new(lifetime_s: u64) -> Self {
        let pki = Arc::new(TestPki::new());
        let broker = Broker::start(&pki, false, false).await;
        let est = EstServer::start(pki.clone(), bundle_for(&pki, broker.addr), lifetime_s).await;
        let artifacts = start_artifacts(&pki).await;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("ca-bundle.pem"), pki.anchors_pem()).unwrap();
        let mut s = Settings::default();
        s.rebase(root);
        s.pki.est_host = "127.0.0.1".into();
        s.pki.est_port = est.addr.port();
        s.pki.ca_bundle = root.join("ca-bundle.pem");
        s.pki.est_pins = vec![hex::encode(pki.services.pin())];
        s.pki.bundle_pubkey = hex::encode(pki.bundle_key.verifying_key().to_bytes());
        s.pki.timeout_s = 10;
        s.telemetry.interval_s = 0;
        s.mqtt.backoff_scale = 0.01;
        s.mqtt.ack_timeout_s = 5;
        s.agent.fw_version = "1.0.0".into();
        s.agent.fw_version_code = 100;
        s.ota.product = "gateway-rpi".into();
        s.ota.reboot_command = Vec::new();
        s.telemetry.fw_image = Some(root.join("factory-image.bin"));
        std::fs::write(root.join("factory-image.bin"), factory_image()).unwrap();
        // Factory provisioning: software identity + bootstrap certificate from the Factory CA.
        let id = SoftwareIdentity::create(&s.identity.dir, DEVICE, TENANT, &SecretSource::File(s.identity.machine_secret.clone())).unwrap();
        let pk = id.generate_bootstrap_key().unwrap();
        let shared: SharedIdentity = Arc::new(id);
        Credentials::install_bootstrap(&s.identity.dir, &shared, pki.bootstrap_cert(&pk).as_slice()).unwrap();
        let (events, _) = broadcast::channel(4096);
        Self { pki, est, broker, artifacts, dir, settings: s, events, clock: Arc::new(Clock::new()) }
    }

    pub fn identity(&self) -> SharedIdentity {
        app::open_identity(&self.settings).unwrap()
    }

    pub fn options(&self, reason: Option<RebootReason>, auto_connect: bool, net_up: bool) -> AgentOptions {
        app::agent_options(&self.settings, self.identity(), self.clock.clone(), self.events.clone(), reason, auto_connect, net_up, true)
    }

    pub async fn start(&self) -> (Agent, mpsc::UnboundedReceiver<RebootReason>) {
        Agent::start(self.options(None, false, true)).await.unwrap()
    }

    pub async fn restart(&self, agent: &Agent, reason: RebootReason) -> (Agent, mpsc::UnboundedReceiver<RebootReason>) {
        let (want, net) = (agent.wants_connection(), agent.net_is_up());
        agent.shutdown().await;
        Agent::start(self.options(Some(reason), want, net)).await.unwrap()
    }

    pub fn topic(&self, class: TopicClass) -> String {
        ids::build_topic(TENANT, DEVICE, class).unwrap()
    }

    /// Tenant-signed downlink envelope.
    pub fn downlink(&self, seq: u64, ts: u64, body: Body, nonce: Option<[u8; 16]>) -> Vec<u8> {
        let kid = Kid::Text(ids::tenant_kid(TENANT).unwrap());
        envelope::encode(&Message { seq, ts, body, nonce }, &self.pki.tenant_key, &kid).unwrap()
    }

    pub fn now(&self) -> u64 {
        self.clock.now_unix()
    }
}

pub fn factory_image() -> Vec<u8> {
    (0..20_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect()
}

/// Wait for an event by name (and optional predicate).
pub async fn wait_event(
    rx: &mut broadcast::Receiver<AgentEvent>,
    name: &str,
    timeout: Duration,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(e)) if e.name == name && pred(&e.data) => return e.data,
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(e)) => panic!("event channel: {e}"),
            Err(_) => panic!("timed out waiting for event {name}"),
        }
    }
}

pub async fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "condition not reached in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub fn operational_key(agent: &Agent) -> PublicKey {
    PublicKey::P256(p256::ecdsa::VerifyingKey::from(agent.credentials().operational.unwrap().p256.unwrap()))
}

pub fn write_file(p: &Path, data: &[u8]) {
    std::fs::write(p, data).unwrap();
}

pub fn _unused(_: &dyn IdentityProvider, _: KeySlot) {}
