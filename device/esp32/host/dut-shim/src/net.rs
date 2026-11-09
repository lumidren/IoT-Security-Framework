//! Transports for the shim.
//!
//! * [`SimLink`]: bytes go to the in-process [`crate::sim_cloud::SimBroker`].
//! * [`TlsLink`]: MQTT over TLS 1.3 only (rustls, `ring` provider), ALPN `mqtt`, client
//!   certificate = operational cert + identity key, server chain verified against the CA roots
//!   whose SPKI SHA-256 is pinned in the trust bundle (contract §4), hostname = broker SAN.
//! * [`est_enroll`]: RFC 7030 `simpleenroll`/`simplereenroll` with the IronMesh nonce and
//!   `X-IronMesh-Attestation` header (the attestation itself is built by the C core).
//!
//! These mirror `components/im_platform_esp/{mqtt_transport,est_client}.c`; they are compiled and
//! unit tested here but were not run against the live PKI/EMQX stack (no Docker on this host).

use crate::der;
use base64::Engine;
use im_host::err::*;
use im_host::ffi::*;
use im_host::SoftIdentity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Settings for running against a real IronMesh stack.
#[derive(Clone)]
pub struct RealConfig {
    pub est_host: String,
    pub est_port: u16,
    /// DER CA certificates (Services CA and/or root) used as trust anchors.
    pub ca_roots: Vec<Vec<u8>>,
    /// Bootstrap certificate (DER) issued by the Factory CA.
    pub bootstrap_cert: Vec<u8>,
    /// Bootstrap private scalar (the shim's stand-in for the ATECC slot 0 key).
    pub bootstrap_key: [u8; 32],
}

pub trait Link {
    fn send(&mut self, data: &[u8]) -> Result<(), String>;
    /// Non-blocking read; `Ok(None)` when nothing arrived.
    fn recv(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn close(&mut self);
    fn closed(&self) -> bool;
    fn is_sim(&self) -> bool {
        false
    }
    fn resumed(&self) -> bool {
        false
    }
    fn tls_version(&self) -> &'static str {
        "TLSv1.3"
    }
}

#[derive(Default)]
pub struct SimLink {
    closed: bool,
}

impl Link for SimLink {
    fn send(&mut self, _data: &[u8]) -> Result<(), String> {
        Ok(()) // routed to the simulated broker by the session callback
    }
    fn recv(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn close(&mut self) {
        self.closed = true;
    }
    fn closed(&self) -> bool {
        self.closed
    }
    fn is_sim(&self) -> bool {
        true
    }
}

/// Map a transport error string to the DUT `connect_failed.reason` vocabulary.
pub fn classify(err: &str) -> &'static str {
    if err.contains("tls_pin_mismatch") || err.contains("UnknownIssuer") || err.contains("pin") {
        "tls_pin_mismatch"
    } else if err.contains("timed out") || err.contains("timeout") {
        "timeout"
    } else if err.contains("BadCertificate") || err.contains("CertificateRevoked") || err.contains("cert_rejected") {
        "cert_rejected"
    } else if err.contains("tls") || err.contains("Alert") || err.contains("PeerIncompatible") || err.contains("alpn") {
        "tls_handshake"
    } else {
        "network"
    }
}

fn spki_hash(cert: &[u8]) -> Option<[u8; 32]> {
    der::parse_cert(cert).map(|c| Sha256::digest(&c.spki).into())
}

/// CA pins (key 5) from a stored trust bundle.
pub fn bundle_pins(bundle: &[u8]) -> Vec<[u8; 32]> {
    let mut s: im_sign1_t = unsafe { core::mem::zeroed() };
    if unsafe { im_cose_sign1_decode(bundle.as_ptr(), bundle.len(), core::ptr::null(), &mut s) } != IM_OK {
        return Vec::new();
    }
    let payload = unsafe { core::slice::from_raw_parts(s.payload, s.payload_len) };
    find_pins(payload).unwrap_or_default()
}

fn find_pins(payload: &[u8]) -> Option<Vec<[u8; 32]>> {
    // tiny CBOR walk: map, find key 5 -> array of bstr(32)
    let mut v = im_cbor_val_t::default();
    unsafe {
        if im_cbor_decode(payload.as_ptr(), payload.len(), core::ptr::null(), &mut v) != IM_OK || v.type_ != IM_CBOR_MAP {
            return None;
        }
    }
    let mut p = v.data;
    let end = unsafe { v.raw.add(v.raw_len) };
    for _ in 0..v.arg {
        let mut k = im_cbor_val_t::default();
        let mut val = im_cbor_val_t::default();
        unsafe {
            if im_cbor_parse(p, end, &mut k) != IM_OK {
                return None;
            }
            p = p.add(k.raw_len);
            if im_cbor_parse(p, end, &mut val) != IM_OK {
                return None;
            }
            p = p.add(val.raw_len);
        }
        if k.type_ == IM_CBOR_UINT && k.arg == 5 && val.type_ == IM_CBOR_ARRAY {
            let mut out = Vec::new();
            let mut q = val.data;
            let vend = unsafe { val.raw.add(val.raw_len) };
            for _ in 0..val.arg {
                let mut it = im_cbor_val_t::default();
                unsafe {
                    if im_cbor_parse(q, vend, &mut it) != IM_OK {
                        return None;
                    }
                    q = q.add(it.raw_len);
                }
                if it.type_ == IM_CBOR_BSTR && it.arg == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(unsafe { core::slice::from_raw_parts(it.data, 32) });
                    out.push(h);
                }
            }
            return Some(out);
        }
    }
    None
}

fn pkcs8(identity: &SoftIdentity) -> Result<PrivateKeyDer<'static>, String> {
    use p256::pkcs8::EncodePrivateKey;
    let der = identity.secret().to_pkcs8_der().map_err(|e| e.to_string())?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.as_bytes().to_vec())))
}

/// Client configs are cached per client certificate so session tickets survive reconnects.
static CONFIGS: Mutex<Vec<(Vec<u8>, Arc<rustls::ClientConfig>)>> = Mutex::new(Vec::new());

fn client_config(
    roots: &[Vec<u8>],
    cert: Option<Vec<u8>>,
    identity: &SoftIdentity,
    alpn: bool,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut key_material = Sha256::new();
    for r in roots {
        key_material.update(r);
    }
    if let Some(c) = &cert {
        key_material.update(c);
    }
    key_material.update(identity.public_raw());
    key_material.update([alpn as u8]);
    let id = key_material.finalize().to_vec();
    if let Some((_, c)) = CONFIGS.lock().unwrap().iter().find(|(k, _)| *k == id) {
        return Ok(c.clone());
    }
    let mut store = rustls::RootCertStore::empty();
    for r in roots {
        store.add(CertificateDer::from(r.clone())).map_err(|e| format!("ca: {e}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(store);
    let mut cfg = match cert {
        Some(c) => builder
            .with_client_auth_cert(vec![CertificateDer::from(c)], pkcs8(identity)?)
            .map_err(|e| e.to_string())?,
        None => builder.with_no_client_auth(),
    };
    if alpn {
        cfg.alpn_protocols = vec![b"mqtt".to_vec()];
    }
    let cfg = Arc::new(cfg);
    CONFIGS.lock().unwrap().push((id, cfg.clone()));
    Ok(cfg)
}

pub struct TlsLink {
    tcp: TcpStream,
    conn: rustls::ClientConnection,
    closed: bool,
    resumed: bool,
}

fn tcp_connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("network: {e}"))?
        .next()
        .ok_or("network: no address")?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| format!("network: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

fn handshake(conn: &mut rustls::ClientConnection, tcp: &mut TcpStream) -> Result<(), String> {
    while conn.is_handshaking() {
        conn.complete_io(tcp).map_err(|e| format!("tls: {e}"))?;
    }
    Ok(())
}

impl TlsLink {
    /// TLS 1.3 + pinned anchors + ALPN mqtt. No MQTT byte is written before the handshake
    /// (and therefore the pin check) has completed.
    pub fn connect(
        real: &RealConfig,
        host: &str,
        port: u16,
        pins: &[[u8; 32]],
        cert: Option<Vec<u8>>,
        identity: &SoftIdentity,
    ) -> Result<Self, String> {
        let anchors: Vec<Vec<u8>> = if pins.is_empty() {
            real.ca_roots.clone()
        } else {
            real.ca_roots
                .iter()
                .filter(|c| spki_hash(c).is_some_and(|h| pins.contains(&h)))
                .cloned()
                .collect()
        };
        if anchors.is_empty() {
            return Err("tls_pin_mismatch: no configured CA matches the bundle pins".into());
        }
        let cert = cert.or_else(|| Some(real.bootstrap_cert.clone()));
        let cfg = client_config(&anchors, cert, identity, true)?;
        let name = ServerName::try_from(host.to_string()).map_err(|e| format!("network: {e}"))?;
        let mut conn = rustls::ClientConnection::new(cfg, name).map_err(|e| format!("tls: {e}"))?;
        let mut tcp = tcp_connect(host, port)?;
        handshake(&mut conn, &mut tcp)?;
        if conn.alpn_protocol() != Some(b"mqtt") {
            return Err("tls: alpn mqtt not negotiated".into());
        }
        let resumed = matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
        tcp.set_nonblocking(true).map_err(|e| format!("network: {e}"))?;
        Ok(Self {
            tcp,
            conn,
            closed: false,
            resumed,
        })
    }
}

impl Link for TlsLink {
    fn send(&mut self, data: &[u8]) -> Result<(), String> {
        self.conn.writer().write_all(data).map_err(|e| e.to_string())?;
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.tcp) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>, String> {
        match self.conn.read_tls(&mut self.tcp) {
            Ok(0) => {
                self.closed = true;
                return Err("eof".into());
            }
            Ok(_) => {
                self.conn.process_new_packets().map_err(|e| e.to_string())?;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(if out.is_empty() { None } else { Some(out) })
    }

    fn close(&mut self) {
        self.conn.send_close_notify();
        let _ = self.conn.write_tls(&mut self.tcp);
        self.closed = true;
    }

    fn closed(&self) -> bool {
        self.closed
    }

    fn resumed(&self) -> bool {
        self.resumed
    }
}

// ---- HTTP/1.1 over TLS (EST, artifact download) ------------------------------------------------

struct Response {
    status: i32,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&b[..line_end]).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        b = &b[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

fn https(host: &str, port: u16, cfg: Arc<rustls::ClientConfig>, request: &[u8]) -> Result<Response, String> {
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    let tcp = tcp_connect(host, port)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(request).map_err(|e| format!("tls: {e}"))?;
    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Err(e) => return Err(format!("tls: {e}")),
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("http: no header end")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("http: bad status")?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    if headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"))
    {
        body = dechunk(&body).ok_or("http: bad chunked body")?;
    }
    Ok(Response { status, headers, body })
}

fn b64_relaxed(s: &[u8]) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = s.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(clean).map_err(|e| e.to_string())
}

pub struct EnrollResult {
    pub cert: der::CertInfo,
    pub bundle: Option<Vec<u8>>,
}

/// RFC 7030 enrollment with the IronMesh attestation. `attest(nonce)` returns the COSE bytes.
pub fn est_enroll(
    real: &RealConfig,
    renew: bool,
    op_cert: Option<&[u8]>,
    identity: &SoftIdentity,
    csr: &[u8],
    attest: impl Fn(&[u8; 32]) -> Result<Vec<u8>, String>,
) -> Result<EnrollResult, (i32, String)> {
    let cert = if renew { op_cert.map(<[u8]>::to_vec) } else { None }.unwrap_or_else(|| real.bootstrap_cert.clone());
    let cfg = client_config(&real.ca_roots, Some(cert), identity, false).map_err(|e| (0, e))?;
    let host = real.est_host.as_str();
    let req = format!("GET /.well-known/est/ironmesh/nonce HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let r = https(host, real.est_port, cfg.clone(), req.as_bytes()).map_err(|e| (0, e))?;
    if r.status != 200 {
        return Err((r.status, String::from_utf8_lossy(&r.body).chars().take(200).collect()));
    }
    let body = String::from_utf8_lossy(&r.body);
    let nonce_b64 = body
        .split("\"nonce\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .ok_or((0, "nonce: bad json".to_string()))?;
    let nonce_raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .map_err(|e| (0, e.to_string()))?;
    let nonce: [u8; 32] = nonce_raw.try_into().map_err(|_| (0, "nonce: not 32 bytes".to_string()))?;
    let att = attest(&nonce).map_err(|e| (0, e))?;
    let att_b64 = base64::engine::general_purpose::STANDARD.encode(att);
    let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr);
    let op = if renew { "simplereenroll" } else { "simpleenroll" };
    let req = format!(
        "POST /.well-known/est/{op} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/pkcs10\r\nContent-Transfer-Encoding: base64\r\nX-IronMesh-Attestation: {att_b64}\r\nContent-Length: {}\r\n\r\n{csr_b64}",
        csr_b64.len()
    );
    let r = https(host, real.est_port, cfg, req.as_bytes()).map_err(|e| (0, e))?;
    if r.status != 200 {
        return Err((r.status, String::from_utf8_lossy(&r.body).chars().take(200).collect()));
    }
    let p7 = b64_relaxed(&r.body).map_err(|e| (r.status, e))?;
    let certs = der::pkcs7_certs(&p7).ok_or((r.status, "pkcs7: unparsable".to_string()))?;
    let leaf = certs
        .into_iter()
        .find(|c| !c.is_ca)
        .ok_or((r.status, "pkcs7: no leaf".to_string()))?;
    let bundle = r
        .header("X-IronMesh-Bundle")
        .map(|v| b64_relaxed(v.as_bytes()))
        .transpose()
        .map_err(|e| (r.status, e))?;
    Ok(EnrollResult { cert: leaf, bundle })
}

/// Download an OTA artifact (`https://host[:port]/path`).
pub fn https_get(real: &RealConfig, url: &str) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("https://").ok_or("only https URLs are allowed")?;
    let (authority, path) = rest
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|e| e.to_string())?),
        None => (authority, 443),
    };
    let ident = SoftIdentity::random();
    let cfg = client_config(&real.ca_roots, None, &ident, false)?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let r = https(host, port, cfg, req.as_bytes())?;
    if r.status != 200 {
        return Err(format!("http {}", r.status));
    }
    Ok(r.body)
}

/// PKCS#10 CSR for the new key: CN = device id, OU = tenant id, O = IronMesh, SAN URI.
pub fn build_csr(key: &SoftIdentity, device_id: &str, tenant_id: &str) -> Result<Vec<u8>, String> {
    use p256::pkcs8::EncodePrivateKey;
    let der = key.secret().to_pkcs8_der().map_err(|e| e.to_string())?;
    let pk = PrivatePkcs8KeyDer::from(der.as_bytes().to_vec());
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pk, &rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, device_id);
    dn.push(rcgen::DnType::OrganizationalUnitName, tenant_id);
    dn.push(rcgen::DnType::OrganizationName, "IronMesh");
    params.distinguished_name = dn;
    let uri = format!("urn:ironmesh:tenant:{tenant_id}:device:{device_id}");
    params.subject_alt_names = vec![rcgen::SanType::URI(rcgen::Ia5String::try_from(uri).map_err(|e| e.to_string())?)];
    let csr = params.serialize_request(&kp).map_err(|e| e.to_string())?;
    Ok(csr.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_has_device_identity_and_is_signed_by_the_new_key() {
        let k = SoftIdentity::random();
        let csr = build_csr(&k, "dev-8f3a1c2b9d4e5f60", "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11").unwrap();
        let (t, rest) = der::tlv(&csr).unwrap();
        assert_eq!(t.tag, 0x30);
        assert!(rest.is_empty());
        let s = String::from_utf8_lossy(&csr);
        assert!(s.contains("dev-8f3a1c2b9d4e5f60") && s.contains("IronMesh") && s.contains("urn:ironmesh:tenant:"));
        // public key of the identity is embedded
        let pk = k.public_raw();
        assert!(csr.windows(65).any(|w| w == pk));
    }

    #[test]
    fn error_classification() {
        assert_eq!(classify("tls: invalid peer certificate: UnknownIssuer"), "tls_pin_mismatch");
        assert_eq!(classify("tls: received fatal alert: ProtocolVersion"), "tls_handshake");
        assert_eq!(classify("network: connection refused"), "network");
        assert_eq!(classify("network: operation timed out"), "timeout");
    }

    #[test]
    fn chunked_decoding() {
        assert_eq!(dechunk(b"4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n").unwrap(), b"Wikipedia");
        assert!(dechunk(b"5\r\nab").is_none());
    }
}
