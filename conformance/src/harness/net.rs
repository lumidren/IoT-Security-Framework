//! TLS server configurations, HTTPS/HTTP serving of axum routers (with the client certificate
//! made available to handlers) and a minimal HTTP/1.1 client for the harness' own calls.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use axum::Router;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};

/// The ring provider.
#[must_use]
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Root store from DER certificates.
///
/// # Errors
/// A certificate rustls refuses as an anchor.
pub fn roots(ders: &[&[u8]]) -> Result<Arc<rustls::RootCertStore>> {
    let mut r = rustls::RootCertStore::empty();
    for d in ders {
        r.add(CertificateDer::from(d.to_vec())).map_err(|e| anyhow!("trust anchor: {e}"))?;
    }
    Ok(Arc::new(r))
}

/// Which protocol versions a listener offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Versions {
    /// TLS 1.3 only (the contract broker).
    Tls13Only,
    /// TLS 1.2 only (C-TLS-3 fault injection).
    Tls12Only,
    /// Both (HTTPS listeners).
    Both,
}

/// Client authentication policy.
pub enum ClientAuth {
    /// No client certificates.
    None,
    /// Optional client certificate chaining to the anchors (EST: `cacerts` is unauthenticated).
    Optional(Arc<rustls::RootCertStore>),
    /// Mandatory client certificate chaining to the anchors (broker).
    Required(Arc<rustls::RootCertStore>),
}

/// Build a server configuration.
///
/// # Errors
/// Invalid key / certificate or verifier construction failure.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    auth: ClientAuth,
    versions: Versions,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = provider();
    let v: &[&rustls::SupportedProtocolVersion] = match versions {
        Versions::Tls13Only => &[&rustls::version::TLS13],
        Versions::Tls12Only => &[&rustls::version::TLS12],
        Versions::Both => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(v)?;
    let builder = match auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Optional(r) => builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(r, provider).allow_unauthenticated().build()?,
        ),
        ClientAuth::Required(r) => {
            builder.with_client_cert_verifier(rustls::server::WebPkiClientVerifier::builder_with_provider(r, provider).build()?)
        }
    };
    let mut cfg = builder.with_single_cert(chain, key)?;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    // Stateful TLS 1.3 resumption (rustls default session cache) plus two tickets per handshake.
    cfg.send_tls13_tickets = 2;
    Ok(Arc::new(cfg))
}

/// Client certificate of the TLS connection a request arrived on (leaf DER), or `None`.
#[derive(Clone, Debug, Default)]
pub struct PeerCert(pub Option<Vec<u8>>);

/// Remote address of the connection a request arrived on.
#[derive(Clone, Debug)]
pub struct PeerAddr(pub SocketAddr);

/// Serve `router` over TLS on `listener`. Handlers can extract [`PeerCert`] and [`PeerAddr`] via
/// `axum::Extension`.
pub fn serve_https(listener: TcpListener, cfg: Arc<rustls::ServerConfig>, router: Router) {
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, addr)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await else { return };
                let peer = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec());
                let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(PeerCert(peer.clone()));
                    req.extensions_mut().insert(PeerAddr(addr));
                    tower::ServiceExt::oneshot(router.clone(), req)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
            });
        }
    });
}

/// Serve `router` over plain HTTP on `listener`.
pub fn serve_http(listener: TcpListener, router: Router) {
    tokio::spawn(async move {
        loop {
            let Ok((tcp, addr)) = listener.accept().await else { return };
            let router = router.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(PeerAddr(addr));
                    tower::ServiceExt::oneshot(router.clone(), req)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
            });
        }
    });
}

/// Bind `host:0` (or a fixed port).
///
/// # Errors
/// Bind failure.
pub async fn bind(host: &str, port: u16) -> Result<TcpListener> {
    TcpListener::bind((host, port)).await.with_context(|| format!("bind {host}:{port}"))
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Headers (lower-case names).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Header lookup (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Body as JSON.
    ///
    /// # Errors
    /// Not JSON.
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body).with_context(|| format!("HTTP {} body is not JSON: {}", self.status, self.text()))
    }

    /// Body as (lossy) text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One HTTP/1.1 request (`http://` or `https://` URL). For HTTPS, `tls` must be supplied.
///
/// # Errors
/// Transport failures and timeouts.
pub async fn http_request(
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
    tls: Option<Arc<rustls::ClientConfig>>,
    timeout: Duration,
) -> Result<HttpResponse> {
    tokio::time::timeout(timeout, http_request_inner(method, url, headers, body, tls))
        .await
        .map_err(|_| anyhow!("{method} {url}: timed out after {timeout:?}"))?
}

async fn http_request_inner(
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<HttpResponse> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("unsupported URL {url}");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h.trim_matches(['[', ']']), p.parse::<u16>()?),
        _ => (authority, if https { 443 } else { 80 }),
    };
    let tcp = TcpStream::connect((host, port)).await.with_context(|| format!("connect {host}:{port}"))?;
    tcp.set_nodelay(true).ok();
    let mut req = hyper::Request::builder().method(method).uri(path).header("host", authority);
    for (k, v) in headers {
        req = req.header(*k, v.as_str());
    }
    let req = req.body(Full::new(Bytes::from(body)))?;
    let resp = if https {
        let cfg = tls.ok_or_else(|| anyhow!("https URL without TLS configuration"))?;
        let name = ServerName::try_from(host.to_owned())?;
        let stream = tokio_rustls::TlsConnector::from(cfg).connect(name, tcp).await.context("TLS handshake")?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        sender.send_request(req).await?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await?;
        tokio::spawn(conn);
        sender.send_request(req).await?
    };
    let status = resp.status().as_u16();
    let headers =
        resp.headers().iter().map(|(k, v)| (k.as_str().to_ascii_lowercase(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    Ok(HttpResponse { status, headers, body })
}

/// A pool of persistent HTTP/1.1 connections to one plain-HTTP origin.
///
/// EMQX keeps a connection pool to its HTTP authn/authz backends; [`http_request`] opens one TCP
/// connection per call, which at load-test rates (thousands of hook calls per second) would leave
/// tens of thousands of client sockets in TIME_WAIT and exhaust the ephemeral port range. The pool
/// hands out idle keep-alive connections, opens new ones up to `max` concurrent requests and
/// retries once on a fresh connection when a reused one turns out to be closed (hook calls are
/// idempotent decisions).
pub struct HookPool {
    host: String,
    port: u16,
    authority: String,
    idle: std::sync::Mutex<Vec<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>,
    permits: tokio::sync::Semaphore,
    opened: std::sync::atomic::AtomicU64,
    max: usize,
    /// Time each request waited for a free pool slot (load-test diagnostics).
    pub permit_wait: crate::load::stats::Recorder,
}

impl HookPool {
    /// Pool for `http://host:port` with at most `max` concurrent requests.
    ///
    /// # Errors
    /// Not an `http://host:port` base URL.
    pub fn new(base: &str, max: usize) -> Result<Self> {
        let rest = base.strip_prefix("http://").ok_or_else(|| anyhow!("hook pool needs an http:// URL, got {base}"))?;
        let authority = rest.trim_end_matches('/').to_owned();
        let (host, port) = authority.rsplit_once(':').ok_or_else(|| anyhow!("hook pool URL {base} has no port"))?;
        Ok(Self {
            host: host.trim_matches(['[', ']']).to_owned(),
            port: port.parse()?,
            authority: authority.clone(),
            idle: std::sync::Mutex::new(Vec::new()),
            permits: tokio::sync::Semaphore::new(max.max(1)),
            opened: std::sync::atomic::AtomicU64::new(0),
            max: max.max(1),
            permit_wait: crate::load::stats::Recorder::new(),
        })
    }

    /// Connections opened so far.
    #[must_use]
    pub fn opened(&self) -> u64 {
        self.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Maximum concurrent requests.
    #[must_use]
    pub fn max(&self) -> usize {
        self.max
    }

    fn take_idle(&self) -> Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
        let mut idle = self.idle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(s) = idle.pop() {
            if !s.is_closed() {
                return Some(s);
            }
        }
        None
    }

    async fn open(&self) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port)).await.with_context(|| format!("connect {}", self.authority))?;
        tcp.set_nodelay(true).ok();
        let (sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await?;
        tokio::spawn(conn);
        self.opened.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(sender)
    }

    /// `POST path` with a body; the connection goes back to the pool after the body was read.
    ///
    /// # Errors
    /// Transport failures and timeouts.
    pub async fn post(&self, path: &str, headers: &[(&str, String)], body: Vec<u8>, timeout: Duration) -> Result<HttpResponse> {
        tokio::time::timeout(timeout, self.post_inner(path, headers, Bytes::from(body)))
            .await
            .map_err(|_| anyhow!("POST {}{path}: timed out after {timeout:?}", self.authority))?
    }

    async fn post_inner(&self, path: &str, headers: &[(&str, String)], body: Bytes) -> Result<HttpResponse> {
        let waited = std::time::Instant::now();
        let _permit = self.permits.acquire().await.map_err(|e| anyhow!("{e}"))?;
        self.permit_wait.record(waited.elapsed());
        let mut last_err = None;
        for attempt in 0..2 {
            let (mut sender, reused) = match self.take_idle() {
                Some(s) if attempt == 0 => (s, true),
                _ => (self.open().await?, false),
            };
            let mut req = hyper::Request::builder().method("POST").uri(path).header("host", self.authority.as_str());
            for (k, v) in headers {
                req = req.header(*k, v.as_str());
            }
            let req = req.body(Full::new(body.clone()))?;
            let resp = match sender.ready().await {
                Ok(()) => sender.send_request(req).await,
                Err(e) => Err(e),
            };
            match resp {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let headers = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.as_str().to_ascii_lowercase(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                        .collect();
                    let body = resp.into_body().collect().await?.to_bytes().to_vec();
                    self.idle.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(sender);
                    return Ok(HttpResponse { status, headers, body });
                }
                Err(e) if reused => last_err = Some(anyhow!("{e}")),
                Err(e) => return Err(anyhow!("POST {}{path}: {e}", self.authority)),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("POST {}{path} failed", self.authority)))
    }
}

/// A TLS client configuration trusting `anchors`, optionally with a client certificate.
///
/// # Errors
/// Invalid anchors or key.
pub fn client_config(
    anchors: &[&[u8]],
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>> {
    let b = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots(anchors)?);
    let mut cfg = match client {
        Some((chain, key)) => b.with_client_auth_cert(chain, key)?,
        None => b.with_no_client_auth(),
    };
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(cfg))
}
