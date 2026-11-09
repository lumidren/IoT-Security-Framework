//! EST client (RFC 7030) with the IronMesh attestation extension (contract §3).
//!
//! Every request runs over a fresh pinned TLS 1.3 connection (sessions are resumed by the shared
//! rustls config) using HTTP/1.1 via `hyper`. Bodies are base64 per RFC 7030 §4.

pub mod bundle;
pub mod pkcs7;
pub mod renewal;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;

use crate::tls::{self, ConnectFailure};

/// EST base path.
pub const BASE_PATH: &str = "/.well-known/est";
/// Attestation header.
pub const HEADER_ATTESTATION: &str = "X-IronMesh-Attestation";
/// Bundle header.
pub const HEADER_BUNDLE: &str = "X-IronMesh-Bundle";
const MAX_BODY: usize = 64 * 1024;

/// EST failure.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EstError {
    /// Transport / TLS failure.
    #[error("EST connect ({reason}): {1}", reason = .0.as_str())]
    Connect(ConnectFailure, String),
    /// Non-2xx response.
    #[error("EST HTTP {status}: {reason}")]
    Http {
        /// Status code.
        status: u16,
        /// Response body (truncated).
        reason: String,
    },
    /// Malformed response.
    #[error("EST protocol: {0}")]
    Protocol(String),
}

impl EstError {
    /// HTTP status for DUT `enroll_failed.http_status` (0 when no response was received).
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            EstError::Http { status, .. } => *status,
            _ => 0,
        }
    }
}

/// A raw HTTP response.
#[derive(Debug, Clone)]
pub struct EstResponse {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: http::HeaderMap,
    /// Body.
    pub body: Bytes,
}

/// Successful enrollment response.
#[derive(Debug, Clone)]
pub struct Enrollment {
    /// Certificates from the certs-only PKCS#7 (leaf first).
    pub certs: Vec<Vec<u8>>,
    /// Raw `X-IronMesh-Bundle` (COSE_Sign1) if present.
    pub bundle: Option<Vec<u8>>,
    /// Server `Date` header (unix s), if parseable.
    pub server_time: Option<u64>,
}

/// EST client bound to one server and one TLS client identity.
#[derive(Clone)]
pub struct EstClient {
    host: String,
    port: u16,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

/// Decode a base64 body, tolerating line breaks (RFC 7030 §4: base64 with CRLF wrapping).
///
/// # Errors
/// On invalid base64.
pub fn decode_b64_body(body: &[u8]) -> Result<Vec<u8>, EstError> {
    let compact: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(&compact).map_err(|e| EstError::Protocol(format!("invalid base64 body: {e}")))
}

fn parse_http_date(v: &str) -> Option<u64> {
    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    let parts: Vec<&str> = v.split_whitespace().collect();
    if parts.len() != 6 || parts[5] != "GMT" {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|m| *m == parts[2])?
        as u32
        + 1;
    let year: i64 = parts[3].parse().ok()?;
    let hms: Vec<u64> = parts[4].split(':').filter_map(|x| x.parse().ok()).collect();
    if hms.len() != 3 {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * i64::from(m) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86400).ok().map(|d| d + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

fn http_date(headers: &http::HeaderMap) -> Option<u64> {
    headers.get(http::header::DATE).and_then(|d| d.to_str().ok()).and_then(parse_http_date)
}

impl EstClient {
    /// New client.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, tls: Arc<rustls::ClientConfig>, timeout: Duration) -> Self {
        Self { host: host.into(), port, tls, timeout }
    }

    /// Perform one request.
    ///
    /// # Errors
    /// [`EstError`].
    pub async fn request(
        &self,
        method: http::Method,
        path: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<EstResponse, EstError> {
        let (stream, _info) =
            tls::connect(self.tls.clone(), &self.host, self.port, self.timeout).await.map_err(|(f, d)| EstError::Connect(f, d))?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
            .await
            .map_err(|e| EstError::Connect(ConnectFailure::Network, e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut builder = http::Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, format!("{}:{}", self.host, self.port))
            .header(http::header::USER_AGENT, concat!("ironmesh-agent/", env!("CARGO_PKG_VERSION")));
        for (k, v) in headers {
            builder = builder.header(*k, v);
        }
        let req = builder.body(Full::new(Bytes::from(body))).map_err(|e| EstError::Protocol(e.to_string()))?;
        let resp = tokio::time::timeout(self.timeout, sender.send_request(req))
            .await
            .map_err(|_| EstError::Connect(ConnectFailure::Timeout, "EST request timed out".into()))?
            .map_err(|e| EstError::Connect(ConnectFailure::Network, e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = tokio::time::timeout(self.timeout, Limited::new(resp.into_body(), MAX_BODY).collect())
            .await
            .map_err(|_| EstError::Connect(ConnectFailure::Timeout, "EST body timed out".into()))?
            .map_err(|e| EstError::Protocol(format!("response body: {e}")))?
            .to_bytes();
        Ok(EstResponse { status, headers, body })
    }

    fn ok(resp: EstResponse) -> Result<EstResponse, EstError> {
        if (200..300).contains(&resp.status) {
            Ok(resp)
        } else {
            let reason = String::from_utf8_lossy(&resp.body[..resp.body.len().min(512)]).trim().to_owned();
            Err(EstError::Http { status: resp.status, reason })
        }
    }

    /// `GET /cacerts`.
    ///
    /// # Errors
    /// [`EstError`].
    pub async fn cacerts(&self) -> Result<Vec<Vec<u8>>, EstError> {
        let resp = Self::ok(self.request(http::Method::GET, &format!("{BASE_PATH}/cacerts"), &[], Vec::new()).await?)?;
        pkcs7::decode_certs_only(&decode_b64_body(&resp.body)?).map_err(|e| EstError::Protocol(e.to_string()))
    }

    /// `GET /ironmesh/nonce` -> 32-byte nonce.
    ///
    /// # Errors
    /// [`EstError`].
    pub async fn nonce(&self) -> Result<[u8; 32], EstError> {
        self.nonce_and_date().await.map(|(n, _)| n)
    }

    /// `GET /ironmesh/nonce` -> 32-byte nonce and the response's `Date` (unix s, if parseable).
    /// The `Date` comes over the mutually authenticated, pinned EST connection (T-10 time hint).
    ///
    /// # Errors
    /// [`EstError`].
    pub async fn nonce_and_date(&self) -> Result<([u8; 32], Option<u64>), EstError> {
        #[derive(serde::Deserialize)]
        struct NonceResponse {
            nonce: String,
        }
        let resp = Self::ok(self.request(http::Method::GET, &format!("{BASE_PATH}/ironmesh/nonce"), &[], Vec::new()).await?)?;
        let date = http_date(&resp.headers);
        let parsed: NonceResponse = serde_json::from_slice(&resp.body).map_err(|e| EstError::Protocol(format!("nonce JSON: {e}")))?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parsed.nonce.trim_end_matches('='))
            .map_err(|e| EstError::Protocol(format!("nonce base64url: {e}")))?;
        let nonce = raw.try_into().map_err(|_| EstError::Protocol("nonce must be 32 bytes".into()))?;
        Ok((nonce, date))
    }

    /// `POST /simpleenroll` or `/simplereenroll` with the attestation header.
    ///
    /// # Errors
    /// [`EstError`].
    pub async fn enroll(&self, reenroll: bool, csr_der: &[u8], attestation: &[u8]) -> Result<Enrollment, EstError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let op = if reenroll { "simplereenroll" } else { "simpleenroll" };
        let headers = [
            ("Content-Type", "application/pkcs10".to_owned()),
            ("Content-Transfer-Encoding", "base64".to_owned()),
            (HEADER_ATTESTATION, b64.encode(attestation)),
        ];
        let resp =
            Self::ok(self.request(http::Method::POST, &format!("{BASE_PATH}/{op}"), &headers, b64.encode(csr_der).into_bytes()).await?)?;
        let certs = pkcs7::decode_certs_only(&decode_b64_body(&resp.body)?).map_err(|e| EstError::Protocol(e.to_string()))?;
        let bundle = match resp.headers.get(HEADER_BUNDLE) {
            None => None,
            Some(v) => Some(
                b64.decode(v.as_bytes().iter().copied().filter(|c| !c.is_ascii_whitespace()).collect::<Vec<u8>>())
                    .map_err(|e| EstError::Protocol(format!("bundle base64: {e}")))?,
            ),
        };
        let server_time = http_date(&resp.headers);
        Ok(Enrollment { certs, bundle, server_time })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(decode_b64_body(b"AAEC\r\nAw==\n").unwrap(), vec![0, 1, 2, 3]);
        assert!(decode_b64_body(b"!!").is_err());
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("garbage"), None);
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None);
        let mut h = http::HeaderMap::new();
        assert_eq!(http_date(&h), None);
        h.insert(http::header::DATE, http::HeaderValue::from_static("Mon, 09 Nov 2026 12:00:00 GMT"));
        assert_eq!(http_date(&h), Some(1_794_225_600));
        assert_eq!(EstError::Http { status: 403, reason: "x".into() }.http_status(), 403);
        assert_eq!(EstError::Protocol("x".into()).http_status(), 0);
        assert!(EstError::Connect(ConnectFailure::Network, "x".into()).to_string().contains("network"));
    }
}
