//! Resumable HTTPS artifact download (`Range: bytes=<n>-`), streamed to disk with a running
//! SHA-256 and a hard size limit (the manifest's `image_size` / `patch_size`).

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};

use crate::tls;

/// Download failure.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// URL rejected (scheme, host allowlist).
    #[error("download URL rejected: {0}")]
    Url(String),
    /// Transport.
    #[error("download transport: {0}")]
    Transport(String),
    /// HTTP status.
    #[error("download HTTP {0}")]
    Http(u16),
    /// More data than announced.
    #[error("download exceeds {0} bytes")]
    TooLarge(u64),
    /// I/O.
    #[error("download I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Parsed `https://host[:port]/path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Path and query.
    pub path: String,
}

/// Parse an HTTPS URL (no userinfo, no fragments).
///
/// # Errors
/// [`DownloadError::Url`].
pub fn parse_https_url(url: &str) -> Result<HttpsUrl, DownloadError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| DownloadError::Url("only https:// URLs are allowed".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || path.contains('#') || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(DownloadError::Url("malformed URL".into()));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse::<u16>().map_err(|_| DownloadError::Url("bad port".into()))?),
        _ => (authority, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || port == 0 {
        return Err(DownloadError::Url("malformed host".into()));
    }
    Ok(HttpsUrl { host: host.to_ascii_lowercase(), port, path: path.to_owned() })
}

/// Download `url` into `part_path`, resuming a previous partial download.
/// Returns `(length, sha256)` of the complete file.
///
/// # Errors
/// [`DownloadError`].
pub async fn download(
    tls_config: Arc<rustls::ClientConfig>,
    url: &HttpsUrl,
    part_path: &Path,
    max_len: u64,
    timeout: Duration,
) -> Result<(u64, [u8; 32]), DownloadError> {
    // Resume: hash what is already on disk.
    let mut hasher = Sha256::new();
    let mut have = 0u64;
    if let Ok(mut f) = std::fs::File::open(part_path) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            have += n as u64;
        }
    }
    if have > max_len {
        std::fs::remove_file(part_path)?;
        hasher = Sha256::new();
        have = 0;
    }
    if have == max_len && max_len > 0 {
        return Ok((have, hasher.finalize().into()));
    }
    let (stream, _) = tls::connect(tls_config, &url.host, url.port, timeout).await.map_err(|(_, d)| DownloadError::Transport(d))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|e| DownloadError::Transport(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = http::Request::builder().method(http::Method::GET).uri(&url.path).header(http::header::HOST, &url.host);
    if have > 0 {
        req = req.header(http::header::RANGE, format!("bytes={have}-"));
    }
    let req = req.body(Empty::<Bytes>::new()).map_err(|e| DownloadError::Transport(e.to_string()))?;
    let resp = tokio::time::timeout(timeout, sender.send_request(req))
        .await
        .map_err(|_| DownloadError::Transport("request timed out".into()))?
        .map_err(|e| DownloadError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    let mut file = match status {
        206 if have > 0 => std::fs::OpenOptions::new().append(true).open(part_path)?,
        200 => {
            hasher = Sha256::new();
            have = 0;
            std::fs::File::create(part_path)?
        }
        s => return Err(DownloadError::Http(s)),
    };
    let mut body = resp.into_body();
    loop {
        let frame = tokio::time::timeout(timeout, body.frame()).await.map_err(|_| DownloadError::Transport("body timed out".into()))?;
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|e| DownloadError::Transport(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            have += data.len() as u64;
            if have > max_len {
                drop(file);
                let _ = std::fs::remove_file(part_path);
                return Err(DownloadError::TooLarge(max_len));
            }
            file.write_all(&data)?;
            hasher.update(&data);
        }
    }
    file.sync_all()?;
    Ok((have, hasher.finalize().into()))
}

/// TLS configuration for artifact downloads: TLS 1.3, webpki validation against `anchors`
/// (no client certificate; integrity comes from the signed manifest).
///
/// # Errors
/// If the anchors cannot be loaded.
pub fn download_tls_config(anchors: &[Vec<u8>]) -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    for a in anchors {
        roots.add(rustls::pki_types::CertificateDer::from(a.clone()))?;
    }
    let cfg = rustls::ClientConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_https_url("https://Example.com/a/b?x=1").unwrap(),
            HttpsUrl { host: "example.com".into(), port: 443, path: "/a/b?x=1".into() }
        );
        assert_eq!(parse_https_url("https://h:8443").unwrap(), HttpsUrl { host: "h".into(), port: 8443, path: "/".into() });
        assert_eq!(parse_https_url("https://[::1]:9/x").unwrap().host, "::1");
        for bad in
            ["http://h/x", "https:///x", "https://u@h/x", "https://h/x#f", "https://h:0/x", "https://h:99999/", "https://h/a b", "ftp://x"]
        {
            assert!(parse_https_url(bad).is_err(), "{bad}");
        }
        assert!(download_tls_config(&[vec![1, 2, 3]]).is_err());
        assert!(download_tls_config(&[]).is_ok());
    }
}
