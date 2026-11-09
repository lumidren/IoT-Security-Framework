//! TLS 1.3-only client configuration with SPKI pinning of the Services CA, hostname checking,
//! mTLS client authentication through the identity backend, and session resumption.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, OtherError, RootCertStore, SignatureAlgorithm, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::identity::{KeySlot, SharedIdentity};
use crate::x509;

/// The process-wide crypto provider (`ring`).
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The broker/EST certificate chain does not lead to a pinned CA key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinMismatch;

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tls_pin_mismatch: issuing CA SPKI is not pinned")
    }
}

impl std::error::Error for PinMismatch {}

/// Server verifier: webpki chain + hostname validation where the **only** trust anchors are the
/// CA keys whose SPKI-SHA256 is pinned (the Services CA, distributed in the trust bundle).
///
/// Anchors are the configured CA certificates plus any presented intermediate whose key is
/// pinned (pinning a key means trusting it as an anchor). A chain that does not validate up to a
/// pinned key - including a rogue CA that copies the Services CA name - is reported as
/// [`PinMismatch`]; hostname, validity and other errors are reported unchanged.
#[derive(Debug)]
pub struct PinnedVerifier {
    anchors: Vec<Vec<u8>>,
    pins: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    /// Build from candidate trust-anchor certificates (DER) and SPKI pins.
    ///
    /// # Errors
    /// If there are no pins.
    pub fn new(anchors_der: &[Vec<u8>], pins: &[[u8; 32]], provider: Arc<CryptoProvider>) -> Result<Self, TlsError> {
        if pins.is_empty() {
            return Err(TlsError::General("no CA pins configured".into()));
        }
        Ok(Self { anchors: anchors_der.to_vec(), pins: pins.to_vec(), provider })
    }

    fn pinned_roots(&self, intermediates: &[CertificateDer<'_>]) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        let candidates = self.anchors.iter().map(Vec::as_slice).chain(intermediates.iter().map(|c| c.as_ref()));
        for der in candidates {
            if x509::parse_cert(der).is_ok_and(|ca| self.pins.contains(&ca.spki_sha256)) {
                let _ = roots.add(CertificateDer::from(der.to_vec()));
            }
        }
        roots
    }
}

fn pin_mismatch() -> TlsError {
    TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(PinMismatch))))
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let roots = self.pinned_roots(intermediates);
        if roots.is_empty() {
            return Err(pin_mismatch());
        }
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
            .build()
            .map_err(|e| TlsError::General(e.to_string()))?;
        match inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer | CertificateError::BadSignature)) => Err(pin_mismatch()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// rustls signing key backed by an identity slot (ECDSA P-256 / SHA-256 only).
#[derive(Clone)]
pub struct IdentityTlsKey {
    provider: SharedIdentity,
    slot: KeySlot,
}

impl std::fmt::Debug for IdentityTlsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityTlsKey").field("slot", &self.slot).finish()
    }
}

impl SigningKey for IdentityTlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256).then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for IdentityTlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        let raw = self.provider.sign(self.slot, &digest).map_err(|e| TlsError::General(e.to_string()))?;
        crate::wire::keys::ecdsa_raw_to_der(&raw).map_err(|e| TlsError::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct FixedClientCert(Arc<CertifiedKey>);

impl ResolvesClientCert for FixedClientCert {
    fn resolve(&self, _hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256).then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Client identity for mTLS: certificate chain (leaf first) and the key slot that signs.
#[derive(Clone)]
pub struct ClientIdentity {
    /// Leaf first.
    pub chain: Vec<Vec<u8>>,
    /// Provider.
    pub provider: SharedIdentity,
    /// Slot holding the leaf's key.
    pub slot: KeySlot,
}

/// Build a TLS 1.3-only client config.
///
/// # Errors
/// If rustls rejects the configuration.
pub fn client_config(
    verifier: Arc<PinnedVerifier>,
    identity: Option<ClientIdentity>,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match identity {
        Some(id) => {
            let chain = id.chain.into_iter().map(CertificateDer::from).collect();
            let key = Arc::new(IdentityTlsKey { provider: id.provider, slot: id.slot });
            builder.with_client_cert_resolver(Arc::new(FixedClientCert(Arc::new(CertifiedKey::new(chain, key)))))
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.resumption = rustls::client::Resumption::in_memory_sessions(64);
    Ok(Arc::new(config))
}

/// Why a TLS connection could not be established (DUT `connect_failed.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectFailure {
    /// The server chain does not lead to a pinned CA.
    TlsPinMismatch,
    /// Handshake failure (protocol version, chain validation, ...).
    TlsHandshake,
    /// The server rejected our certificate.
    CertRejected,
    /// MQTT CONNACK not authorized.
    NotAuthorized,
    /// TCP / DNS failure.
    Network,
    /// Timed out.
    Timeout,
}

impl ConnectFailure {
    /// Stable reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ConnectFailure::TlsPinMismatch => "tls_pin_mismatch",
            ConnectFailure::TlsHandshake => "tls_handshake",
            ConnectFailure::CertRejected => "cert_rejected",
            ConnectFailure::NotAuthorized => "not_authorized",
            ConnectFailure::Network => "network",
            ConnectFailure::Timeout => "timeout",
        }
    }
}

/// Classify a TLS error.
#[must_use]
pub fn classify_tls_error(err: &TlsError) -> ConnectFailure {
    use rustls::AlertDescription as A;
    match err {
        TlsError::InvalidCertificate(CertificateError::Other(OtherError(e))) if e.downcast_ref::<PinMismatch>().is_some() => {
            ConnectFailure::TlsPinMismatch
        }
        TlsError::AlertReceived(
            A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::AccessDenied
            | A::CertificateRequired,
        ) => ConnectFailure::CertRejected,
        _ => ConnectFailure::TlsHandshake,
    }
}

fn classify_io(err: &std::io::Error) -> ConnectFailure {
    if let Some(tls) = err.get_ref().and_then(|e| e.downcast_ref::<TlsError>()) {
        return classify_tls_error(tls);
    }
    if err.kind() == std::io::ErrorKind::TimedOut {
        return ConnectFailure::Timeout;
    }
    // A peer that closes during the handshake after our certificate was sent rejected it.
    if matches!(err.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset) {
        return ConnectFailure::TlsHandshake;
    }
    ConnectFailure::TlsHandshake
}

/// Facts about an established TLS session (DUT `connected` event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// e.g. `TLSv1.3`.
    pub version: String,
    /// Negotiated ALPN.
    pub alpn: Option<String>,
    /// The session was resumed from a ticket.
    pub resumed: bool,
}

/// Open a TCP connection and complete a pinned TLS handshake.
///
/// # Errors
/// A classified [`ConnectFailure`] with a detail message.
pub async fn connect(
    config: Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<(TlsStream<TcpStream>, TlsInfo), (ConnectFailure, String)> {
    let server_name = ServerName::try_from(host.to_owned()).map_err(|e| (ConnectFailure::Network, e.to_string()))?;
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Err(_) => return Err((ConnectFailure::Timeout, "TCP connect timed out".into())),
        Ok(Err(e)) => return Err((ConnectFailure::Network, e.to_string())),
        Ok(Ok(s)) => s,
    };
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(config);
    let tls = match tokio::time::timeout(timeout, connector.connect(server_name, tcp)).await {
        Err(_) => return Err((ConnectFailure::Timeout, "TLS handshake timed out".into())),
        Ok(Err(e)) => return Err((classify_io(&e), e.to_string())),
        Ok(Ok(s)) => s,
    };
    let (_, conn) = tls.get_ref();
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_owned(),
        Some(v) => format!("{v:?}"),
        None => "unknown".to_owned(),
    };
    let info = TlsInfo {
        version,
        alpn: conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned()),
        resumed: matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed)),
    };
    Ok((tls, info))
}

/// SHA-256 pin of a certificate's SPKI.
///
/// # Errors
/// On a malformed certificate.
pub fn spki_pin(cert_der: &[u8]) -> Result<[u8; 32], x509::X509Error> {
    Ok(x509::parse_cert(cert_der)?.spki_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        let pin = TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(PinMismatch))));
        assert_eq!(classify_tls_error(&pin), ConnectFailure::TlsPinMismatch);
        assert_eq!(classify_tls_error(&TlsError::AlertReceived(rustls::AlertDescription::BadCertificate)), ConnectFailure::CertRejected);
        assert_eq!(classify_tls_error(&TlsError::AlertReceived(rustls::AlertDescription::ProtocolVersion)), ConnectFailure::TlsHandshake);
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, pin);
        assert_eq!(classify_io(&io), ConnectFailure::TlsPinMismatch);
        assert_eq!(classify_io(&std::io::Error::from(std::io::ErrorKind::TimedOut)), ConnectFailure::Timeout);
        assert_eq!(classify_io(&std::io::Error::from(std::io::ErrorKind::UnexpectedEof)), ConnectFailure::TlsHandshake);
        for f in [
            ConnectFailure::TlsPinMismatch,
            ConnectFailure::TlsHandshake,
            ConnectFailure::CertRejected,
            ConnectFailure::NotAuthorized,
            ConnectFailure::Network,
            ConnectFailure::Timeout,
        ] {
            assert!(!f.as_str().is_empty());
        }
        assert!(PinMismatch.to_string().contains("pin"));
    }
}
