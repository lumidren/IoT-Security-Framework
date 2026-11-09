//! Zero-touch enrollment and certificate rotation (contract §3): nonce -> fresh key -> CSR ->
//! attestation (signed by the *current* identity key) -> `simpleenroll` / `simplereenroll` ->
//! verify the issued certificate and the trust bundle -> persist -> promote the key.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::est::bundle::{self, TrustBundle};
use crate::est::{EstClient, EstError};
use crate::identity::{IdentityError, IdentitySigner, KeySlot, SharedIdentity};
use crate::persist;
use crate::telemetry::FirmwareInfo;
use crate::tls::{self, ClientIdentity, PinnedVerifier};
use crate::wire::attestation;
use crate::wire::cose::Kid;
use crate::x509::{self, CertInfo};

/// Enrollment failure.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// EST transport / HTTP error.
    #[error(transparent)]
    Est(#[from] EstError),
    /// Identity backend error.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The response failed validation.
    #[error("enrollment response rejected: {0}")]
    Invalid(String),
    /// Local configuration problem.
    #[error("enrollment not possible: {0}")]
    NotProvisioned(String),
    /// Persistence.
    #[error("enrollment I/O: {0}")]
    Io(#[from] std::io::Error),
}

impl EnrollError {
    /// HTTP status (0 if none).
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            EnrollError::Est(e) => e.http_status(),
            _ => 0,
        }
    }

    /// Short reason for DUT events.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            EnrollError::Est(EstError::Http { reason, .. }) => reason.clone(),
            EnrollError::Est(EstError::Connect(f, _)) => f.as_str().to_owned(),
            other => other.to_string(),
        }
    }
}

/// The certificates and trust material of the device (in the identity directory).
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// Bootstrap certificate (factory).
    pub bootstrap: Option<CertInfo>,
    /// Current operational certificate.
    pub operational: Option<CertInfo>,
    /// Verified trust bundle.
    pub bundle: Option<TrustBundle>,
    /// Trust anchors (factory CA bundle + EST `cacerts`).
    pub anchors: Vec<Vec<u8>>,
}

const BOOTSTRAP_CRT: &str = "bootstrap.crt";
const OPERATIONAL_CRT: &str = "operational.crt";
const BUNDLE: &str = "bundle.cose";
const CA_CHAIN: &str = "ca-chain.pem";

fn read_cert(path: &Path) -> Result<Option<CertInfo>, EnrollError> {
    match persist::read_bounded(path, 64 * 1024)? {
        None => Ok(None),
        Some(bytes) => {
            let der = x509::pem_or_der_first(&bytes).map_err(|e| EnrollError::Invalid(e.to_string()))?;
            x509::parse_cert(&der).map(Some).map_err(|e| EnrollError::Invalid(e.to_string()))
        }
    }
}

impl Credentials {
    /// Load and reconcile (a crash between storing the certificate and promoting the key is
    /// completed here).
    ///
    /// # Errors
    /// I/O or parse errors.
    pub fn load(dir: &Path, identity: &SharedIdentity, bundle_key: Option<&[u8; 32]>, factory_anchors: &Path) -> Result<Self, EnrollError> {
        let bootstrap = read_cert(&dir.join(BOOTSTRAP_CRT))?;
        let operational = read_cert(&dir.join(OPERATIONAL_CRT))?;
        if let Some(op) = &operational {
            let op_key = identity.public_key(KeySlot::Operational).ok();
            let pending_key = identity.public_key(KeySlot::Pending).ok();
            if op.p256.is_some() && op.p256 != op_key && op.p256 == pending_key {
                tracing::warn!("completing interrupted enrollment: promoting pending key");
                identity.commit_pending()?;
            }
        }
        let bundle = match (persist::read_bounded(&dir.join(BUNDLE), 64 * 1024)?, bundle_key) {
            (Some(raw), Some(key)) => match bundle::verify_bundle(&raw, key) {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::error!(error = %e, "stored trust bundle failed verification; ignoring it");
                    None
                }
            },
            _ => None,
        };
        let mut anchors = Vec::new();
        for path in [factory_anchors.to_path_buf(), dir.join(CA_CHAIN)] {
            if let Some(bytes) = persist::read_bounded(&path, 1024 * 1024)? {
                if let Ok(certs) = x509::pem_or_der_all(&bytes) {
                    for c in certs {
                        if !anchors.contains(&c) {
                            anchors.push(c);
                        }
                    }
                }
            }
        }
        Ok(Self { bootstrap, operational, bundle, anchors })
    }

    /// The identity to present to EST: the operational certificate while valid, else bootstrap.
    #[must_use]
    pub fn current(&self, now: u64) -> Option<(CertInfo, KeySlot)> {
        if let Some(op) = self.operational.as_ref().filter(|c| c.not_after > now) {
            return Some((op.clone(), KeySlot::Operational));
        }
        self.bootstrap.as_ref().filter(|c| c.not_after > now).map(|c| (c.clone(), KeySlot::Bootstrap))
    }

    /// Valid operational certificate.
    #[must_use]
    pub fn operational_valid(&self, now: u64) -> Option<&CertInfo> {
        self.operational.as_ref().filter(|c| c.not_after > now && c.not_before <= now.saturating_add(300))
    }

    /// Install the factory bootstrap certificate.
    ///
    /// # Errors
    /// I/O or validation errors (CN/OU must match the identity, key must match the bootstrap key).
    pub fn install_bootstrap(dir: &Path, identity: &SharedIdentity, cert_pem_or_der: &[u8]) -> Result<CertInfo, EnrollError> {
        let der = x509::pem_or_der_first(cert_pem_or_der).map_err(|e| EnrollError::Invalid(e.to_string()))?;
        let info = x509::parse_cert(&der).map_err(|e| EnrollError::Invalid(e.to_string()))?;
        if info.subject_cn.as_deref() != Some(identity.device_id()) {
            return Err(EnrollError::Invalid("bootstrap certificate CN is not the device id".into()));
        }
        if info.p256 != identity.public_key(KeySlot::Bootstrap).ok() {
            return Err(EnrollError::Invalid("bootstrap certificate does not match the bootstrap key".into()));
        }
        persist::write_atomic(&dir.join(BOOTSTRAP_CRT), x509::to_pem("CERTIFICATE", &der).as_bytes())?;
        Ok(info)
    }
}

/// Inputs to one enrollment.
pub struct EnrollRequest<'a> {
    /// Identity.
    pub identity: &'a SharedIdentity,
    /// Credentials.
    pub creds: &'a Credentials,
    /// Identity directory.
    pub dir: PathBuf,
    /// EST host / port.
    pub est_host: &'a str,
    /// EST port.
    pub est_port: u16,
    /// Pins for the EST server (bundle pins, or factory pins before the first bundle).
    pub pins: Vec<[u8; 32]>,
    /// Baked-in bundle key.
    pub bundle_key: Option<[u8; 32]>,
    /// Firmware identity for the attestation.
    pub fw: FirmwareInfo,
    /// Attestation envelope sequence number.
    pub seq: u64,
    /// Now (unix s).
    pub now: u64,
    /// Network timeout.
    pub timeout: Duration,
    /// Force `simpleenroll` with the bootstrap identity.
    pub force_bootstrap: bool,
}

/// Result of a successful enrollment.
#[derive(Debug, Clone)]
pub struct EnrollOutcome {
    /// New operational certificate.
    pub certificate: CertInfo,
    /// Previous certificate serial (re-enrollment).
    pub previous_serial: Option<String>,
    /// Bundle (new or previous).
    pub bundle: Option<TrustBundle>,
    /// Re-enrollment?
    pub reenroll: bool,
    /// Server time from the `Date` header.
    pub server_time: Option<u64>,
}

/// Run one enrollment (bootstrap or re-enrollment) and persist the result.
///
/// # Errors
/// [`EnrollError`]; on any failure the operational key and certificate are unchanged.
pub async fn enroll(req: EnrollRequest<'_>) -> Result<EnrollOutcome, EnrollError> {
    let identity = req.identity;
    let (current, slot) = if req.force_bootstrap {
        req.creds
            .bootstrap
            .clone()
            .filter(|c| c.not_after > req.now)
            .map(|c| (c, KeySlot::Bootstrap))
            .ok_or_else(|| EnrollError::NotProvisioned("no valid bootstrap certificate".into()))?
    } else {
        req.creds.current(req.now).ok_or_else(|| EnrollError::NotProvisioned("no valid bootstrap or operational certificate".into()))?
    };
    let reenroll = slot == KeySlot::Operational;
    if req.creds.anchors.is_empty() {
        return Err(EnrollError::NotProvisioned("no trust anchors (pki.ca_bundle)".into()));
    }
    if req.pins.is_empty() {
        return Err(EnrollError::NotProvisioned("no CA pins for the EST server (pki.est_pins)".into()));
    }
    let verifier = Arc::new(
        PinnedVerifier::new(&req.creds.anchors, &req.pins, tls::provider()).map_err(|e| EnrollError::NotProvisioned(e.to_string()))?,
    );
    let tls_config = tls::client_config(
        verifier,
        Some(ClientIdentity { chain: vec![current.der.clone()], provider: identity.clone(), slot }),
        &[b"http/1.1"],
    )
    .map_err(|e| EnrollError::NotProvisioned(e.to_string()))?;
    let client = EstClient::new(req.est_host, req.est_port, tls_config, req.timeout);
    let nonce = client.nonce().await?;
    let pending = identity.generate_operational_key()?;
    let id2 = identity.clone();
    let sign = move |d: &[u8; 32]| id2.sign(KeySlot::Pending, d).map_err(|e| e.to_string());
    let csr =
        x509::build_csr(identity.device_id(), identity.tenant_id(), &pending, &sign).map_err(|e| EnrollError::Invalid(e.to_string()))?;
    let evidence = identity.attestation_evidence(&nonce)?;
    let signer = IdentitySigner { provider: identity.clone(), slot };
    let att = attestation::build_attestation(
        &signer,
        &Kid::Bytes(current.kid.clone()),
        req.seq,
        req.now,
        &nonce,
        &csr,
        &req.fw.hash,
        &req.fw.version,
        identity.se_type(),
        evidence,
    )
    .map_err(|e| EnrollError::Invalid(e.to_string()))?;
    let resp = client.enroll(reenroll, &csr, &att).await?;
    let leaf_der = resp
        .certs
        .iter()
        .find(|c| x509::parse_cert(c).ok().and_then(|i| i.p256) == Some(pending))
        .cloned()
        .ok_or_else(|| EnrollError::Invalid("no issued certificate matches the new key".into()))?;
    let leaf = x509::parse_cert(&leaf_der).map_err(|e| EnrollError::Invalid(e.to_string()))?;
    if leaf.subject_cn.as_deref() != Some(identity.device_id()) {
        return Err(EnrollError::Invalid("issued certificate CN is not the device id".into()));
    }
    if leaf.not_after <= req.now {
        return Err(EnrollError::Invalid("issued certificate is already expired".into()));
    }
    let bundle = match (&resp.bundle, req.bundle_key) {
        (Some(raw), Some(key)) => {
            let b = bundle::verify_bundle(raw, &key).map_err(|e| EnrollError::Invalid(e.to_string()))?;
            persist::write_atomic(&req.dir.join(BUNDLE), raw)?;
            Some(b)
        }
        (Some(_), None) => return Err(EnrollError::NotProvisioned("no bundle key configured (pki.bundle_pubkey)".into())),
        (None, _) if !reenroll && req.creds.bundle.is_none() => {
            return Err(EnrollError::Invalid("first enrollment response carries no trust bundle".into()))
        }
        (None, _) => req.creds.bundle.clone(),
    };
    // Refresh the CA chain (best effort) for future anchors.
    if let Ok(cas) = client.cacerts().await {
        let pem: String = cas.iter().map(|c| x509::to_pem("CERTIFICATE", c)).collect();
        persist::write_atomic(&req.dir.join(CA_CHAIN), pem.as_bytes())?;
    }
    persist::write_atomic(&req.dir.join(OPERATIONAL_CRT), x509::to_pem("CERTIFICATE", &leaf_der).as_bytes())?;
    identity.commit_pending()?;
    Ok(EnrollOutcome {
        previous_serial: req.creds.operational.as_ref().map(CertInfo::serial_hex),
        certificate: leaf,
        bundle,
        reenroll,
        server_time: resp.server_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::software::SoftwareIdentity;

    #[test]
    fn credentials_selection() {
        let dir = tempfile::tempdir().unwrap();
        let id: SharedIdentity = Arc::new(SoftwareIdentity::ephemeral("dev-0000000000000001", "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"));
        let c = Credentials::load(dir.path(), &id, None, &dir.path().join("none.pem")).unwrap();
        assert!(c.current(0).is_none());
        assert!(c.operational_valid(0).is_none());
        let mut info = x509::CertInfo {
            der: vec![],
            kid: vec![1],
            not_before: 0,
            not_after: 100,
            subject_cn: None,
            subject_ou: vec![],
            issuer_der: vec![],
            subject_der: vec![],
            spki_der: vec![],
            spki_sha256: [0; 32],
            p256: None,
        };
        let creds = Credentials { bootstrap: Some(info.clone()), operational: None, bundle: None, anchors: vec![] };
        assert_eq!(creds.current(5).unwrap().1, KeySlot::Bootstrap);
        info.not_after = 50;
        let creds = Credentials { operational: Some(info), ..creds };
        assert_eq!(creds.current(5).unwrap().1, KeySlot::Operational);
        assert_eq!(creds.current(60).unwrap().1, KeySlot::Bootstrap);
        assert!(creds.current(200).is_none());
        assert_eq!(EnrollError::NotProvisioned("x".into()).http_status(), 0);
        assert!(EnrollError::Invalid("bad".into()).reason().contains("bad"));
        assert!(Credentials::install_bootstrap(dir.path(), &id, b"junk").is_err());
    }
}
