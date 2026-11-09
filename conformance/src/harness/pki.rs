//! The hermetic test PKI (contract §2): Root (P-384), Factory (P-384), Device (P-256) and
//! Services (P-256) CAs built with rcgen, a self-signed *rogue* "IronMesh Services CA" that no
//! device pins (C-TLS-2), server certificates for the broker / EST / artifact listeners, the
//! Ed25519 bundle key, and certificate profiles that mirror `services/pki/internal/ca`.

use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType,
    SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use crate::util;

/// Public base URL embedded in device certificates (CRL DP / AIA OCSP), like `PKI_PUBLIC_BASE_URL`.
pub const PUBLIC_BASE_URL: &str = "https://pki.ironmesh.test";

/// A certificate authority.
pub struct Ca {
    /// Display name.
    pub name: &'static str,
    /// Parameters (needed to sign with rcgen).
    pub params: CertificateParams,
    /// Private key.
    pub key: KeyPair,
    /// Certificate DER.
    pub der: Vec<u8>,
}

impl Ca {
    /// rcgen issuer handle.
    #[must_use]
    pub fn issuer(&self) -> Issuer<'_, &KeyPair> {
        // From the certificate itself, so CAs loaded from disk sign exactly like generated ones.
        Issuer::from_ca_cert_der(&CertificateDer::from(self.der.as_slice()), &self.key)
            .unwrap_or_else(|_| Issuer::from_params(&self.params, &self.key))
    }

    /// SHA-256 of the SubjectPublicKeyInfo (the pin format of the bundle, contract §4).
    #[must_use]
    pub fn spki_pin(&self) -> [u8; 32] {
        spki_sha256(&self.der).unwrap_or([0; 32])
    }

    /// PEM.
    #[must_use]
    pub fn pem(&self) -> String {
        util::pem("CERTIFICATE", &self.der)
    }
}

/// A leaf certificate and its PKCS#8 key.
#[derive(Clone)]
pub struct Leaf {
    /// Certificate DER.
    pub der: Vec<u8>,
    /// PKCS#8 private key DER.
    pub key_der: Vec<u8>,
}

impl Leaf {
    /// Leaf + issuing CA.
    #[must_use]
    pub fn chain(&self, ca: &Ca) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.der.clone()), CertificateDer::from(ca.der.clone())]
    }

    /// rustls private key.
    #[must_use]
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }
}

/// SHA-256 over a certificate's SPKI.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
    let (_, c) = x509_parser::parse_x509_certificate(cert_der).map_err(|e| anyhow!("parse certificate: {e}"))?;
    Ok(Sha256::digest(c.public_key().raw).into())
}

fn ca_params(cn: &str, ou: Option<&str>) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.distinguished_name.push(DnType::OrganizationName, "IronMesh");
    if let Some(ou) = ou {
        p.distinguished_name.push(DnType::OrganizationalUnitName, ou);
    }
    p.distinguished_name.push(DnType::CommonName, cn);
    p.serial_number = Some(SerialNumber::from_slice(&util::random_serial()));
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + time::Duration::days(365 * 5);
    p.use_authority_key_identifier_extension = true;
    Ok(p)
}

fn p384() -> Result<KeyPair> {
    Ok(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?)
}

fn p256() -> Result<KeyPair> {
    Ok(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?)
}

fn self_signed(name: &'static str, cn: &str, key: KeyPair, years: i64) -> Result<Ca> {
    let mut params = ca_params(cn, None)?;
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * years);
    params.use_authority_key_identifier_extension = false;
    let der = params.self_signed(&key)?.der().to_vec();
    Ok(Ca { name, params, key, der })
}

fn intermediate(name: &'static str, cn: &str, key: KeyPair, parent: &Ca, years: i64) -> Result<Ca> {
    let mut params = ca_params(cn, None)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * years);
    let der = params.signed_by(&key, &parent.issuer())?.der().to_vec();
    Ok(Ca { name, params, key, der })
}

/// Hosts every server certificate is valid for.
fn server_sans(extra: &[String]) -> Vec<String> {
    let mut v = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    for h in extra {
        if !v.contains(h) {
            v.push(h.clone());
        }
    }
    v
}

/// A `svc-*` client certificate (`CN=<cn>, OU=services, O=IronMesh`, clientAuth), the profile of
/// `pkictl issue-server` that the policy authn hook requires for service principals.
fn service_client_leaf(ca: &Ca, cn: &str) -> Result<Leaf> {
    let key = p256()?;
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::OrganizationName, "IronMesh");
    p.distinguished_name.push(DnType::OrganizationalUnitName, "services");
    p.distinguished_name.push(DnType::CommonName, cn);
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.serial_number = Some(SerialNumber::from_slice(&util::random_serial()));
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + time::Duration::days(90);
    p.use_authority_key_identifier_extension = true;
    let der = p.signed_by(&key, &ca.issuer())?.der().to_vec();
    Ok(Leaf { der, key_der: key.serialize_der() })
}

fn server_leaf(ca: &Ca, cn: &str, sans: &[String]) -> Result<Leaf> {
    let key = p256()?;
    let mut p = CertificateParams::new(sans.to_vec())?;
    p.distinguished_name.push(DnType::OrganizationName, "IronMesh");
    p.distinguished_name.push(DnType::OrganizationalUnitName, "services");
    p.distinguished_name.push(DnType::CommonName, cn);
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.serial_number = Some(SerialNumber::from_slice(&util::random_serial()));
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + time::Duration::days(90);
    p.use_authority_key_identifier_extension = true;
    let der = p.signed_by(&key, &ca.issuer())?.der().to_vec();
    Ok(Leaf { der, key_der: key.serialize_der() })
}

/// AuthorityInfoAccess with one OCSP accessLocation (rcgen has no first-class AIA support).
fn aia_ocsp_extension(url: &str) -> CustomExtension {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = body.len();
        if n < 0x80 {
            v.push(n as u8);
        } else if n < 0x100 {
            v.extend_from_slice(&[0x81, n as u8]);
        } else {
            v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(body);
        v
    }
    // id-ad-ocsp 1.3.6.1.5.5.7.48.1
    let oid = tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);
    let loc = tlv(0x86, url.as_bytes());
    let desc = tlv(0x30, &[oid, loc].concat());
    let aia = tlv(0x30, &desc);
    CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], aia)
}

/// A device certificate profile.
#[derive(Debug, Clone)]
pub struct DeviceCertSpec {
    /// Device id (CN).
    pub device_id: String,
    /// Tenant id (OU).
    pub tenant_id: String,
    /// Bootstrap (Factory CA) or operational (Device CA).
    pub bootstrap: bool,
    /// Software assurance (adds OU `assurance:software`, contract §10).
    pub software: bool,
    /// Lifetime in seconds.
    pub lifetime_s: u64,
}

/// A revoked serial, for the CRL.
#[derive(Debug, Clone)]
pub struct CrlEntry {
    /// Serial (big-endian, minimal).
    pub serial: Vec<u8>,
    /// Revocation time (Unix s).
    pub revoked_at: u64,
    /// CRL reason.
    pub reason: RevocationReason,
}

/// The hermetic PKI.
pub struct TestPki {
    /// Root CA (P-384).
    pub root: Ca,
    /// Factory CA (P-384): bootstrap certificates.
    pub factory: Ca,
    /// Device CA (P-256): operational certificates.
    pub device: Ca,
    /// Services CA (P-256): broker / EST / artifact server certificates. Devices pin its SPKI.
    pub services: Ca,
    /// Rogue self-signed CA impersonating the Services CA's name; never pinned.
    pub rogue: Ca,
    /// Rogue self-signed CA with its own name; never pinned.
    pub rogue_distinct: Ca,
    /// Broker server certificate (Services CA).
    pub broker: Leaf,
    /// Rogue broker certificate (rogue CA, impersonating name).
    pub rogue_broker: Leaf,
    /// Rogue broker certificate (rogue CA with a distinct name).
    pub rogue_distinct_broker: Leaf,
    /// EST server certificate (Services CA).
    pub est: Leaf,
    /// Artifact server certificate (Services CA).
    pub artifacts: Leaf,
    /// `svc-registry` client certificate (Services CA): the downlink publisher's MQTT identity.
    pub registry_client: Leaf,
    /// PKI bundle signing key (Ed25519, baked into firmware).
    pub bundle_key: ed25519_dalek::SigningKey,
    /// Revoked operational serials (CRL content).
    pub revoked: Mutex<Vec<CrlEntry>>,
    crl_number: Mutex<u64>,
}

impl TestPki {
    /// Generate the whole hierarchy. `extra_hosts` are added to every server certificate (for
    /// HIL runs where the device reaches the harness over the LAN).
    ///
    /// # Errors
    /// rcgen failures.
    pub fn generate(extra_hosts: &[String]) -> Result<Self> {
        Self::generate_with(extra_hosts, None)
    }

    /// Like [`TestPki::generate`]; `rogue_cn` is the subject CN the rogue CA impersonates
    /// (default: this PKI's Services CA name).
    ///
    /// # Errors
    /// rcgen failures.
    pub fn generate_with(extra_hosts: &[String], rogue_cn: Option<&str>) -> Result<Self> {
        let root = self_signed("root", "IronMesh Test Root CA", p384()?, 20)?;
        let factory = intermediate("factory", "IronMesh Test Factory CA", p384()?, &root, 10)?;
        let device = intermediate("device", "IronMesh Test Device CA", p256()?, &root, 5)?;
        let services = intermediate("services", "IronMesh Test Services CA", p256()?, &root, 5)?;
        let rogue = self_signed("rogue", rogue_cn.unwrap_or("IronMesh Test Services CA"), p256()?, 5)?;
        let rogue_distinct = self_signed("rogue-distinct", "Evil Corp Broker CA", p256()?, 5)?;
        let sans = server_sans(extra_hosts);
        Ok(Self {
            broker: server_leaf(&services, "mqtt", &sans)?,
            rogue_broker: server_leaf(&rogue, "mqtt", &sans)?,
            rogue_distinct_broker: server_leaf(&rogue_distinct, "mqtt", &sans)?,
            est: server_leaf(&services, "pki", &sans)?,
            artifacts: server_leaf(&services, "ota", &sans)?,
            registry_client: service_client_leaf(&services, "svc-registry")?,
            root,
            factory,
            device,
            services,
            rogue,
            rogue_distinct,
            bundle_key: ed25519_dalek::SigningKey::from_bytes(&util::random_bytes(32).try_into().map_err(|_| anyhow!("rng"))?),
            revoked: Mutex::new(Vec::new()),
            crl_number: Mutex::new(1),
        })
    }

    /// Persist the CAs, their keys and the bundle key (HIL stations provision boards from it).
    ///
    /// # Errors
    /// I/O.
    pub fn save(&self, dir: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        for ca in [&self.root, &self.factory, &self.device, &self.services] {
            std::fs::write(dir.join(format!("{}-ca.crt", ca.name)), ca.pem())?;
            std::fs::write(dir.join(format!("{}-ca.key.pem", ca.name)), ca.key.serialize_pem())?;
        }
        std::fs::write(dir.join("bundle.seed.hex"), hex::encode(self.bundle_key.to_bytes()))?;
        std::fs::write(dir.join("bundle.pub.hex"), hex::encode(self.bundle_key.verifying_key().to_bytes()))?;
        std::fs::write(dir.join("anchors.pem"), self.device_anchors_pem())?;
        std::fs::write(dir.join("est-pin.hex"), hex::encode(self.services.spki_pin()))?;
        Ok(())
    }

    /// Load a PKI written by [`TestPki::save`] (new server and rogue certificates are issued).
    ///
    /// # Errors
    /// Missing / invalid files.
    pub fn load(dir: &std::path::Path, extra_hosts: &[String]) -> Result<Self> {
        let ca = |name: &'static str| -> Result<Ca> {
            let pem = std::fs::read(dir.join(format!("{name}-ca.crt")))?;
            let der = util::pem_block(&pem, "CERTIFICATE").ok_or_else(|| anyhow!("{name}-ca.crt"))?;
            let key = KeyPair::from_pem(&std::fs::read_to_string(dir.join(format!("{name}-ca.key.pem")))?)?;
            let params = CertificateParams::new(Vec::<String>::new())?;
            Ok(Ca { name, params, key, der })
        };
        let seed: [u8; 32] =
            hex::decode(std::fs::read_to_string(dir.join("bundle.seed.hex"))?.trim())?.try_into().map_err(|_| anyhow!("bundle seed"))?;
        let (root, factory, device, services) = (ca("root")?, ca("factory")?, ca("device")?, ca("services")?);
        let rogue = self_signed("rogue", &pki_cn(&services.der), p256()?, 5)?;
        let rogue_distinct = self_signed("rogue-distinct", "Evil Corp Broker CA", p256()?, 5)?;
        let sans = server_sans(extra_hosts);
        Ok(Self {
            broker: server_leaf(&services, "mqtt", &sans)?,
            rogue_broker: server_leaf(&rogue, "mqtt", &sans)?,
            rogue_distinct_broker: server_leaf(&rogue_distinct, "mqtt", &sans)?,
            est: server_leaf(&services, "pki", &sans)?,
            artifacts: server_leaf(&services, "ota", &sans)?,
            registry_client: service_client_leaf(&services, "svc-registry")?,
            root,
            factory,
            device,
            services,
            rogue,
            rogue_distinct,
            bundle_key: ed25519_dalek::SigningKey::from_bytes(&seed),
            revoked: Mutex::new(Vec::new()),
            crl_number: Mutex::new(1),
        })
    }
    /// Factory trust anchors given to devices: Root + Services CA (PEM).
    #[must_use]
    pub fn device_anchors_pem(&self) -> String {
        format!("{}{}", self.root.pem(), self.services.pem())
    }

    /// The pins of the trust bundle: Services CA and Root (as the real PKI does).
    #[must_use]
    pub fn bundle_pins(&self) -> Vec<[u8; 32]> {
        vec![self.services.spki_pin(), self.root.spki_pin()]
    }

    /// Issue a device certificate for `spki_der` (SubjectPublicKeyInfo DER).
    ///
    /// # Errors
    /// rcgen failures.
    pub fn issue_device_cert(&self, spec: &DeviceCertSpec, spki_der: &[u8]) -> Result<Vec<u8>> {
        let spki = rcgen::SubjectPublicKeyInfo::from_der(spki_der).context("subject public key")?;
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.distinguished_name.push(DnType::OrganizationName, "IronMesh");
        if spec.bootstrap {
            // Like pkictl issue-bootstrap: the tenant OU plus the bootstrap marker.
            p.distinguished_name.push(DnType::OrganizationalUnitName, spec.tenant_id.clone());
            p.distinguished_name.push(DnType::CustomDnType(vec![2, 5, 4, 11]), format!("bootstrap:{}", spec.tenant_id));
        } else {
            p.distinguished_name.push(DnType::OrganizationalUnitName, spec.tenant_id.clone());
            if spec.software {
                // rcgen keys the DN by attribute type; a second OU needs the OID spelled out.
                p.distinguished_name.push(DnType::CustomDnType(vec![2, 5, 4, 11]), "assurance:software");
            }
        }
        p.distinguished_name.push(DnType::CommonName, spec.device_id.clone());
        let urn = ironmesh_agent::x509::device_urn(&spec.tenant_id, &spec.device_id);
        p.subject_alt_names = vec![SanType::URI(urn.try_into().map_err(|e| anyhow!("urn: {e:?}"))?)];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.serial_number = Some(SerialNumber::from_slice(&util::random_serial()));
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::seconds(1);
        p.not_after = p.not_before + time::Duration::seconds(spec.lifetime_s as i64);
        p.use_authority_key_identifier_extension = true;
        if !spec.bootstrap {
            p.crl_distribution_points = vec![CrlDistributionPoint { uris: vec![format!("{PUBLIC_BASE_URL}/crl/device-ca.crl")] }];
            p.custom_extensions = vec![aia_ocsp_extension(&format!("{PUBLIC_BASE_URL}/ocsp"))];
        }
        let issuer = if spec.bootstrap { &self.factory } else { &self.device };
        Ok(p.signed_by(&spki, &issuer.issuer())?.der().to_vec())
    }

    /// Record a revocation and return the regenerated CRL.
    ///
    /// # Errors
    /// rcgen failures.
    pub fn revoke(&self, serial: &[u8]) -> Result<Vec<u8>> {
        self.revoke_with_reason(serial, RevocationReason::KeyCompromise)
    }

    /// Record a revocation with a CRL reason and return the regenerated CRL.
    ///
    /// # Errors
    /// rcgen failures.
    pub fn revoke_with_reason(&self, serial: &[u8], reason: RevocationReason) -> Result<Vec<u8>> {
        {
            let mut r = self.revoked.lock().map_err(|_| anyhow!("lock"))?;
            if !r.iter().any(|e| e.serial == serial) {
                r.push(CrlEntry { serial: serial.to_vec(), revoked_at: util::now_unix(), reason });
            }
        }
        self.crl()
    }

    /// The current Device CA CRL (DER), nextUpdate 24 h (contract §2).
    ///
    /// # Errors
    /// rcgen failures.
    pub fn crl(&self) -> Result<Vec<u8>> {
        let entries = self.revoked.lock().map_err(|_| anyhow!("lock"))?.clone();
        let number = {
            let mut n = self.crl_number.lock().map_err(|_| anyhow!("lock"))?;
            *n += 1;
            *n
        };
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now - time::Duration::seconds(1),
            next_update: now + time::Duration::hours(24),
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: entries
                .iter()
                .map(|e| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&e.serial),
                    revocation_time: time::OffsetDateTime::from_unix_timestamp(e.revoked_at as i64).unwrap_or(now),
                    reason_code: Some(e.reason),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        Ok(params.signed_by(&self.device.issuer())?.der().to_vec())
    }
}

fn pki_cn(der: &[u8]) -> String {
    cert_facts(der).ok().and_then(|f| f.cn).unwrap_or_default()
}

/// Parsed facts about a certificate the harness needs.
#[derive(Debug, Clone)]
pub struct CertFacts {
    /// Serial, minimal big-endian (the device kid, WIRE_FORMAT §3.3).
    pub serial: Vec<u8>,
    /// Lower-case hex of `serial`.
    pub serial_hex: String,
    /// Subject CN.
    pub cn: Option<String>,
    /// Subject OUs.
    pub ous: Vec<String>,
    /// RFC 4514 subject string, the way EMQX renders `${cert_subject}`.
    pub subject: String,
    /// Issuer RFC 4514 string.
    pub issuer: String,
    /// SHA-256 of the SPKI.
    pub spki_sha256: [u8; 32],
    /// Raw SubjectPublicKey bits (65-byte uncompressed point for P-256).
    pub public_key_raw: Vec<u8>,
    /// SPKI DER.
    pub spki_der: Vec<u8>,
    /// notBefore / notAfter (Unix s).
    pub not_before: u64,
    /// notAfter (Unix s).
    pub not_after: u64,
    /// SAN URIs.
    pub san_uris: Vec<String>,
}

/// Parse a certificate.
///
/// # Errors
/// Malformed DER.
pub fn cert_facts(der: &[u8]) -> Result<CertFacts> {
    use x509_parser::extensions::GeneralName;
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("parse certificate: {e}"))?;
    let serial = {
        let raw = c.raw_serial();
        let mut s = raw;
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        s.to_vec()
    };
    let cn = c.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).map(str::to_owned);
    let ous = c.subject().iter_organizational_unit().filter_map(|a| a.as_str().ok().map(str::to_owned)).collect();
    let mut san_uris = Vec::new();
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for n in &san.value.general_names {
            if let GeneralName::URI(u) = n {
                san_uris.push((*u).to_owned());
            }
        }
    }
    Ok(CertFacts {
        serial_hex: hex::encode(&serial),
        serial,
        cn,
        ous,
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        spki_sha256: Sha256::digest(c.public_key().raw).into(),
        public_key_raw: c.public_key().subject_public_key.data.to_vec(),
        spki_der: c.public_key().raw.to_vec(),
        not_before: c.validity().not_before.timestamp().max(0) as u64,
        not_after: c.validity().not_after.timestamp().max(0) as u64,
        san_uris,
    })
}

/// Whether `child_der` was issued by `ca` (issuer name match and signature verification).
#[must_use]
pub fn issued_by(child_der: &[u8], ca: &Ca) -> bool {
    let Ok((_, child)) = x509_parser::parse_x509_certificate(child_der) else { return false };
    let Ok((_, issuer)) = x509_parser::parse_x509_certificate(&ca.der) else { return false };
    child.issuer() == issuer.subject() && child.verify_signature(Some(issuer.public_key())).is_ok()
}

/// Parse an IP or host for logs.
#[must_use]
pub fn is_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_and_profiles() {
        let pki = TestPki::generate(&[]).unwrap();
        assert!(issued_by(&pki.factory.der, &pki.root));
        assert!(issued_by(&pki.device.der, &pki.root));
        assert!(issued_by(&pki.services.der, &pki.root));
        assert!(!issued_by(&pki.rogue.der, &pki.root));
        assert!(issued_by(&pki.broker.der, &pki.services));
        assert!(issued_by(&pki.rogue_broker.der, &pki.rogue));
        assert_ne!(pki.rogue.spki_pin(), pki.services.spki_pin(), "the rogue CA is not pinned");

        let key = p256::SecretKey::random(&mut rand::thread_rng());
        use p256::pkcs8::EncodePublicKey;
        let spki = key.public_key().to_public_key_der().unwrap();
        let tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";
        let spec = DeviceCertSpec {
            device_id: "dev-0011223344556677".into(),
            tenant_id: tenant.into(),
            bootstrap: false,
            software: true,
            lifetime_s: 600,
        };
        let op = pki.issue_device_cert(&spec, spki.as_bytes()).unwrap();
        assert!(issued_by(&op, &pki.device));
        let f = cert_facts(&op).unwrap();
        assert_eq!(f.cn.as_deref(), Some("dev-0011223344556677"));
        assert_eq!(f.ous, vec![tenant.to_string(), "assurance:software".to_string()]);
        assert_eq!(f.san_uris, vec![ironmesh_agent::x509::device_urn(tenant, "dev-0011223344556677")]);
        assert!((599..=601).contains(&(f.not_after - f.not_before)));
        assert_eq!(f.serial.len(), 16);
        assert!(f.subject.contains("CN=dev-0011223344556677") && f.subject.contains("O=IronMesh"), "{}", f.subject);
        // The agent's own parser agrees on the kid.
        let a = ironmesh_agent::x509::parse_cert(&op).unwrap();
        assert_eq!(a.kid, f.serial);
        assert_eq!(a.spki_sha256, f.spki_sha256);

        let boot = pki.issue_device_cert(&DeviceCertSpec { bootstrap: true, ..spec.clone() }, spki.as_bytes()).unwrap();
        assert!(issued_by(&boot, &pki.factory));
        assert_eq!(cert_facts(&boot).unwrap().ous, vec![tenant.to_string(), format!("bootstrap:{tenant}")]);

        let dir = tempfile::tempdir().unwrap();
        pki.save(dir.path()).unwrap();
        let loaded = TestPki::load(dir.path(), &[]).unwrap();
        assert_eq!(loaded.device.der, pki.device.der);
        assert_eq!(loaded.bundle_key.to_bytes(), pki.bundle_key.to_bytes());
        let op2 = loaded.issue_device_cert(&spec, spki.as_bytes()).unwrap();
        assert!(issued_by(&op2, &pki.device), "a loaded CA signs with the persisted key");
        assert!(issued_by(&loaded.broker.der, &pki.services));
        let crl = pki.revoke(&f.serial).unwrap();
        let (_, parsed) = x509_parser::parse_x509_crl(&crl).unwrap();
        assert_eq!(parsed.iter_revoked_certificates().count(), 1);
    }
}
