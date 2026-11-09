//! The cloud side of the suite.
//!
//! [`Cloud`] is what the cases talk to. Its default backend is the **hermetic cloud**: an rcgen
//! PKI, an EST server, a registry double, an MQTT 5 broker double and an OTA artifact server, all
//! in-process, plus the **real policy service** binary as a subprocess (every CONNECT, PUBLISH and
//! SUBSCRIBE is decided by it, and its revocation kick goes back to the broker double through the
//! EMQX management API). With `--pki-bin` the **real PKI service** replaces the in-process EST
//! server and CA ([`realpki`]). The `--stack` backend ([`stack`]) points the same cases at a real
//! deployment. Operations a backend cannot offer return [`Unsupported`], which the runner reports
//! as `not_applicable` with the reason.

pub mod broker;
pub mod downlink;
pub mod est;
pub mod jwt;
pub mod keys;
pub mod net;
pub mod ota;
pub mod pki;
pub mod policy;
pub mod realpki;
pub mod registry;
pub mod stack;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ironmesh_agent::wire::ids::{self, TopicClass};

use broker::{Broker, BrokerCerts, DenyAction};
use downlink::TenantSigner;
use est::{BundleSpec, EnrollRecord, EstServer};
use keys::HarnessKeys;
use ota::ArtifactServer;
use pki::{DeviceCertSpec, TestPki};
use policy::{PolicyClient, PolicyService, PolicySpawn, ReleaseEvent, RevocationEvent};
use realpki::RealPki;
use registry::{DeviceRecord, FakeRegistry};

/// The harness cannot offer an operation in the current mode; the case is not applicable.
#[derive(Debug, Clone)]
pub struct Unsupported(pub String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Unsupported {}

/// Shorthand for an [`Unsupported`] error.
#[must_use]
pub fn unsupported(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Unsupported(msg.into()))
}

/// What a device needs to reach the cloud (baked in at the factory).
#[derive(Debug, Clone)]
pub struct DeviceEndpoints {
    /// EST host (as devices address it).
    pub est_host: String,
    /// EST port.
    pub est_port: u16,
    /// Factory trust anchors (PEM): Root + Services CA.
    pub anchors_pem: String,
    /// Factory SPKI pins (hex) for the EST server before the bundle is known.
    pub est_pins_hex: Vec<String>,
    /// PKI bundle public key (hex Ed25519).
    pub bundle_pubkey_hex: String,
}

/// Options for starting the hermetic cloud.
#[derive(Debug, Clone)]
pub struct CloudOptions {
    /// Address the listeners bind to.
    pub bind_host: String,
    /// Host devices use to reach the listeners (server certificate SAN, bundle broker host).
    pub advertise_host: String,
    /// Policy service binary.
    pub policy_bin: PathBuf,
    /// Real PKI binary and `pkictl` (replace the in-process EST server / CA).
    pub real_pki: Option<(PathBuf, PathBuf)>,
    /// Persistent harness PKI directory (export-pki; HIL boards are provisioned from it).
    pub pki_dir: Option<PathBuf>,
    /// Fixed EST port (0: any; HIL firmware has the port in Kconfig).
    pub est_port: u16,
    /// Run directory (logs, state).
    pub run_dir: PathBuf,
    /// Repository root (vector keys).
    pub repo_root: PathBuf,
    /// Tenant id.
    pub tenant_id: String,
    /// Extra policy service environment (load tests: production cache TTLs, log level).
    pub policy_env: Vec<(String, String)>,
    /// Persistent hook connection pool size for the broker double (`None`: one connection per call).
    pub hook_pool: Option<usize>,
}

/// The enrollment authority of the hermetic backend.
pub enum Authority {
    /// In-process EST server and rcgen CAs.
    Builtin(EstServer),
    /// The real PKI service.
    Real(Box<RealAuthority>),
}

/// The real PKI and the endpoints devices use for it.
pub struct RealAuthority {
    /// The process.
    pub pki: tokio::sync::Mutex<RealPki>,
    /// Device endpoints.
    pub endpoints: DeviceEndpoints,
    /// The tenant policy provisioned through the PKI tenant-policy API (`GET /v1/tenants/{t}/policy`).
    pub tenant_policy: serde_json::Value,
    /// Authorization probe of the PKI management API: (`svc-ota` writing the command key, first
    /// use of a token, replay of the same token) HTTP statuses.
    pub authz_probe: (u16, u16, u16),
}

/// How a certificate is revoked (what the PKI publisher's event says).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeScope {
    /// One certificate (`POST /v1/certificates/{serial}/revoke`, `device_deny=false`). The policy
    /// service still deny-lists the device for the reasons `keyCompromise` / `cessationOfOperation`.
    Certificate {
        /// RFC 5280 reason name.
        reason: String,
    },
}

/// The hermetic backend.
pub struct Hermetic {
    /// Harness PKI (always present: rogue CAs, artifact server certificate, builtin authority).
    pub pki: Arc<TestPki>,
    /// Registry double + CRL distribution point.
    pub registry: Arc<FakeRegistry>,
    /// Enrollment authority.
    pub authority: Authority,
    /// Broker double.
    pub broker: Broker,
    /// Artifact server.
    pub artifacts: ArtifactServer,
    /// The real policy service.
    pub policy: tokio::sync::Mutex<PolicyService>,
    /// Client of the policy service.
    pub policy_client: PolicyClient,
    /// Host devices use.
    pub advertise_host: String,
}

/// Backends.
pub enum Backend {
    /// In-process doubles + real policy service (+ optionally the real PKI).
    Hermetic(Box<Hermetic>),
    /// A real deployment.
    Stack(Box<stack::Stack>),
}

/// Timing of one revocation.
#[derive(Debug, Clone)]
pub struct RevokeTiming {
    /// When the harness started the revocation.
    pub started: Instant,
    /// When the revocation call returned (policy `202` / PKI `200`).
    pub acknowledged: Instant,
    /// Path taken.
    pub path: String,
}

/// The cloud the cases run against.
pub struct Cloud {
    /// Tenant of every device of this run.
    pub tenant_id: String,
    /// Signing keys.
    pub keys: HarnessKeys,
    /// Downlink signer (tenant command key).
    pub signer: TenantSigner,
    /// Backend.
    pub backend: Backend,
    /// Run directory.
    pub run_dir: PathBuf,
    /// Bootstrap certificates issued in this run, by device.
    pub bootstraps: Mutex<HashMap<String, Vec<u8>>>,
}

fn reserve_port(host: &str) -> Result<u16> {
    policy::free_port(host)
}

impl Cloud {
    /// Build a cloud around a backend.
    #[must_use]
    pub fn new(tenant_id: String, keys: HarnessKeys, backend: Backend, run_dir: PathBuf) -> Self {
        Self {
            signer: TenantSigner::new(&tenant_id, keys.tenant.clone()),
            tenant_id,
            keys,
            backend,
            run_dir,
            bootstraps: Mutex::new(HashMap::new()),
        }
    }

    /// Start the hermetic cloud.
    ///
    /// # Errors
    /// Any component failing to start (notably the policy / PKI binaries).
    pub async fn start_hermetic(o: &CloudOptions) -> Result<Self> {
        std::fs::create_dir_all(&o.run_dir)?;
        let keys = HarnessKeys::load(&o.repo_root);
        let extra =
            if o.advertise_host == "127.0.0.1" || o.advertise_host == "localhost" { vec![] } else { vec![o.advertise_host.clone()] };
        let mut sans = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        sans.extend(extra.iter().cloned());
        // Real PKI: key ceremony first (the rogue CA impersonates its Services CA name).
        let material = match &o.real_pki {
            Some((_, pkictl)) => {
                Some(realpki::ceremony(pkictl, &o.run_dir.join("pki-data"), &sans).await.context("real PKI key ceremony")?)
            }
            None => None,
        };
        let pki = Arc::new(match &o.pki_dir {
            Some(dir) => TestPki::load(dir, &extra).with_context(|| format!("load the harness PKI from {}", dir.display()))?,
            None => TestPki::generate_with(&extra, material.as_ref().map(|m| m.services_cn.as_str()))?,
        });
        let registry_token = hex::encode(crate::util::random_bytes(16));
        let registry = Arc::new(FakeRegistry::start(&o.bind_host, registry_token).await?);
        registry.set_crl(pki.crl()?);
        let device_ca_file = o.run_dir.join("device-ca.pem");
        std::fs::write(&device_ca_file, crate::util::pem("CERTIFICATE", material.as_ref().map_or(&pki.device.der, |m| &m.device)))?;
        let services_ca_file = o.run_dir.join("services-ca.pem");
        std::fs::write(&services_ca_file, crate::util::pem("CERTIFICATE", material.as_ref().map_or(&pki.services.der, |m| &m.services)))?;
        // The policy service needs the broker's management API URL and the broker needs the policy
        // client: reserve the management port first, start the policy service, then the broker.
        let mgmt_port = reserve_port(&o.bind_host)?;
        let pki_ports = match material {
            Some(_) => Some((reserve_port(&o.bind_host)?, reserve_port(&o.bind_host)?)),
            None => None,
        };
        let crl_url = match pki_ports {
            Some((_, plain)) => format!("http://{}:{plain}/crl/device-ca.crl", o.bind_host),
            None => format!("{}/crl/device-ca.crl", registry.url()),
        };
        let emqx_key = format!("conformance-{}", hex::encode(crate::util::random_bytes(4)));
        let emqx_secret = hex::encode(crate::util::random_bytes(16));
        let svc = PolicyService::spawn(PolicySpawn {
            binary: o.policy_bin.clone(),
            host: o.bind_host.clone(),
            emqx_api_url: format!("http://{}:{mgmt_port}", o.bind_host),
            emqx_key: emqx_key.clone(),
            emqx_secret: emqx_secret.clone(),
            registry_url: registry.url(),
            registry_token: registry.token.clone(),
            crl_url,
            crl_issuer_file: device_ca_file,
            services_ca_file: Some(services_ca_file),
            state_dir: o.run_dir.join("policy-state"),
            log_file: o.run_dir.join("policy.log"),
            extra_env: o.policy_env.clone(),
        })
        .await
        .context("start the policy service")?;
        let policy_client = match o.hook_pool {
            Some(n) => svc.client.clone().with_hook_pool(n)?,
            None => svc.client.clone(),
        };
        let certs = match &material {
            Some(m) => {
                let mut c = BrokerCerts::hermetic(&pki);
                c.normal = m.broker_identity();
                c.client_anchors = vec![m.root.clone(), m.device.clone()];
                c.service_client = Some(m.registry_client.leaf());
                c
            }
            None => BrokerCerts::hermetic(&pki),
        };
        let broker =
            Broker::start_with_mgmt(&o.bind_host, mgmt_port, certs, policy_client.clone(), DenyAction::Disconnect, emqx_key, emqx_secret)
                .await?;
        let cloud_signer_pub = TenantSigner::new(&o.tenant_id, keys.tenant.clone()).public();
        let fw_keys = vec![keys.firmware.verifying_key().to_bytes().to_vec()];
        let artifacts = match &material {
            Some(m) => ArtifactServer::start_with(&o.bind_host, &o.advertise_host, m.artifacts.rustls()).await?,
            None => ArtifactServer::start(&o.bind_host, &o.advertise_host, &pki).await?,
        };
        let authority = match (material, &o.real_pki) {
            (Some(m), Some((bin, pkictl))) => {
                let wiring = realpki::Wiring {
                    host: o.bind_host.clone(),
                    sans: sans.clone(),
                    policy_url: policy_client.base.clone(),
                    policy_token: policy_client.pki_token.clone(),
                    policy_hmac: String::from_utf8_lossy(&policy_client.pki_hmac).into_owned(),
                    registry_url: registry.url(),
                    registry_token: registry.token.clone(),
                    broker_host: o.advertise_host.clone(),
                    broker_port: broker.addr.port(),
                    log_file: o.run_dir.join("pki.log"),
                };
                let (mtls, plain) = pki_ports.unwrap_or((0, 0));
                let real = RealPki::spawn_on(bin, pkictl, m, &wiring, mtls, plain).await.context("start the real PKI service")?;
                // Tenant policy through the PKI tenant-policy API, as the owning services do, before any
                // device enrolls: the bundles then carry the harness's command key and firmware key.
                let tenant_policy = real
                    .provision_tenant(&o.tenant_id, &cloud_signer_pub, &fw_keys)
                    .await
                    .context("provision the tenant policy through the PKI tenant-policy API")?;
                let authz_probe = real.probe_authorization(&o.tenant_id).await.context("PKI management API authorization probe")?;
                let ep = DeviceEndpoints {
                    est_host: o.advertise_host.clone(),
                    est_port: real.mtls_port,
                    anchors_pem: format!(
                        "{}{}",
                        crate::util::pem("CERTIFICATE", &real.material.root),
                        crate::util::pem("CERTIFICATE", &real.material.services)
                    ),
                    est_pins_hex: vec![hex::encode(pki::spki_sha256(&real.material.services)?)],
                    bundle_pubkey_hex: hex::encode(real.material.bundle_pubkey),
                };
                Authority::Real(Box::new(RealAuthority { pki: tokio::sync::Mutex::new(real), endpoints: ep, tenant_policy, authz_probe }))
            }
            _ => Authority::Builtin(
                EstServer::start(
                    &o.bind_host,
                    o.est_port,
                    pki.clone(),
                    registry.clone(),
                    o.tenant_id.clone(),
                    BundleSpec {
                        tenant_cmd_pubkey: cloud_signer_pub,
                        fw_signing_pubkeys: fw_keys,
                        broker_host: o.advertise_host.clone(),
                        broker_port: broker.addr.port(),
                    },
                )
                .await?,
            ),
        };
        Ok(Self::new(
            o.tenant_id.clone(),
            keys,
            Backend::Hermetic(Box::new(Hermetic {
                pki,
                registry,
                authority,
                broker,
                artifacts,
                policy: tokio::sync::Mutex::new(svc),
                policy_client,
                advertise_host: o.advertise_host.clone(),
            })),
            o.run_dir.clone(),
        ))
    }

    /// Mode name.
    #[must_use]
    pub fn mode(&self) -> &'static str {
        match &self.backend {
            Backend::Hermetic(h) if matches!(h.authority, Authority::Real(..)) => "hermetic + real PKI",
            Backend::Hermetic(_) => "hermetic",
            Backend::Stack(_) => "stack",
        }
    }

    /// Why downlinks / firmware cannot be trusted by devices in this mode (`None`: they can). With
    /// the real PKI the tenant command key and firmware keys are provisioned through its
    /// tenant-policy API at start-up, so its bundles carry them.
    #[must_use]
    pub fn bundle_limits(&self) -> Option<String> {
        match &self.backend {
            Backend::Stack(s) if !s.has_tenant_key() => Some("the stack's tenant command key is not configured (--stack-config)".into()),
            _ => None,
        }
    }

    /// Environment lines describing how the hardened services were wired and probed at start-up:
    /// CA files and JWT settings of the policy service, the single-use check of its management
    /// API, and with the real PKI the tenant policy it stores and its authorization probe.
    pub async fn wiring_report(&self) -> Vec<(String, String)> {
        let Backend::Hermetic(h) = &self.backend else { return Vec::new() };
        let mut out = vec![(
            "policy_wiring".to_string(),
            "authn bodies carry cert_pem + cert_serial (emqx.conf template); POLICY_REQUIRE_CERT_SERIAL=true, POLICY_DEVICE_CA_FILE / \
             POLICY_SERVICES_CA_FILE set, POLICY_JWT_PUBLIC_KEY_PEM + POLICY_JWT_SINGLE_USE=true; svc-registry authenticated with a \
             Services CA client certificate"
                .to_string(),
        )];
        match h.policy_client.replay_mgmt_token().await {
            Ok((a, b)) => out.push((
                "policy_mgmt_jwt_single_use".into(),
                format!("GET /v1/revocations with one token twice -> {a} then {b} (want 200 then 401)"),
            )),
            Err(e) => out.push(("policy_mgmt_jwt_single_use".into(), format!("probe failed: {e:#}"))),
        }
        if let Authority::Real(ra) = &h.authority {
            let (owner, first, replay) = ra.authz_probe;
            out.push(("pki_tenant_policy".into(), format!("provisioned via the PKI tenant-policy API: {}", ra.tenant_policy)));
            out.push((
                "pki_mgmt_authorization".into(),
                format!(
                    "svc-ota PUT command-key -> {owner} (want 403); one operator token used twice -> {first} then {replay} (want 200 then 401)"
                ),
            ));
            out.push(("pki_supersede_grace".into(), format!("{} s", realpki::SUPERSEDE_GRACE.as_secs())));
        }
        out
    }

    /// Base URL of the OTA artifact server (`ota.base_url` / download allowlist of the devices).
    #[must_use]
    pub fn artifact_base_url(&self) -> Option<String> {
        match &self.backend {
            Backend::Hermetic(h) => Some(h.artifacts.base_url()),
            Backend::Stack(s) => s.artifact_base_url(),
        }
    }

    /// Host of [`Cloud::artifact_base_url`].
    #[must_use]
    pub fn artifact_host(&self) -> Option<String> {
        let url = self.artifact_base_url()?;
        let rest = url.split_once("://").map_or(url.as_str(), |(_, r)| r);
        let authority = rest.split('/').next().unwrap_or_default();
        let host = if let Some(v6) = authority.strip_prefix('[') {
            v6.split(']').next().unwrap_or_default()
        } else {
            authority.rsplit_once(':').map_or(authority, |(h, _)| h)
        };
        (!host.is_empty()).then(|| host.to_owned())
    }

    /// The hermetic backend, or [`Unsupported`].
    ///
    /// # Errors
    /// In `--stack` mode.
    pub fn hermetic(&self, what: &str) -> Result<&Hermetic> {
        match &self.backend {
            Backend::Hermetic(h) => Ok(h),
            Backend::Stack(_) => Err(unsupported(format!("{what} requires the hermetic cloud (not available in --stack mode)"))),
        }
    }

    /// The broker double, or [`Unsupported`].
    ///
    /// # Errors
    /// In `--stack` mode.
    pub fn broker(&self, what: &str) -> Result<&Broker> {
        Ok(&self.hermetic(what)?.broker)
    }

    /// Endpoints devices are provisioned with.
    #[must_use]
    pub fn endpoints(&self) -> DeviceEndpoints {
        match &self.backend {
            Backend::Hermetic(h) => match &h.authority {
                Authority::Builtin(est) => DeviceEndpoints {
                    est_host: h.advertise_host.clone(),
                    est_port: est.addr.port(),
                    anchors_pem: h.pki.device_anchors_pem(),
                    est_pins_hex: vec![hex::encode(h.pki.services.spki_pin())],
                    bundle_pubkey_hex: hex::encode(h.pki.bundle_key.verifying_key().to_bytes()),
                },
                Authority::Real(ra) => ra.endpoints.clone(),
            },
            Backend::Stack(s) => s.endpoints(),
        }
    }

    /// Factory: issue the bootstrap certificate for a device CSR (DER).
    ///
    /// # Errors
    /// Invalid CSR / issuance failure.
    pub async fn issue_bootstrap(&self, device_id: &str, csr_der: &[u8]) -> Result<Vec<u8>> {
        let der = match &self.backend {
            Backend::Hermetic(h) => match &h.authority {
                Authority::Builtin(_) => {
                    let (_, _, pk) = ironmesh_agent::x509::inspect_csr(csr_der).map_err(|e| anyhow!("bootstrap CSR: {e}"))?;
                    use p256::pkcs8::EncodePublicKey;
                    let spki = pk.to_public_key_der().map_err(|e| anyhow!("{e}"))?;
                    h.pki.issue_device_cert(
                        &DeviceCertSpec {
                            device_id: device_id.to_owned(),
                            tenant_id: self.tenant_id.clone(),
                            bootstrap: true,
                            software: false,
                            lifetime_s: 10 * 365 * 86_400,
                        },
                        spki.as_bytes(),
                    )?
                }
                Authority::Real(ra) => ra.pki.lock().await.issue_bootstrap(device_id, &self.tenant_id, csr_der).await?,
            },
            Backend::Stack(s) => s.issue_bootstrap(device_id, &self.tenant_id, csr_der).await?,
        };
        if let Ok(mut b) = self.bootstraps.lock() {
            b.insert(device_id.to_owned(), der.clone());
        }
        Ok(der)
    }

    /// Bootstrap certificate issued to `device_id` in this run.
    #[must_use]
    pub fn bootstrap_cert(&self, device_id: &str) -> Option<Vec<u8>> {
        self.bootstraps.lock().ok().and_then(|b| b.get(device_id).cloned())
    }

    /// Manufacture record in the registry (state `manufactured`).
    ///
    /// # Errors
    /// Registry failures.
    pub async fn register_device(&self, device_id: &str, se_type: &str, bootstrap_serial_hex: &str, product: &str) -> Result<()> {
        match &self.backend {
            Backend::Hermetic(h) => {
                h.registry.register(
                    device_id,
                    DeviceRecord {
                        tenant_id: self.tenant_id.clone(),
                        state: registry::MANUFACTURED.into(),
                        se_type: se_type.into(),
                        bootstrap_serial_hex: bootstrap_serial_hex.into(),
                        assurance_level: None,
                        product: product.into(),
                        certificates: Vec::new(),
                    },
                );
                Ok(())
            }
            Backend::Stack(s) => s.register_device(device_id, se_type, bootstrap_serial_hex, product).await,
        }
    }

    /// Quarantine a device like the registry (`POST /v1/devices/{id}/quarantine`): the lifecycle
    /// state change first, then the PKI revoke-all of the device's current certificates
    /// (`device_deny=true` events: the policy service deny-lists the device id and kicks its
    /// session). A device without operational certificates has nothing to revoke.
    ///
    /// # Errors
    /// Registry / PKI / policy failures.
    pub async fn quarantine(&self, device_id: &str) -> Result<()> {
        match &self.backend {
            Backend::Hermetic(h) => {
                h.registry.set_state(device_id, registry::QUARANTINED);
                match &h.authority {
                    Authority::Builtin(est) => {
                        let serials: Vec<String> =
                            est.records(device_id).into_iter().filter_map(|r| r.issued_serial_hex).filter(|s| !est.is_revoked(s)).collect();
                        for serial in serials {
                            self.builtin_revoke(h, est, device_id, &serial, "cessationOfOperation", true).await?;
                        }
                    }
                    Authority::Real(ra) => {
                        ra.pki.lock().await.revoke_all(device_id, "cessationOfOperation").await?;
                    }
                }
                Ok(())
            }
            Backend::Stack(s) => s.quarantine(device_id).await,
        }
    }

    /// Release a quarantined device (registry `POST /v1/devices/{id}/release`, API_CONTRACT §1.2):
    /// the registry double moves it to `active` (`409` unless quarantined), then the PKI release
    /// pushes the `device_release` event that lifts the policy service's device-level deny; the
    /// revoked certificates stay revoked, so the device must re-enroll.
    ///
    /// # Errors
    /// The registry refusing the release, or the PKI / policy rejecting the event.
    pub async fn release_device(&self, device_id: &str) -> Result<()> {
        let h = self.hermetic("releasing a device")?;
        let r = net::http_request(
            "POST",
            &format!("{}/v1/devices/{device_id}/release", h.registry.url()),
            &[("authorization", format!("Bearer {}", h.registry.token)), ("content-type", "application/json".into())],
            br#"{"note":"conformance release"}"#.to_vec(),
            None,
            Duration::from_secs(5),
        )
        .await?;
        if r.status != 200 {
            return Err(anyhow!("registry release answered {}: {}", r.status, r.text()));
        }
        match &h.authority {
            Authority::Builtin(_) => {
                h.policy_client
                    .publish_release(&ReleaseEvent {
                        event_id: format!("conformance-{}", crate::util::uuid4()),
                        event: "device_release".into(),
                        device_id: device_id.to_owned(),
                        tenant_id: self.tenant_id.clone(),
                        released_at: policy::rfc3339_now()?,
                    })
                    .await?;
            }
            Authority::Real(ra) => {
                ra.pki.lock().await.release(device_id, &self.tenant_id, "conformance release").await?;
            }
        }
        Ok(())
    }

    /// In-process authority: what the PKI's revoke does (store, CRL regenerated with the reason,
    /// signed event with `device_deny` pushed to the real policy service).
    async fn builtin_revoke(
        &self,
        h: &Hermetic,
        est: &EstServer,
        device_id: &str,
        serial_hex: &str,
        reason: &str,
        device_deny: bool,
    ) -> Result<()> {
        let serial = hex::decode(serial_hex)?;
        est.revoke(serial_hex);
        h.registry.set_crl(h.pki.revoke_with_reason(&serial, crl_reason(reason))?);
        let ev = RevocationEvent {
            event_id: format!("conformance-{}", crate::util::uuid4()),
            serial: serial_hex.to_owned(),
            device_id: device_id.to_owned(),
            tenant_id: self.tenant_id.clone(),
            reason: reason.to_owned(),
            revoked_at: policy::rfc3339_now()?,
            device_deny,
        };
        h.policy_client.publish_revocation(&ev).await?;
        Ok(())
    }

    fn builtin_est(&self, what: &str) -> Result<&EstServer> {
        match &self.hermetic(what)?.authority {
            Authority::Builtin(est) => Ok(est),
            Authority::Real(..) => {
                Err(unsupported(format!("{what} needs the in-process EST server (the real PKI handles EST in this run)")))
            }
        }
    }

    /// Operational certificate lifetime for one device (short-lived certificates, C-ROT-2).
    ///
    /// # Errors
    /// [`Unsupported`] with the real PKI / in `--stack` mode (the real PKI bounds the TTL to 7-30 d).
    pub fn set_cert_lifetime(&self, device_id: &str, seconds: u64) -> Result<()> {
        self.builtin_est("short-lived operational certificates (the real PKI bounds PKI_OPERATIONAL_CERT_TTL to 168h-720h)")?
            .set_lifetime(device_id, seconds);
        Ok(())
    }

    /// EST attempts of a device as seen by the in-process EST server.
    ///
    /// # Errors
    /// [`Unsupported`] with the real PKI / in `--stack` mode.
    pub fn enrollments(&self, device_id: &str) -> Result<Vec<EnrollRecord>> {
        Ok(self.builtin_est("inspecting EST requests")?.records(device_id))
    }

    /// The certificate with `serial_hex` (as issued).
    ///
    /// # Errors
    /// Unknown serial.
    pub async fn certificate(&self, serial_hex: &str) -> Result<Vec<u8>> {
        match &self.backend {
            Backend::Hermetic(h) => match &h.authority {
                Authority::Builtin(est) => {
                    est.issued(serial_hex).ok_or_else(|| anyhow!("no certificate with serial {serial_hex} was issued"))
                }
                Authority::Real(ra) => ra.pki.lock().await.certificate(serial_hex).await,
            },
            Backend::Stack(s) => s.certificate(serial_hex).await,
        }
    }

    /// The real PKI's record of one certificate (`GET /v1/certificates/{serial}`: `status`,
    /// `revocation.reason`, ...).
    ///
    /// # Errors
    /// [`Unsupported`] without a real PKI.
    pub async fn pki_certificate_record(&self, serial_hex: &str) -> Result<serde_json::Value> {
        match &self.hermetic("the PKI management API")?.authority {
            Authority::Real(ra) => ra.pki.lock().await.certificate_record(serial_hex).await,
            Authority::Builtin(_) => Err(unsupported("the PKI management API needs the real PKI")),
        }
    }

    /// Whether the enrollment authority revokes the previous certificate by itself after a
    /// renewal (the real PKI's supersede-on-renewal, `PKI_SUPERSEDE_GRACE`), and after how long.
    #[must_use]
    pub fn supersedes_on_renewal(&self) -> Option<Duration> {
        match &self.backend {
            Backend::Hermetic(h) if matches!(h.authority, Authority::Real(..)) => Some(realpki::SUPERSEDE_GRACE),
            _ => None,
        }
    }

    /// The PKI's records of a device (`GET /v1/devices/{id}/certificates`).
    ///
    /// # Errors
    /// [`Unsupported`] without a real PKI.
    pub async fn pki_device_certificates(&self, device_id: &str) -> Result<serde_json::Value> {
        match &self.hermetic("the PKI management API")?.authority {
            Authority::Real(ra) => ra.pki.lock().await.device_certificates(device_id).await,
            Authority::Builtin(_) => Err(unsupported("the PKI management API needs the real PKI")),
        }
    }

    /// Revoke the operational certificate `serial_hex` of `device_id`.
    ///
    /// In-process authority, exactly what the PKI does on `POST /v1/certificates/{serial}/revoke`:
    /// record the revocation, regenerate the CRL, and push the signed event to the real policy
    /// service (`POST /internal/v1/revocations`, bearer + HMAC), which deny-lists the device and
    /// kicks the session through the broker's EMQX management API. With the real PKI, its own
    /// revoke API is called and its publisher does the push.
    ///
    /// # Errors
    /// The policy service / PKI rejecting the request.
    pub async fn revoke(&self, device_id: &str, serial_hex: &str) -> Result<RevokeTiming> {
        self.revoke_with(device_id, serial_hex, &RevokeScope::Certificate { reason: "keyCompromise".into() }).await
    }

    /// Revoke one certificate with an explicit reason (`device_deny=false`, as the PKI's
    /// single-certificate revoke sends it).
    ///
    /// # Errors
    /// The policy service / PKI rejecting the request.
    pub async fn revoke_with(&self, device_id: &str, serial_hex: &str, scope: &RevokeScope) -> Result<RevokeTiming> {
        let RevokeScope::Certificate { reason } = scope;
        let started = Instant::now();
        match &self.backend {
            Backend::Hermetic(h) => match &h.authority {
                Authority::Builtin(est) => {
                    self.builtin_revoke(h, est, device_id, serial_hex, reason, false).await?;
                    Ok(RevokeTiming {
                        started,
                        acknowledged: Instant::now(),
                        path: format!(
                            "harness PKI (CRL regenerated, reason {reason}) -> signed POST /internal/v1/revocations \
                             (bearer + HMAC, device_deny=false) -> real policy -> EMQX API kick"
                        ),
                    })
                }
                Authority::Real(ra) => {
                    ra.pki.lock().await.revoke(serial_hex, reason).await?;
                    Ok(RevokeTiming {
                        started,
                        acknowledged: Instant::now(),
                        path: format!(
                            "real PKI POST /v1/certificates/{{serial}}/revoke (reason {reason}, single-use ES256 JWT) -> outbox -> \
                             PKI publisher (device_deny=false) -> real policy -> EMQX API kick"
                        ),
                    })
                }
            },
            Backend::Stack(s) => {
                s.revoke(serial_hex, reason).await?;
                Ok(RevokeTiming {
                    started,
                    acknowledged: Instant::now(),
                    path: "POST /v1/certificates/{serial}/revoke (real stack)".into(),
                })
            }
        }
    }

    /// Topic of a device.
    ///
    /// # Errors
    /// Invalid ids.
    pub fn topic(&self, device_id: &str, class: TopicClass) -> Result<String> {
        ids::build_topic(&self.tenant_id, device_id, class).map_err(|e| anyhow!("{e}"))
    }

    /// Publish a downlink to a device topic as the registry / OTA service.
    ///
    /// # Errors
    /// Policy denial or transport failure.
    pub async fn inject(&self, device_id: &str, class: TopicClass, payload: Vec<u8>, retain: bool) -> Result<usize> {
        let topic = self.topic(device_id, class)?;
        match &self.backend {
            Backend::Hermetic(h) => {
                // A downlink right after CONNACK may race the device's SUBSCRIBE.
                let _ = crate::util::wait_for(Duration::from_secs(3), || (h.broker.subscribers(&topic) > 0).then_some(())).await;
                Ok(h.broker.inject(&topic, payload, retain).await?.len())
            }
            Backend::Stack(s) => s.inject(&topic, payload, retain).await,
        }
    }

    /// Host an artifact; returns its HTTPS URL.
    ///
    /// # Errors
    /// [`Unsupported`] when no artifact server is available.
    pub fn host_artifact(&self, bytes: Vec<u8>) -> Result<String> {
        match &self.backend {
            Backend::Hermetic(h) => Ok(h.artifacts.put(bytes)),
            Backend::Stack(s) => s.host_artifact(bytes),
        }
    }

    /// Whether downlinks can be signed with a key the devices trust.
    #[must_use]
    pub fn can_sign_downlinks(&self) -> bool {
        self.bundle_limits().is_none()
    }

    /// Stop the subprocesses.
    pub async fn shutdown(&self) {
        if let Backend::Hermetic(h) = &self.backend {
            h.policy.lock().await.stop().await;
            if let Authority::Real(ra) = &h.authority {
                ra.pki.lock().await.stop().await;
            }
        }
    }

    /// Health check of the backend between cases.
    ///
    /// # Errors
    /// A subprocess died.
    pub async fn check_alive(&self) -> Result<()> {
        if let Backend::Hermetic(h) = &self.backend {
            if !h.policy.lock().await.alive() {
                return Err(anyhow!("the policy service process exited; see {}", self.run_dir.join("policy.log").display()));
            }
            if let Authority::Real(ra) = &h.authority {
                if !ra.pki.lock().await.alive() {
                    return Err(anyhow!("the PKI service process exited; see {}", self.run_dir.join("pki.log").display()));
                }
            }
        }
        Ok(())
    }
}

/// CRL reason code for an RFC 5280 reason name.
#[must_use]
pub fn crl_reason(name: &str) -> rcgen::RevocationReason {
    use rcgen::RevocationReason as R;
    match name {
        "unspecified" => R::Unspecified,
        "cACompromise" => R::CaCompromise,
        "affiliationChanged" => R::AffiliationChanged,
        "superseded" => R::Superseded,
        "cessationOfOperation" => R::CessationOfOperation,
        "certificateHold" => R::CertificateHold,
        "privilegeWithdrawn" => R::PrivilegeWithdrawn,
        "aACompromise" => R::AaCompromise,
        _ => R::KeyCompromise,
    }
}

/// Default per-step timeout.
pub const STEP: Duration = Duration::from_secs(20);
