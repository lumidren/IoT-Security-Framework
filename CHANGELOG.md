# Changelog

All notable changes to IronMesh are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Firmware `version_code` (anti-rollback counter) is
listed next to each firmware-affecting release.

## [Unreleased]

### Security
- **Revocation at the broker.** The policy authn hook now receives the client certificate
  (`cert_pem`, `cert_serial`) at MQTT CONNECT, checks its issuer (Device CA or Services CA) and
  refuses revoked serials as well as deny-listed device ids. A CONNECT without a serial is denied
  (`POLICY_REQUIRE_CERT_SERIAL`, default on). Superseded certificates are revoked by serial only, so
  a renewed device is never locked out (THREAT_MODEL T-13, T-37).
- **Durable revocation delivery.** PKI revocations and their policy events are written to a
  `revocation_outbox` in one transaction and retried until every policy replica has acknowledged
  them (`PKI_POLICY_FANOUT=dns` over the policy headless Service). New metric
  `ironmesh_revocation_outbox_pending` (T-26).
- **Device release.** Releasing a quarantined device now sends a `device_release` event through the
  PKI outbox that lifts the device-level deny on every policy replica; revoked serials stay revoked
  and the device re-enrolls (T-70).
- **Service-to-service tokens.** PKI, policy, registry and OTA accept a service JWT only with
  `iat`, `exp` and `jti`, a lifetime of at most 300 s and a `jti` not seen before on that instance;
  PKI and policy bind the token subject to a presented Services CA certificate; every caller mints a
  fresh token per request (T-50).
- **TLS 1.3 only** on the PKI listener (EST, OCSP, management) and on the new optional policy TLS
  listener (T-30).
- **Console.** Per-request nonce CSP without inline scripts, Origin/Referer checks on every
  mutation, SameSite=Strict session cookies, and step-up re-authentication (sign-in within 300 s)
  for quarantine, release, decommission, configuration, policy, API-key, role, tenant-setting and
  campaign start/halt/rollback actions (T-51, T-65).
- **Deployment.** EMQX management API (18083) reachable only from policy, registry, ota and
  Prometheus, and no longer from the VPC (the NLB health-checks 8883); per-client EMQX message and
  byte rate limits with the `BrokerClientQuotaExceeded` alert; services connect on a separate
  internal listener (8884); Kyverno `verifyImages` admission and deploy-by-verified-digest in
  production; SCRAM and per-service ACLs on the development Redpanda; narrower per-service egress
  (T-38, T-40, T-67, T-71, T-76).
- **Devices.** The Linux agent encrypts its offline buffer (AES-256-GCM), keeps an HMAC-sealed,
  fail-closed anti-rollback floor and a forward-only time floor from authenticated EST responses;
  both device implementations download OTA artifacts only from allowlisted hosts; the ESP32 pins
  EST like MQTT (T-09, T-10, T-29, T-57, T-60).
- **Configuration.** The retained device configuration is re-wrapped to the new certificate key on
  every enrollment and renewal (T-48).
- Threat model: T-26, T-29, T-30, T-51, T-60, T-67 and T-70 are now mitigated; T-48 moved from not
  mitigated to partially mitigated. Compliance: IEC 62443-4-2 CR 1.9 and CR 1.14 are now satisfied.

### Added
- Monorepo skeleton, Apache-2.0 license, binding design contract (`docs/DESIGN_CONTRACT.md`).
- Security policy with defined support period, contribution guide.
- PKI tenant-policy API (command key owned by the registry, firmware keys owned by OTA,
  software-key policy) and `POST /v1/devices/{id}/release`.
- PKI bundle signing key loaded from AWS Secrets Manager (`PKI_BUNDLE_KEY_SECRET_ARN`), separate
  migration and runtime database roles with forced row-level security, optional RDS IAM login.
- Optional TLS 1.3 listener for the policy service and `POLICY_OIDC_JWKS_URL` for issuers the
  service cannot reach directly.
- `healthcheck` subcommands for the PKI, policy and bridge images.
- ESP32 factory-provisioned EST pin (`tools/factory_provision.py --est-pin`) and
  `CONFIG_IRONMESH_OTA_HOST`; Linux agent `ota.allowed_hosts`.
- Kyverno image-verification policy in the Helm chart (`admission.imageVerification`) and a policy
  headless Service for revocation fan-out.

### Changed
- The registry is the only holder of tenant command keys; OTA requests OtaNotify signing from the
  registry. Tenant public keys and firmware keys reach the PKI through retried outboxes.
- The PKI reports each enrollment to the registry synchronously and revokes the new certificate if
  that report fails (the device retries after `Retry-After`).
- Deployments resolve release tags to image digests and deploy by digest only.
- EST on the ESP32 now fails closed when no pin is available.
- `PKI_SUPERSEDE_GRACE` (default 1 h) controls when a renewed device's previous certificate is
  revoked.

### Fixed
- Revocation pushes could be lost on a PKI restart and reached only one policy replica.
- A released device stayed denied at CONNECT by the quarantine's device-level deny.
- Supersede-on-renewal revocation was not wired in the PKI application.
- The Linux anti-rollback floor could be lowered by a failed or corrupted write.
- An empty OTA host allowlist on Linux accepted any host.
