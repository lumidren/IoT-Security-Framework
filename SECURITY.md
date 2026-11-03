# Security Policy

## Supported versions

| Version line | Status                | Security fixes until |
|--------------|-----------------------|----------------------|
| 1.x          | Supported             | 2031-11-03 (5 years from 1.0.0 GA) |
| 0.x          | Pre-release, no support | n/a |

Firmware images and cloud services are versioned together. The defined support period for device
firmware built from this repository is **five years from the general-availability date of each major
version**, published here and in `CHANGELOG.md`, as required by ETSI EN 303 645 provision 5.3-13.

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public GitHub issue.

* Email: `security@ironmesh.dev` (PGP key fingerprint published at `https://ironmesh.dev/.well-known/security.txt`;
  a copy of `security.txt` is in `docs/security.txt`).
* GitHub: use the repository's **private vulnerability reporting** form
  (Security tab -> Report a vulnerability).

Include: affected component (firmware target, service, console), version or commit, reproduction
steps, impact assessment, and whether you believe the issue is being exploited.

### What to expect

| Step                                 | Target time            |
|--------------------------------------|------------------------|
| Acknowledgement                      | 2 business days        |
| Triage and severity (CVSS 4.0)       | 5 business days        |
| Fix for Critical/High                | 30 days                |
| Fix for Medium                       | 90 days                |
| Coordinated disclosure               | on fix release, or 90 days after report, whichever is first |

We credit reporters in the release notes unless they prefer to stay anonymous. We do not pursue
legal action against good-faith research that respects this policy, avoids privacy violations,
data destruction, and service disruption, and does not test against fleets you do not own.

## Scope

In scope: everything in this repository: device firmware (ESP32, Linux agent), PKI/EST/OCSP,
policy service and Rego policies, MQTT broker configuration, bridge, registry, OTA service, anomaly
engine, console, Helm chart, Terraform, CI workflows.

Out of scope: vulnerabilities in third-party dependencies that are already public and have no
IronMesh-specific exposure (report upstream; tell us if we are slow to update), social engineering,
physical attacks that require destructive access to a secure element.

## Security update delivery

* Services: signed container images (`cosign`) published to `ghcr.io/lumidren/ironmesh-*`; SBOMs
  (CycloneDX) are attached as image attestations.
* Firmware: signed images (Ed25519, optional ML-DSA-65) distributed through the OTA service with
  staged rollouts; devices verify signatures and anti-rollback counters before applying. Security
  updates are flagged `severity: security` in the OTA manifest metadata and bypass the default
  canary dwell time only when the operator explicitly approves.
* Advisories are published as GitHub Security Advisories with CVE identifiers where applicable.

## Hardening expectations for deployers

See `RUNBOOK.md` and `THREAT_MODEL.md`. In particular: keep the root CA offline, use the
`prod` firmware profile (Secure Boot v2, flash encryption, JTAG disabled), disable
`allow_software_keys` for production tenants, and enable auto-quarantine only after tuning rules in
dry-run mode.

## Cryptographic inventory

| Purpose                     | Algorithm                                  |
|-----------------------------|--------------------------------------------|
| Device identity             | ECDSA P-256 / SHA-256 (ES256)              |
| CA keys                     | ECDSA P-384 (root, factory), P-256 (device, services) |
| Transport                   | TLS 1.3 only, AEAD suites, ALPN `mqtt`     |
| Payload integrity           | COSE_Sign1 ES256 (device), EdDSA (cloud)   |
| Firmware signing            | Ed25519 + optional ML-DSA-65 hybrid        |
| Config confidentiality      | HPKE DHKEM(P-256)/HKDF-SHA256/AES-128-GCM + AES-256-GCM |
| Secrets at rest             | AES-256-GCM, keys in KMS/HSM               |
| Internal service auth       | mTLS + ES256 JWT (5 min)                   |
