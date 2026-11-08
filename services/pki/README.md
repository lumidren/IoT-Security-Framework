# IronMesh Device PKI (`services/pki`)

The Device PKI issues and revokes every certificate in IronMesh and is the trust anchor for
zero-touch provisioning. It implements [DESIGN_CONTRACT.md](../../docs/DESIGN_CONTRACT.md) §2
(hierarchy and profiles), §3 (EST + attestation), §7 (ports) and §9 (metrics).

```
IronMesh Root CA (offline, 20 y, P-384)
├── IronMesh Factory CA   (10 y, P-384)  -> bootstrap certs (10 y)          pkictl issue-bootstrap
├── IronMesh Device CA    (5 y, P-256)   -> operational certs (14 d)        EST simpleenroll/simplereenroll
└── IronMesh Services CA  (5 y, P-256)   -> broker/EST/API server certs      pkictl issue-server
```

Two binaries:

* `pki` – the service: EST (RFC 7030) with IronMesh attestation, OCSP responder and management
  API on the **mTLS listener (:8443)**; CRL, Prometheus metrics and health on the **plain
  listener (:8444)**.
* `pkictl` – offline ceremonies (root with Shamir quorum, intermediates, bundle key), factory
  issuance of bootstrap certificates, server certificates, and operator commands (revoke, crl,
  ocsp-check).

## Build and test

```sh
make build            # bin/pki, bin/pkictl (static, CGO_ENABLED=0)
make test             # go test ./... -race -cover
make cover            # per-package coverage + coverage.html
make lint             # golangci-lint (config in .golangci.yml)
```

Everything runs with `go test ./...` and no external dependencies: the store has an in-memory
implementation, the Registry and Policy services are faked, and `internal/testutil` builds a full
PKI (all four CAs, OCSP signer, bundle key, a test TPM attestation CA) behind `httptest` mTLS
servers. Postgres tests run only when `PKI_TEST_DATABASE_URL` is set; SoftHSM tests only with
`-tags pkcs11` and `SOFTHSM2_CONF`.

## Configuration (`pki`)

| Variable | Default | Meaning |
|---|---|---|
| `PKI_ENV` | `development` | `production` refuses `PKI_KMS=file` at startup (`requireProductionKMS`) |
| `PKI_LISTEN_MTLS` | `:8443` | EST, OCSP, management API (TLS, optional client certs) |
| `PKI_LISTEN_PLAIN` | `:8444` | `/crl/device-ca.crl`, `/metrics`, `/healthz`, `/readyz` |
| `PKI_DATABASE_URL` | – | Postgres DSN (pgx). Unset = in-memory store (dev only, warns) |
| `PKI_KMS` | `file` | `file` (dev only, warns), `softhsm` (PKCS#11, `-tags pkcs11`), `awskms` |
| `PKI_FILE_KMS_PASSPHRASE` | – | Passphrase for file-backed keys (Argon2id + AES-256-GCM) |
| `PKI_CA_DIR` | `./pki-data` | Directory written by `pkictl` (see layout below) |
| `PKI_KEY_DEVICE_CA` / `PKI_KEY_SERVICES_CA` | per backend | Key reference: file path, KMS alias/ARN or PKCS#11 label |
| `PKI_BUNDLE_KEY_FILE` | `<CA_DIR>/bundle.key.json` | Ed25519 bundle signing key (always file-backed; KMS has no Ed25519) |
| `PKI_OPERATIONAL_CERT_TTL` | `336h` | Operational cert lifetime, bounded **168h–720h** |
| `PKI_NONCE_TTL` | `120s` | Attestation nonce lifetime |
| `PKI_PUBLIC_BASE_URL` | `https://pki.ironmesh.local` | Base of the CRL DP / AIA OCSP URLs embedded in certs |
| `PKI_SERVER_CERT_FILE` / `PKI_SERVER_KEY_FILE` | – | Listener certificate; unset = issued at start from the Services CA |
| `PKI_SERVER_SANS` | `pki,pki.ironmesh.local,localhost,127.0.0.1` | SANs of the self-issued listener certificate |
| `PKI_POLICY_URL` / `PKI_POLICY_TOKEN` / `PKI_POLICY_HMAC_KEY` | – | Policy service for revocation push (HMAC key falls back to the token) |
| `PKI_REGISTRY_URL` / `PKI_REGISTRY_TOKEN` | – | Registry for lifecycle checks. Unset = every device treated as active (dev only, warns) |
| `PKI_MGMT_ALLOWED_CNS` | `svc-registry,svc-policy,svc-console` | Services CA client CNs allowed on the management API |
| `PKI_MGMT_JWT_PUBLIC_KEY_FILE` | – | PEM `PUBLIC KEY` blocks (P-256) trusted for ES256 bearer JWTs (`aud=pki`) |
| `PKI_DEFAULT_ALLOW_SOFTWARE_KEYS` | `false` | Policy for tenants without a stored policy |
| `PKI_TPM_AK_CA_FILE` / `PKI_TPM_ALLOWED_PCR_DIGESTS` | – | Service-wide TPM attestation CA bundle and hex PCR digests (merged into tenant policies) |
| `PKI_BROKER_HOST` / `PKI_BROKER_PORT` | `mqtt.ironmesh.local` / `8883` | Defaults for the trust bundle |
| `PKI_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PKI_SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown budget |

Logs are JSON (`ts, level, service, trace_id, span_id, tenant_id, device_id, msg`); the
`traceparent` request header is propagated into `trace_id`/`span_id`.

## Endpoints

mTLS listener (`PKI_LISTEN_MTLS`):

| Method & path | Auth | Description |
|---|---|---|
| `GET /.well-known/est/cacerts` | none | certs-only PKCS#7 (root, factory, device, services) |
| `GET /.well-known/est/csrattrs` | none | CsrAttrs: ecPublicKey, P-256, ecdsa-with-SHA256 |
| `GET /.well-known/est/ironmesh/nonce` | device cert | `{"nonce": "<base64url 32 B>", "expires_at": …}`; 120 s, single use, bound to the device |
| `POST /.well-known/est/simpleenroll` | **bootstrap** cert (Factory CA) | `application/pkcs10` base64 CSR + `X-IronMesh-Attestation` |
| `POST /.well-known/est/simplereenroll` | **operational** cert (Device CA), same device id | same |
| `POST /ocsp`, `GET /ocsp/{base64}` | none | RFC 6960 responder for Device CA certs; nonce echoed; delegated signer (EKU OCSPSigning); 60 s cache |
| `POST /v1/certificates/{serial}/revoke` | Services CA cert (allow-listed CN) or ES256 JWT `aud=pki` | `{"reason": "keyCompromise"}` → revocation result incl. `published` |
| `GET /v1/certificates/{serial}` | same | record + status (`valid`, `revoked`, `expired`) + PEM |
| `GET /v1/devices/{device_id}/certificates` | same | all certificates of a device |
| `POST /v1/devices/{device_id}/revoke-all` | same | revoke every current certificate |
| `GET /v1/ca/chain` | same | PEM bundle |
| `GET /v1/stats` | same | totals and expiring counts (24h/72h/7d) |

Plain listener (`PKI_LISTEN_PLAIN`): `GET /crl/device-ca.crl` (`application/pkix-crl`, `ETag`,
`Last-Modified`, 304 support; regenerated on every revocation and every 60 s; nextUpdate 24 h),
`GET /metrics`, `GET /healthz`, `GET /readyz`.

### Enrollment checks (contract §3 step 5)

1. TLS client chain (Factory CA for `simpleenroll`, Device CA for `simplereenroll`), certificate
   profile, validity and revocation state.
2. CSR signature; CN = device id and OU = tenant id of the client certificate; ECDSA P-256; a
   **fresh** key (not the identity key); SAN URI, if present, matches.
3. `X-IronMesh-Attestation` COSE_Sign1 (ES256) verified with the client certificate key; `kid`
   (when present) equals the certificate serial.
4. Nonce consumed atomically: unknown/used → 401, expired → 401, issued to another device → 401.
5. `sha256(csr_der)` binding → 400 on mismatch.
6. Tenant policy: `software` requires `allow_software_keys`; `tpm2` requires evidence whose AK
   certificate chains to the tenant's EK/AK CA, a TPMS_ATTEST quote (magic, `TPM_ST_ATTEST_QUOTE`,
   qualifying data = nonce), a valid ECDSA/RSASSA signature, PCR bank SHA-256 over exactly
   PCRs 0,2,4,7 and a `pcrDigest` on the allow list.
7. Registry lifecycle state in `manufactured | provisioned | active`.
8. Issue the operational certificate (profile per §2), record it with the assurance level, record
   the assurance level in the Registry, return the certs-only PKCS#7 plus `X-IronMesh-Bundle`
   (COSE_Sign1 by the Ed25519 bundle key over `{1: tenant_cmd_pubkey, 2: fw_signing_pubkeys,
   3: broker_host, 4: broker_port, 5: ca_pins}`).

Error codes follow RFC 7030: 400 malformed, 401 authentication (nonce, signatures, revoked), 403
policy/identity, 415 wrong content type, 429 rate limited (`Retry-After`).

### Threat-model controls (THREAT_MODEL.md)

| Control | Where | Behaviour |
|---|---|---|
| `rateLimit` | `internal/est/ratelimit.go` | Token buckets per source IP (300 burst, 1200/min) and per device (10 burst, 30/min) on the nonce and enrollment endpoints; 429 + `Retry-After` |
| `rejectReusedKey` | `internal/est/handler.go` | The CSR key must differ from every SPKI ever certified for the device (bootstrap and operational); reuse → 400 |
| `checkBootstrapSerialMatchesManufactureRecord` | `internal/est/identity.go` | First enrollment must present the bootstrap certificate serial the Registry recorded at manufacture (`bootstrap_serial`); mismatch → 403 |
| `checkSeTypeAgainstManufactureRecord` | `internal/est/handler.go` | The attested `se_type` must equal the Registry's manufacture record (`se_type`); mismatch → 403 |
| `supersedePrevious` | `internal/est/handler.go` | On successful `simplereenroll` the previous operational certificate is revoked (reason `superseded`) after a 1 h grace; the response carries `X-IronMesh-Previous-Revoked-At` |
| `requireProductionKMS` | `cmd/pki/main.go` | `PKI_ENV=production` with `PKI_KMS=file` refuses to start |

Registry records without `se_type` / `bootstrap_serial` (legacy devices) are not constrained by the
two manufacture-record checks. The supersede timer is in-process: a restart during the grace period
leaves the previous certificate valid until it expires (14 d) or is revoked manually.

### Revocation flow

`POST /v1/certificates/{serial}/revoke` writes the revocation, regenerates the CRL, invalidates
the OCSP cache and **synchronously** POSTs `{"event_id","serial","device_id","tenant_id","reason",
"revoked_at"}` to `PKI_POLICY_URL/internal/v1/revocations` with `Authorization: Bearer
<PKI_POLICY_TOKEN>` and `X-IronMesh-Signature: sha256=<hex HMAC-SHA256 over the body>`, retrying 3
times with 500 ms backoff. `ironmesh_revocation_latency_seconds` measures request → publish ack;
`ironmesh_revocation_publish_latency_seconds` the publish alone.

## Metrics

`ironmesh_cert_expiring_total{window="24h|72h|7d"}`, `ironmesh_revocation_latency_seconds`,
`ironmesh_revocation_publish_latency_seconds`, `ironmesh_revocation_publish_failures_total`,
`ironmesh_revocations_total{reason}`, `ironmesh_est_requests_total{op,code}`,
`ironmesh_certs_issued_total{kind}`, `ironmesh_auth_failures_total`,
`ironmesh_ocsp_requests_total{status}`, `ironmesh_crl_generations_total`,
`ironmesh_attestation_failures_total{reason}` plus Go/process collectors.

## Key ceremony (`pkictl`)

`PKI_CA_DIR` layout: `root-ca.crt`, `root-ca.key.json`, `root-share-<n>.txt`, `factory-ca.crt`,
`factory-ca.key.json`, `device-ca.crt`, `device-ca.key.json`, `services-ca.crt`,
`services-ca.key.json`, `bundle.key.json`, `bundle.pub.pem`, `chain.pem`.

```sh
export PKI_FILE_KMS_PASSPHRASE='…'          # never passed on the command line

# 1. Offline root, 3-of-5 quorum over the root key-encryption key (KEK).
pkictl init-root --dir ./pki-data --quorum-shares 5 --quorum-threshold 3
#    -> root-ca.crt, root-ca.key.json (AES-GCM under the KEK), root-share-1..5.txt
#    Hand each share to a different custodian; delete them from the ceremony machine.

# 2. Whenever the root must sign, custodians reconstruct the KEK (any 3 shares) and
#    re-wrap the root key under a session passphrase for the duration of the ceremony.
pkictl recover-root --dir ./pki-data --shares share-1.txt,share-3.txt,share-5.txt --out /tmp/root.key.json

# 3. Intermediates (keys in the chosen KMS: --kms file|awskms|softhsm, --key-ref …).
pkictl init-intermediate --dir ./pki-data --kind factory  --root-key /tmp/root.key.json
pkictl init-intermediate --dir ./pki-data --kind device   --root-key /tmp/root.key.json
pkictl init-intermediate --dir ./pki-data --kind services --root-key /tmp/root.key.json
shred -u /tmp/root.key.json

# 4. Bundle signing key (Ed25519); bake bundle.pub.pem into firmware.
pkictl init-bundle-key --dir ./pki-data

# 5. Factory flow. Software devices get a key + bootstrap cert; secure-element devices
#    submit a CSR for the key generated in the ATECC608 / TPM.
pkictl issue-bootstrap --dir ./pki-data --tenant 7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11 --device dev-8f3a1c2b9d4e5f60
pkictl issue-bootstrap --dir ./pki-data --tenant … --device dev-… --csr device.csr
#    -> devices/<device>.crt (+ factory CA), <device>.key.pem (software only), <device>.record.json

# 6. Server certificates for internal services (CN on the management allow list).
pkictl issue-server --dir ./pki-data --cn svc-registry --san registry,10.0.0.5

# Operator commands against a running service
pkictl revoke     --url https://pki:8443 --serial <hex> --reason keyCompromise --ca chain.pem --cert svc.crt --key svc.key
pkictl crl        --url http://pki:8444/crl/device-ca.crl
pkictl ocsp-check --url https://pki:8443/ocsp --cert-file device.crt --issuer pki-data/device-ca.crt --ca chain.pem
```

With `--kms awskms` the root/intermediate keys are created as `ECC_NIST_P256/P384` SIGN_VERIFY
keys and never leave KMS; quorum is then enforced by the KMS key policy, so `--quorum-*` applies
to the file backend only. With `--kms softhsm` (build tag `pkcs11`) keys are token-resident,
sensitive and non-extractable.

## Store

`internal/store.Store` (certificates, revocations, nonces, CRL number, tenant policies) has an
in-memory implementation and a Postgres implementation (`internal/store/postgres`, pgx v5) whose
migrations are embedded and applied at start under an advisory lock. Tables carry `tenant_id` and
row-level-security policies keyed on `ironmesh.tenant_id` (contract §8).

Tenant policy fields: `allow_software_keys`, `allowed_pcr_digests`, `ak_ca_pem`,
`tenant_cmd_pubkey`, `fw_signing_pubkeys`, `broker_host`, `broker_port`.
