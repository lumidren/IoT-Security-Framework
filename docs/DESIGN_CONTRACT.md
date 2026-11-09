# IronMesh Design Contract

This document is the binding interface contract between every IronMesh component. Any change here is
a breaking change and must be reflected in `CHANGELOG.md`, the conformance suite, and both firmware
targets. Where this file and any other document disagree, this file wins.

## 1. Identifiers

| Entity    | Format                                  | Example                                   |
|-----------|-----------------------------------------|-------------------------------------------|
| Tenant    | UUIDv4 (lower-case, hyphenated)         | `7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11`    |
| Device    | `dev-` + 16 lower-case hex chars         | `dev-8f3a1c2b9d4e5f60`                    |
| Group     | slug `[a-z0-9-]{1,48}`                   | `eu-west-gateways`                        |
| Campaign  | UUIDv4                                   |                                           |
| Firmware  | `<product>/<semver>` + SHA-256 of image  | `gateway-rpi/2.4.1`                       |

The device id is **minted by the Registry at manufacture time** and embedded in the bootstrap
certificate. Devices never choose their own id. A device's identity for every authorization decision is
the id carried in the **verified X.509 certificate**, never a string in a payload or MQTT client id.

## 2. PKI hierarchy and certificate profiles

```
IronMesh Root CA (offline, 20 y, P-384)
├── IronMesh Factory CA   (online at factory, 10 y, P-384)  -> bootstrap certs (10 y)
├── IronMesh Device CA    (online, 5 y, P-256)              -> operational certs (14 d)
└── IronMesh Services CA  (online, 5 y, P-256)              -> broker/EST/API server certs (90 d)
```

Device key algorithm is **ECDSA P-256** everywhere (ATECC608 supports only P-256). All device
signatures are ECDSA/SHA-256 (`ES256`, COSE alg `-7`).

Operational (and bootstrap) device certificate profile:

| Field                     | Value                                                                 |
|---------------------------|-----------------------------------------------------------------------|
| Subject CN                | device id                                                             |
| Subject OU                | tenant id                                                             |
| Subject O                 | `IronMesh`                                                            |
| SAN URI                   | `urn:ironmesh:tenant:<tenant>:device:<device>`                        |
| Key usage                 | digitalSignature                                                      |
| Extended key usage        | clientAuth                                                            |
| Validity (operational)    | 14 days (`IRONMESH_OPERATIONAL_CERT_TTL`, bounded to 7–30 d)          |
| Validity (bootstrap)      | 10 years                                                              |
| CRL DP / AIA OCSP         | `https://pki.<domain>/crl/device-ca.crl`, `https://pki.<domain>/ocsp` |
| Serial                    | 128-bit random                                                        |

Bootstrap certificates additionally carry EKU `clientAuth` only and OU `bootstrap:<tenant>`; the
Device CA refuses to issue an operational cert unless the TLS client cert chains to the Factory CA
(first enrollment) or to the Device CA for the **same device id** (re-enrollment).

**Renewal**: devices call `simplereenroll` when `now >= notBefore + 50% lifetime` (so 7 days before
expiry) with jitter of up to 10% of lifetime. If renewal fails the device retries with exponential
backoff (base 60 s, cap 6 h) until expiry; after expiry it falls back to bootstrap enrollment.

**Revocation**: PKI writes to its `revocations` table, regenerates the CRL (next update 24 h, published
every 60 s or on change), answers OCSP with `revoked`, and **pushes** a signed revocation event to the
Policy service (`POST /internal/v1/revocations`) which (1) marks the device denied in its in-memory
cache and (2) kicks the live MQTT session via the EMQX management API. End-to-end budget: **< 10 s**
from `POST /v1/certificates/{serial}/revoke` to broker disconnect; the conformance suite asserts this.

## 3. Provisioning (EST, RFC 7030) and attestation

EST base path: `/.well-known/est`. Supported operations: `cacerts`, `csrattrs`, `simpleenroll`,
`simplereenroll`. Content types per RFC 7030 (`application/pkcs10` in, `application/pkcs7-mime;
smime-type=certs-only` out, base64 bodies). TLS client auth is mandatory on `simpleenroll` and
`simplereenroll`.

Attestation flow:

1. Device `GET /.well-known/est/ironmesh/nonce` (mTLS with bootstrap or current cert) ->
   `{"nonce": "<base64url 32 bytes>", "expires_at": "..."}`. Nonce TTL 120 s, single use.
2. Device generates a **new** P-256 key in the secure element (new slot or TPM transient object),
   builds a CSR (CN = device id from its cert, OU = tenant id).
3. Device builds an attestation COSE_Sign1 (see §5) signed by the **current identity key**
   (bootstrap key on first enrollment) over a CBOR map:
   `{1: nonce, 2: sha256(csr_der), 3: fw_hash(32 bytes), 4: fw_version(tstr), 5: se_type(tstr), 6: evidence}`
   where `se_type` is one of `atecc608`, `tpm2`, `optee`, `software`.
   `evidence` is `null` for `atecc608`/`software`; for `tpm2` it is `{1: quote(TPMS_ATTEST bytes),
   2: signature, 3: ak_cert_der}` over PCRs 0,2,4,7 with the nonce as qualifying data.
4. Device `POST /.well-known/est/simpleenroll` with header `X-IronMesh-Attestation: <base64 COSE>`.
5. Server verifies: TLS cert chain + revocation; CN matches CSR CN; nonce fresh and unused; csr hash
   binding; attestation signature by the TLS client key; `se_type` policy (tenant may require >=
   hardware assurance); TPM quote signature and PCR policy where applicable; device lifecycle state is
   `manufactured` or `provisioned` or `active` (never `quarantined`/`decommissioned`).
6. Server issues the cert, records `assurance_level` (`hardware` or `software`) on the device, and
   returns the certs-only PKCS#7. The response also carries header `X-IronMesh-Bundle` with a
   base64 CBOR map `{1: tenant_cmd_pubkey(32 bytes Ed25519), 2: fw_signing_pubkeys([bstr]), 3:
   broker_host, 4: broker_port, 5: ca_pins([bstr sha256 of SPKI])}` signed as COSE_Sign1 by the
   PKI's bundle key. Devices verify the bundle signature with the PKI bundle public key baked into
   firmware at factory time.

## 4. MQTT

* Protocol: MQTT 5.0 over TLS 1.3 only, ALPN `mqtt`, port 8883. TLS 1.2 and below are rejected.
* Mutual auth: broker requires a client cert chaining to the Device CA. Username is taken from the
  certificate CN by the broker (EMQX `peer_cert_as_username = cn`); client id MUST equal CN.
  Any CONNECT where client id != CN is rejected by the Policy service authn hook.
* Pinning: devices pin the SHA-256 of the **Services CA** SPKI (distributed in the bundle) and
  additionally require the broker cert SAN to match the configured host.
* Session: `clean_start=false`, session expiry interval 7 days, receive maximum 32, keep-alive 60 s.
* Reconnect backoff: exponential, base 1 s, factor 2, cap 300 s, full jitter.
* Offline buffering: devices persist telemetry in a ring buffer and replay it in order on
  reconnect; the `seq` field preserves ordering server-side. Linux agents keep up to 10 000
  messages. ESP32 devices keep a plaintext 1 MiB `storage` partition (about 2 048 records on 8 MiB
  flash): records are signed, not secret, and NOR bit-clear acknowledgements are incompatible with
  flash encryption. When the buffer is full the oldest records are overwritten and the gap is
  visible to the cloud as a `seq` jump.

Topic scheme (`<t>` = tenant id, `<d>` = device id). Devices publish to `pub` topics and subscribe to
`sub` topics; **all** other topics are denied by the Policy service.

| Topic                               | Dir  | QoS | Content                                  |
|-------------------------------------|------|-----|------------------------------------------|
| `im/v1/<t>/<d>/telemetry`           | pub  | 1   | COSE_Sign1(Telemetry)                    |
| `im/v1/<t>/<d>/events`              | pub  | 1   | COSE_Sign1(Event)                        |
| `im/v1/<t>/<d>/shadow/reported`     | pub  | 1   | COSE_Sign1(ShadowReported)               |
| `im/v1/<t>/<d>/cmd/ack`             | pub  | 1   | COSE_Sign1(CommandAck)                   |
| `im/v1/<t>/<d>/ota/status`          | pub  | 1   | COSE_Sign1(OtaStatus)                    |
| `im/v1/<t>/<d>/shadow/desired`      | sub  | 1   | COSE_Sign1(ShadowDesired) by tenant key  |
| `im/v1/<t>/<d>/cmd/req`             | sub  | 1   | COSE_Sign1(Command) by tenant key        |
| `im/v1/<t>/<d>/ota/notify`          | sub  | 1   | COSE_Sign1(OtaNotify) by tenant key      |
| `im/v1/<t>/<d>/config`              | sub  | 1   | COSE_Encrypt0 (per-device key wrap)      |

Retained messages are permitted only on `shadow/desired`, `ota/notify` and `config`, and `config`
is always ciphertext. Wildcards in device subscriptions are denied. Shared subscriptions are reserved
for the bridge (`$share/bridge/im/v1/#`) and are authenticated with a Services CA certificate whose
CN is `svc-bridge`.

## 5. Payload envelope (CBOR + COSE)

Every device <-> cloud message is a `COSE_Sign1` (RFC 9052, tag 18) with:

* protected header: `{1: -7 (ES256) | -8 (EdDSA), 4: kid}` where `kid` is the cert serial (bstr) for
  devices and `tenant-cmd-<tenant>` (tstr) for cloud-originated messages.
* unprotected header: empty.
* payload: canonical (deterministic) CBOR map with integer keys:

| Key | Name       | Type        | Rule                                                        |
|-----|------------|-------------|-------------------------------------------------------------|
| 1   | `seq`      | uint64      | strictly increasing per (device, direction); persisted       |
| 2   | `ts`       | uint (unix s)| receiver accepts `|now - ts| <= 300 s` else rejects; retainable downlink types 4, 7, 9 enforce only `ts - now <= 300 s` |
| 3   | `type`     | uint        | message type (see below)                                     |
| 4   | `body`     | map         | type-specific                                               |
| 5   | `nonce`    | bstr(16)    | present on `Command`/`CommandAck`; ack echoes command nonce   |

Message types: 1 Telemetry, 2 Event, 3 ShadowReported, 4 ShadowDesired, 5 Command, 6 CommandAck,
7 OtaNotify, 8 OtaStatus, 9 Config (inside Encrypt0), 10 Attestation.

**Replay protection**: receivers keep the last accepted `seq` per replay stream (server: in
Postgres per device; device: in NVS/keyring per tenant key **and downlink message type**, because
the registry signs types 4, 5, 9 and the OTA service signs type 7 with the same tenant key). Messages with `seq <= last` are dropped and counted
(`ironmesh_replay_rejected_total`). Devices persist `seq` before sending so a reboot never reuses one.

Telemetry body (`type=1`): `{1: cpu_pct(float), 2: mem_pct, 3: net_rx_bytes, 4: net_tx_bytes,
5: temp_c, 6: uptime_s, 7: auth_failures(uint), 8: fw_hash(bstr32), 9: fw_version(tstr),
10: proc_count(uint, Linux), 11: top_procs([tstr], Linux, max 10), 12: rssi(int, ESP32),
13: free_heap(uint, ESP32), 14: lat(float, optional), 15: lon(float, optional)}`.

Command body (`type=5`): `{1: cmd_id(tstr UUID), 2: name(tstr), 3: args(map), 4: idempotency_key(tstr),
5: expires_at(uint)}`. CommandAck body: `{1: cmd_id, 2: status(0 ok|1 rejected|2 failed|3 expired),
3: result(map), 4: error(tstr)}`.

OtaNotify body (`type=7`): `{1: campaign_id, 2: manifest(bstr: signed manifest, §6), 3: url(tstr),
4: delta_from(bstr32 or null)}`. OtaStatus body: `{1: campaign_id, 2: state(uint), 3: progress_pct,
4: error(tstr), 5: fw_hash(bstr32 after apply)}` with states 0 received, 1 downloading, 2 verifying,
3 applying, 4 rebooting, 5 success, 6 rolled_back, 7 rejected.

Config (`type=9`): the Registry wraps a fresh 256-bit AES key per message using **HPKE** (RFC 9180,
DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM) to the device's **current certificate public
key**, then AES-256-GCM encrypts the tenant-signed Config envelope (sign-then-encrypt). Encoded as
`COSE_Encrypt0` with protected `{1: 3 (A256GCM)}`; the HPKE `enc` and wrapped key travel in
header parameter `-70000`. `device/common/WIRE_FORMAT.md` fixes the exact byte layout. Plaintext config is
never retained on the broker.

## 6. Firmware image and manifest

Firmware artifact = `image.bin` + `manifest.cbor` + `manifest.sig`. The manifest is CBOR:

```
{1: product(tstr), 2: version(tstr semver), 3: version_code(uint, monotonic anti-rollback),
 4: image_sha256(bstr32), 5: image_size(uint), 6: created_at(uint), 7: min_version_code(uint),
 8: delta: null | {1: base_sha256(bstr32), 2: patch_sha256(bstr32), 3: patch_size(uint)},
 9: signing_key_id(tstr)}
```

Signature = `COSE_Sign1` over the manifest bytes with **two** signatures in a `COSE_Sign` (tag 98):
Ed25519 (alg -8) mandatory, ML-DSA-65 (alg -49, draft-ietf-cose-dilithium) optional; firmware
verifies Ed25519 always and ML-DSA when `IRONMESH_PQ_REQUIRED` is set. Devices accept an image only
if: all required signatures verify with a key in the bundle's `fw_signing_pubkeys`; `image_sha256`
matches the downloaded bytes; `version_code > current_version_code` (anti-rollback, also enforced by
ESP32 eFuse secure version); `product` matches. Delta patches use the IronMesh block-delta format
(`device/common/DELTA_FORMAT.md`): 4 KiB blocks, ops `COPY(old_block_index)` and `LITERAL(bytes)`.

A/B: the inactive slot is written, marked `pending`, the device reboots; the new image must call
`ota_mark_healthy()` within 120 s after passing its health checks (MQTT connected + telemetry
acked), otherwise the bootloader (ESP32 rollback / Linux agent `boot_count`) reverts.

## 7. Services, ports and APIs (local compose)

| Service       | Lang   | Port  | Notes                                                              |
|---------------|--------|-------|--------------------------------------------------------------------|
| emqx          | -      | 8883 mTLS, 18083 API | authn/authz via HTTP to `policy`                     |
| pki           | Go     | 8443 (EST+OCSP+API, mTLS), 8444 (CRL, plain) | KMS/SoftHSM backed                |
| policy        | Go     | 8081  | EMQX hooks, OPA (Rego) embedded, revocation cache, kick            |
| bridge        | Go     | 8082 (metrics) | `$share/bridge/im/v1/#` -> Redpanda topic `im.ingest`         |
| registry      | Python | 8000  | FastAPI; devices, twin, commands, tenants, audit, config           |
| ota           | Python | 8001  | FastAPI; artifacts, signing (KMS), campaigns, rollouts             |
| anomaly       | Python | 8002  | Kafka consumer, rules + Isolation Forest, quarantine, SIEM out     |
| console       | TS     | 3000  | Next.js 15                                                         |
| redpanda      | -      | 9092  | topics `im.ingest`, `im.auth`, `im.alerts`, `im.audit`             |
| postgres      | -      | 5432  | databases `registry`, `ota`, `pki`, `anomaly`                      |
| otel-collector| -      | 4317  | traces/metrics                                                     |

Internal service-to-service calls use mTLS with Services CA certs and a signed JWT (ES256,
`aud=<service>`, 5 min). Public APIs (console -> registry/ota) use OIDC bearer tokens; the console
never talks to the broker directly.

Device lifecycle states: `manufactured -> provisioned -> active -> quarantined -> active |
decommissioned`. `decommissioned` is terminal. Transitions are audited.

## 8. Tenancy

Every table carrying tenant data has `tenant_id uuid NOT NULL` and a Postgres **row-level security**
policy `tenant_id = current_setting('ironmesh.tenant_id')::uuid`. Services connect as a non-owner role
(`registry_app`) that cannot bypass RLS and set the tenant on every transaction. Cross-tenant tests
in each service prove isolation.

## 9. Observability names

Metrics prefix `ironmesh_`. Required: `ironmesh_connected_devices`, `ironmesh_auth_failures_total`,
`ironmesh_cert_expiring_total{window}`, `ironmesh_ota_result_total{result}`,
`ironmesh_anomaly_alerts_total{rule}`, `ironmesh_revocation_latency_seconds` (histogram),
`ironmesh_replay_rejected_total`. Logs: JSON, fields `ts, level, service, trace_id, span_id, tenant_id,
device_id, msg`. Traces: W3C traceparent propagated in MQTT 5 user property `traceparent`.

## 10. Assurance levels

| Level      | Key storage                                   | Cert OU marker  | Allowed by default? |
|------------|-----------------------------------------------|-----------------|---------------------|
| `hardware` | ATECC608, TPM 2.0, OP-TEE                     | (none)          | yes                 |
| `software` | encrypted NVS (ESP32) / OS keyring or file with 0600 + at-rest key (Linux) | `assurance:software` | tenant policy (`allow_software_keys`), **off** in prod profile |

Software-key devices are displayed with a warning badge in the console and excluded from
`hardware_only` groups.
