# IronMesh Service API Contract

Companion to `DESIGN_CONTRACT.md`. This file fixes the HTTP and WebSocket interfaces between the
fleet console and the cloud services, and between services. Services publish OpenAPI documents at
`/openapi.json` that must match this contract; the console's generated client (`console/src/lib/api/`)
is checked against those documents in CI.

## 0. Conventions

* Base URL per service: registry `:8000`, ota `:8001`, anomaly `:8002`, policy `:8081`, pki `:8443`.
  The console never calls services from the browser; Next.js route handlers under
  `/api/proxy/<service>/...` forward requests server-side with the user's access token.
* Authentication: `Authorization: Bearer <OIDC access token>` (JWT, verified against the IdP JWKS,
  `aud` must contain `ironmesh-api`). Tenant is derived from the token claim `tenant_id`; users with
  the platform role `platform_admin` may pass `X-IronMesh-Tenant: <uuid>` to act in another tenant
  (audited). Service-to-service calls run over mTLS and authenticate with either an ES256 JWT
  signed by the caller's Services CA key (`aud=<service name>`, `iss`/`sub` = caller, required
  `iat`, `exp` and `jti`, `exp - iat` at most 300 s; every receiver accepts a `jti` only once per
  instance, so callers mint a fresh token for every request, 60 s lifetime) or a static token
  bound to exactly one calling service (registry: `REGISTRY_INTERNAL_TOKENS`, a JSON map of
  caller -> token). Each internal endpoint names the callers it accepts; a token or JWT for any
  other service gets `403`.
* RBAC roles (per tenant): `owner`, `admin`, `operator`, `viewer`, `factory`. Mutations below list
  the minimum role. API keys (`imk_` prefix, SHA-256 stored) carry a role and optional scopes and are
  accepted in the same header.
* Pagination: `?cursor=<opaque>&limit=<1..200>` -> `{"items": [...], "next_cursor": "..."|null}`.
* Timestamps: RFC 3339 UTC strings. IDs as in `DESIGN_CONTRACT.md` §1.
* Errors: RFC 9457 problem details `{"type","title","status","detail","instance","errors":[...]}`.
  Validation errors `422`, auth `401`, forbidden `403`, conflict `409`, idempotency replay returns
  the original response with `Idempotency-Replayed: true`.
* Every mutation writes an audit event (`§1.9`).
* Request/response bodies are JSON (`application/json`), except firmware upload (multipart).

## 1. Registry (`services/registry`, port 8000)

### 1.1 Tenant
* `GET /v1/tenants/me` -> `Tenant {id, name, settings: {allow_software_keys: bool, auto_quarantine: bool,
  operational_cert_ttl_hours: int, default_group: str|null}, created_at}`
* `PATCH /v1/tenants/me/settings` (admin) body partial settings -> `Tenant`

### 1.2 Devices
`DeviceSummary {id, tenant_id, product, hw_revision, state: "manufactured"|"provisioned"|"active"|"quarantined"|"decommissioned",
assurance_level: "hardware"|"software"|null, se_type: "atecc608"|"tpm2"|"optee"|"software"|null,
groups: [slug], tags: {k: v}, connected: bool, last_seen_at, fw_version, fw_hash_hex,
cert: {serial_hex, not_after, status: "valid"|"expiring"|"expired"|"revoked"|"none"},
location: {lat, lon}|null, open_alerts: int}`

`DeviceDetail = DeviceSummary + {bootstrap_serial_hex, created_at, provisioned_at, activated_at,
quarantined_at, quarantine_reason, decommissioned_at, twin_version, last_telemetry: TelemetrySample|null,
certificates: [{serial_hex, not_before, not_after, revoked_at, revocation_reason, issuer}]}`

* `GET /v1/devices?state=&group=&tag=k:v&q=&connected=&assurance=&cursor=&limit=` -> page of `DeviceSummary`
* `POST /v1/devices` (factory|admin) body `{id?, product, hw_revision, se_type, bootstrap_serial_hex, tags?}`;
  if `id` omitted the registry mints `dev-<16 hex>`. -> `201 DeviceDetail` (state `manufactured`)
* `GET /v1/devices/{id}` -> `DeviceDetail`
* `PATCH /v1/devices/{id}` (operator) body `{tags?, groups?}` -> `DeviceDetail`
* `POST /v1/devices/{id}/quarantine` (operator) body `{reason}` -> `DeviceDetail`; side effects: PKI
  revoke-all, policy cache deny, EMQX kick; `409` if `decommissioned`.
* `POST /v1/devices/{id}/release` (admin) body `{note}` -> `DeviceDetail` (state `active`;
  device must re-enroll). `409` unless `quarantined`. Side effects: the registry calls the PKI
  `POST /v1/devices/{id}/release` (§5) while holding the device row, which pushes a
  `device_release` event to the policy service and lifts the quarantine's device-level deny; the
  certificates revoked by the quarantine stay revoked, so only a newly enrolled certificate is
  admitted at CONNECT. If the PKI is unreachable the device still becomes `active`, the call is
  queued in the action outbox (`pki_release`, retried with backoff, audited
  `device.pki_release_failed` / `action.pki_release.completed`) and the device stays refused at
  CONNECT until it succeeds; a later quarantine or decommission cancels a queued release. If the
  quarantine's own PKI revoke-all is still queued and the PKI still cannot complete it, the release
  is refused with `503` (`Retry-After: 30`) and the device stays `quarantined`.
* `POST /v1/devices/{id}/decommission` (admin) body `{reason}` -> `DeviceDetail` (terminal).
* `GET /v1/devices/{id}/timeline?from=&to=&kinds=&cursor=` -> page of
  `TimelineEvent {id, at, kind: "lifecycle"|"connect"|"disconnect"|"enroll"|"renew"|"revoke"|"command"|"ota"|"alert"|"config"|"twin"|"authz_denied", summary, data}`
* `GET /v1/devices/{id}/telemetry?from=&to=&metrics=cpu_pct,mem_pct,temp_c,net_rx_bytes,net_tx_bytes,rssi,free_heap&step=60s`
  -> `{series: [{metric, points: [[ts, value], ...]}]}` (max 2 000 points per metric)
* `GET /v1/devices/{id}/certificates` -> `[Certificate]` (proxied from PKI, cached 30 s)

### 1.3 Groups and tags
* `GET /v1/groups` -> `[Group {slug, name, description, hardware_only: bool, member_count, created_at}]`
* `POST /v1/groups` (operator) body `{slug, name, description?, hardware_only?}` -> `201 Group`
* `PATCH /v1/groups/{slug}` (operator) -> `Group`; `DELETE /v1/groups/{slug}` (admin) -> `204`
* `PUT /v1/groups/{slug}/members` (operator) body `{add: [device_id], remove: [device_id]}` ->
  `{added, removed, rejected: [{device_id, reason}]}` (`hardware_only` groups reject software devices)

### 1.4 Twin (shadow)
`Twin {device_id, version: int, desired: object, reported: object, delta: object, desired_updated_at, reported_updated_at}`
* `GET /v1/devices/{id}/twin` -> `Twin`
* `PATCH /v1/devices/{id}/twin/desired` (operator) body `{patch: object, expected_version?: int}` ->
  `Twin` (`409` on version mismatch). Publishes signed `ShadowDesired` (retained) to the device.
* `DELETE /v1/devices/{id}/twin/desired/{path}` (operator) -> `Twin`

### 1.5 Commands
`Command {cmd_id, device_id, name, args, idempotency_key, status: "pending"|"sent"|"acked"|"failed"|"rejected"|"expired",
created_by, created_at, sent_at, acked_at, expires_at, result, error}`
* `POST /v1/devices/{id}/commands` (operator) headers `Idempotency-Key` (or body `idempotency_key`)
  body `{name, args: object, ttl_s: 30..86400}` -> `202 Command`
* `GET /v1/devices/{id}/commands?status=&cursor=` -> page
* `GET /v1/commands/{cmd_id}` -> `Command`
* `POST /v1/groups/{slug}/commands` (operator) body as above -> `{batch_id, commands: [Command]}`

### 1.6 Device configuration (encrypted)
* `GET /v1/devices/{id}/config` -> `{version, config: object, delivered_at, acked_at}` (plaintext is
  shown only to `admin`+; stored encrypted at rest with the tenant data key)
* `PUT /v1/devices/{id}/config` (admin) body `{config: object}` -> `{version, published_at}`; the
  registry HPKE-wraps to the device's current certificate key and publishes `COSE_Encrypt0` retained
  on `.../config`.

### 1.7 Provisioning queue
* `GET /v1/provisioning?state=manufactured|provisioned|failed&cursor=` -> page of
  `ProvisioningItem {device_id, product, se_type, state, bootstrap_serial_hex, created_at, last_attempt_at,
  last_error, attempts}`
* `POST /v1/provisioning/{device_id}/approve` (operator) -> `DeviceSummary` (only needed when tenant
  setting `require_manual_approval` is true; otherwise enrollment auto-activates)
* `POST /v1/provisioning/{device_id}/reject` (operator) body `{reason}` -> `DeviceSummary`

### 1.8 Fleet overview
* `GET /v1/fleet/summary` ->
  `{devices_total, by_state: {state: n}, connected, disconnected, assurance: {hardware, software},
  certs: {expiring_24h, expiring_7d, expired, revoked}, firmware: [{version, count}],
  alerts_open: {critical, high, medium, low}, campaigns_running, map: [{device_id, lat, lon, state, open_alerts}]}`
* `GET /v1/fleet/health?window=1h` -> `{connect_rate, auth_failures, msgs_per_s, replay_rejected, p99_ingest_ms}`

### 1.9 Audit
`AuditEvent {id, at, tenant_id, actor: {type: "user"|"api_key"|"service"|"system", id, name}, action,
target: {type, id}, outcome: "success"|"failure", ip, request_id, details}`
* `GET /v1/audit?actor=&action=&target_type=&target_id=&from=&to=&cursor=` -> page (viewer+)
* `GET /v1/audit/export?from=&to=&format=ndjson` (admin) -> streamed NDJSON

### 1.10 Users, roles, API keys
* `GET /v1/users` (admin) -> `[User {id, email, name, role, last_login_at}]`
* `PUT /v1/users/{id}/role` (owner) body `{role}` -> `User`
* `GET /v1/api-keys` (admin) -> `[ApiKey {id, name, prefix, role, scopes, created_at, last_used_at, expires_at}]`
* `POST /v1/api-keys` (admin) body `{name, role, scopes?, expires_at?}` -> `201 {api_key: ApiKey, secret}` (secret shown once)
* `DELETE /v1/api-keys/{id}` (admin) -> `204`

### 1.11 WebSocket `GET /v1/ws`
Handshake: `POST /v1/ws/ticket` -> `{ticket, expires_in: 60}`; connect to `/v1/ws?ticket=...`.
Server sends JSON frames `{type, at, data}` for: `device.connected`, `device.disconnected`,
`device.state_changed`, `device.telemetry` (sampled, at most 1 frame/s/device), `twin.updated`,
`command.updated`, `alert.created`, `alert.updated`, `campaign.updated`, `provisioning.updated`,
`audit.created`. Client may send `{"type":"subscribe","topics":["device:<id>","fleet","campaign:<id>","alerts"]}`;
default subscription is `fleet` + `alerts`. Ping every 30 s.

### 1.12 Internal
* `GET /internal/v1/devices/{id}/lifecycle` (policy, anomaly) -> `{device_id, tenant_id, state, assurance_level, product}`
  (policy service; service JWT `aud=registry`)
* `POST /internal/v1/tenants/{tenant}/devices/resolve` (OTA) body `{groups: [slug], tags: {k: v},
  device_ids: [id], states?: [state]}` -> `{items: [{device_id, product, state, fw_version, fw_hash_hex,
  connected}]}`; resolves campaign targets (union of the three selectors, max 100 000 items).
* `POST /internal/v1/tenants/{tenant}/devices/{id}/downlink` (OTA) body `{type: "ota_notify",
  body: object (contract §5 OtaNotify body, bstr fields hex-encoded), retain: bool}` ->
  `{seq, published_at}`. The registry is the **only holder of the tenant command key**: it signs
  every downlink (ShadowDesired, Command, OtaNotify, Config) and publishes it. Other services never
  receive the private key.
* `POST /internal/v1/devices/{id}/enrolled` (PKI) body `{serial_hex, not_before, not_after, se_type, assurance_level, fw_version, fw_hash_hex}`
  -> transitions `manufactured -> provisioned -> active` and records the cert.
* `GET /internal/v1/tenants/{tenant}/devices/{id}` (PKI, during EST) -> `{device_id, tenant_id, state, assurance_level, se_type, bootstrap_serial}`
  where `bootstrap_serial` is the lower-case hex serial recorded at manufacture; `404` if the device is unknown in that tenant.
* `POST /internal/v1/tenants/{tenant}/devices/{id}/assurance` (PKI) body `{assurance_level}` -> `204`
* `POST /internal/v1/devices/{id}/quarantine` (anomaly) body `{reason, alert_id}` -> same as public.

## 2. OTA (`services/ota`, port 8001)

`Firmware {id, product, version, version_code, sha256_hex, size, created_at, created_by, signed_manifest_b64,
signing_key_id, pq_signed: bool, notes, severity: "normal"|"security"}`
`Stage {index, percent: 1..100, dwell_s, max_failure_rate: 0..1, state: "pending"|"running"|"dwelling"|"passed"|"halted", started_at, finished_at,
counts: {targeted, notified, downloading, verifying, applying, success, failed, rolled_back, rejected}}`
`Campaign {id, name, firmware: Firmware, target: {groups: [slug], device_ids: [id], tags: {k: v}}, delta: bool,
severity, stages: [Stage], current_stage: int, state: "draft"|"running"|"paused"|"halted"|"completed"|"rolled_back"|"cancelled",
halt_reason, created_by, created_at, started_at, finished_at, parent_campaign_id, totals: {...same keys as Stage.counts}}`

* `POST /v1/firmware` (admin) multipart: `image` (binary), `metadata` (JSON `{product, version, version_code, notes?, severity?}`)
  -> `201 Firmware` (service hashes, signs with KMS Ed25519 and optional ML-DSA, stores to object storage)
* `GET /v1/firmware?product=&cursor=` -> page; `GET /v1/firmware/{id}`; `GET /v1/firmware/by-hash/{sha256_hex}`
* `GET /v1/firmware/{id}/manifest` -> `application/cbor` signed manifest; `GET /v1/firmware/{id}/image` -> pre-signed URL redirect (302)
* `POST /v1/campaigns` (operator) body `{name, firmware_id, target, delta?, severity?, stages?}`;
  default stages `[{percent:1, dwell_s:3600, max_failure_rate:0.05}, {percent:10, dwell_s:3600, max_failure_rate:0.05}, {percent:100, dwell_s:0, max_failure_rate:0.05}]`
  -> `201 Campaign` (state `draft`)
* `GET /v1/campaigns?state=&cursor=` -> page; `GET /v1/campaigns/{id}` -> `Campaign`
* `POST /v1/campaigns/{id}/start|pause|resume|cancel` (operator) -> `Campaign`
* `POST /v1/campaigns/{id}/halt` (operator) body `{reason}` -> `Campaign`
* `POST /v1/campaigns/{id}/rollback` (admin) body `{reason}` -> `201 Campaign` (child campaign with
  re-signed previous image carrying a higher `version_code`)
* `GET /v1/campaigns/{id}/devices?state=&cursor=` -> page of
  `CampaignDevice {device_id, state, progress_pct, error, notified_at, updated_at, fw_hash_hex}`
* `GET /v1/campaigns/{id}/audit?cursor=` -> page of `AuditEvent`
* `GET /v1/signing-keys` -> `[{key_id, algorithm: "Ed25519"|"ML-DSA-65", public_key_b64, active, created_at}]`
* Internal: `POST /internal/v1/ota/status` (ingest path) body = decoded `OtaStatus` + device id;
  `GET /internal/v1/firmware/known-hashes?product=` -> `[sha256_hex]` (anomaly engine)

## 3. Anomaly (`services/anomaly`, port 8002)

`Alert {id, tenant_id, device_id, rule: "impossible_travel"|"auth_burst"|"topic_violation"|"fw_hash_mismatch"|"beaconing"|"isolation_forest",
severity: "critical"|"high"|"medium"|"low", score: float, features: object, explanation: str, created_at,
state: "open"|"acked"|"resolved", acked_by, resolved_by, actions: [{type: "quarantine"|"notify"|"none", at, result}]}`

* `GET /v1/alerts?state=&severity=&rule=&device_id=&from=&to=&cursor=` -> page
* `GET /v1/alerts/{id}` -> `Alert`
* `POST /v1/alerts/{id}/ack` (operator) body `{note}`; `POST /v1/alerts/{id}/resolve` (operator) body `{note, false_positive: bool}` -> `Alert`
* `GET /v1/rules` -> `[Rule {name, enabled, severity, params: object, description, dry_run: bool}]`
* `PUT /v1/rules/{name}` (admin) body `{enabled?, severity?, params?, dry_run?}` -> `Rule`
* `POST /v1/rules/{name}/dry-run` (operator) body `{from, to, params?}` -> `{would_fire: int, sample: [Alert]}`
* `GET /v1/devices/{id}/baseline` -> `{device_class, samples, trained_at, score_threshold, feature_means: object, recent_scores: [[ts, score]]}`
* `GET /v1/quarantine?cursor=` -> page of `{device_id, quarantined_at, reason, alert_id, by: "auto"|"user:<id>"}`
* `GET /v1/settings` / `PATCH /v1/settings` (admin) -> `{auto_quarantine: bool, quarantine_min_severity, siem: {ecs_webhook_url, syslog_host, syslog_port, enabled}}`

## 4. Policy (`services/policy`, port 8081)

Authentication: the console forwards the user's OIDC access token (verified against
`POLICY_OIDC_ISSUER` JWKS, `aud` contains `ironmesh-api`, role from the `role` claim); services may
instead present an ES256 service JWT with `aud=policy`.

* `GET /v1/policy` (admin) -> `{version, updated_at, updated_by, rego: str, sha256_hex}`
* `PUT /v1/policy` (owner) body `{rego: str, message: str}` -> validates (compiles, runs the embedded
  Rego test suite; refuses if any built-in invariant test fails) -> `{version, sha256_hex}`; `422`
  with compiler diagnostics on failure
* `POST /v1/policy/evaluate` (operator) body `{input: {clientid, username, tenant_id, device_id, kind, topic, action, qos, retain}}`
  -> `{result: "allow"|"deny", matched_rules: [str], trace: [str], evaluated_version}` (dry-run, never cached)
* `GET /v1/policy/history?cursor=` -> page of `{version, updated_at, updated_by, message, sha256_hex}`
* `GET /v1/revocations?cursor=` (viewer) -> page of `{serial_hex, device_id, tenant_id, reason, revoked_at, applied_at, kicked: bool}`

## 5. PKI management (`services/pki`, port 8443, mTLS + service JWT; console reaches it via registry proxy)

See `services/pki/README.md`: `POST /v1/certificates/{serial}/revoke`, `GET /v1/certificates/{serial}`,
`GET /v1/devices/{id}/certificates`, `POST /v1/devices/{id}/revoke-all`, `GET /v1/ca/chain`, `GET /v1/stats`.

* `POST /v1/devices/{id}/release` (registry only: Services CA cert CN `svc-registry` or service JWT
  `sub` `registry`/`svc-registry`; other callers `403`, independent of the CN allow list) body
  `{tenant_id, note?}` -> `202 {event_id, event: "device_release", device_id, tenant_id,
  released_at, published, publish_error?}`; `409` if the device's certificates belong to another
  tenant, `422` validation. Writes a `device_release` event into the revocation outbox (same
  durable delivery as revocations: signed with the bearer + `X-IronMesh-Signature` HMAC, retried
  with backoff, fanned out to every policy replica) as
  `POST <policy>/internal/v1/revocations` body `{event_id, event: "device_release", device_id,
  tenant_id, released_at}`. The policy service deduplicates by `event_id` and removes the
  device-level deny of every revocation with `revoked_at <= released_at`; serial-level denies stay.
  Revocation event bodies are unchanged and carry no `event` member.

Tenant policy (what the EST bundle carries and what enrollment allows); callers authenticate with
mTLS (Services CA, CN allowlist) or a service JWT, and each field has exactly one owner:

* `PUT /v1/tenants/{tenant}/command-key` (registry) body `{public_key_b64}` (32-byte Ed25519) -> `204`
* `PUT /v1/tenants/{tenant}/firmware-keys` (ota) body `{public_keys_b64: [..]}` (Ed25519 32 bytes
  and/or ML-DSA-65 1952 bytes) -> `204`
* `PUT /v1/tenants/{tenant}/enrollment` (registry) body `{allow_software_keys: bool}` -> `204`
* `GET /v1/tenants/{tenant}/policy` -> `{command_key_b64, firmware_keys_b64, allow_software_keys, updated_at}`

After issuing a certificate the PKI calls the registry's `POST /internal/v1/devices/{id}/enrolled`
synchronously; enrollment fails with `503` (and the certificate is revoked) if the registry cannot
record it, so a device is never `active` in the PKI but `manufactured` in the registry.

## 6. Event bus topics (Redpanda)

| Topic        | Key                 | Value (JSON unless noted)                                              | Producer | Consumers           |
|--------------|---------------------|------------------------------------------------------------------------|----------|---------------------|
| `im.ingest`  | `<tenant>/<device>` | raw COSE bytes + headers `mqtt_topic, tenant_id, device_id, msg_class, received_at, traceparent` | bridge | registry, ota, anomaly |
| `im.auth`    | `<clientid>`        | `{event: "connected"|"disconnected"|"authn_failed"|"authz_denied", clientid, peerhost, reason, topic?, action?, at}` | bridge (from EMQX webhook) | anomaly, registry |
| `im.alerts`  | `<tenant>/<device>` | `Alert`                                                                | anomaly  | registry (timeline, WS), SIEM forwarder |
| `im.audit`   | `<tenant>`          | `AuditEvent`                                                           | all      | registry (audit store), SIEM |
| `im.commands`| `<tenant>/<device>` | `{cmd_id, device_id, status, at}`                                       | registry | ota (campaign device state), anomaly |
| `im.campaigns`| `<tenant>`         | `{type: "campaign.updated", at, tenant_id, data: Campaign + {campaign_id}}` | ota      | registry (relayed to WebSocket `fleet` and `campaign:<id>`) |
