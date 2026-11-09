# IronMesh OTA service

FastAPI service on port **8001** that stores firmware, signs manifests (Ed25519 + optional
ML-DSA-65), builds `IMDELTA1` patches and runs staged rollout campaigns. The binding specs are
`docs/DESIGN_CONTRACT.md` (§5 OtaNotify/OtaStatus, §6 manifest and A/B, §8 tenancy, §9 metrics),
`docs/API_CONTRACT.md` §2 and §6, `device/common/WIRE_FORMAT.md` and
`device/common/DELTA_FORMAT.md`. All wire encoding (manifest signing and verification, delta
make/apply, envelope signing, ML-DSA) comes from `libs/python/ironmesh-wire`; nothing is
reimplemented here.

## Layout

| Path | Contents |
|---|---|
| `src/ironmesh_ota/api/` | Routers: firmware, campaigns, internal, health/metrics |
| `services/firmware.py` | Upload, signing, pre-notify verification, delta generation, rollback re-sign |
| `services/rollout.py` | Stage engine, OtaNotify requests to the registry, status ingestion, halts, timeouts, redelivery |
| `services/key_sync.py` | Pushes the firmware public keys to the PKI tenant policy (outbox `pki_key_sync`) |
| `services/campaigns.py` | Campaign API operations: create/approve/start/pause/resume/cancel/halt/rollback |
| `controller.py` | Background rollout controller behind a Postgres advisory lock |
| `ingest.py` | `POST /internal/v1/ota/status` and the `im.ingest` consumer (`msg_class=ota_status`) |
| `signing.py`, `keytool.py` | `Signer` protocol, KMS-wrapped and passphrase-file key rings, rotation |
| `storage.py` | `ArtifactStore` protocol: S3 (conditional writes, Object Lock, SSE-KMS) and local FS |
| `repository/` | `Database` protocol, SQLAlchemy async + RLS implementation, in-memory fake |
| `migrations/` | Alembic schema with `FORCE ROW LEVEL SECURITY` and the `ota_app` role |
| `integrations/` | Registry (resolve + downlink), PKI (device keys, firmware-key policy), EMQX/MQTT (retained clears), Kafka and leader-lock adapters (protocol + fake each) |

## API

Every endpoint in API_CONTRACT §2 is implemented with the contract's field names (the console
schemas in `console/src/lib/api/schemas.ts` validate them). Errors are RFC 9457
`application/problem+json` with `errors: [{field, message}]`. Campaign mutations honour
`Idempotency-Key` and replay the stored response with `Idempotency-Replayed: true`.

| Method and path | Min. role |
|---|---|
| `POST /v1/firmware` (multipart `image` + `metadata`) | admin |
| `GET /v1/firmware`, `/v1/firmware/{id}`, `/v1/firmware/by-hash/{sha256_hex}` | viewer |
| `GET /v1/firmware/{id}/manifest` (`application/cbor`), `GET /v1/firmware/{id}/image` (302) | viewer |
| `GET /v1/signing-keys` | viewer |
| `POST /v1/campaigns`, `POST /v1/campaigns/{id}/start\|pause\|resume\|cancel\|halt\|approve` | operator |
| `POST /v1/campaigns/{id}/rollback` | admin |
| `GET /v1/campaigns`, `/{id}`, `/{id}/devices`, `/{id}/audit` | viewer |
| `POST /internal/v1/ota/status`, `GET /internal/v1/firmware/known-hashes?product=&tenant_id=` | service |
| `GET /healthz`, `/readyz`, `/metrics`, `/openapi.json` | none |

Extensions beyond the contract, all additive: `Campaign.requires_approval/approved_by/approved_at`,
`Firmware.min_version_code/rollback_of`, `CampaignDevice.stage_index/delta_from_hex`, the optional
`min_version_code` upload field and the four-eyes `approve` endpoint.

Authentication: OIDC access tokens (`aud` contains `ironmesh-api`, claims `sub`, `tenant_id`,
`role` or `roles`); `platform_admin` (in `platform_roles` or `roles`) may act in another tenant
via `X-IronMesh-Tenant`, which is flagged as `cross_tenant` in the audit details. Internal
endpoints accept an ES256 service JWT (`aud=ota`, `iat`/`exp`/`jti` required, at most 5 minutes,
caller in `OTA_INTERNAL_ALLOWED_SERVICES`; each `jti` is accepted once per instance while
`OTA_SERVICE_JWT_SINGLE_USE=true`, the default, remembered until `exp` + 30 s in a bounded cache of
`OTA_SERVICE_JWT_REPLAY_CACHE_SIZE` ids, default 100000) or the chart's shared
`OTA_INTERNAL_TOKEN`. Outgoing service JWTs (`iss=sub=ota`, to the registry and the PKI) are
minted fresh for every request (random `jti`, 60 s lifetime, never cached), because the PKI,
policy and registry reject a reused `jti`. API keys (`imk_…`)
are rejected with 401, since only the registry can verify them.

## Firmware, signing and storage

* **Upload** streams the multipart body: the image is hashed (SHA-256) and spooled to a private
  temp file as it arrives. The upload aborts with 413 once `OTA_MAX_IMAGE_BYTES` is exceeded, and
  metadata is capped at `OTA_MAX_METADATA_BYTES`. Product, semver and `version_code` are
  validated. `version_code` must **exceed every existing code for the product** in the tenant,
  checked again under a per-product advisory transaction lock, and duplicate versions return 409.
* **Manifest** (`WIRE_FORMAT.md` §6.1): field 9 carries `OTA_SIGNING_KEY_ID` (informational
  name). The API `signing_key_id` is the Ed25519 key id `SHA-256(pubkey)[0:8]` hex, the same value
  `/v1/signing-keys` lists. Every signature is checked once more with the wire library before it is
  stored, and the operation is audited as `firmware.sign` (key ids, purpose, manifest hash).
* **Keys**: `OTA_SIGNING_PROVIDER=kms-wrapped` fetches `OTA_SIGNING_KEY_SECRET_ARN` from Secrets
  Manager and unwraps it with `kms:Decrypt` under the symmetric CMK `OTA_SIGNING_KEK_KEY_ID`
  (default `alias/ironmesh-firmware-kek`, encryption context
  `{"purpose": "ironmesh-firmware-signing"}`). The seed exists only in memory. The secret holds a
  key ring JSON `{"version":1,"keys":[{algorithm, seed_b64, created_at, active}]}` or a bare
  32-byte Ed25519 seed. `OTA_SIGNING_PROVIDER=file` (dev only, refused in `OTA_ENV=prod`) reads a
  scrypt/AES-256-GCM encrypted key ring (`OTA_SIGNING_KEYRING_FILE` + `OTA_SIGNING_PASSPHRASE`)
  or a PKCS#8 PEM (`OTA_SIGNING_PRIVATE_KEY_PEM` / `OTA_SIGNING_KEY_FILE`, encrypted when a
  passphrase is set, generated when `OTA_SIGNING_KEY_GENERATE_IF_MISSING=true`).
* **Rotation**: `python -m ironmesh_ota.keytool rotate --file ring.json [--algorithm ML-DSA-65]`
  adds a new active key. Older keys stay listed and trusted, so images signed before the rotation
  still verify. `OTA_PQ_SIGNING_ENABLED` adds the ML-DSA-65 signature whenever the ring has an
  active ML-DSA key.
* **Artifacts** are written once. The S3 store uses `If-None-Match: *`, optional Object Lock
  (`OTA_S3_OBJECT_LOCK_MODE`/`_DAYS`, which needs a bucket created with Object Lock) and SSE-KMS
  (`OTA_S3_KMS_KEY_ARN`). Downloads use SigV4 pre-signed URLs. The filesystem store writes
  read-only files with atomic create-if-absent semantics and serves `/v1/artifacts/<key>?exp=&sig=`
  links signed with `OTA_DOWNLOAD_HMAC_SECRET`. Re-putting identical bytes is a no-op, and
  different bytes under the same key return 409.

## Rollouts

* **Targeting** is resolved at start time with the registry's
  `POST /internal/v1/tenants/{tenant}/devices/resolve` (API_CONTRACT §1.12). A device is targeted
  when it is in any listed group, listed by id, or carries all listed tags. Only `active` devices
  of the firmware's product qualify, and devices already running the image are skipped. Skipped
  devices and the reason are recorded in the `campaign.start` audit event.
* **Stages** default to 1% → 10% → 100% (dwell 3600/3600/0 s, max failure rate 0.05). Percents
  must be strictly increasing and end at 100. Each stage covers `ceil(N·p/100)` devices
  cumulatively. Devices are ordered by `SHA-256(campaign_id ":" device_id)`, so a re-run selects
  the same canary and the order does not depend on the registry's ordering.
* A stage is **notified**, then **dwells** once every device has a final outcome, then **passes**
  after `dwell_s`. Empty stages are skipped. The dwell timer only runs while the campaign is
  running.
* **Automatic halt**: when `(failed + rolled_back + rejected) / attempted > max_failure_rate`
  with at least `min(OTA_HALT_MIN_SAMPLE, stage size)` outcomes, or immediately on any
  `rolled_back` in the first stage. A halt clears the retained notify of devices that have not
  started. **Resume** after a halt only counts outcomes that arrive after the resume, and re-sends
  the withdrawn notifies.
* Devices that never report are marked `failed`/`TIMEOUT` after `OTA_DEVICE_TIMEOUT_S`. A later
  real report still records the true outcome.
* **OtaNotify is signed by the registry**, the only holder of the tenant command key. After the
  campaign transaction commits, each body goes to
  `POST /internal/v1/tenants/{tenant}/devices/{id}/downlink` (`{type: "ota_notify", body, retain:
  true}`, `bstr` fields hex, W3C `traceparent` header); the registry signs it on the device's
  type-7 replay stream and publishes it retained. A notify counts as delivered once the registry
  answers (`last_notified_at`); undelivered ones are re-sent by the controller after
  `OTA_NOTIFY_RETRY_S` (running campaigns only), and resuming a halted campaign re-sends every
  withdrawn notify. Delivered notifies are never re-signed: receivers enforce only the future
  bound of the timestamp window for retained types 4/7/9 (WIRE_FORMAT §3.6). Final outcomes and
  terminal campaign states clear the retained message; the clear (an empty, unsigned payload) is
  the only thing this service still publishes to the broker itself.
* **Firmware keys in the PKI**: the service owns `PUT /v1/tenants/{t}/firmware-keys`
  (API_CONTRACT §5). Every tenant with firmware is listed in the `pki_key_sync` outbox (added in
  the transaction of its first upload, backfilled by migration `0002`). The controller leader
  pushes all trusted public keys (Ed25519 and ML-DSA-65) to tenants whose last accepted key-set
  digest differs from the current ring, retrying failures after 60 s; startup marks every tenant
  for a fresh push, so a signing-key rotation (new ring, restart) reaches the PKI.
* **Verification before notify**: the signed manifest is re-verified with the trusted keys, its
  fields are checked against the record, and the stored image (and each delta patch) is re-hashed
  at campaign start, at every stage start and on resume. A mismatch fails the start (409, audited)
  or halts the running campaign (`artifact verification failed: <WIRE CODE>`).
* **Delta** (`delta: true`): one IMDELTA1 patch per distinct base hash in the population, with a
  signed delta manifest. The service applies each patch with the wire library and checks the
  result equals the image exactly before storing it. Bases unknown to the store, and patches that
  are not smaller than the image, fall back to the full image. A device that rejects a delta with
  a `DELTA_*`/`MF_NO_DELTA`/`MF_HASH_MISMATCH`/`MF_SIZE_MISMATCH` error gets one full-image
  notify instead of being counted as a failure.
* **Four-eyes**: a `security` campaign whose canary dwell is under
  `OTA_FOUR_EYES_MIN_DWELL_S` (1 h), or that has no canary stage, cannot start until a second
  operator, distinct from the creator, calls `POST /v1/campaigns/{id}/approve`.
* **Rollback** (admin, with a reason) re-signs the image the affected devices ran before (their
  most common recorded base, otherwise the newest older release) as `<version>+rollback.<code>`
  with `version_code = max + 1`. That satisfies anti-rollback on the devices. It then creates and
  starts a child campaign (single 100% stage) targeting exactly the devices that reported
  success on the bad version. The parent becomes `rolled_back`. Rollback children are exempt
  from four-eyes: the image was released before, and the action is admin-only and audited on
  both campaigns.
* **Leader election**: every replica runs the controller loop, but only the holder of
  `pg_try_advisory_lock(OTA_LEADER_LOCK_KEY)` on a dedicated session drives campaigns. The holder
  re-checks the lock every tick and steps down if its session dies. API actions and status
  ingestion run the same engine synchronously, inside a transaction that locks the campaign row.

## Tenancy

Every tenant table has `tenant_id uuid NOT NULL`, `ENABLE` + `FORCE ROW LEVEL SECURITY` and the
policy `tenant_id = NULLIF(current_setting('ironmesh.tenant_id', true), '')::uuid` (USING and WITH
CHECK). Each transaction starts with `set_config('ironmesh.tenant_id', $1, true)`, the bind-param
form of `SET LOCAL`. The service connects as `ota_app`, which owns nothing and has no BYPASSRLS.
`firmware`, `firmware_deltas` and `audit_events` are INSERT/SELECT only for that role. Two
identifier-only tables have no RLS: `campaign_schedule` (the controller's work queue) and
`firmware_hash_index` (signed image hashes for the anomaly engine).

## Observability

Logs are structlog JSON with `ts, level, service, trace_id, span_id, tenant_id, device_id, msg`
(`OTA_LOG_FORMAT=console` gives readable dev output). OTLP traces are enabled with
`OTA_OTEL_ENABLED`. Metrics:

* `ironmesh_ota_result_total{result}`, `ironmesh_ota_campaign_stage{tenant_id,campaign_id}` and
  `ironmesh_ota_campaign_devices{state}`
* `ironmesh_replay_rejected_total` and `ironmesh_ota_ingest_rejected_total{code}`
* `ironmesh_ota_signing_operations_total{purpose,algorithm}` and
  `ironmesh_ota_notifications_total{kind}`
* `ironmesh_ota_campaign_transitions_total{state}`, `ironmesh_ota_controller_leader` and
  `ironmesh_ota_controller_tick_seconds`

The service publishes `campaign.updated` frames (`{type, at, tenant_id, data: Campaign}`) to
`OTA_KAFKA_TOPIC_CAMPAIGNS` (default `im.campaigns`) for the registry's WebSocket relay, and every
audit event to `im.audit`.

## Configuration

Names follow `deploy/helm/ironmesh` (ota block). Empty values mean "default".

| Group | Variables |
|---|---|
| Server | `OTA_ENV` (`dev`/`test`/`prod`), `OTA_LISTEN_PORT`, `OTA_LOG_LEVEL`, `OTA_LOG_FORMAT`, `OTA_PUBLIC_BASE_URL` |
| Database | `OTA_DB_HOST/PORT/NAME/USER/SSLMODE/IAM_AUTH/PASSWORD` or `OTA_DATABASE_URL`; `OTA_DATABASE_BACKEND=memory` for local experiments |
| Storage | `OTA_ARTIFACT_STORE` (`s3`/`filesystem`), `OTA_ARTIFACT_BUCKET`, `OTA_S3_KMS_KEY_ARN`, `OTA_S3_REGION`, `OTA_S3_OBJECT_LOCK_MODE`, `OTA_ARTIFACT_PATH`, `OTA_DOWNLOAD_HMAC_SECRET`, `OTA_DOWNLOAD_URL_TTL_S` |
| Signing | `OTA_SIGNING_PROVIDER` (`kms-wrapped`/`file`), `OTA_SIGNING_KEK_KEY_ID`, `OTA_SIGNING_KEY_SECRET_ARN`, `OTA_SIGNING_KEY_ID`, `OTA_PQ_SIGNING_ENABLED`, `OTA_REQUIRE_PQ`, `OTA_SIGNING_PRIVATE_KEY_PEM`, `OTA_SIGNING_KEY_FILE`, `OTA_SIGNING_KEYRING_FILE`, `OTA_SIGNING_PASSPHRASE` |
| Auth | `OTA_OIDC_ISSUER`, `OTA_OIDC_AUDIENCE`, `OTA_OIDC_JWKS_URL`, `OTA_INTERNAL_TOKEN` (accepted on `/internal/*`; also the PKI bearer when no service-JWT key is set), `OTA_SERVICE_PUBLIC_KEYS_DIR`, `OTA_SERVICE_TOKEN_KEY_FILE` (ES256 service JWTs, `iss=sub=ota`, one per request), `OTA_INTERNAL_ALLOWED_SERVICES`, `OTA_SERVICE_JWT_SINGLE_USE` (default `true`), `OTA_SERVICE_JWT_REPLAY_CACHE_SIZE` (default `100000`) |
| Peers | `OTA_REGISTRY_URL` + `OTA_REGISTRY_TOKEN` (secret: the `ota` entry of the registry's `REGISTRY_INTERNAL_TOKENS`; without it a service JWT `aud=registry` is used), `OTA_PKI_URL` (device keys and the firmware-key policy push), `OTA_EMQX_API_URL`, `OTA_EMQX_API_KEY`, `OTA_EMQX_API_SECRET` (or `OTA_MQTT_HOST` for a direct MQTT 5 client; retained-notify clears only), `OTA_TLS_CERT_FILE/KEY_FILE/CA_FILE` |
| Kafka | `OTA_KAFKA_BROKERS`, `OTA_KAFKA_TOPIC_INGEST/AUDIT/CAMPAIGNS/COMMANDS`, `OTA_KAFKA_CONSUMER_GROUP`, `OTA_KAFKA_TLS_ENABLED` |
| Controller | `OTA_CONTROLLER_ENABLED`, `OTA_CONTROLLER_INTERVAL_S`, `OTA_DEVICE_TIMEOUT_S`, `OTA_NOTIFY_RETRY_S` (default 60: re-send notifies the registry did not accept), `OTA_HALT_MIN_SAMPLE`, `OTA_FOUR_EYES_MIN_DWELL_S`, `OTA_LEADER_LOCK_KEY` |

`OTA_ENV=prod` refuses to start without Postgres, S3, KMS-wrapped firmware signing, OIDC, a
broker, Kafka, the registry (with `OTA_REGISTRY_TOKEN` or `OTA_SERVICE_TOKEN_KEY_FILE`) and the
PKI. The service holds no tenant command keys.

## Development

```sh
# Windows: %LOCALAPPDATA%\Programs\Python\Python312\python.exe (64-bit 3.12)
python -m venv .venv
.venv/Scripts/python -m pip install -e ../../libs/python/ironmesh-wire -e ".[dev]"
.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m ruff format --check .
.venv/Scripts/python -m mypy
.venv/Scripts/python -m bandit -c pyproject.toml -r src
.venv/Scripts/python -m pytest --cov=ironmesh_ota          # fails under 90 %
.venv/Scripts/python -m pytest -m "not postgres"           # unit tests only
```

Tests marked `postgres` run against `OTA_TEST_DATABASE_URL` (an owner role; CI service
container) or a throw-away server from the `pgserver` wheel, and are skipped when neither is
available. S3, KMS and Secrets Manager are exercised with `moto`. Registry, PKI and EMQX are
exercised with `httpx.MockTransport`; campaign tests use a registry fake that decodes the
downlink JSON like the registry, signs with a test tenant key and publishes to a recording broker.

Schema: `OTA_MIGRATION_DATABASE_URL=postgresql+asyncpg://owner@host/ota python -m ironmesh_ota.migrate`.
The migration creates `ota_app NOLOGIN` if it is missing. Infrastructure grants it LOGIN and a
credential.

Dev keys: `OTA_SIGNING_PASSPHRASE=… python -m ironmesh_ota.keytool init --out ring.json --mldsa`.

## Container

```sh
docker build -f services/ota/Dockerfile -t ghcr.io/lumidren/ironmesh-ota:dev .   # repo root
```

The build is multi-stage. The runtime image is `python:3.12-slim`, runs as uid/gid 10001, has a
read-only-root-compatible layout (writable `/tmp` and `/var/lib/ironmesh/ota`) and a `/healthz`
HEALTHCHECK.

## Known gaps

* Live MQTT (`AiomqttPublisher`), Kafka (`KafkaEventPublisher`, `IngestConsumer`), RDS IAM auth
  and JWKS discovery are thin adapters excluded from unit coverage. They need the compose or
  cluster environment.
* `OTA_KAFKA_TOPIC_COMMANDS` is accepted but not consumed. Campaign device state comes from
  OtaStatus.
* Retained-notify clears still go straight to the broker (EMQX API): the registry's downlink
  endpoint only accepts signed `ota_notify` bodies. A registry `409` (device no longer `active`)
  is retried by redelivery until the device times out.
* Firmware-key pushes run on the controller leader (and once at startup); with
  `OTA_CONTROLLER_ENABLED=false` only the startup push happens.

Maintained by lumidren.
