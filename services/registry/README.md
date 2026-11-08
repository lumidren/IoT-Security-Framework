# IronMesh Device Registry & Fleet Service

FastAPI service (port 8000) that owns the device lifecycle, twins, commands, encrypted device
configuration, the provisioning queue, fleet aggregation, users / API keys and the hash-chained
audit log. Binding specs: `docs/DESIGN_CONTRACT.md`, `docs/API_CONTRACT.md` §1 and §6,
`device/common/WIRE_FORMAT.md`. All COSE/CBOR/HPKE/id/topic handling uses the reference library
`libs/python/ironmesh-wire`.

## Layout

| Path | Purpose |
|------|---------|
| `app/main.py` | app factory (`uvicorn app.main:create_app --factory`), lifespan, middleware, background jobs |
| `app/settings.py` | `REGISTRY_*` settings (pydantic-settings), names per the Helm env-var contract |
| `app/auth.py`, `app/api/deps.py` | OIDC/JWKS, `imk_` API keys, service JWTs, RBAC + scopes |
| `app/api/routes.py` | every endpoint of API_CONTRACT §1.1-1.12, `/healthz`, `/readyz`, `/metrics` |
| `app/lifecycle.py` | lifecycle state machine (allowed transitions, terminal `decommissioned`) |
| `app/services/*` | devices + orchestration, twin, commands, config, admin (tenant/groups/users/keys/audit/fleet), ingest |
| `app/repo/` | `Repository` protocol, in-memory fake, PostgreSQL implementation (SQLAlchemy Core + asyncpg) |
| `app/integrations/` | `EventBus` (aiokafka / memory), `MqttPublisher` (paho v2 / fake), KMS (local file KEK / AWS KMS), PKI, OTA, EMQX clients |
| `app/ws.py` | WebSocket tickets, hub, subscriptions, telemetry sampling |
| `migrations/` | Alembic: tables, indexes, RLS, roles/grants, SECURITY DEFINER helpers, partitions |
| `app/seed.py` | demo data: `python -m app.seed --tenant demo --devices 500` |

## Running

```bash
python -m venv .venv && .venv/bin/pip install -e ../../libs/python/ironmesh-wire -e ".[dev]"
REGISTRY_MIGRATION_DATABASE_URL=postgresql+asyncpg://owner:...@db/registry alembic upgrade head
# operators: ALTER ROLE registry_app PASSWORD '...'   (role is created NOBYPASSRLS by the migration)
REGISTRY_DB_HOST=db REGISTRY_DB_PASSWORD=... uvicorn app.main:create_app --factory --proxy-headers
python -m app.seed --tenant demo --devices 500 --owner-sub <oidc-sub> --owner-email you@example.com
```

Container (build context = repository root): `docker build -f services/registry/Dockerfile .`
Multi-stage `python:3.12-slim`, runs as UID 10001, `uvicorn --proxy-headers` (trusted proxy range via
`FORWARDED_ALLOW_IPS`), migrations shipped in `/srv/migrations`.

## Environment variables

| Variable | Default | Notes |
|----------|---------|-------|
| `REGISTRY_LISTEN_PORT` | `8000` | HTTP port (health, metrics and API on the same port) |
| `REGISTRY_LOG_LEVEL` / `REGISTRY_LOG_FORMAT` | `info` / `json` | JSON fields `ts, level, service, trace_id, span_id, tenant_id, device_id, msg` |
| `REGISTRY_DB_HOST` `_PORT` `_NAME` `_USER` | `localhost` `5432` `registry` `registry_app` | app connects as the non-owner RLS role |
| `REGISTRY_DB_PASSWORD` (secret) | - | ignored when `REGISTRY_DB_IAM_AUTH=true` (RDS IAM token per connection) |
| `REGISTRY_DB_SSLMODE` | - | `require`, `verify-full`, ... passed to asyncpg |
| `REGISTRY_DATABASE_URL` | - | full SQLAlchemy URL, overrides `REGISTRY_DB_*` |
| `REGISTRY_MIGRATION_DATABASE_URL` | - | schema-owner DSN, Alembic only |
| `REGISTRY_REPO_BACKEND` | `postgres` | `memory` for local experiments |
| `REGISTRY_OIDC_ISSUER` / `REGISTRY_OIDC_AUDIENCE` | - / `ironmesh-api` | JWKS discovered from the issuer (`REGISTRY_OIDC_JWKS_URL` overrides), cached `REGISTRY_OIDC_JWKS_CACHE_SECONDS` |
| `REGISTRY_OIDC_TENANT_CLAIM` / `_ROLE_CLAIM` / `_PLATFORM_ROLES_CLAIM` | `tenant_id` / `role` / `platform_roles` | `platform_admin` in the latter enables `X-IronMesh-Tenant` |
| `REGISTRY_INTERNAL_TOKEN` (secret) | - | shared bearer for `/internal/*` (= `PKI_REGISTRY_TOKEN`, `POLICY_REGISTRY_TOKEN`) |
| `REGISTRY_SERVICE_JWT_TRUSTED_KEYS` | `{}` | JSON `{"pki": "<PEM>", "policy": "...", "anomaly": "..."}`: ES256 keys accepted on `/internal/*` (`aud=registry`, <= 5 min) |
| `REGISTRY_SERVICE_JWT_PRIVATE_KEY_FILE` | - | P-256 key used to mint the registry's own service JWTs (`aud=pki` / `aud=ota`) |
| `REGISTRY_KAFKA_BROKERS` | `localhost:9092` | plus `REGISTRY_KAFKA_TOPIC_{INGEST,AUTH,ALERTS,AUDIT,COMMANDS}`, `REGISTRY_KAFKA_CONSUMER_GROUP` |
| `REGISTRY_KAFKA_TLS_ENABLED` / `_SASL_MECHANISM` / `_SASL_USERNAME` / `_SASL_PASSWORD` | `false` / `none` | `SCRAM-SHA-512` or `AWS_MSK_IAM` (needs `aws-msk-iam-sasl-signer-python`) |
| `REGISTRY_PKI_URL` `REGISTRY_OTA_URL` `REGISTRY_POLICY_URL` | chart service names | mTLS with `REGISTRY_TLS_{CERT,KEY,CA}_FILE` |
| `REGISTRY_EMQX_API_URL` + `REGISTRY_EMQX_API_KEY` / `_SECRET` (secrets) | - | direct session kick, used only as containment when PKI revocation fails |
| `REGISTRY_MQTT_HOST` / `_PORT` / `_CLIENT_ID` | `ironmesh-emqx` / `8883` / `svc-registry` | downlink publisher: MQTT 5, TLS 1.3, ALPN `mqtt`, client cert from `REGISTRY_TLS_*` |
| `REGISTRY_KMS_BACKEND` | `local` | `local` (`REGISTRY_KMS_LOCAL_KEK_FILE`, auto-created 0600 outside prod) or `aws` (`REGISTRY_KMS_AWS_KEY_ID`, `REGISTRY_KMS_AWS_REGION`) |
| `REGISTRY_PUBLIC_BASE_URL` | - | advertised in the OpenAPI `servers` |
| `REGISTRY_MAX_SKEW_SECONDS` | `300` | envelope timestamp window |
| `REGISTRY_TELEMETRY_RETENTION_DAYS` / `_PARTITIONS_AHEAD_DAYS` | `30` / `3` | daily partitions of `telemetry_samples` |
| `REGISTRY_SWEEPER_INTERVAL_SECONDS` / `REGISTRY_MAINTENANCE_INTERVAL_SECONDS` | `5` / `300` | command expiry + outbox retries + health flush / partitions + gauges |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | - | enables the OTLP trace exporter (FastAPI + SQLAlchemy instrumentation) |

## Endpoints

| Method | Path | Min role |
|--------|------|----------|
| GET | `/v1/tenants/me` | viewer |
| PATCH | `/v1/tenants/me/settings` | admin |
| GET/POST | `/v1/devices` | viewer / admin or factory |
| GET/PATCH | `/v1/devices/{id}` | viewer / operator |
| POST | `/v1/devices/{id}/quarantine` · `/release` · `/decommission` | operator · admin · admin |
| GET | `/v1/devices/{id}/timeline` · `/telemetry` · `/certificates` | viewer |
| GET/POST | `/v1/groups` | viewer / operator |
| PATCH/DELETE | `/v1/groups/{slug}` | operator / admin |
| PUT | `/v1/groups/{slug}/members` | operator |
| GET | `/v1/devices/{id}/twin` | viewer |
| PATCH | `/v1/devices/{id}/twin/desired` | operator (`409` on `expected_version` mismatch) |
| DELETE | `/v1/devices/{id}/twin/desired/{path}` | operator (`a/b` or `a.b`) |
| POST/GET | `/v1/devices/{id}/commands` | operator / viewer (`Idempotency-Key`, replay sets `Idempotency-Replayed: true`) |
| GET | `/v1/commands/{cmd_id}` | viewer |
| POST | `/v1/groups/{slug}/commands` | operator |
| GET/PUT | `/v1/devices/{id}/config` | viewer (plaintext admin+) / admin |
| GET | `/v1/provisioning` | viewer |
| POST | `/v1/provisioning/{id}/approve` · `/reject` | operator |
| GET | `/v1/fleet/summary` · `/v1/fleet/health?window=1h` | viewer |
| GET | `/v1/audit` · `/v1/audit/export?format=ndjson` · `/v1/audit/verify` | viewer · admin · admin |
| GET | `/v1/users` · PUT `/v1/users/{id}/role` | admin · owner |
| GET/POST | `/v1/api-keys` · DELETE `/v1/api-keys/{id}` | admin |
| POST | `/v1/ws/ticket` → WS `/v1/ws?ticket=` | viewer |
| GET | `/internal/v1/devices/{id}/lifecycle` | service `policy` |
| POST | `/internal/v1/devices/{id}/enrolled` | service `pki` |
| GET | `/internal/v1/tenants/{tenant}/devices/{id}` | service `pki` → `{device_id, tenant_id, state, assurance_level, se_type, bootstrap_serial}` |
| POST | `/internal/v1/tenants/{tenant}/devices/{id}/assurance` | service `pki` → `204` |
| POST | `/internal/v1/devices/{id}/quarantine` | service `anomaly` |
| GET | `/healthz` · `/readyz` · `/metrics` · `/openapi.json` | none |

Errors are RFC 9457 `application/problem+json` (`type, title, status, detail, instance, errors`).
Pagination: `?cursor=&limit=1..200` → `{items, next_cursor}` (opaque keyset cursors).
API-key scopes: `tenant:read|write`, `devices:read|write|lifecycle`, `twin:read|write`,
`commands:read|write`, `config:read|write`, `groups:read|write`, `provisioning:read|write`,
`fleet:read`, `audit:read|export`, `users:read|write`, `apikeys:write`, `ws:connect`.

## Design notes

* **Tenancy**: every repository call runs inside `SELECT set_config('ironmesh.tenant_id', $1, true)`
  (= `SET LOCAL`) as `registry_app`; policies are `tenant_id = current_setting('ironmesh.tenant_id')::uuid`
  with `ENABLE` + `FORCE ROW LEVEL SECURITY`. An unset setting errors (fail closed). The few lookups
  needed before the tenant is known are `SECURITY DEFINER` functions (`registry_device_tenant`,
  `registry_api_key_lookup`, `registry_tenant_ids`, partition maintenance).
* **Lifecycle orchestration**: the state change commits first (policy lookups deny immediately),
  then PKI `revoke-all` (which drives the policy cache deny and the EMQX kick) runs with retries.
  On failure an outbox action is retried with backoff, a `failure` audit event records the
  compensation, and the registry kicks the session through the EMQX API as containment.
* **Ingest** (`im.ingest`): topic/header/certificate identity binding (CN = device, OU = tenant
  from the PKI-issued certificate), `envelope.decode` for the WIRE_FORMAT §3.6 order, then the
  replay compare-and-set in `device_replay` (`numeric(20,0)`, uint64) in the same transaction that
  applies the message. Rejections are counted per code (`ironmesh_ingest_rejected_total`,
  `ironmesh_replay_rejected_total`). Also consumes `im.auth`, `im.alerts` and `im.audit`.
* **Audit**: append-only (grants + trigger), per-tenant chain `hash = sha256(prev_hash || canonical_json)`
  with a head row; `/v1/audit/verify` checks sequence continuity, links, hashes, column/body
  agreement and the head (tail truncation).
* **Config**: plaintext JSON is AES-256-GCM encrypted at rest with a per-tenant data key wrapped by
  KMS; the published message is a tenant-signed Config envelope HPKE-wrapped (`COSE_Encrypt0`) to
  the device's current certificate key and retained.
* **Metrics**: `ironmesh_connected_devices`, `ironmesh_auth_failures_total`,
  `ironmesh_replay_rejected_total`, `ironmesh_devices_total{state}`,
  `ironmesh_http_requests_total{route,method,code}`, ingest/command/lifecycle/WS counters.

## Tests

```bash
.venv/Scripts/python -m pytest --cov=app        # memory + PostgreSQL (pgserver) backends
ruff check . && ruff format --check . && mypy && bandit -c pyproject.toml -r app
```

Tests marked `postgres` start a throwaway PostgreSQL 16 from the `pgserver` wheel; in CI set
`REGISTRY_TEST_DATABASE_URL` (owner DSN, e.g. a `postgres:16` service) and optionally
`REGISTRY_TEST_APP_DATABASE_URL`; `REGISTRY_TEST_NO_PGSERVER=1` skips them.

## Known limitations

* The WebSocket hub and ticket store are per process. With several replicas, frames produced by
  another replica's Kafka partitions are not fanned out; add a broadcast channel (e.g. Postgres
  `LISTEN/NOTIFY`) in front of `Hub.publish`.
* `campaigns_running` in `/v1/fleet/summary` is `0`: campaigns are owned by the OTA service.
* `/v1/fleet/health` `p99_ingest_ms` is the max of per-replica, per-minute p99s (an upper bound).
* Retained `ShadowDesired` / `Config` messages carry the publish timestamp; a device that connects
  more than `max_skew` (300 s) later rejects them as `ENV_TS_SKEW` under WIRE_FORMAT §3.6. Devices
  need a "resend desired" request or the contract a skew exemption for retained downlinks.
