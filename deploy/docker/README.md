# IronMesh local stack (Docker Compose)

The full control plane, broker, data stores, observability and a 500-device virtual fleet on one
machine. This is the developer loop and the stack the conformance suite and the HIL job run
against (ARCHITECTURE.md section 7).

```bash
scripts/demo/quickstart.sh          # Linux / macOS / WSL / Git Bash
scripts/demo/quickstart.ps1         # Windows PowerShell
```

The quickstart generates `deploy/docker/.env` with random secrets, starts the stack, waits for
the virtual fleet to enroll, uploads a signed demo firmware, starts a staged campaign and waits
until the misbehaving device is auto-quarantined. It then prints the console URL and the demo
credentials. Manual use:

```bash
cp deploy/docker/.env.example deploy/docker/.env    # replace every __GENERATE__
docker compose -f deploy/docker/docker-compose.yml up -d --wait
docker compose -f deploy/docker/docker-compose.yml run --rm demo-tools status
docker compose -f deploy/docker/docker-compose.yml down        # add -v to wipe all state
```

## Services

| Service | Image | Host port | Notes |
|---|---|---|---|
| `init-volumes` | busybox | - | one-shot; the only container with capabilities (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`) to hand the named volumes to uid 10001 |
| `postgres` | `postgres:16` | - | databases `pki`, `registry`, `ota`, `anomaly`; roles `<db>_owner` (migrations) and `<db>_app` (runtime, `NOBYPASSRLS`, `pki_app` included), `ironmesh_backup` (`postgres/10-ironmesh.sh`) |
| `redpanda` | Redpanda 24.3 | - | single node; the topics `im.ingest`, `im.auth`, `im.alerts`, `im.audit`, `im.commands`, `im.campaigns` are created by the bridge (`BRIDGE_KAFKA_TOPICS_CREATE=true`, 3 partitions, replication 1) |
| `fleet-provision` | `device/agent-rs/Dockerfile` | - | `ironmesh-fleet provision`: 500 software identities + bootstrap CSRs, once (the image is distroless, so a static busybox copied into the `tools` volume by `init-volumes` provides the re-run guard) |
| `pki-init` | `pki-init/Dockerfile` (pkictl) | - | dev hierarchy (root, factory, device, services CAs, Ed25519 bundle key), service certificates, broker certificate, EMQX API key file, factory bootstrap certificates for the fleet, `fleet.toml` |
| `pki` | `services/pki` | 8443 (EST/OCSP/API, mTLS), 8444 (CRL) | file KMS, bundle key file (`PKI_BUNDLE_KEY_FILE`); migrates as `pki_owner` (`PKI_MIGRATION_DATABASE_URL`) and runs as `pki_app` (`PKI_DATABASE_URL`, forced RLS); enrolled callback to the registry (`PKI_REGISTRY_URL` + `PKI_REGISTRY_TOKEN`); the delegated OCSP signer is derived at start |
| `policy` | `services/policy` | - | EMQX authn/authz, revocation cache, management API accepting console OIDC tokens (`POLICY_OIDC_*`) |
| `emqx` | `emqx/emqx:5.8.9` | 8883 (mTLS), 18083 (dashboard) | `services/policy/deploy/emqx/emqx.conf` + env overrides for certificate paths, API keys, the policy hook token and the bridge webhook token |
| `bridge` | `services/bridge` | - | `$share/bridge/im/v1/#` -> `im.ingest`, EMQX client events (`POST /emqx/events`) -> `im.auth`; creates the Kafka topics before it turns ready |
| `registry-migrate`, `registry`, `registry-seed` | `services/registry` | 8000 (API + WebSocket) | `alembic upgrade head` as `registry_owner` (0001 + 0002 downlink sequences); runtime as `registry_app`; the only holder of tenant command keys, pushes the public key and `allow_software_keys` to the PKI tenant-policy API; `python -m app.seed` creates the demo tenant and owner directly in the database before the registry starts, so the registry's start-up reconciliation creates and pushes the tenant command key |
| `ota-migrate`, `ota-init`, `ota` | `services/ota` | - | migrations as `ota_owner`; `keytool init` creates the encrypted firmware signing key ring; campaign targets and OtaNotify downlinks go through the registry (`OTA_REGISTRY_TOKEN`), firmware keys are pushed to the PKI tenant-policy API |
| `anomaly` | `services/anomaly` | - | migrates itself as `anomaly_owner` (`ANOMALY_DATABASE_MIGRATE_URL`), auto-quarantine on |
| `console` | `console` (production build) | 3000 | Auth.js against the bundled Keycloak realm |
| `keycloak` | Keycloak 26 | 8180 (via the console's network namespace) | realm `ironmesh`, demo user, hard-coded `tenant_id`/`role` claims, audience `ironmesh-api` |
| `seed` | OTA image + `scripts/demo/demo.py` | - | factory registration of the fleet (`POST /v1/devices`) and a baseline firmware upload, then waits until the PKI tenant policy carries the registry's command key and the OTA firmware keys (`GET /v1/tenants/{t}/policy`, mTLS as `svc-ota`) so enrolling devices get a complete trust bundle |
| `fleet` | `device/agent-rs/Dockerfile` | - | `ironmesh-fleet run --count 500 --anomalous 1` |
| `otel-collector`, `prometheus`, `grafana` | upstream | 9090, 3001 | provisioned from `observability/` |

`demo-tools` (profile `tools`) runs `scripts/demo/demo.py` on demand:
`docker compose run --rm demo-tools campaign|wait-active|wait-quarantine|status`.

## Hardening

Health checks run each image's own binary: `/usr/local/bin/pki healthcheck`, `/policy healthcheck`
and `/bridge healthcheck` (against `/readyz`) in the distroless Go images, a `python -c` urllib
probe in the Python images; there are no curl probe sidecars.

Every long-running container: `cap_drop: [ALL]`, `no-new-privileges`, non-root user (IronMesh
images run as uid/gid 10001; PostgreSQL as 999; the upstream images as their own users), no
`privileged`, `json-file` logs with rotation. Read-only root filesystems everywhere except the
stateful upstream images that write outside their data volume (PostgreSQL, Redpanda, EMQX,
Keycloak). Writable paths are named volumes or size-limited `tmpfs`.

Secrets come from the generated, git-ignored `.env`. They are delivered as files wherever the
consumer reads files: PostgreSQL and Grafana use compose `secrets` (`*_FILE`), TLS identities live
in one volume per service (`tls-<service>`, mounted read-only at `/etc/ironmesh/tls`), the OTA
firmware key ring is a passphrase-encrypted file, the EMQX API keys are a bootstrap file. The
IronMesh services have no `_FILE` variants for their remaining secrets (tokens, DB passwords,
passphrases), so those are environment variables interpolated from `.env`, never literals in
the compose file.

Only `pki` (8443/8444) and `emqx` (8883) are meant for devices; they bind to
`IRONMESH_DEVICE_BIND_ADDR` (loopback by default, `0.0.0.0` on the HIL runner). Everything else
binds to `IRONMESH_BIND_ADDR` (loopback).

## Identity provider

The console reaches Keycloak at `http://localhost:8180` both from the browser and server-side
because Keycloak shares the console container's network namespace (`network_mode:
service:console`). Services validate tokens against the issuer string
`http://localhost:8180/realms/ironmesh` and fetch keys from
`http://console:8180/realms/ironmesh/protocol/openid-connect/certs` (`*_OIDC_JWKS_URL`).
Restart `keycloak` after recreating `console`.

Keycloak is used instead of Dex: the OTA service only reads the `tenant_id` and `role`/`roles`
claims, and Dex cannot add custom claims to static users, so a Dex user could sign in but every
API call would be rejected. To use your own IdP see `compose.override.example.yml`.

## Environment variable names

`docker-compose.yml` uses exactly the names in each service's settings module:

| Service | Settings module |
|---|---|
| pki | `services/pki/internal/config/config.go` (`PKI_*`) |
| policy | `services/policy/internal/config/config.go` (`POLICY_*`) + `POLICY_JWT_*` in `cmd/policy/main.go` |
| bridge | `services/bridge/internal/config/config.go` (`BRIDGE_*`, `OTEL_*`) |
| registry | `services/registry/app/settings.py` (`REGISTRY_*`), `REGISTRY_MIGRATION_DATABASE_URL` (Alembic) |
| ota | `services/ota/src/ironmesh_ota/settings.py` (`OTA_*`), `OTA_MIGRATION_DATABASE_URL` (migrate) |
| anomaly | `services/anomaly/src/ironmesh_anomaly/config.py` (`ANOMALY_*`, `OTEL_EXPORTER_OTLP_ENDPOINT`) |
| console | `console/src/lib/env.ts`, `console/src/lib/server/env.ts`, `console/src/auth.ts` |

`python scripts/ci/check_env_contract.py` cross-checks the compose file, the Helm values and the
Kustomize ConfigMaps against those modules (CI job `infra`).

## Shared secrets

| `.env` value | Must equal |
|---|---|
| `PKI_REGISTRY_TOKEN`, `POLICY_REGISTRY_TOKEN`, `ANOMALY_INTERNAL_TOKEN`, `OTA_REGISTRY_TOKEN` | the `pki`, `policy`, `anomaly`, `ota` entries of `REGISTRY_INTERNAL_TOKENS` (four distinct tokens) |
| `PKI_POLICY_TOKEN`, `PKI_POLICY_HMAC_KEY` | `POLICY_PKI_TOKEN`, `POLICY_PKI_HMAC_SECRET` |
| `POLICY_HOOK_TOKEN` | the EMQX authn/authz `X-IronMesh-Hook-Token` headers |
| `BRIDGE_EVENTS_TOKEN` | the EMQX `ironmesh_auth_events` action header (`EMQX_ACTIONS__HTTP__IRONMESH_AUTH_EVENTS__PARAMETERS__HEADERS__X-IRONMESH-HOOK-TOKEN`) |
| `PKI_DB_PASSWORD`, `PKI_DB_OWNER_PASSWORD` | `pki_app` (`PKI_DATABASE_URL`) and `pki_owner` (`PKI_MIGRATION_DATABASE_URL`) |

An `.env` generated before a variable was introduced lacks it, and `docker compose` stops with
`required variable ... is missing a value`; the quickstart scripts append every missing
`__GENERATE__` entry of `.env.example` with a fresh random value.

## Known limitations (tracked in the integration report)

* `policy` discovers the IdP from `POLICY_OIDC_ISSUER` (`<issuer>/.well-known/openid-configuration`)
  and has no JWKS URL override. The issuer every token carries, `http://localhost:8180/realms/ironmesh`,
  is not reachable from the policy container (Keycloak lives in the console's network namespace),
  so console calls to the policy management API fail OIDC discovery in this stack until the policy
  service gains a JWKS URL setting. Device authn/authz is unaffected.
* Existing volumes keep their state: `pki-data`/`pgdata` from an older stack still work (`pki_app`
  was already created), but the obsolete `ota-keys/tenant-keys/` directory is simply ignored.
* Tempo/Loki are not part of the stack; the collector's trace/log exporters retry and the
  `debug` exporter prints a sample. Prometheus' `ironmesh-console` and `alertmanager` targets are
  down by design (no console `/metrics`, no Alertmanager).
