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
| `postgres` | `postgres:16` | - | databases `pki`, `registry`, `ota`, `anomaly`; roles `<db>_owner` (migrations) and `<db>_app` (runtime, `NOBYPASSRLS`), `ironmesh_backup` (`postgres/10-ironmesh.sh`) |
| `redpanda` + `redpanda-init` | Redpanda 24.3 | - | single node; the init job creates `im.ingest`, `im.auth`, `im.alerts`, `im.audit`, `im.commands`, `im.campaigns` |
| `fleet-provision` | `device/agent-rs/Dockerfile` | - | `ironmesh-fleet provision`: 500 software identities + bootstrap CSRs, once (the image is distroless, so a static busybox copied into the `tools` volume by `init-volumes` provides the re-run guard) |
| `pki-init` | `pki-init/Dockerfile` (pkictl) | - | dev hierarchy (root, factory, device, services CAs, Ed25519 bundle key), service certificates, broker certificate, EMQX API key file, factory bootstrap certificates for the fleet, `fleet.toml` |
| `pki` | `services/pki` | 8443 (EST/OCSP/API, mTLS), 8444 (CRL) | file KMS, Postgres store; the delegated OCSP signer is derived at start |
| `policy` (+ `policy-probe`) | `services/policy` | - | EMQX authn/authz, revocation cache; distroless, so a curl sidecar carries the health state |
| `emqx` | `emqx/emqx:5.8.9` | 8883 (mTLS), 18083 (dashboard) | `services/policy/deploy/emqx/emqx.conf` + env overrides for certificate paths, API keys and the hook token |
| `bridge` (+ `bridge-probe`) | `services/bridge` | - | `$share/bridge/im/v1/#` -> `im.ingest` |
| `registry-migrate`, `registry`, `registry-seed` | `services/registry` | 8000 (API + WebSocket) | Alembic as `registry_owner`; runtime as `registry_app`; `python -m app.seed` creates the demo tenant and owner |
| `ota-migrate`, `ota-init`, `ota` | `services/ota` | - | Alembic as `ota_owner`; `keytool` creates the encrypted signing key ring and tenant command key |
| `anomaly` | `services/anomaly` | - | migrates itself as `anomaly_owner` (`ANOMALY_DATABASE_MIGRATE_URL`), auto-quarantine on |
| `console` | `console` (production build) | 3000 | Auth.js against the bundled Keycloak realm |
| `keycloak` | Keycloak 26 | 8180 (via the console's network namespace) | realm `ironmesh`, demo user, hard-coded `tenant_id`/`role` claims, audience `ironmesh-api` |
| `seed` | OTA image + `scripts/demo/demo.py` | - | factory registration of the fleet (`POST /v1/devices`) and the PKI tenant policy |
| `fleet` | `device/agent-rs/Dockerfile` | - | `ironmesh-fleet run --count 500 --anomalous 1` |
| `otel-collector`, `prometheus`, `grafana` | upstream | 9090, 3001 | provisioned from `observability/` |

`demo-tools` (profile `tools`) runs `scripts/demo/demo.py` on demand:
`docker compose run --rm demo-tools campaign|wait-active|wait-quarantine|status`.

## Hardening

Every long-running container: `cap_drop: [ALL]`, `no-new-privileges`, non-root user (IronMesh
images run as uid/gid 10001; PostgreSQL as 999; the upstream images as their own users), no
`privileged`, `json-file` logs with rotation. Read-only root filesystems everywhere except the
stateful upstream images that write outside their data volume (PostgreSQL, Redpanda, EMQX,
Keycloak). Writable paths are named volumes or size-limited `tmpfs`.

Secrets come from the generated, git-ignored `.env`. They are delivered as files wherever the
consumer reads files: PostgreSQL and Grafana use compose `secrets` (`*_FILE`), TLS identities live
in one volume per service (`tls-<service>`, mounted read-only at `/etc/ironmesh/tls`), the OTA key
ring and tenant key are passphrase-encrypted files, the EMQX API keys are a bootstrap file. The
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

## Known limitations (tracked in the integration report)

* `pki` applies its migrations with `PKI_DATABASE_URL` and therefore runs as `pki_owner`; the
  PKI tables do not `FORCE` row-level security, so RLS is not enforced for it in this stack.
* The PKI has no API for tenant policies (bundle `tenant_cmd_pubkey`, `fw_signing_pubkeys`,
  `allow_software_keys`); `demo.py seed` writes the row directly.
* The OTA service and the registry each hold their own tenant command key; the bundle carries
  the OTA key, so OTA notifications verify on devices but registry-signed commands / desired
  state do not until the key is shared.
* EMQX rule-engine forwarding to the bridge webhook (`/emqx/events`) is not configured by
  `emqx.conf`, so `im.auth` only carries policy-originated events.
* Tempo/Loki are not part of the stack; the collector's trace/log exporters retry and the
  `debug` exporter prints a sample. Prometheus' `ironmesh-console` and `alertmanager` targets are
  down by design (no console `/metrics`, no Alertmanager).
