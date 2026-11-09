# IronMesh Policy Service

EMQX 5 authentication/authorization backend, revocation cache with live-session kick, CRL fallback
poller and the policy management API. Implements `docs/DESIGN_CONTRACT.md` §2 (revocation), §4
(MQTT topic scheme and rules), §7, §9 and `docs/API_CONTRACT.md` §4.

```
EMQX ──POST /emqx/authn──▶ policy ──GET /internal/v1/devices/{id}/lifecycle──▶ registry
     ──POST /emqx/authz──▶ policy (OPA/Rego, embedded, hot-swappable)
PKI  ──POST /internal/v1/revocations (HMAC + bearer)──▶ policy ──DELETE /api/v5/clients/{id}──▶ EMQX
PKI  ◀──GET /crl/device-ca.crl (every 5 s, ETag)──── policy          (fallback path)
console ──GET/PUT /v1/policy, POST /v1/policy/evaluate, GET /v1/policy/history, GET /v1/revocations──▶ policy
```

## Decision rules

**authn** (`POST /emqx/authn`, body `{clientid, username, peerhost, cert_common_name, cert_subject}`):

1. A client certificate is mandatory (`cert_common_name` present), `clientid == CN`, and `username`
   (set by EMQX from the CN) must equal the CN.
2. CN `dev-<16 hex>` → device: subject `O=IronMesh`, exactly one UUID `OU` = tenant (bootstrap OUs are
   rejected), not in the revocation cache (by device id, and by serial when `cert_serial`/`cert_pem`
   is supplied), Registry lifecycle `provisioned` or `active` (cached 30 s, 2 s timeout,
   fail-closed unless `POLICY_REGISTRY_FAIL_OPEN=true`, which is logged at error level on start).
3. CN `svc-bridge` / `svc-registry` → service: subject `O=IronMesh`, `OU=services`.
4. Response `{"result":"allow","is_superuser":false,"client_attrs":{"tenant_id","device_id","kind"}}`
   or `{"result":"deny"}`. Denials are counted in `ironmesh_auth_failures_total{reason}`.

**authz** (`POST /emqx/authz`, body `{clientid, username, topic, action, qos, retain, client_attrs}`):
evaluates `policy/rego/mqtt_acl.rego` (package `ironmesh.mqtt`) with the session attributes; the
decision is cached 10 s keyed by (clientid, topic, action, retain, qos) and flushed on every policy
hot swap. Anything not explicitly allowed is denied, including `$SYS`, wildcards for devices, QoS 2,
retained device publishes, and cross-device/cross-tenant topics.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `POLICY_LISTEN` | `:8081` | HTTP listen address |
| `POLICY_EMQX_API_URL` | `http://emqx:18083` | EMQX management API |
| `POLICY_EMQX_API_KEY` / `POLICY_EMQX_API_SECRET` | — (required) | API key for `DELETE /api/v5/clients/{id}` |
| `POLICY_PKI_CRL_URL` | `http://pki:8444/crl/device-ca.crl` | CRL distribution point |
| `POLICY_CRL_POLL_INTERVAL` | `5s` | CRL poll interval (ETag honoured) |
| `POLICY_CRL_ISSUER_CERT_FILE` | — | Device CA certificate to verify CRL signatures (strongly recommended) |
| `POLICY_PKI_HMAC_SECRET` | — (required) | HMAC-SHA256 key for `X-IronMesh-Signature` |
| `POLICY_PKI_TOKEN` | — (required) | Bearer token the PKI presents on revocation events |
| `POLICY_REGISTRY_URL` | — (required) | Registry base URL |
| `POLICY_REGISTRY_TOKEN` | — | Bearer token for the Registry |
| `POLICY_REGISTRY_FAIL_OPEN` | `false` | Admit devices when the Registry is unreachable (loud) |
| `POLICY_REGISTRY_TIMEOUT` / `POLICY_REGISTRY_CACHE_TTL` | `2s` / `30s` | Lookup bounds |
| `POLICY_STATE_DIR` | — | Snapshot dir for `revocations.json` and `policy_history.json` |
| `POLICY_HOOK_TOKEN` | — | If set, EMQX must send it in `X-IronMesh-Hook-Token` |
| `POLICY_AUTHZ_CACHE_TTL` | `10s` | Decision cache lifetime |
| `POLICY_JWT_PUBLIC_KEY_PEM` | — | P-256 public key(s) (PEM) verifying ES256 service JWTs (`aud=policy`) on the management API |
| `POLICY_JWT_ISSUER` | — | Optional required `iss` of service JWTs |
| `POLICY_OIDC_ISSUER` | — | IdP issuer URL; enables console OIDC access tokens on the management API. The JWKS is discovered from `<issuer>/.well-known/openid-configuration` on first use, cached (1 h) and refreshed when a token names an unknown `kid` (at most every 30 s); tokens must carry exactly this `iss` |
| `POLICY_OIDC_AUDIENCE` | `ironmesh-api` | Value `aud` must contain for OIDC tokens |
| `POLICY_OIDC_ROLE_CLAIM` | `role` | Claim holding the role; dotted paths (`realm_access.roles`) and arrays are accepted (highest known role wins). Tenant comes from `tenant_id` |
| `POLICY_LOG_LEVEL` | `info` | debug/info/warn/error (JSON logs: `ts, level, service, msg, tenant_id, device_id`) |

## Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `POST /emqx/authn`, `POST /emqx/authz` | optional hook token | EMQX backends |
| `POST /internal/v1/revocations` | bearer + HMAC | PKI revocation event → cache, snapshot, kick (202) |
| `GET /v1/policy` | bearer admin | active Rego, version, sha256, updated_at/by |
| `PUT /v1/policy` | bearer owner | compile + embedded invariant tests → 422 diagnostics, else persisted version + atomic hot swap |
| `POST /v1/policy/evaluate` | bearer operator | dry run with OPA trace, `matched_rules`, never cached |
| `GET /v1/policy/history`, `GET /v1/revocations` | bearer viewer | cursor pagination (`?cursor=&limit=`); tokens with `tenant_id` only see that tenant's revocations |
| `GET /metrics`, `GET /healthz`, `GET /readyz`, `GET /openapi.json` | none | ops |

"bearer" is either a console OIDC access token (RS256, PS256 or ES256, verified against the
`POLICY_OIDC_ISSUER` JWKS, `aud` ⊇ `POLICY_OIDC_AUDIENCE`, role from `POLICY_OIDC_ROLE_CLAIM`)
or an ES256 service JWT verified with `POLICY_JWT_PUBLIC_KEY_PEM` (`aud=policy`, role from
`role`); the first verifier that accepts the token wins. With neither configured `/v1/*` answers
503. `alg` values other than those three (e.g. `none`, `HS256`) and keys of the wrong type for
the header `alg` are rejected before signature verification.

Health check for the distroless image: `policy healthcheck [--url URL] [--timeout 3s]` GETs
`http://127.0.0.1:<port of POLICY_LISTEN>/healthz` and exits `0` on 2xx, `1` otherwise (TLS
verification is skipped only for an `https` URL on a loopback host). Example:
`test: ["CMD", "/policy", "healthcheck"]` (path as installed by the Dockerfile).

Metrics: `ironmesh_auth_failures_total{reason}`, `ironmesh_authz_decisions_total{result,action}`,
`ironmesh_revocation_apply_latency_seconds` and the contract alias
`ironmesh_revocation_latency_seconds` (revoked_at → kick done), `ironmesh_revocations_total{source}`,
`ironmesh_kick_total{result}`, `ironmesh_crl_poll_total{result}`, `ironmesh_registry_lookups_total{result}`.

## EMQX configuration

`deploy/emqx/emqx.conf` configures the mTLS-only listener (8883, TLS 1.3, `verify_peer`,
`fail_if_no_peer_cert`, `peer_cert_as_username = cn`), HTTP authn/authz pointing at this service,
`authorization.no_match = deny`, `deny_action = disconnect`, cache 10 s, and `deploy/emqx/acl.conf`
as deny-all fallback. It also configures the auth-event webhook to the bridge: HTTP connector
`ironmesh_bridge` (`http://bridge:8082`), HTTP action `ironmesh_auth_events`
(`POST /emqx/events`, header `x-ironmesh-hook-token` = `BRIDGE_EVENTS_TOKEN`, no body template so
the selected event map is posted as JSON) and rule `ironmesh_auth_events` selecting
`client.connected`, `client.disconnected`, failed `client.check_authn_complete` and denied
`client.check_authz_complete` events. Override the token placeholder at deploy time
(`EMQX_ACTIONS__HTTP__IRONMESH_AUTH_EVENTS__PARAMETERS__HEADERS__X-IRONMESH-HOOK-TOKEN`). Keys marked `VERIFY` in the file (ALPN option, `cert_pem` placeholder) must be
checked against the deployed EMQX release because the broker was not available locally.

## Development

```sh
go test ./... -cover            # includes the Rego suite via the OPA Go test runner
go test ./... -race -cover      # Linux/macOS; on Windows -race needs cgo (gcc)
go vet ./... && gofmt -l .
```

The Rego unit tests in `policy/rego/mqtt_acl_test.rego` are executed by
`internal/engine` (`TestEmbeddedInvariantSuitePasses`) and `internal/hooks/rego_test.go`; the same
suite gates every `PUT /v1/policy`.
