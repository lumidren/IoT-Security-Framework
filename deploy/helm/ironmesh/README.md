# ironmesh Helm chart

Deploys the IronMesh control plane (pki, policy, bridge, registry, ota, anomaly, console),
EMQX 5 as the mTLS MQTT broker (dependency `emqx` 5.8.9) and, optionally, self-hosted Redpanda
(dependency `redpanda` 26.2.5). Ports, metric names and topics follow `docs/DESIGN_CONTRACT.md`;
internal HTTP calls follow `docs/API_CONTRACT.md`.

```bash
helm dependency update deploy/helm/ironmesh
helm upgrade --install ironmesh deploy/helm/ironmesh -n ironmesh --create-namespace \
  -f deploy/helm/ironmesh/values.yaml \
  -f deploy/helm/ironmesh/values-prod.yaml \
  -f deploy/helm/ironmesh/values-prod.generated.yaml   # from: terraform output -raw helm_values
helm -n ironmesh test ironmesh
```

`fullnameOverride: ironmesh` keeps in-cluster names stable (`ironmesh-pki`, `ironmesh-policy`,
...) so every `*_URL` in the values is valid whatever the release name.

## What is rendered per service

| Object                    | Notes                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------------|
| Deployment                | non-root (10001), read-only root FS, `drop: [ALL]`, seccomp RuntimeDefault, startup/liveness (`/healthz`)/readiness (`/readyz`) probes, zone + host topology spread, emptyDirs for `writableDirs` |
| Service                   | ClusterIP, named ports from `services.<name>.ports`, label `ironmesh.dev/job=ironmesh-<name>` |
| ConfigMap                 | `services.<name>.config` + shared defaults (database, kafka, public URLs)                     |
| Secret / ExternalSecret   | `ironmesh-<name>-secret` with the keys in `secretKeys` (ESO when `externalSecrets.enabled`)   |
| ServiceAccount            | `eks.amazonaws.com/role-arn` from `serviceAccount.roleArn`, token automount off               |
| HorizontalPodAutoscaler   | CPU utilisation (bridge included: the shared subscription balances by replica count)          |
| PodDisruptionBudget       | `minAvailable` (2 in prod)                                                                    |
| Certificate               | Services CA mTLS identity `svc-<name>` (cert-manager CA issuer)                               |
| NetworkPolicy             | default deny + contract allow list (see below)                                                |
| ServiceMonitor            | when `monitoring.enabled`; job label `ironmesh-<name>`                                        |

Release-level: Ingress (nginx or alb) **or** TargetGroupBindings (Terraform ALB/NLB),
public `Certificate`, EMQX listener `Certificate`, EMQX/Redpanda ServiceMonitors,
PrometheusRule (embeds `rules/ironmesh.rules.yml`, identical to
`observability/prometheus/rules/ironmesh.rules.yml`), db-init hook Job, `helm test` pod.

## Environment variable contract

The chart sets exactly the variables each service reads; the names below are taken from the
code (`services/pki/internal/config/config.go`, `services/policy/internal/config/config.go` +
`cmd/policy/main.go`, `services/bridge/internal/config/config.go`,
`services/registry/app/settings.py`, `services/ota/src/ironmesh_ota/settings.py`,
`services/anomaly/src/ironmesh_anomaly/config.py`, `console/src/lib/env.ts`,
`console/src/lib/server/env.ts`, `console/src/auth.ts`). CI enforces it with
`python scripts/ci/check_env_contract.py`, which fails on any name a service does not read.

Empty values are dropped from the ConfigMap. Shared fallbacks: `<P>_DB_HOST/PORT/SSLMODE/IAM_AUTH`
from `database`; `<P>_KAFKA_BROKERS` from the Redpanda sub-chart or `kafka.bootstrapServers`;
`<P>_KAFKA_SASL_MECHANISM`, `<P>_KAFKA_TLS_ENABLED` and `BRIDGE_KAFKA_TLS` from `kafka` (only
when the service declares the key); `PKI_PUBLIC_BASE_URL` / `REGISTRY_PUBLIC_BASE_URL` /
`OTA_PUBLIC_BASE_URL` / `NEXT_PUBLIC_APP_URL` from the public hosts; `PKI_BROKER_HOST` from the
mqtt host; `OTA_OTEL_ENDPOINT` from `otelCollector.endpoint`; `NEXT_PUBLIC_ENVIRONMENT` from
`global.environment`. Secrets are listed in `services.<name>.secretKeys` and are expected in the
Secret / Secrets Manager JSON `<secretPathPrefix><service>`.

| Service  | Plain (ConfigMap)                                                                                                   | Secret                                                                 |
|----------|---------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| pki      | `PKI_ENV` `PKI_LISTEN_MTLS` `PKI_LISTEN_PLAIN` `PKI_KMS` (`awskms`/`softhsm`/`file`) `PKI_CA_DIR` `PKI_BUNDLE_KEY_FILE` `PKI_KEY_DEVICE_CA` `PKI_KEY_SERVICES_CA` `PKI_PUBLIC_BASE_URL` `PKI_POLICY_URL` `PKI_REGISTRY_URL` `PKI_NONCE_TTL` `PKI_OPERATIONAL_CERT_TTL` `PKI_SERVER_CERT_FILE` `PKI_SERVER_KEY_FILE` `PKI_MGMT_ALLOWED_CNS` `PKI_MGMT_JWT_PUBLIC_KEY_FILE` `PKI_DEFAULT_ALLOW_SOFTWARE_KEYS` `PKI_TPM_AK_CA_FILE` `PKI_TPM_ALLOWED_PCR_DIGESTS` `PKI_BROKER_HOST` `PKI_BROKER_PORT` `PKI_LOG_LEVEL` `PKI_SHUTDOWN_TIMEOUT` (also read: `PKI_SERVER_SANS`, `PKI_PKCS11_MODULE`, `PKI_PKCS11_TOKEN`) | `PKI_DATABASE_URL` `PKI_POLICY_TOKEN` `PKI_POLICY_HMAC_KEY` `PKI_REGISTRY_TOKEN` `PKI_FILE_KMS_PASSPHRASE` `PKI_PKCS11_PIN` |
| policy   | `POLICY_LISTEN` `POLICY_EMQX_API_URL` `POLICY_PKI_CRL_URL` `POLICY_CRL_POLL_INTERVAL` `POLICY_CRL_ISSUER_CERT_FILE` `POLICY_REGISTRY_URL` `POLICY_REGISTRY_FAIL_OPEN` `POLICY_REGISTRY_TIMEOUT` `POLICY_REGISTRY_CACHE_TTL` `POLICY_SERVICE_CIDRS` `POLICY_STATE_DIR` `POLICY_AUTHZ_CACHE_TTL` `POLICY_SHUTDOWN_TIMEOUT` `POLICY_LOG_LEVEL` `POLICY_JWT_ISSUER` | `POLICY_EMQX_API_KEY` `POLICY_EMQX_API_SECRET` `POLICY_PKI_HMAC_SECRET` `POLICY_PKI_TOKEN` `POLICY_REGISTRY_TOKEN` `POLICY_HOOK_TOKEN` `POLICY_JWT_PUBLIC_KEY_PEM` |
| bridge   | `BRIDGE_LISTEN` `BRIDGE_MQTT_URL` `BRIDGE_MQTT_CLIENT_ID` `BRIDGE_MQTT_TOPIC` `BRIDGE_MQTT_KEEPALIVE` `BRIDGE_MQTT_SESSION_EXPIRY` `BRIDGE_TLS_{CERT,KEY,CA}_FILE` `BRIDGE_TLS_SERVER_NAME` `BRIDGE_KAFKA_BROKERS` `BRIDGE_KAFKA_INGEST_TOPIC` `BRIDGE_KAFKA_AUTH_TOPIC` `BRIDGE_KAFKA_TLS` `BRIDGE_KAFKA_TLS_CA_FILE` `BRIDGE_MAX_INFLIGHT` `BRIDGE_LOG_LEVEL` `BRIDGE_SHUTDOWN_TIMEOUT` (also read: `BRIDGE_MQTT_CONNECT_RETRY`) | `BRIDGE_EVENTS_TOKEN` |
| registry | `REGISTRY_ENVIRONMENT` `REGISTRY_LISTEN_PORT` `REGISTRY_DB_{HOST,PORT,NAME,USER,SSLMODE,IAM_AUTH}` `REGISTRY_KAFKA_BROKERS` `REGISTRY_KAFKA_TOPIC_{INGEST,AUTH,ALERTS,AUDIT,COMMANDS,CAMPAIGNS}` `REGISTRY_KAFKA_CONSUMER_GROUP` `REGISTRY_KAFKA_{SASL_MECHANISM,TLS_ENABLED}` `REGISTRY_PKI_URL` `REGISTRY_POLICY_URL` `REGISTRY_OTA_URL` `REGISTRY_EMQX_API_URL` `REGISTRY_OIDC_{ISSUER,AUDIENCE,JWKS_URL}` `REGISTRY_PUBLIC_BASE_URL` `REGISTRY_TLS_{CERT,KEY,CA}_FILE` `REGISTRY_SERVICE_JWT_PRIVATE_KEY_FILE` `REGISTRY_MQTT_{HOST,PORT,CLIENT_ID}` `REGISTRY_KMS_BACKEND` `REGISTRY_KMS_LOCAL_KEK_FILE` `REGISTRY_KMS_AWS_{KEY_ID,REGION}` `REGISTRY_LOG_{LEVEL,FORMAT}` | `REGISTRY_DB_PASSWORD` `REGISTRY_INTERNAL_TOKENS` (JSON `{"pki":…,"policy":…,"anomaly":…}`) `REGISTRY_EMQX_API_KEY` `REGISTRY_EMQX_API_SECRET` `REGISTRY_KAFKA_SASL_PASSWORD` `REGISTRY_MIGRATION_DATABASE_URL` (migration hook only) |
| ota      | `OTA_ENV` `OTA_LISTEN_PORT` `OTA_DB_{HOST,PORT,NAME,USER,SSLMODE,IAM_AUTH}` `OTA_KAFKA_BROKERS` `OTA_KAFKA_TOPIC_{INGEST,COMMANDS,AUDIT,CAMPAIGNS}` `OTA_KAFKA_CONSUMER_GROUP` `OTA_KAFKA_{SASL_MECHANISM,TLS_ENABLED}` `OTA_ARTIFACT_STORE` `OTA_ARTIFACT_BUCKET` `OTA_S3_KMS_KEY_ARN` `OTA_S3_REGION` `OTA_AWS_REGION` `OTA_ARTIFACT_PATH` `OTA_SIGNING_PROVIDER` `OTA_SIGNING_KEK_KEY_ID` `OTA_SIGNING_KEY_SECRET_ARN` `OTA_SIGNING_KEY_ID` `OTA_PQ_SIGNING_ENABLED` `OTA_TENANT_KEYS_PROVIDER` `OTA_TENANT_KEYS_KEK_KEY_ID` `OTA_TENANT_KEY_SECRET_PREFIX` `OTA_PUBLIC_BASE_URL` `OTA_PKI_URL` `OTA_REGISTRY_URL` `OTA_EMQX_API_URL` `OTA_OIDC_{ISSUER,AUDIENCE,JWKS_URL}` `OTA_TLS_{CERT,KEY,CA}_FILE` `OTA_LOG_{LEVEL,FORMAT}` `OTA_OTEL_ENABLED` `OTA_OTEL_ENDPOINT` | `OTA_DB_PASSWORD` `OTA_INTERNAL_TOKEN` `OTA_EMQX_API_KEY` `OTA_EMQX_API_SECRET` `OTA_SIGNING_PRIVATE_KEY_PEM` (file provider only) `OTA_DOWNLOAD_HMAC_SECRET` `OTA_KAFKA_SASL_PASSWORD` `OTA_MIGRATION_DATABASE_URL` (migration hook only) |
| anomaly  | `ANOMALY_ENVIRONMENT` `ANOMALY_LISTEN_PORT` `ANOMALY_DB_{HOST,PORT,NAME,USER,SSLMODE,IAM_AUTH,REGION}` `ANOMALY_KAFKA_BROKERS` `ANOMALY_KAFKA_TOPIC_{INGEST,AUTH,COMMANDS,ALERTS,AUDIT}` `ANOMALY_KAFKA_CONSUMER_GROUP` `ANOMALY_KAFKA_{SASL_MECHANISM,TLS_ENABLED}` `ANOMALY_{REGISTRY,POLICY,OTA,PKI}_URL` `ANOMALY_AUTO_QUARANTINE` `ANOMALY_QUARANTINE_MIN_SEVERITY` `ANOMALY_MODEL_DIR` `ANOMALY_OIDC_{ISSUER,AUDIENCE,JWKS_URL}` `ANOMALY_TLS_{CERT,KEY,CA}_FILE` `ANOMALY_LOG_{LEVEL,FORMAT}` | `ANOMALY_DB_PASSWORD` `ANOMALY_INTERNAL_TOKEN` `ANOMALY_SIEM_WEBHOOK_URL` `ANOMALY_SIEM_WEBHOOK_SECRET` `ANOMALY_KAFKA_SASL_PASSWORD` `ANOMALY_DATABASE_MIGRATE_URL` |
| console  | `PORT` `HOSTNAME` `NODE_ENV` `NEXT_TELEMETRY_DISABLED` `AUTH_TRUST_HOST` `CONSOLE_{REGISTRY,OTA,ANOMALY,POLICY}_URL` `CONSOLE_OIDC_{ISSUER,CLIENT_ID}` `NEXT_PUBLIC_APP_URL` `NEXT_PUBLIC_OIDC_{ISSUER,CLIENT_ID}` `NEXT_PUBLIC_ENVIRONMENT` (`NEXT_PUBLIC_*` are also build-time; health probe `/api/health`) | `AUTH_SECRET` `CONSOLE_OIDC_CLIENT_SECRET` |
| all      | `OTEL_SERVICE_NAME` `OTEL_EXPORTER_OTLP_ENDPOINT` `OTEL_EXPORTER_OTLP_PROTOCOL` `OTEL_RESOURCE_ATTRIBUTES` `OTEL_TRACES_SAMPLER(_ARG)` `POD_NAME` `POD_NAMESPACE` `NODE_NAME` `POD_IP` | |

Values that must match across secrets:

* `PKI_POLICY_TOKEN` = `POLICY_PKI_TOKEN`, `PKI_POLICY_HMAC_KEY` = `POLICY_PKI_HMAC_SECRET`.
* `REGISTRY_INTERNAL_TOKENS` = `{"pki": PKI_REGISTRY_TOKEN, "policy": POLICY_REGISTRY_TOKEN,
  "anomaly": ANOMALY_INTERNAL_TOKEN}`. The three tokens must be **distinct**: each one
  authenticates exactly one caller and the registry enforces the per-endpoint caller allowlist.
* `POLICY_HOOK_TOKEN` = the EMQX `X-IronMesh-Hook-Token` header (derived by the EMQX ExternalSecret).
* `POLICY_EMQX_API_KEY/SECRET`, `REGISTRY_EMQX_API_KEY/SECRET`, `OTA_EMQX_API_KEY/SECRET` = the
  EMQX bootstrap API keys (the `ironmesh-emqx-api-keys` ExternalSecret renders all three).
* The db-init Job additionally reads `<DB>_DB_OWNER_PASSWORD` / `<DB>_DB_PASSWORD` and
  `BACKUP_DB_PASSWORD` from the service Secrets when IAM authentication is off.

Mounts: Services CA identity at `/etc/ironmesh/tls` (`tls.crt`, `tls.key`, `ca.crt`; subject
`O=IronMesh, OU=services`, which the policy authn hook requires for `svc-*` principals), Device CA
bundle at `/etc/ironmesh/device-ca/ca.crt` (pki, policy), PKI CA material and bundle key from
`pkiCa.existingSecret` at `/etc/ironmesh/ca` (pki).

Migrations: `templates/job-migrate.yaml` runs the registry and ota migrations as hooks
(`migrations.enabled`); anomaly and pki migrate themselves at start.

## Broker

EMQX is configured through `emqx.emqxConfig` environment overrides: a single listener `ssl:default`
on 8883, TLS 1.3 only, `verify_peer` + `fail_if_no_peer_cert`, `partial_chain` against the Device
CA bundle, `verify_peer_ext_key_usage = clientAuth`, `mqtt.peer_cert_as_username = cn`,
`enable_authn = quick_deny_anonymous`; HTTP authn/authz to `ironmesh-policy:8081/emqx/{authn,authz}`
with the hook token header, `authorization.no_match = deny`, `deny_action = disconnect`, 10 s
authz cache (revocations are enforced by the policy kick, not the cache TTL). The policy service
kicks sessions through `DELETE /api/v5/clients/{clientid}` using the bootstrap API key.

## Networking

`networkPolicy.enabled` renders default-deny for the namespace plus: DNS, OTLP egress to the
collector, HTTPS egress (STS/KMS/S3/Secrets Manager/OIDC/SIEM), devices -> emqx 8883 and pki
8443/8444, emqx -> policy 8081, policy -> emqx 18083 / pki 8444 / registry 8000, pki -> policy /
postgres, bridge -> emqx 8883 / kafka, registry/ota/anomaly -> postgres / kafka / pki 8443,
console -> registry/ota/anomaly, Prometheus -> metrics ports. `additionalAllows` toggles the
extra calls required by the API contract (pki -> registry enrolment callback, registry ->
policy/ota/EMQX API, anomaly -> registry/policy/ota, console -> policy, policy -> kafka, EMQX ->
bridge webhook).

## Exposure

* **AWS (staging/prod)**: `aws.targetGroupBindings.enabled` binds console/registry/ota to the
  Terraform ALB and emqx (8883) / pki (8443, 8444) to the NLB. Security group rules are managed
  by Terraform (`manageNetworking: false`).
* **Any cluster**: `ingress.enabled` with class `nginx` (TLS from cert-manager, `Certificate`
  with the three hosts) or `alb` (ACM certificate ARN + WAF ACL annotations). The broker and PKI
  then need a `LoadBalancer`/`NodePort` service outside this chart (see `deploy/k8s`).

## PKI material

* Services CA (KMS, `ironmesh-<env>-services-ca`) signs a **Services issuing CA** during the
  ceremony; its key lives in a cert-manager CA `Issuer` (`internalTls.certManager.issuerRef`) that
  issues the 90-day service identities and the broker listener certificate. Devices pin the
  Services CA SPKI; the chain presented by EMQX contains it.
* Device CA + Factory CA certificates (public) go into the `deviceCa.existingSecret` bundle used
  by EMQX (`cacertfile`) and pki/policy.
* The firmware Ed25519 key never enters the cluster as a Secret (ESO is denied by IAM); ota
  unwraps it from Secrets Manager at runtime through `OTA_SIGNING_KEY_SECRET_ARN`.
* The PKI bundle key is Ed25519 as well. Terraform keeps the seed in Secrets Manager
  (`<prefix>pki/bundle-signing-key`, symmetric CMK `bundle_kek`, pki IRSA role only, ESO denied).
  The pki service currently loads the bundle key only from `PKI_BUNDLE_KEY_FILE` (a pkictl key
  file encrypted under `PKI_FILE_KMS_PASSPHRASE`), which the ceremony operator places in the
  `pkiCa.existingSecret` Secret as `bundle.key.json`.

## Databases

`dbInit.enabled` runs a pre-install/pre-upgrade Job that creates `registry`, `ota`, `pki`,
`anomaly`, the roles `<db>_owner` (migrations), `<db>_app` (runtime, RLS applies) and
`ironmesh_backup` (read-only), granting `rds_iam` when `database.iamAuth` is true. It needs
`dbInit.adminSecretName` with `username`/`password` (the RDS-managed master secret synced by ESO
from `ironmesh/<env>/postgres-admin`).

## Values files

* `values.yaml` – defaults, documented inline.
* `values-staging.yaml` / `values-prod.yaml` – environment posture (replicas, HPA bounds, PDBs,
  MSK IAM, External Secrets, node placement for the broker in prod).
* `values-<env>.generated.yaml` – written by `terraform output -raw helm_values`, git-ignored.

## Validation

CI runs `helm lint`, `helm template | kubeconform -strict -ignore-missing-schemas` (CRDs:
ExternalSecret, ServiceMonitor, PrometheusRule, Certificate, TargetGroupBinding) and checks that
`rules/ironmesh.rules.yml` equals the Prometheus copy.
