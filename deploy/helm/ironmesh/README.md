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

The chart defines the environment of every service. Names are prefixed per service; database
and Kafka keys fall back to the shared `database` / `kafka` values when empty. Secrets are
listed in `services.<name>.secretKeys` and are expected in the Secret/Secrets Manager JSON.

| Service  | Plain (ConfigMap)                                                                                                   | Secret                                                                 |
|----------|---------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| pki      | `PKI_LISTEN_MTLS` `PKI_LISTEN_PLAIN` `PKI_KEY_PROVIDER` `PKI_KMS_{ROOT_CA,FACTORY_CA,DEVICE_CA,SERVICES_CA,BUNDLE}_KEY_ID` `PKI_KEY_DIR` `PKI_PUBLIC_BASE_URL` `PKI_POLICY_URL` `PKI_REGISTRY_URL` `PKI_CRL_PUBLISH_INTERVAL` `PKI_CRL_NEXT_UPDATE` `PKI_OCSP_ENABLED` `PKI_NONCE_TTL` `IRONMESH_OPERATIONAL_CERT_TTL` `PKI_DEVICE_CA_BUNDLE_FILE` `PKI_TLS_{CERT,KEY,CA}_FILE` `PKI_DB_{HOST,PORT,NAME,USER,SSLMODE,IAM_AUTH}` `PKI_LOG_LEVEL` `PKI_LOG_FORMAT` | `PKI_DB_PASSWORD` `PKI_POLICY_TOKEN` `PKI_POLICY_HMAC_SECRET` `PKI_REGISTRY_TOKEN` `PKI_FILE_KMS_PASSPHRASE` |
| policy   | exactly `services/policy/internal/config/config.go`: `POLICY_LISTEN` `POLICY_EMQX_API_URL` `POLICY_PKI_CRL_URL` `POLICY_CRL_POLL_INTERVAL` `POLICY_CRL_ISSUER_CERT_FILE` `POLICY_REGISTRY_URL` `POLICY_REGISTRY_FAIL_OPEN` `POLICY_REGISTRY_TIMEOUT` `POLICY_REGISTRY_CACHE_TTL` `POLICY_STATE_DIR` `POLICY_AUTHZ_CACHE_TTL` `POLICY_SHUTDOWN_TIMEOUT` `POLICY_LOG_LEVEL` + `POLICY_KAFKA_*` `POLICY_TLS_*` | `POLICY_EMQX_API_KEY` `POLICY_EMQX_API_SECRET` `POLICY_PKI_HMAC_SECRET` `POLICY_PKI_TOKEN` `POLICY_REGISTRY_TOKEN` `POLICY_HOOK_TOKEN` |
| bridge   | `BRIDGE_LISTEN` `BRIDGE_MQTT_URL` `BRIDGE_MQTT_CLIENT_ID` `BRIDGE_SHARED_SUBSCRIPTION` `BRIDGE_MQTT_KEEPALIVE` `BRIDGE_KAFKA_BROKERS` `BRIDGE_KAFKA_TOPIC_{INGEST,AUTH,AUDIT}` `BRIDGE_KAFKA_TOPICS_CREATE` `BRIDGE_KAFKA_TOPIC_{PARTITIONS,REPLICATION}` `BRIDGE_KAFKA_{SASL_MECHANISM,SASL_USERNAME,TLS_ENABLED}` `BRIDGE_TLS_*` `BRIDGE_LOG_*` | `BRIDGE_HOOK_TOKEN` `BRIDGE_KAFKA_SASL_PASSWORD` |
| registry | `REGISTRY_LISTEN_PORT` `REGISTRY_DB_*` `REGISTRY_KAFKA_*` `REGISTRY_PKI_URL` `REGISTRY_POLICY_URL` `REGISTRY_OTA_URL` `REGISTRY_EMQX_API_URL` `REGISTRY_OIDC_{ISSUER,AUDIENCE}` `REGISTRY_PUBLIC_BASE_URL` `REGISTRY_TLS_*` `REGISTRY_LOG_*` | `REGISTRY_DB_PASSWORD` `REGISTRY_INTERNAL_TOKEN` `REGISTRY_EMQX_API_KEY` `REGISTRY_EMQX_API_SECRET` |
| ota      | `OTA_LISTEN_PORT` `OTA_DB_*` `OTA_KAFKA_*` `OTA_ARTIFACT_STORE` `OTA_ARTIFACT_BUCKET` `OTA_S3_KMS_KEY_ARN` `OTA_ARTIFACT_PATH` `OTA_SIGNING_PROVIDER` `OTA_SIGNING_KEK_KEY_ID` `OTA_SIGNING_KEY_SECRET_ARN` `OTA_SIGNING_KEY_ID` `OTA_PQ_SIGNING_ENABLED` `OTA_PUBLIC_BASE_URL` `OTA_PKI_URL` `OTA_REGISTRY_URL` `OTA_EMQX_API_URL` `OTA_OIDC_*` `OTA_TLS_*` `OTA_LOG_*` | `OTA_DB_PASSWORD` `OTA_INTERNAL_TOKEN` `OTA_EMQX_API_KEY` `OTA_EMQX_API_SECRET` `OTA_SIGNING_PRIVATE_KEY_PEM` (file provider only) |
| anomaly  | `ANOMALY_LISTEN_PORT` `ANOMALY_DB_*` `ANOMALY_KAFKA_*` `ANOMALY_{REGISTRY,POLICY,OTA,PKI}_URL` `ANOMALY_AUTO_QUARANTINE` `ANOMALY_QUARANTINE_MIN_SEVERITY` `ANOMALY_MODEL_DIR` `ANOMALY_OIDC_*` `ANOMALY_TLS_*` `ANOMALY_LOG_*` | `ANOMALY_DB_PASSWORD` `ANOMALY_INTERNAL_TOKEN` `ANOMALY_SIEM_WEBHOOK_URL` |
| console  | `PORT` `HOSTNAME` `NODE_ENV` `NEXT_TELEMETRY_DISABLED` `CONSOLE_{REGISTRY,OTA,ANOMALY,POLICY}_URL` `CONSOLE_OIDC_{ISSUER,CLIENT_ID}` `NEXT_PUBLIC_APP_URL` `NEXT_PUBLIC_OIDC_{ISSUER,CLIENT_ID,AUDIENCE}` `NEXT_PUBLIC_ENVIRONMENT` | `AUTH_SECRET` `CONSOLE_OIDC_CLIENT_SECRET` |
| all      | `OTEL_SERVICE_NAME` `OTEL_EXPORTER_OTLP_ENDPOINT` `OTEL_EXPORTER_OTLP_PROTOCOL` `OTEL_RESOURCE_ATTRIBUTES` `OTEL_TRACES_SAMPLER(_ARG)` `POD_NAME` `POD_NAMESPACE` `NODE_NAME` `POD_IP` | |

Shared values pairs that must match: `PKI_POLICY_TOKEN` = `POLICY_PKI_TOKEN`,
`PKI_POLICY_HMAC_SECRET` = `POLICY_PKI_HMAC_SECRET`, `*_REGISTRY_TOKEN`/`*_INTERNAL_TOKEN` =
`REGISTRY_INTERNAL_TOKEN`, `POLICY_HOOK_TOKEN` = the EMQX `X-IronMesh-Hook-Token` header
(derived automatically by the EMQX ExternalSecret), `POLICY_EMQX_API_KEY/SECRET` = the EMQX
bootstrap API key (derived automatically). `deploy/k8s` uses the same names.

Mounts: Services CA identity at `/etc/ironmesh/tls` (`tls.crt`, `tls.key`, `ca.crt`), Device CA
bundle at `/etc/ironmesh/device-ca/ca.crt` (pki, policy).

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
