# deploy/k8s – Kustomize dev stack

Plain manifests for a single-node development cluster (kind or minikube): Postgres 16,
Redpanda (single node), EMQX 5 (single node, mTLS listener), the OpenTelemetry collector and
the seven IronMesh services, each with the same environment variable names as the Helm chart
(`deploy/helm/ironmesh/README.md`, "Environment variable contract"). Service names follow the
design contract's compose names: `pki`, `policy`, `bridge`, `registry`, `ota`, `anomaly`,
`console`, `emqx`, `redpanda`, `postgres`, `otel-collector`.

```bash
kind create cluster --name ironmesh --config deploy/k8s/kind-config.yaml
# NetworkPolicy-enforcing CNI (kindnet does not enforce policies)
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml
# cert-manager provides the dev CA hierarchy and the service identities
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.21.3/cert-manager.yaml
kubectl -n cert-manager rollout status deploy/cert-manager-webhook
kubectl apply -k deploy/k8s/overlays/dev
kubectl -n ironmesh get pods -w
```

Host ports (kind): console `http://localhost:3000`, registry `http://localhost:8000`, EMQX
`mqtts://localhost:8883` (devices only), PKI EST/OCSP `https://localhost:8443`,
CRL `http://localhost:8444/crl/device-ca.crl`. The EMQX dashboard / management API is not mapped
(THREAT_MODEL T-76): `kubectl -n ironmesh port-forward svc/emqx-api 18083:18083` when debugging.
EMQX has three Services: `emqx` (8883, devices, NodePort in dev), `emqx-internal` (8884, the
internal service listener for `svc-bridge` / `svc-registry`) and `emqx-api` (18083, reachable from
policy, registry, ota and Prometheus only).

## What the dev overlay changes

* images `ghcr.io/lumidren/ironmesh-<service>:dev`
* NodePort services for console, emqx, pki, registry (`overlays/dev/patches/nodeports.yaml`)
* development credentials via `secretGenerator` (stable names, no hash suffix): `pki-secret`,
  `policy-secret`, `bridge-secret`, `registry-secret`, `ota-secret`, `anomaly-secret`,
  `console-secret`, `emqx-env`, `emqx-api-keys`, `redpanda-users`, `postgres-admin`, `dev-db`.
  Shared pairs are
  consistent (policy hook token, bridge webhook token = the EMQX `ironmesh_auth_events` action
  header, PKI<->policy token/HMAC, EMQX API key/secret) and `REGISTRY_INTERNAL_TOKENS` holds one
  distinct token per caller (`pki` = `PKI_REGISTRY_TOKEN`, `policy` = `POLICY_REGISTRY_TOKEN`,
  `anomaly` = `ANOMALY_INTERNAL_TOKEN`, `ota` = `OTA_REGISTRY_TOKEN`).
* `pki-secret` carries `PKI_DATABASE_URL` (runtime role `pki_app`, `NOBYPASSRLS`) and
  `PKI_MIGRATION_DATABASE_URL` (schema owner `pki_owner`, used only to migrate at start);
  `registry-secret` / `ota-secret` carry the owner DSNs of the migration Jobs.

## Keys and tenant policy

The registry is the only holder of tenant command keys (wrapped with `REGISTRY_KMS_*`); it pushes
the public key and `allow_software_keys` to the PKI tenant-policy API over mTLS as
`svc-registry`. The OTA service pushes its firmware signing keys there as `svc-ota`, requests
OtaNotify downlinks from the registry (`OTA_REGISTRY_TOKEN`) and holds no tenant key. The PKI
calls the registry's enrolled callback with `PKI_REGISTRY_URL` / `PKI_REGISTRY_TOKEN`.

## Dev PKI

The `pki` service reads its CA material in the `pkictl` layout (`services/pki/README.md`):
`PKI_KMS=file`, `PKI_CA_DIR=/etc/ironmesh/ca` with `root-ca.crt`, `factory-ca.crt`,
`device-ca.crt`, `services-ca.crt`, `device-ca.key.json`, `services-ca.key.json` and
`bundle.key.json` (Ed25519), all encrypted under `PKI_FILE_KMS_PASSPHRASE`. cert-manager's
`tls.key` PEM files cannot be used for that, so create the Secret from a pkictl hierarchy (the
compose `pki-init` image does exactly this):

```bash
export PKI_FILE_KMS_PASSPHRASE=dev-file-kms-passphrase      # = pki-secret in the dev overlay
pkictl init-root --dir ./pki-dev
for k in factory device services; do pkictl init-intermediate --dir ./pki-dev --kind $k; done
pkictl init-bundle-key --dir ./pki-dev
kubectl -n ironmesh create secret generic ironmesh-dev-pki-ca   --from-file=./pki-dev/root-ca.crt --from-file=./pki-dev/factory-ca.crt   --from-file=./pki-dev/device-ca.crt --from-file=./pki-dev/services-ca.crt   --from-file=./pki-dev/device-ca.key.json --from-file=./pki-dev/services-ca.key.json   --from-file=./pki-dev/bundle.key.json
```

`base/pki-dev/issuers.yaml` still builds a cert-manager hierarchy for the service identities
(`<service>-tls`, CN `svc-<service>`, subject `O=IronMesh, OU=services` as the policy authn hook
requires) and the EMQX/Postgres server certificates. Until those identities are issued from the
same Services CA as the pkictl hierarchy (load `services-ca` into a cert-manager CA Issuer), the
bundle's Services CA pin and the broker certificate do not match for real devices; use the
compose stack (`deploy/docker`) for end-to-end device tests. In staging/prod the CA keys are KMS
keys (Terraform) and only the Services *issuing* CA lives in cert-manager.

## Observability in dev

The in-namespace collector exports application metrics on `otel-collector:8889` and logs
traces/logs with the `debug` exporter. For Prometheus + Grafana install kube-prometheus-stack
in an `observability` namespace and load `observability/prometheus/rules/ironmesh.rules.yml`
and `observability/grafana/dashboards/*.json`; the pods carry `prometheus.io/scrape`
annotations and the `allow-prometheus-scrape` NetworkPolicy admits any namespace's
`app.kubernetes.io/name=prometheus` pods.

## Notes for service authors

* OIDC: there is no identity provider in the dev stack; `*_OIDC_ISSUER` (including
  `POLICY_OIDC_ISSUER`, which enables console tokens on the policy management API) is empty.
  Point it at a local Dex/Keycloak when working on authenticated routes.
* OTA: `OTA_ARTIFACT_STORE=filesystem` on a 10 Gi PVC and `OTA_SIGNING_PROVIDER=file` with
  `OTA_SIGNING_KEY_GENERATE_IF_MISSING=true` (a dev Ed25519 key is created on first start;
  test vectors live in `libs/python/ironmesh-wire/tests/keys`).
* Kafka: Redpanda runs in `dev-container` mode with SASL/SCRAM-SHA-512 enforced (THREAT_MODEL
  T-72). The `redpanda-init` Job (`base/redpanda/init-job.yaml`) creates the users `admin`
  (superuser, ACL writes only), `bridge`, `registry`, `ota`, `anomaly` from `redpanda-users`, sets
  `enable_sasl=true` and writes per-service topic ACLs plus `<svc>-*` consumer-group ACLs (the MSK
  IAM grants of `deploy/terraform/aws/modules/iam`). Services authenticate with
  `<SVC>_KAFKA_SASL_{MECHANISM,USERNAME}` (ConfigMap) and `<SVC>_KAFKA_SASL_PASSWORD` (secret). The
  bridge creates the topics (`im.ingest`, `im.auth`, `im.alerts`, `im.audit`, `im.commands`,
  `im.campaigns`) on boot (`BRIDGE_KAFKA_TOPICS_CREATE=true`, 3 partitions, replication 1).
  Known gap: the OTA service declares `OTA_KAFKA_SASL_*` but its Kafka clients do not use them
  yet, so its Kafka publish/consume fails until that code change lands.
* Revocation fan-out: `pki` pushes revocations to `policy-headless` (`PKI_POLICY_FANOUT=dns`), a
  headless Service resolving to every ready policy pod.
* EMQX forwards client lifecycle / authn-failure / authz-deny events to the bridge
  (`POST bridge:8082/emqx/events` -> `im.auth`) through the connector, action and rule set in
  `base/emqx/configmap.yaml`; the action's token header lives in `emqx-env`.
* Migrations: the `registry-migrate` (`alembic upgrade head`, all revisions incl.
  `0002_downlink_sequences`) and `ota-migrate` Jobs in `base/services/{registry,ota}.yaml` run as
  the schema owners and are garbage-collected 10 minutes after they finish (a Job's pod template
  is immutable: `kubectl -n ironmesh delete job registry-migrate ota-migrate` before re-applying
  with new images if they still exist); the services retry until the schema exists. anomaly
  migrates itself via `ANOMALY_DATABASE_MIGRATE_URL`, pki via `PKI_MIGRATION_DATABASE_URL`.
* Health endpoints: `/healthz` (liveness) and `/readyz` (readiness) on the service port; the PKI
  serves both, plus `/metrics` and the CRL, on the plain 8444 listener because 8443 is mTLS. The
  console serves `/api/health` only. Probes stay HTTP here; the compose stack uses the binaries'
  own `healthcheck` subcommands instead.

## Validation

`kubectl kustomize deploy/k8s/overlays/dev` must render, and CI runs `kubeconform -strict
-ignore-missing-schemas` (cert-manager CRDs) against the rendered output.
