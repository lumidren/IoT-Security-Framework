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
`mqtts://localhost:8883` (dashboard `http://localhost:18083`), PKI EST/OCSP `https://localhost:8443`,
CRL `http://localhost:8444/crl/device-ca.crl`.

## What the dev overlay changes

* images `ghcr.io/lumidren/ironmesh-<service>:dev`
* NodePort services for console, emqx, pki, registry (`overlays/dev/patches/nodeports.yaml`)
* development credentials via `secretGenerator` (stable names, no hash suffix): `pki-secret`,
  `policy-secret`, `bridge-secret`, `registry-secret`, `ota-secret`, `anomaly-secret`,
  `console-secret`, `emqx-env`, `emqx-api-keys`, `postgres-admin`, `dev-db`. Shared pairs are
  consistent (hook token, PKI<->policy token/HMAC, EMQX API key/secret) and
  `REGISTRY_INTERNAL_TOKENS` holds one distinct token per caller (`pki` = `PKI_REGISTRY_TOKEN`,
  `policy` = `POLICY_REGISTRY_TOKEN`, `anomaly` = `ANOMALY_INTERNAL_TOKEN`).

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

* OIDC: there is no identity provider in the dev stack; `*_OIDC_ISSUER` is empty. Point it at a
  local Dex/Keycloak when working on authenticated routes.
* OTA: `OTA_ARTIFACT_STORE=filesystem` on a 10 Gi PVC and `OTA_SIGNING_PROVIDER=file` with
  `OTA_SIGNING_KEY_GENERATE_IF_MISSING=true` (a dev Ed25519 key is created on first start;
  test vectors live in `libs/python/ironmesh-wire/tests/keys`).
* Kafka: Redpanda runs in `dev-container` mode (topic auto-creation on). No IronMesh service
  creates topics; production topics (`im.ingest`, `im.auth`, `im.alerts`, `im.audit`,
  `im.commands`, `im.campaigns`) are created out of band.
* Migrations: the dev stack does not run the registry/ota Alembic migrations (the Helm chart's
  `job-migrate.yaml` does); anomaly migrates itself via `ANOMALY_DATABASE_MIGRATE_URL`, pki via
  `PKI_DATABASE_URL`.
* Health endpoints: `/healthz` (liveness) and `/readyz` (readiness) on the service port; the PKI
  serves both, plus `/metrics` and the CRL, on the plain 8444 listener because 8443 is mTLS. The
  console serves `/api/health` only.

## Validation

`kubectl kustomize deploy/k8s/overlays/dev` must render, and CI runs `kubeconform -strict
-ignore-missing-schemas` (cert-manager CRDs) against the rendered output.
