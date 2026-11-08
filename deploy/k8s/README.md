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
  consistent (hook token, PKI<->policy token/HMAC, EMQX API key/secret, internal registry token).

## Dev PKI

`base/pki-dev/issuers.yaml` builds the contract's hierarchy with cert-manager: Dev Root CA
(P-384) -> Factory CA (P-384), Device CA (P-256), Services CA (P-256) + a bundle signing key.
The `pki` service runs with `PKI_KEY_PROVIDER=file` and the CA material projected under
`/etc/ironmesh/ca/{root,factory,device,services,bundle}/tls.{crt,key}`; EMQX trusts the Device
CA (`partial_chain`) for client certificates; every service gets a Services CA identity
(`<service>-tls`, CN `svc-<service>`), and Postgres serves TLS with a Services CA certificate.
In staging/prod the CA keys are KMS keys (Terraform) and only the Services *issuing* CA lives in
cert-manager.

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
* Kafka: Redpanda runs in `dev-container` mode with topics created by the bridge on boot
  (`BRIDGE_KAFKA_TOPICS_CREATE`, replication factor 1).
* Health endpoints: `/healthz` (liveness) and `/readyz` (readiness) on the service port; the PKI
  serves both, plus `/metrics` and the CRL, on the plain 8444 listener because 8443 is mTLS.

## Validation

`kubectl kustomize deploy/k8s/overlays/dev` must render, and CI runs `kubeconform -strict
-ignore-missing-schemas` (cert-manager CRDs) against the rendered output.
