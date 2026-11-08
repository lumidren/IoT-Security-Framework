# observability/

OpenTelemetry collector configuration, Prometheus scrape config and rules, and Grafana
provisioning + dashboards for IronMesh. Everything here is keyed on the names fixed in
`docs/DESIGN_CONTRACT.md` §7 (ports) and §9 (metrics).

```
observability/
├── otel-collector/config.yaml              OTLP in (4317/4318) -> Prometheus 8889, OTLP traces, OTLP/HTTP logs, debug
├── prometheus/prometheus.yml               static targets for the compose/dev stack (job = ironmesh-<service>)
├── prometheus/rules/ironmesh.rules.yml     recording + alerting rules (embedded verbatim by the Helm chart)
├── grafana/provisioning/datasources/       Prometheus (uid prometheus) and Tempo (uid tempo)
├── grafana/provisioning/dashboards/        file provider for the IronMesh folder
├── grafana/dashboards/*.json               fleet-overview, pki, ota, anomaly, broker, slo
└── grafana/generate_dashboards.py          dashboards-as-code; regenerates the JSON files
```

## Scrape targets

| job                        | target                 | path                          | note                                              |
|----------------------------|------------------------|-------------------------------|---------------------------------------------------|
| `ironmesh-pki`             | `pki:8444`             | `/metrics`                    | plain listener (8443 is mTLS EST/OCSP)            |
| `ironmesh-policy`          | `policy:8081`          | `/metrics`                    |                                                   |
| `ironmesh-bridge`          | `bridge:8082`          | `/metrics`                    | metrics-only port per contract                    |
| `ironmesh-registry`        | `registry:8000`        | `/metrics`                    |                                                   |
| `ironmesh-ota`             | `ota:8001`             | `/metrics`                    |                                                   |
| `ironmesh-anomaly`         | `anomaly:8002`         | `/metrics`                    |                                                   |
| `ironmesh-console`         | `console:3000`         | `/metrics`                    | Next.js route handler; drop the job if absent     |
| `ironmesh-emqx`            | `emqx:18083`           | `/api/v5/prometheus/stats`    | `prometheus.enable_basic_auth = false`            |
| `ironmesh-redpanda`        | `redpanda:9644`        | `/public_metrics`             |                                                   |
| `ironmesh-otel-collector`  | `otel-collector:8888`  | `/metrics`                    | collector self-telemetry                          |
| `ironmesh-otlp-metrics`    | `otel-collector:8889`  | `/metrics`                    | OTLP-pushed metrics, `honor_labels` keeps job      |

On Kubernetes the Helm chart's ServiceMonitors set the same `job` labels (`ironmesh.dev/job`),
so rules and dashboards work unchanged.

## Metrics

Contract-required (`docs/DESIGN_CONTRACT.md` §9):

| Metric                                  | Type      | Labels    | Emitted by            |
|-----------------------------------------|-----------|-----------|-----------------------|
| `ironmesh_connected_devices`            | gauge     |           | bridge / registry     |
| `ironmesh_auth_failures_total`          | counter   | `reason` (policy), none (pki) | policy, pki |
| `ironmesh_cert_expiring_total`          | gauge     | `window`=24h,72h,7d | pki         |
| `ironmesh_ota_result_total`             | counter   | `result`=success,failed,rolled_back,rejected | ota |
| `ironmesh_anomaly_alerts_total`         | counter   | `rule`    | anomaly               |
| `ironmesh_revocation_latency_seconds`   | histogram |           | policy (revoked_at → kick, the 10 s budget), pki (revoke → policy ack) |
| `ironmesh_replay_rejected_total`        | counter   |           | registry / ingest     |

Already implemented by the services (`services/*/internal/metrics`): `ironmesh_authn_decisions_total{result,kind}`,
`ironmesh_authz_decisions_total{result,action}`, `ironmesh_authz_cache_total{outcome}`,
`ironmesh_revocation_apply_latency_seconds`, `ironmesh_revocations_total{source|reason}`,
`ironmesh_kick_total{result}`, `ironmesh_crl_poll_total{result}`, `ironmesh_crl_revoked_serials`,
`ironmesh_crl_last_success_timestamp_seconds`, `ironmesh_registry_lookups_total{result}`,
`ironmesh_revocation_cache_entries`, `ironmesh_revocation_publish_latency_seconds`,
`ironmesh_revocation_publish_failures_total`, `ironmesh_est_requests_total{op,code}`,
`ironmesh_certs_issued_total{kind}`, `ironmesh_ocsp_requests_total{status}`,
`ironmesh_crl_generations_total`, `ironmesh_attestation_failures_total{reason}`.

Extended metrics the dashboards and rules expect from the remaining services (same prefix,
documented here so the teams implement matching names):

| Metric                                            | Type      | Labels                        | Service  |
|---------------------------------------------------|-----------|-------------------------------|----------|
| `ironmesh_devices_total`                          | gauge     | `state`, `assurance`          | registry |
| `ironmesh_http_requests_total`                    | counter   | `route`, `method`, `code`     | registry, ota, anomaly, policy, pki |
| `ironmesh_http_request_duration_seconds`          | histogram | `route`, `method`             | same     |
| `ironmesh_bridge_messages_forwarded_total`        | counter   | `topic`                       | bridge   |
| `ironmesh_bridge_forward_errors_total`            | counter   | `reason`                      | bridge   |
| `ironmesh_bridge_kafka_produce_latency_seconds`   | histogram |                               | bridge   |
| `ironmesh_ota_campaigns`                          | gauge     | `state`                       | ota      |
| `ironmesh_ota_campaign_progress_ratio`            | gauge     | `campaign_id`, `campaign`     | ota      |
| `ironmesh_ota_campaign_stage_percent`             | gauge     | `campaign_id`, `campaign`     | ota      |
| `ironmesh_ota_campaign_devices`                   | gauge     | `campaign_id`, `state`        | ota      |
| `ironmesh_ota_firmware_uploads_total`             | counter   |                               | ota      |
| `ironmesh_ota_signatures_total`                   | counter   | `algorithm`                   | ota      |
| `ironmesh_anomaly_quarantines_total`              | counter   | `rule`                        | anomaly  |
| `ironmesh_anomaly_open_alerts`                    | gauge     | `severity`                    | anomaly  |
| `ironmesh_anomaly_auto_quarantine_enabled`        | gauge     |                               | anomaly  |
| `ironmesh_anomaly_model_score`                    | histogram |                               | anomaly  |
| `ironmesh_anomaly_model_score_threshold`          | gauge     | `device_class`                | anomaly  |
| `ironmesh_anomaly_consumer_lag_messages`          | gauge     | `topic`                       | anomaly  |
| `ironmesh_anomaly_messages_processed_total`       | counter   |                               | anomaly  |

EMQX native metrics used (`/api/v5/prometheus/stats`): `emqx_connections_count`,
`emqx_live_connections_count`, `emqx_sessions_count`, `emqx_subscriptions_count`,
`emqx_retained_count`, `emqx_cluster_nodes_running`, `emqx_client_connected`,
`emqx_client_disconnected`, `emqx_packets_connack_auth_error`, `emqx_messages_received`,
`emqx_messages_sent`, `emqx_messages_dropped(_expired|_no_subscribers|_quota_exceeded|_receive_maximum)`,
`emqx_delivery_dropped(_queue_full)`, `emqx_authentication_success|failure`,
`emqx_authorization_allow|deny|cache_hit`, `emqx_bytes_received|sent`, `emqx_vm_cpu_use`,
`emqx_vm_used_memory`, `emqx_cert_expiry_at`.

## Alerts (`prometheus/rules/ironmesh.rules.yml`)

| Alert                      | Condition                                                                 | Severity |
|----------------------------|---------------------------------------------------------------------------|----------|
| AuthFailureBurst           | `rate(ironmesh_auth_failures_total[2m]) > 5/s` for 2m                     | critical |
| RevocationLatencyHigh      | p99 `ironmesh_revocation_latency_seconds` (policy) > 8 s for 5m           | critical |
| RevocationPublishFailures  | PKI → policy publish failures > 0 for 5m                                  | critical |
| CrlStale                   | policy CRL last success older than 10 min                                 | warning  |
| CertExpiryBacklog          | `ironmesh_cert_expiring_total{window="24h"} > 0` for 1h                   | warning  |
| OtaFailureRateHigh         | failure share > 5% over 10m (with traffic)                                | critical |
| AnomalyRateSpike           | alert rate > 0.5/s and > 3x the previous hour                             | warning  |
| ConnectedDevicesDrop       | connected devices < 80% of 5 min ago (fleet > 50)                         | critical |
| BridgeForwardErrors        | > 0.1 errors/s or > 1% of forwarded                                       | warning  |
| ReplayRejectedSpike        | `rate(ironmesh_replay_rejected_total[5m]) > 1/s` for 5m                   | warning  |
| BrokerMessagesDropped      | EMQX drops > 10 msg/s for 10m                                             | warning  |
| ServiceDown                | `up{job=~"ironmesh-.*"} == 0` for 2m                                      | critical |
| ApiErrorBudgetBurnFast/Slow| multi-window burn rate on `ironmesh_http_requests_total` (SLO 99.9%)      | critical / warning |

Recording rules provide `ironmesh:ota_success_ratio:10m|1h`, `ironmesh:ota_failure_ratio:10m`,
`ironmesh:revocation_latency_seconds:p50_5m|p99_5m`, `ironmesh:revocation_within_budget_ratio:30m`,
`ironmesh:http_error_ratio:5m|30m|1h|6h`, `ironmesh:http_request_duration_seconds:p99_5m`,
`ironmesh:broker_up_ratio:5m` and a few convenience rates.

## Dashboards

Generated by `grafana/generate_dashboards.py` (Grafana 10/11, `schemaVersion` 39, datasource uid
`prometheus`, no `__inputs`). Each dashboard carries the `ironmesh` tag so the dashboard-list
link navigates between them.

| File                  | uid                | Content                                                                     |
|-----------------------|--------------------|-----------------------------------------------------------------------------|
| `fleet-overview.json` | `ironmesh-fleet`   | connected devices, auth failures, message rate, certificate expiry, device state breakdown, firing alerts |
| `pki.json`            | `ironmesh-pki`     | issuance rate, EST/OCSP/CRL, revocation latency heatmap + percentiles vs 10 s budget, attestation failures |
| `ota.json`            | `ironmesh-ota`     | success/failure ratios, campaign progress and stage gauges, results by outcome, rollbacks |
| `anomaly.json`        | `ironmesh-anomaly` | alerts by rule, quarantines, Isolation Forest score heatmap, consumer lag     |
| `broker.json`         | `ironmesh-broker`  | EMQX connections/sessions/drops/authz, policy decisions, bridge throughput and errors |
| `slo.json`            | `ironmesh-slo`     | 30-day SLO attainment, error budgets, multi-window burn rates, SLIs          |

Mount `grafana/provisioning` at `/etc/grafana/provisioning` and `grafana/dashboards` at
`/var/lib/grafana/dashboards/ironmesh`.

## Validation

`python -c "import json,glob; [json.load(open(f)) for f in glob.glob('observability/grafana/dashboards/*.json')]"`
and PyYAML on every `.yaml`/`.yml`; CI additionally runs `promtool check rules` and
`promtool check config`, and diffs `prometheus/rules/ironmesh.rules.yml` against the Helm copy.
