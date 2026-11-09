# IronMesh Bridge

Consumes the broker shared subscription `$share/bridge/im/v1/#` as `svc-bridge` (MQTT 5 over mTLS,
`github.com/eclipse/paho.golang`) and forwards every device message to Redpanda topic `im.ingest`
(`github.com/twmb/franz-go`). Also receives EMQX webhook events on `POST /emqx/events` and forwards
connect/disconnect/authn-failed/authz-denied events to `im.auth`. Implements
`docs/DESIGN_CONTRACT.md` §4/§7/§9 and `docs/API_CONTRACT.md` §6.

```
EMQX ──$share/bridge/im/v1/#──▶ MQTTSource ──▶ Consumer (semaphore 1024) ──▶ Forwarder ──▶ Kafka im.ingest
                                                    └── PUBACK only after Kafka acked (at-least-once)
EMQX ──POST /emqx/events──▶ EventsHandler ──▶ Kafka im.auth
```

## Record format (`im.ingest`)

* key: `<tenant>/<device>`; value: raw COSE bytes (payload untouched)
* headers: `mqtt_topic`, `tenant_id`, `device_id`, `msg_class`
  (`telemetry|events|shadow_reported|cmd_ack|ota_status`), `received_at` (RFC 3339 nano, UTC),
  `traceparent` (+`tracestate`) propagated from the MQTT 5 user property through an OpenTelemetry
  `bridge.forward` span.
* Topics that do not match `im/v1/<uuid>/<dev-id>/<class>` and cloud-originated classes
  (`shadow/desired`, `cmd/req`, `ota/notify`, `config`) are acknowledged and dropped
  (`ironmesh_bridge_dropped_total{reason}`).

## Delivery semantics

Manual MQTT acknowledgements are enabled; a message is PUBACKed only after `ProduceSync` returned
without error. Produce failures are retried with exponential backoff until success or shutdown;
messages still unacknowledged at shutdown are redelivered by the broker (persistent session, 7 d
expiry). The CONNECT advertises `Receive Maximum = BRIDGE_MAX_INFLIGHT`, so the broker never has
more messages in flight than the consumer semaphore admits.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BRIDGE_LISTEN` | `:8082` | metrics / health / `/emqx/events` |
| `BRIDGE_MQTT_URL` | `ssl://emqx:8883` | broker (`ssl`/`tls`/`mqtts` = mTLS; `mqtt` plaintext for dev only) |
| `BRIDGE_MQTT_CLIENT_ID` | `svc-bridge` | must equal the certificate CN |
| `BRIDGE_MQTT_TOPIC` | `$share/bridge/im/v1/#` | shared subscription |
| `BRIDGE_TLS_CERT_FILE` / `BRIDGE_TLS_KEY_FILE` / `BRIDGE_TLS_CA_FILE` | — (required for mTLS) | Services CA client cert, key, and CA bundle used to verify the broker |
| `BRIDGE_TLS_SERVER_NAME` | broker hostname | expected broker SAN |
| `BRIDGE_KAFKA_BROKERS` | `redpanda:9092` | comma-separated seed brokers |
| `BRIDGE_KAFKA_INGEST_TOPIC` / `BRIDGE_KAFKA_AUTH_TOPIC` | `im.ingest` / `im.auth` | |
| `BRIDGE_KAFKA_TLS_ENABLED` (alias `BRIDGE_KAFKA_TLS`) | `false` | TLS (1.2+) to the brokers; either variable set to `true` enables it |
| `BRIDGE_KAFKA_TLS_CA_FILE` | — | CA bundle verifying the brokers; empty = system roots (Amazon MSK) |
| `BRIDGE_KAFKA_SASL_MECHANISM` | `none` | `none`, `plain`, `scram-sha-512` or `aws-msk-iam` (franz-go `sasl/plain`, `sasl/scram`, `sasl/aws`). `plain` and `aws-msk-iam` require TLS. MSK IAM credentials come from the default AWS chain (env, IRSA / web identity, ECS, EC2 role) and are re-resolved on every connection; the region is taken from the broker host name (fallback `AWS_REGION`) |
| `BRIDGE_KAFKA_SASL_USERNAME` / `BRIDGE_KAFKA_SASL_PASSWORD` | — | Credentials for `plain` / `scram-sha-512` (required with those) |
| `BRIDGE_KAFKA_TOPICS_CREATE` | `false` | On boot create `im.ingest`, `im.auth` (the configured ingest/auth topic names), `im.alerts`, `im.audit`, `im.commands`, `im.campaigns` with the kadm admin API; existing topics count as success (settings untouched), any other error aborts startup |
| `BRIDGE_KAFKA_TOPIC_PARTITIONS` | `12` | Partitions of created topics (1–10000) |
| `BRIDGE_KAFKA_TOPIC_REPLICATION` | `3` | Replication factor of created topics (`-1` = broker default) |
| `BRIDGE_MAX_INFLIGHT` | `1024` | semaphore and MQTT receive maximum |
| `BRIDGE_EVENTS_TOKEN` | — | shared secret EMQX must send on `/emqx/events` in `X-IronMesh-Hook-Token` (or as `Authorization: Bearer`) |
| `BRIDGE_MQTT_KEEPALIVE` / `BRIDGE_MQTT_SESSION_EXPIRY` | `60s` / `168h` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | enables OTLP/gRPC trace export |
| `OTEL_SERVICE_NAME` | `ironmesh-bridge` | |
| `BRIDGE_LOG_LEVEL` | `info` | JSON logs with `ts, level, service, msg, trace_id, span_id` |

Metrics: `ironmesh_bridge_messages_total{class}`, `ironmesh_bridge_forward_errors_total`,
`ironmesh_bridge_dropped_total{reason}`, `ironmesh_bridge_inflight`, `ironmesh_bridge_ack_errors_total`,
`ironmesh_bridge_auth_events_total{event}`, `ironmesh_connected_devices` (derived from EMQX
connect/disconnect events), `ironmesh_bridge_mqtt_connected`, `ironmesh_bridge_forward_latency_seconds`.

## EMQX webhook

`services/policy/deploy/emqx/emqx.conf` configures it (EMQX 5.8 connector + HTTP action + rule):
`POST http://bridge:8082/emqx/events` with `X-IronMesh-Hook-Token: <BRIDGE_EVENTS_TOKEN>`
(`Authorization: Bearer <token>` is accepted too; when the hook header is present it alone
decides) for the events `client.connected`, `client.disconnected`, `client.check_authn_complete`
and `client.check_authz_complete`, body = the rule's selected event map as JSON (one object per
request; arrays are accepted too). The legacy names `client.authenticate failed` /
`client.authorize denied` are accepted. Successful authn/authz completions are ignored; failures
become `authn_failed` / `authz_denied`. A 503 response asks EMQX to retry.

## Health check

The image is distroless (no curl): `bridge healthcheck [--url URL] [--timeout 3s]` GETs
`http://127.0.0.1:<port of BRIDGE_LISTEN>/healthz` and exits `0` on 2xx, `1` otherwise (TLS
verification is skipped only for an `https` URL on a loopback host). Example:
`test: ["CMD", "/bridge", "healthcheck"]`.

## Development

```sh
go test ./... -cover            # paho exercised against an in-process fake MQTT 5 broker, franz-go against kfake
go test ./... -race -cover      # Linux/macOS; on Windows -race needs cgo (gcc)
go vet ./... && gofmt -l .
```
