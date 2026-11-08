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
| `BRIDGE_KAFKA_TLS` / `BRIDGE_KAFKA_TLS_CA_FILE` | `false` / — | TLS to Redpanda |
| `BRIDGE_MAX_INFLIGHT` | `1024` | semaphore and MQTT receive maximum |
| `BRIDGE_EVENTS_TOKEN` | — | bearer token EMQX must send on `/emqx/events` |
| `BRIDGE_MQTT_KEEPALIVE` / `BRIDGE_MQTT_SESSION_EXPIRY` | `60s` / `168h` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | enables OTLP/gRPC trace export |
| `OTEL_SERVICE_NAME` | `ironmesh-bridge` | |
| `BRIDGE_LOG_LEVEL` | `info` | JSON logs with `ts, level, service, msg, trace_id, span_id` |

Metrics: `ironmesh_bridge_messages_total{class}`, `ironmesh_bridge_forward_errors_total`,
`ironmesh_bridge_dropped_total{reason}`, `ironmesh_bridge_inflight`, `ironmesh_bridge_ack_errors_total`,
`ironmesh_bridge_auth_events_total{event}`, `ironmesh_connected_devices` (derived from EMQX
connect/disconnect events), `ironmesh_bridge_mqtt_connected`, `ironmesh_bridge_forward_latency_seconds`.

## EMQX webhook

Point an EMQX rule-engine HTTP action at `POST http://bridge:8082/emqx/events` with
`Authorization: Bearer <BRIDGE_EVENTS_TOKEN>` for the events `client.connected`,
`client.disconnected`, `client.check_authn_complete` and `client.check_authz_complete` (the legacy
names `client.authenticate failed` / `client.authorize denied` are accepted too). Successful authn/authz
completions are ignored; failures become `authn_failed` / `authz_denied`. A 503 response asks EMQX
to retry.

## Development

```sh
go test ./... -cover            # paho exercised against an in-process fake MQTT 5 broker, franz-go against kfake
go test ./... -race -cover      # Linux/macOS; on Windows -race needs cgo (gcc)
go vet ./... && gofmt -l .
```
