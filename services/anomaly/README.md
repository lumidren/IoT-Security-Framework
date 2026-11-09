# IronMesh Anomaly — runtime anomaly and threat detection

`services/anomaly` (port 8002) consumes the event bus, verifies every device envelope, keeps
per-device streaming state, runs five detection rules plus an unsupervised Isolation Forest,
raises alerts, optionally auto-quarantines devices through the registry, and forwards alerts to
SIEMs. Its HTTP API is the one in `docs/API_CONTRACT.md` §3, and the console calls it as specified there.

```
im.ingest (COSE) ──► verify envelope (ironmesh-wire, PKI key cache) ─┐
im.auth   (JSON) ──► attribute to tenant (registry directory) ───────┼─► state store ─► rules + model
im.audit  (JSON) ──► quarantines/releases done by users ─────────────┘          │
                                                                                ▼
                  im.alerts ◄── publish ◄── actions (quarantine, SIEM) ◄── alert manager (dedup,
                  im.audit  ◄── every decision                               suppression, escalation)
```

## Running

```bash
python -m venv .venv && .venv/Scripts/pip install -e ../../libs/python/ironmesh-wire -e ".[dev]"
python -m ironmesh_anomaly            # needs Kafka; without ANOMALY_DB_* it uses an in-memory repo
docker build -f services/anomaly/Dockerfile -t ironmesh-anomaly .   # from the repository root
```

The image is a multi-stage build that runs as UID/GID 10001. It works with a read-only root
filesystem and only needs `/tmp` and `/var/lib/ironmesh/anomaly` to be writable.

### Configuration

Environment variables follow the Helm chart table (`deploy/helm/ironmesh/README.md`):

| Variable | Default | Purpose |
|---|---|---|
| `ANOMALY_LISTEN_PORT` | `8002` | HTTP port (`/healthz`, `/readyz`, `/metrics`, `/v1/...`) |
| `ANOMALY_DATABASE_URL` | – | full DSN; overrides `ANOMALY_DB_*` |
| `ANOMALY_DB_{HOST,PORT,NAME,USER,PASSWORD,SSLMODE,IAM_AUTH}` | `anomaly`/`anomaly_app` | Postgres (RLS role `anomaly_app`; `verify-*` adds `sslrootcert=ANOMALY_TLS_CA_FILE`; IAM auth mints RDS tokens per connection) |
| `ANOMALY_DATABASE_MIGRATE_URL` | – | owner DSN; when set the schema is applied at start-up |
| `ANOMALY_KAFKA_{BROKERS,CONSUMER_GROUP,TLS_ENABLED,SASL_MECHANISM,SASL_USERNAME,SASL_PASSWORD}` | `redpanda:9092`, `anomaly-engine` | bus (`none`/`PLAIN`/`SCRAM-*`/`AWS_MSK_IAM`) |
| `ANOMALY_KAFKA_TOPIC_{INGEST,AUTH,ALERTS,AUDIT}` | `im.*` | topics |
| `ANOMALY_{REGISTRY,POLICY,OTA,PKI}_URL` | cluster DNS | upstream services |
| `ANOMALY_TLS_{CERT,KEY,CA}_FILE` | – | Services CA identity for outbound mTLS; the key also signs ES256 service JWTs (`iss = sub = anomaly`, `kid = svc-anomaly`) |
| `ANOMALY_INTERNAL_TOKEN` (secret) | – | bearer for the registry's internal endpoints (`lifecycle`, `quarantine`): the `anomaly` entry of the registry's `REGISTRY_INTERNAL_TOKENS` map; without it a service JWT is sent |
| `ANOMALY_AUTO_QUARANTINE`, `ANOMALY_QUARANTINE_MIN_SEVERITY` | `false`, `high` | defaults for tenants without stored settings |
| `ANOMALY_QUARANTINE_MAX_PER_HOUR`, `ANOMALY_QUARANTINE_BREAKER_COOLDOWN_S` | `10`, `3600` | circuit breaker |
| `ANOMALY_MODEL_DIR` / `ANOMALY_MODEL_S3_BUCKET` | `/var/lib/ironmesh/anomaly/models` | model store |
| `ANOMALY_GEOIP_DB_PATH` | – | GeoLite2-City `.mmdb` (offline); unset disables IP-based travel |
| `ANOMALY_OIDC_{ISSUER,AUDIENCE,JWKS_URL,PUBLIC_KEY_FILE}` | aud `ironmesh-api` | API auth; JWKS URL from issuer discovery by default |
| `ANOMALY_SIEM_WEBHOOK_URL` | – | platform-wide ECS webhook (in addition to per-tenant sinks) |
| `ANOMALY_SIEM_WEBHOOK_SECRET` | – | HMAC key for `X-IronMesh-Signature` (webhooks are disabled without it) |
| `ANOMALY_SIEM_SYSLOG_TRANSPORT` | `tls` | `tls` (RFC 5425, port 6514), `tcp`, `udp` (RFC 5426, port 514) |
| `ANOMALY_LOG_{LEVEL,FORMAT}` | `info`, `json` | structlog JSON with `ts, level, service, trace_id, span_id, tenant_id, device_id, msg` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | – | OTLP/gRPC traces (spans per bus record continue the `traceparent` header) |

## Streaming pipeline

* **`im.ingest`** carries raw COSE_Sign1 bytes plus the bridge headers. Each record goes through
  the following checks, and the first failure decides the outcome:
  1. The topic is parsed (`ironmesh_wire.ids.parse_topic`), and the headers must agree with it.
  2. The device must be registered to the tenant in the topic.
  3. The `kid` is turned into a cert serial, and the cert is fetched from the PKI with
     `GET /v1/certificates/{serial}`. The cert is cached for 5 min (30 s for a negative or revoked
     result), and its CN must match the PKI record.
  4. The cert must belong to the topic's device and tenant, and its status must be `valid`.
  5. `ironmesh_wire.envelope.decode` checks the uplink profile, the ES256 signature, the payload,
     `|received_at - ts| <= 300 s`, and that `seq` strictly increases. The last `seq` is
     persisted in the state snapshot.
  6. The message type must match the topic class.

  A verification failure counts as a security event. It becomes an `envelope_rejected` event for
  the device, which counts toward `auth_burst`. It is also recorded in
  `ironmesh_anomaly_envelope_rejected_total{reason}` and audited as `anomaly.envelope_rejected`,
  at most once per (device, reason) per minute. A replay is dropped and counted in
  `ironmesh_replay_rejected_total` but raises no alert, because redeliveries after a restart are
  replays too. If the PKI is unreachable, the record is retried and not committed.
* **`im.auth`** carries `connected`, `disconnected`, `authn_failed` and `authz_denied` events. The
  client id must be a device id. The tenant comes from the registry directory
  (`/internal/v1/devices/{id}/lifecycle`, callers `policy` and `anomaly`, cached), whose
  `product` is the device class that selects the per-class model and known-hash set.
* **`im.audit`** (optional) carries `device.quarantine` and `device.release` decisions taken by
  users. They are recorded with `by: "user:<id>"` and keep quarantined devices out of training.
* **State**: an in-memory store keyed by `(tenant, device)`. All buffers are bounded. Dirty
  states are snapshotted to Postgres every `ANOMALY_SNAPSHOT_INTERVAL_S` (60 s) and restored at
  start-up.
* **Exactly-once-ish processing**: records are processed in order. Alerts are persisted, their
  actions taken and the alert published *before* the batch's offsets are committed. If a
  dependency fails, the processed prefix is committed and the consumer seeks back to the failed
  record. A batch that is delivered again is absorbed by the persisted `seq` and by the durable
  dedup lookup in the repository.

## Rules

Every rule is a class with validated `params`, a `severity` and `enabled`/`dry_run` flags, and
each tenant can override these with `PUT /v1/rules/{name}`. A rule is a pure function of
`(event, device state, observation)`. `POST /v1/rules/{name}/dry-run` replays the tenant's stored
events (7-day retention) through a fresh state store, so you can tune parameters on real
history.

### `impossible_travel` (high)

There are two sources of location fixes: GPS (telemetry keys 14/15, from mobile classes) and the
GeoIP location of a connect's source IP (offline MaxMind reader; private addresses are never
looked up). For two consecutive fixes from the same source:

```
d     = 2R·asin( sqrt( sin²(Δφ/2) + cos φ1 · cos φ2 · sin²(Δλ/2) ) )      R = 6371.0088 km
d'    = max(0, d − acc1 − acc2)              (GeoIP accuracy radii; 0 for GPS)
v     = d' / max(|t2 − t1|, min_dt_s)        fire iff d' ≥ min_distance_km and v > max_speed_kmh
score = 1 − max_speed_kmh / v
```

Tuning: `max_speed_kmh=900` (a commercial airliner), `min_distance_km=5` (GPS jitter),
`min_dt_s=1`, and `use_gps` / `use_ip`. For cellular devices whose carrier NAT egress moves
between countries, raise `min_distance_km` or turn off `use_ip`.

### `auth_burst` (high, critical at `critical_multiplier`×)

The rule fires when the count in the window strictly exceeds `threshold`:
`N(t) = Σ failures in (t − window_s, t]`. It is evaluated in two places.

* **Per device**: broker `authn_failed` events, rejected envelopes and (with
  `include_device_reported`) deltas of the device's own `auth_failures` counter. The counter is
  reset-aware: a lower value or a lower uptime means the device rebooted.
* **Per source IP within the tenant**: every failure from one peer address, whatever client id it
  claimed. The alert goes to the device being targeted and lists every device targeted in the
  window.

Defaults are `threshold=10` and `window_s=60`, with severity critical from 10× the threshold.
The window is capped at 1 h.

### `topic_violation` (high, critical when repeated)

Every `authz_denied` for a device is a detection. It is classified as a wildcard, a reserved
topic, outside `im/v1`, another tenant's namespace, another device's namespace, or the wrong
direction for the topic class. With `repeat_threshold` (3) or more denies in `repeat_window_s`
(1 h), severity becomes critical.

### `fw_hash_mismatch` (critical)

All the reasons found are reported in a single detection:
`unknown_hash` means telemetry `fw_hash` is not in the OTA known hashes for the device's product
(`/internal/v1/firmware/known-hashes`, cached 5 min; this check is skipped when that list is
unavailable). `differs_from_installed` means the hash differs from the hash reported by the last
`OtaStatus` with state `success`. `unexpected_change` means the hash changed between samples with
no successful install in between, which catches a re-flash to an older image that is still
known.

### `beaconing` (high)

This rule looks for periodic outbound behaviour that the telemetry schedule does not explain.
It uses robust statistics throughout, so the bursts it is looking for cannot hide themselves by
inflating the baseline.

**Tx-burst channel.** `r_i = Δnet_tx_bytes / Δts` is the per-interval transmit rate over the last
256 samples.

```
m = median(r)                      s = max(1.4826 · MAD(r), rate_floor_bps, 0.01·m)
burst_i ⇔ (r_i − m)/s ≥ burst_z  ∧  r_i ≥ min_burst_ratio · m
gaps    g_j = b_{j+1} − b_j  (samples),  intervals d_j = t(b_{j+1}) − t(b_j)  (seconds)
CV_rob  = 1.4826 · MAD(d) / median(d)
ACF(k)  = Σ (r_i − m)(r_{i+k} − m) / Σ (r_i − m)²        (median-centred autocorrelation)
fire ⇔ #bursts ≥ min_bursts ∧ median(g) ≥ min_lag ∧ CV_rob ≤ max_interval_cv
       ∧ max_{k∈[min_lag,max_lag]} ACF(k) ≥ min_acf ∧ median(r_b)/m ≥ min_volume_ratio
       ∧ last burst within 2·median(g) samples of the end (the beacon is still active)
```

`1.4826·MAD` is a consistent estimator of σ for Gaussian noise, with a 50 % breakdown point, so
up to half the samples can be bursts without moving the baseline. The robust CV works as a
measure of periodicity: for a fixed-period beacon the interval MAD is about 0, while random
(Poisson) spikes have CV ≈ 1. The ACF peak independently confirms periodicity and tolerates a
missed or extra burst. `min_lag ≥ 2` is the "beyond the expected telemetry cadence" condition.
A burst in every interval is a level shift, which is left to the Isolation Forest.

Defaults: `burst_z=8`, `min_burst_ratio=3`, `min_bursts=4`, `max_interval_cv=0.15`,
`min_acf=0.4`, `min_lag=2`, `max_lag=64`, `min_volume_ratio=3`, `min_samples=30`.

**Reconnect channel.** The connect inter-arrival times within `connect_window_s` (24 h) are
periodic when there are at least `connect_min_events` (6) connects, `CV_rob ≤ connect_max_cv`
(0.1) and the median period is at most `connect_max_period_s` (1 h). Legitimate reconnects use
exponential backoff with full jitter (contract §4), and their CV is far above 0.1.

### `isolation_forest` (medium)

Features are computed per accepted telemetry sample, using a rolling window for rates:
`cpu_pct`, `mem_pct`, `temp_c`, `log1p(rx B/s)`, `log1p(tx B/s)`, `proc_count`,
`auth_failures Δ`, `rssi`, `log1p(free_heap)`, and `msg_rate` (msgs/min from the inter-arrivals
in a 5-min window). Counter deltas are reset-aware.

* **Class model**: one `IsolationForest` per `(tenant, product)`, scored as
  `c = −decision_function(x)`. scikit-learn places the offset so that a fraction `contamination`
  of the training set has `c > 0`. Scoring walks the fitted trees directly (`FastForest`, which
  is verified against scikit-learn when the model is built, and takes about 0.2 ms per sample
  against about 11 ms for `decision_function`).
* **Device baseline**: `d = max_j |x_j − median_j| / max(1.4826·MAD_j, floor_j)` over the
  device's own history (the last 256 samples).
* **Decision**: the rule fires iff `d ≥ z_threshold` **and** either `√(c_n·d_n) > 0.5`, where
  `c_n = ½(1+tanh(c/τ))`, `d_n = ½(1+tanh((d−z)/z))` and τ is the std of the training scores, or
  a deviating feature lies outside the class envelope `[q0.1%, q99.9%] ± 10 %`. The class model
  always has to agree, but a feature that is constant across the class, such as
  `auth_failures Δ = 0`, cannot be split on by the forest, and the envelope covers that case.
  The score reported is `√(c_n·d_n)`, and the baseline endpoint reports the threshold 0.5.
* **Cold start**: a device raises no alerts until it has `min_samples` (50) samples, and a class
  model is trained only once there are `min_train_samples` (200) samples from at least
  `min_train_devices` (3) devices.
* **Training**: every `ANOMALY_TRAINING_INTERVAL_S` (1 h) per (tenant, class) with a fixed seed.
  The model is persisted with joblib to the model store (a directory with atomic 0600 writes, or
  S3 with SSE-KMS). Its SHA-256 is recorded in Postgres, which is a separate trust domain from the
  blob store, and checked **before** unpickling. A mismatch or a metadata mismatch refuses the
  model.
* **Poisoning resistance**:
  * samples from quarantined devices are excluded, whether quarantined in the state, by a
    registry record, or by a user through `im.audit`;
  * samples inside `[created_at − exclusion_margin_s, resolved_at | now]` of any open, acked or
    true-positive alert on the device are excluded. Alerts resolved as false positives stay in
    training, so analyst feedback teaches the model;
  * each device contributes at most `max_samples_per_device` (200, a uniform subsample);
  * at least 3 devices are needed per class.

  One compromised device can therefore neither dominate nor define "normal" for its class.
  Models are per tenant, so one tenant cannot poison another tenant's model.
* **Drift**: `ironmesh_anomaly_model_drift_psi{device_class}` is the population stability index
  of live scores against the training deciles (`PSI = Σ (a_i − e_i)·ln(a_i/e_i)`). Below 0.1 is
  stable and above 0.25 means you should retrain or investigate. The other model metrics are
  `ironmesh_anomaly_model_age_seconds{device_class}`, `..._model_score_threshold` and the
  `ironmesh_anomaly_model_score` / `ironmesh_anomaly_score` histograms.

Tuning: raise `contamination` (0.01) for more sensitivity, and set `z_threshold` (6) and
`min_consecutive` (1) for how persistent a deviation must be.

## Alerting

* **Dedup**: a detection for the same `(tenant, device, rule)` is merged into a non-resolved alert
  last seen within `ANOMALY_DEDUP_WINDOW_S` (15 min). The merge increments `occurrences`, takes
  the maximum score and keeps the latest features. The lookup goes to the repository, so it
  survives restarts.
* **Escalation**: the severity becomes `max(existing, detection)`, raised one level when
  occurrences reach 3 and again at 10 (`ANOMALY_ESCALATE_AFTER`). New and escalated alerts are
  published to `im.alerts` (key `<tenant>/<device>`, value = the contract `Alert`). Ack and
  resolve publish the update too.
* **Suppression**: `resolve` with `false_positive: true` suppresses that (device, rule) for
  24 h. The period doubles with each further false positive, up to 7 days.
* Metrics: `ironmesh_anomaly_alerts_total{rule}`, `ironmesh_anomaly_open_alerts{severity}` and
  `ironmesh_anomaly_suppressed_total{rule,reason}`.

## Auto-quarantine policy

A new or escalated alert goes through the gates below. The first gate that matches decides the
outcome, and every decision is audited to `im.audit` as `anomaly.quarantine_decision`, with the
decision, the reason, the alert, the rule, the severity and the settings:

1. `auto_quarantine_disabled`
2. `below_min_severity`
3. `already_quarantined`
4. `dry_run`: the rule is in dry-run mode. The alert still exists and is marked `dry_run`, and the
   alert action reads `dry_run: would quarantine`.
5. `circuit_open`
6. `rate_limited`: more than `ANOMALY_QUARANTINE_MAX_PER_HOUR` (10) auto-quarantines in the
   trailing hour for the tenant. The breaker opens for the cool-down period and
   `anomaly.quarantine_breaker_opened` is audited. A stale known-hash list or a bad rule therefore
   cannot take the fleet down.
7. Otherwise the policy calls `POST /internal/v1/devices/{id}/quarantine` (`{reason, alert_id}`,
   `Idempotency-Key`). The registry revokes the certs, drops the ACL and kicks the session. The
   call retries 5xx and 429 responses with exponential backoff and full jitter, treats 409
   (decommissioned) as final, and records the result as an alert action.

Metrics: `ironmesh_anomaly_quarantines_total{rule,mode=auto|dry_run|manual}`,
`ironmesh_anomaly_quarantine_decisions_total{decision,reason}`,
`ironmesh_anomaly_quarantine_breaker_trips_total` and
`ironmesh_anomaly_auto_quarantine_enabled`.

## SIEM outputs

* **ECS 8.x JSON**:
  * `@timestamp`, `ecs.version=8.11.0`, `message`;
  * `event.{kind=alert, category=[intrusion_detection], type=[info], id, created, severity,
    risk_score, module, dataset, action}`;
  * `rule.{name,id,ruleset,category}`, `host.id` (= the device id), `observer.{vendor,product,
    type=ids,version}`, `organization.id` (= the tenant), `source.ip` when known;
  * `threat.{framework=MITRE ATT&CK, tactic, technique}`: auth_burst T1110, impossible_travel
    T1078, topic_violation T1046, fw_hash_mismatch T1601, beaconing T1071.
* **RFC 5424 syslog**: `<PRI>1 TS HOST ironmesh-anomaly PROCID <RULE> [ironmesh@32473 alertId=…
  tenantId=… deviceId=… rule=… severity=… score=… state=…] BOM msg`.
  `PRI = facility·8 + severity`: critical→2, high→3, medium→4, low→5, and the default facility
  is 10 (authpriv). It is sent over TCP+TLS (RFC 5425, octet-counting framing) by default, with
  TCP and UDP (RFC 5426, one datagram per message) as alternatives.
* **Webhook**: ECS JSON, signed with
  `X-IronMesh-Signature: t=<unix>,v1=hex(HMAC-SHA256(secret, "<t>." + body))`. Receivers verify
  with a constant-time compare and a 5-min tolerance (`siem.verify_webhook`). Per-tenant targets
  come from `PATCH /v1/settings`, and `ANOMALY_SIEM_WEBHOOK_URL` adds a platform-wide target.
* **Delivery**: each sink has a bounded queue and a worker. Failures are retried with exponential
  backoff and full jitter (5 attempts) and then go to a bounded dead-letter queue (1000 entries;
  the oldest are evicted and counted). `redrive(sink)` retries the dead letters. Metrics:
  `ironmesh_anomaly_siem_deliveries_total{sink,result}`, `..._siem_dlq_size` and
  `..._siem_dlq_dropped_total`.
* **SSRF guard**: tenant-supplied targets must use `https`, may not embed credentials, and may not
  be local names. Every resolved address must be public unicast, checked when the settings are
  saved and again at send time (against DNS rebinding). Loopback, RFC 1918, link-local and cloud
  metadata, CGNAT, multicast and reserved ranges are refused.

## API

The API implements `docs/API_CONTRACT.md` §3: `GET /v1/alerts` (filters, keyset cursor),
`GET /v1/alerts/{id}`, `POST …/ack|resolve` (operator), `GET /v1/rules`,
`PUT /v1/rules/{name}` (admin), `POST /v1/rules/{name}/dry-run` (operator, window ≤ 31 days),
`GET /v1/devices/{id}/baseline`, `GET /v1/quarantine`, and `GET`/`PATCH /v1/settings` (admin).

* **Authentication**: OIDC bearer JWTs, asymmetric algorithms only, `aud ∋ ironmesh-api`, the
  issuer checked, and the tenant taken from `tenant_id`.
* **Roles**: `viewer < operator < admin < owner`. `platform_admin` may act in another tenant with
  `X-IronMesh-Tenant` as admin, and such requests are audited.
* **Errors and audit**: errors are RFC 9457 problem details, and every mutation is audited to
  `im.audit`.
* **API keys**: `imk_` keys are rejected here with 401. They are a registry concern.

## Persistence

`src/ironmesh_anomaly/migrations/001_init.sql` creates every tenant table with
`tenant_id uuid NOT NULL` and a **forced** RLS policy
`tenant_id = NULLIF(current_setting('ironmesh.tenant_id', true), '')::uuid`. It also grants the
non-owner role `anomaly_app` (NOBYPASSRLS). The repository sets the tenant on every transaction.
`anomaly_tenants` holds only tenant ids so that start-up can enumerate tenants.

## Development checks

```bash
.venv/Scripts/python -m pytest --cov            # unit + scenario + postgres (pgserver) tests
.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m ruff format --check .
.venv/Scripts/python -m mypy                    # --strict; local stubs for aiokafka/joblib/sklearn
.venv/Scripts/python -m bandit -c pyproject.toml -r src
```

Postgres tests (`-m postgres`) start a throwaway server with the pip `pgserver` package. Set
`IRONMESH_TEST_PG_DSN` to an owner DSN to use an existing server, as CI does with a service
container. `tests/test_scenario.py` runs 203 simulated devices through real signed envelopes.
