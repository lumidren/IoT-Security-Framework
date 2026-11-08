"""Prometheus metrics (prefix ``ironmesh_``; names fixed by DESIGN_CONTRACT section 9)."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

ALERTS = Counter(
    "ironmesh_anomaly_alerts_total", "New alerts raised by the anomaly engine", ["rule"]
)
ALERT_UPDATES = Counter(
    "ironmesh_anomaly_alert_updates_total",
    "Detections merged into an existing open alert (dedup) or escalations",
    ["rule", "kind"],
)
SUPPRESSED = Counter(
    "ironmesh_anomaly_suppressed_total",
    "Detections dropped by suppression (false-positive feedback, disabled rule)",
    ["rule", "reason"],
)
EVENTS = Counter("ironmesh_anomaly_events_total", "Bus records processed", ["topic", "result"])
ENVELOPE_REJECTED = Counter(
    "ironmesh_anomaly_envelope_rejected_total",
    "im.ingest envelopes that failed verification (treated as security events)",
    ["reason"],
)
REPLAY_REJECTED = Counter(
    "ironmesh_replay_rejected_total", "Messages dropped because seq was not strictly increasing"
)
AUTH_FAILURES = Counter(
    "ironmesh_auth_failures_total", "Authentication failures observed on im.auth"
)
PROCESSING_SECONDS = Histogram(
    "ironmesh_anomaly_processing_seconds",
    "Per-record processing latency",
    ["topic"],
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0),
)
MODEL_AGE = Gauge(
    "ironmesh_anomaly_model_age_seconds",
    "Age of the oldest active Isolation Forest model per device class",
    ["device_class"],
)
MODEL_DRIFT = Gauge(
    "ironmesh_anomaly_model_drift_psi",
    "Population stability index of live isolation scores vs the training distribution",
    ["device_class"],
)
MODEL_TRAININGS = Counter(
    "ironmesh_anomaly_model_trainings_total", "Model training runs", ["result"]
)
QUARANTINE_DECISIONS = Counter(
    "ironmesh_anomaly_quarantine_decisions_total",
    "Auto-quarantine policy decisions",
    ["decision", "reason"],
)
BREAKER_TRIPS = Counter(
    "ironmesh_anomaly_quarantine_breaker_trips_total",
    "Times the per-tenant auto-quarantine circuit breaker opened",
)
SIEM_DELIVERIES = Counter(
    "ironmesh_anomaly_siem_deliveries_total", "SIEM delivery attempts", ["sink", "result"]
)
SIEM_DLQ_SIZE = Gauge("ironmesh_anomaly_siem_dlq_size", "Dead-letter queue depth", ["sink"])
SIEM_DLQ_DROPPED = Counter(
    "ironmesh_anomaly_siem_dlq_dropped_total", "Dead letters evicted (DLQ full)", ["sink"]
)
DEVICES_TRACKED = Gauge("ironmesh_anomaly_devices_tracked", "Devices in the state store")

# --- names used by the committed Grafana dashboards / Prometheus rules (observability/README) --
QUARANTINES = Counter(
    "ironmesh_anomaly_quarantines_total",
    "Quarantines: mode=auto (taken by the policy engine), dry_run (would have been taken), "
    "manual (taken by a user, learned from im.audit)",
    ["rule", "mode"],
)
OPEN_ALERTS = Gauge("ironmesh_anomaly_open_alerts", "Non-resolved alerts", ["severity"])
AUTO_QUARANTINE_ENABLED = Gauge(
    "ironmesh_anomaly_auto_quarantine_enabled",
    "1 if auto-quarantine is enabled by default or for at least one tenant",
)
_SCORE_BUCKETS = (0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.9, 1.0)
MODEL_SCORE = Histogram(
    "ironmesh_anomaly_model_score",
    "Isolation Forest anomaly score -score_samples(x) in (0, 1]; higher = more anomalous",
    buckets=_SCORE_BUCKETS,
)
ANOMALY_SCORE = Histogram(
    "ironmesh_anomaly_score",
    "Combined anomaly score (class model x device baseline) in [0, 1]; > 0.5 = anomalous",
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)
MODEL_SCORE_THRESHOLD = Gauge(
    "ironmesh_anomaly_model_score_threshold",
    "Isolation Forest decision threshold (-offset_) per device class (max over tenants)",
    ["device_class"],
)
CONSUMER_LAG = Gauge(
    "ironmesh_anomaly_consumer_lag_messages", "Consumer group lag per topic", ["topic"]
)
MESSAGES_PROCESSED = Counter(
    "ironmesh_anomaly_messages_processed_total", "Bus records processed successfully"
)
HTTP_REQUESTS = Counter(
    "ironmesh_http_requests_total", "HTTP requests", ["route", "method", "code"]
)
