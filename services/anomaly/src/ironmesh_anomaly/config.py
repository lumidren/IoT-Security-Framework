"""Service configuration.

Environment variables are prefixed ``ANOMALY_`` and match the Helm chart's env-var table
(``deploy/helm/ironmesh/README.md``): ``ANOMALY_LISTEN_PORT``, ``ANOMALY_DB_*``,
``ANOMALY_KAFKA_*``, ``ANOMALY_{REGISTRY,POLICY,OTA,PKI}_URL``, ``ANOMALY_AUTO_QUARANTINE``,
``ANOMALY_QUARANTINE_MIN_SEVERITY``, ``ANOMALY_MODEL_DIR``, ``ANOMALY_OIDC_*``, ``ANOMALY_TLS_*``,
``ANOMALY_LOG_*`` and the secrets ``ANOMALY_DB_PASSWORD``, ``ANOMALY_INTERNAL_TOKEN``,
``ANOMALY_SIEM_WEBHOOK_URL``. ``ANOMALY_DATABASE_URL`` overrides the ``ANOMALY_DB_*`` parts.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import Severity


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ANOMALY_", extra="ignore")

    service_name: str = "anomaly"
    environment: str = "dev"
    listen_host: str = "0.0.0.0"  # noqa: S104 container bind  # nosec B104
    listen_port: int = 8002
    log_level: str = "info"
    log_format: Literal["json", "console"] = "json"

    # --- database --------------------------------------------------------------------------
    database_url: SecretStr | None = None
    """Full DSN override (``postgresql://...``); otherwise built from ``ANOMALY_DB_*``."""
    database_migrate_url: SecretStr | None = None
    """DSN of the owner role used to apply migrations at start-up (optional)."""
    db_host: str = ""
    db_port: int | None = None
    db_name: str = "anomaly"
    db_user: str = "anomaly_app"
    db_password: SecretStr | None = None
    db_sslmode: str = ""
    db_iam_auth: bool = False
    db_region: str | None = None
    db_pool_max: int = 10
    store_events: bool = True
    event_retention_days: int = 7
    snapshot_interval_s: float = 60.0

    # --- event bus -------------------------------------------------------------------------
    kafka_brokers: str = "redpanda:9092"
    kafka_consumer_group: str = "anomaly-engine"
    kafka_topic_ingest: str = "im.ingest"
    kafka_topic_auth: str = "im.auth"
    kafka_topic_alerts: str = "im.alerts"
    kafka_topic_audit: str = "im.audit"
    kafka_topic_commands: str = "im.commands"
    kafka_sasl_mechanism: str = ""
    """``""`` (none), ``PLAIN``, ``SCRAM-SHA-256``, ``SCRAM-SHA-512`` or ``AWS_MSK_IAM``."""
    kafka_sasl_username: str | None = None
    kafka_sasl_password: SecretStr | None = None
    kafka_tls_enabled: bool = False
    kafka_consume_audit: bool = True
    poll_max_records: int = 500
    poll_timeout_ms: int = 1000

    # --- upstream services (mTLS with the Services CA identity + service auth) ------------
    registry_url: str = "http://ironmesh-registry:8000"
    policy_url: str = "http://ironmesh-policy:8081"
    ota_url: str = "http://ironmesh-ota:8001"
    pki_url: str = "https://ironmesh-pki:8443"
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    tls_ca_file: str | None = None
    internal_token: SecretStr | None = None
    """Bearer for the registry's internal endpoints (lifecycle, quarantine): the ``anomaly``
    entry of the registry's ``REGISTRY_INTERNAL_TOKENS`` map."""
    service_jwt_key_file: str | None = None
    """ES256 key for service JWTs; defaults to ``ANOMALY_TLS_KEY_FILE`` (Services CA key)."""
    service_jwt_kid: str = "svc-anomaly"
    http_timeout_s: float = 5.0
    pki_key_cache_ttl_s: float = 300.0
    pki_negative_cache_ttl_s: float = 30.0
    known_hashes_ttl_s: float = 300.0
    device_cache_ttl_s: float = 300.0
    max_clock_skew_s: int = 300

    # --- geo / model -----------------------------------------------------------------------
    geoip_db_path: str | None = None
    model_dir: str = "/var/lib/ironmesh/anomaly/models"
    model_s3_bucket: str | None = None
    model_s3_prefix: str = "anomaly-models/"
    training_interval_s: float = 3600.0
    training_seed: int = 1337

    # --- auto quarantine (defaults for tenants without stored settings) -------------------
    auto_quarantine: bool = False
    quarantine_min_severity: Severity = Severity.HIGH
    quarantine_max_per_hour: int = 10
    quarantine_breaker_cooldown_s: float = 3600.0
    quarantine_retry_attempts: int = 4
    quarantine_retry_base_s: float = 0.5

    # --- alerting --------------------------------------------------------------------------
    dedup_window_s: float = 900.0
    fp_suppression_s: float = 86400.0
    fp_suppression_max_s: float = 7 * 86400.0
    escalate_after: list[int] = Field(default_factory=lambda: [3, 10])

    # --- SIEM ------------------------------------------------------------------------------
    siem_webhook_url: SecretStr | None = None
    """Platform-wide ECS webhook receiving every tenant's alerts (in addition to tenant sinks)."""
    siem_webhook_secret: SecretStr | None = None
    """HMAC key for ``X-IronMesh-Signature``; required for any webhook delivery."""
    siem_syslog_transport: Literal["tls", "udp", "tcp"] = "tls"
    siem_syslog_ca_file: str | None = None
    siem_syslog_facility: int = 10  # authpriv
    siem_allow_private_targets: bool = False
    siem_max_attempts: int = 5
    siem_backoff_base_s: float = 0.5
    siem_backoff_max_s: float = 30.0
    siem_dlq_max: int = 1000
    siem_queue_max: int = 10000

    # --- API auth (OIDC) -------------------------------------------------------------------
    oidc_issuer: str | None = None
    oidc_audience: str = "ironmesh-api"
    oidc_jwks_url: str | None = None
    """Defaults to the issuer's discovery document ``jwks_uri``."""
    oidc_public_key_file: str | None = None
    oidc_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    oidc_leeway_s: int = 30

    # --- OpenTelemetry (standard OTEL_* variables are honoured by the SDK too) -------------
    otlp_endpoint: str | None = Field(None, validation_alias="OTEL_EXPORTER_OTLP_ENDPOINT")

    run_pipeline: bool = True

    @field_validator("oidc_issuer", "oidc_jwks_url", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("db_iam_auth", "kafka_tls_enabled", "auto_quarantine", mode="before")
    @classmethod
    def _blank_bool(cls, value: object) -> object:
        return False if value == "" else value

    @field_validator("db_port", mode="before")
    @classmethod
    def _blank_port(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("log_level", mode="after")
    @classmethod
    def _upper(cls, value: str) -> str:
        return value.upper()

    def database_dsn(self) -> str | None:
        """The runtime DSN (``None`` = no database configured: in-memory repository)."""
        if self.database_url is not None:
            return self.database_url.get_secret_value()
        if not self.db_host:
            return None
        auth = quote(self.db_user, safe="")
        if self.db_password is not None and not self.db_iam_auth:
            auth += ":" + quote(self.db_password.get_secret_value(), safe="")
        port = f":{self.db_port}" if self.db_port else ""
        dsn = f"postgresql://{auth}@{self.db_host}{port}/{quote(self.db_name, safe='')}"
        params: list[str] = []
        if self.db_sslmode:
            params.append(f"sslmode={quote(self.db_sslmode, safe='')}")
            if self.db_sslmode.startswith("verify") and self.tls_ca_file:
                params.append(f"sslrootcert={quote(self.tls_ca_file, safe='')}")
        return dsn + ("?" + "&".join(params) if params else "")

    def jwt_key_file(self) -> str | None:
        return self.service_jwt_key_file or self.tls_key_file
