"""Runtime configuration (environment variables prefixed ``REGISTRY_``).

Names follow the Helm chart's env-var contract (``deploy/helm/ironmesh/README.md``):
``REGISTRY_LISTEN_PORT``, ``REGISTRY_DB_*``, ``REGISTRY_KAFKA_*``,
``REGISTRY_{PKI,POLICY,OTA}_URL``,
``REGISTRY_EMQX_API_URL``, ``REGISTRY_OIDC_{ISSUER,AUDIENCE}``, ``REGISTRY_PUBLIC_BASE_URL``,
``REGISTRY_TLS_*``, ``REGISTRY_LOG_*`` and the secrets ``REGISTRY_DB_PASSWORD``,
``REGISTRY_INTERNAL_TOKENS``, ``REGISTRY_EMQX_API_KEY``, ``REGISTRY_EMQX_API_SECRET``.
``REGISTRY_DATABASE_URL`` overrides the ``REGISTRY_DB_*`` parts when set.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from urllib.parse import quote

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class RepoBackend(StrEnum):
    POSTGRES = "postgres"
    MEMORY = "memory"


class BusBackend(StrEnum):
    KAFKA = "kafka"
    MEMORY = "memory"


class MqttBackend(StrEnum):
    PAHO = "paho"
    MEMORY = "memory"


class KmsBackend(StrEnum):
    LOCAL = "local"
    AWS = "aws"


class Settings(BaseSettings):
    """All knobs of the service. See README.md for the full table."""

    model_config = SettingsConfigDict(env_prefix="REGISTRY_", extra="ignore")

    environment: str = "dev"
    listen_host: str = "0.0.0.0"  # noqa: S104  # nosec B104 - container listens on all interfaces
    listen_port: int = 8000
    public_base_url: str | None = None
    log_level: str = "info"
    log_format: str = "json"  # json | console

    # --- persistence -----------------------------------------------------------------------
    repo_backend: RepoBackend = RepoBackend.POSTGRES
    database_url: SecretStr | None = None
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "registry"
    db_user: str = "registry_app"
    db_password: SecretStr | None = None
    db_sslmode: str | None = None  # disable | prefer | require | verify-ca | verify-full
    db_iam_auth: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 10

    # --- auth ------------------------------------------------------------------------------
    oidc_issuer: str = "https://idp.ironmesh.local/realms/ironmesh"
    oidc_audience: str = "ironmesh-api"
    oidc_jwks_url: str | None = (
        None  # default: discovered from <issuer>/.well-known/openid-configuration
    )
    oidc_jwks_cache_seconds: int = 600
    oidc_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256", "PS256"])
    oidc_tenant_claim: str = "tenant_id"
    oidc_role_claim: str = "role"
    oidc_platform_roles_claim: str = "platform_roles"
    oidc_leeway_seconds: int = 30
    internal_tokens: dict[str, SecretStr] = Field(default_factory=dict)
    """Per-caller bearer tokens for ``/internal/*`` as JSON, e.g.
    ``{"pki": "<PKI_REGISTRY_TOKEN>", "policy": "<POLICY_REGISTRY_TOKEN>", "anomaly": "..."}``.
    A token authenticates exactly one calling service, so the per-endpoint caller allowlist
    applies to it just as it does to service JWTs."""
    service_jwt_audience: str = "registry"
    service_jwt_trusted_keys: dict[str, str] = Field(default_factory=dict)
    """``{"pki": "<PEM public key>", "policy": "...", "anomaly": "..."}`` (JSON in the env)."""
    service_jwt_private_key_file: str | None = None
    service_jwt_issuer: str = "registry"
    ws_ticket_ttl_seconds: int = 60

    # --- Kafka -----------------------------------------------------------------------------
    bus_backend: BusBackend = BusBackend.KAFKA
    kafka_brokers: str = "localhost:9092"
    kafka_consumer_group: str = "registry-ingest"
    kafka_topic_ingest: str = "im.ingest"
    kafka_topic_auth: str = "im.auth"
    kafka_topic_alerts: str = "im.alerts"
    kafka_topic_audit: str = "im.audit"
    kafka_topic_commands: str = "im.commands"
    kafka_topic_campaigns: str = "im.campaigns"
    """``campaign.updated`` frames produced by the OTA service and relayed to WebSocket clients."""
    kafka_sasl_mechanism: str = "none"  # none | SCRAM-SHA-512 | AWS_MSK_IAM
    kafka_sasl_username: str | None = None
    kafka_sasl_password: SecretStr | None = None
    kafka_tls_enabled: bool = False
    ingest_enabled: bool = True

    # --- service mesh ----------------------------------------------------------------------
    pki_url: str = "https://ironmesh-pki:8443"
    policy_url: str = "http://ironmesh-policy:8081"
    ota_url: str = "http://ironmesh-ota:8001"
    emqx_api_url: str = "http://ironmesh-emqx:18083"
    emqx_api_key: SecretStr | None = None
    emqx_api_secret: SecretStr | None = None
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    tls_ca_file: str | None = None
    http_timeout_seconds: float = 5.0
    pki_cert_cache_seconds: int = 30
    orchestration_attempts: int = 3
    orchestration_backoff_seconds: float = 0.5

    mqtt_backend: MqttBackend = MqttBackend.PAHO
    mqtt_host: str = "ironmesh-emqx"
    mqtt_port: int = 8883
    mqtt_client_id: str = "svc-registry"

    kms_backend: KmsBackend = KmsBackend.LOCAL
    kms_local_kek_file: str = "./.secrets/registry-kek.bin"
    kms_aws_key_id: str | None = None
    kms_aws_region: str | None = None

    # --- envelope / ingest / jobs ----------------------------------------------------------
    max_skew_seconds: int = 300
    telemetry_retention_days: int = 30
    telemetry_partitions_ahead_days: int = 3
    sweeper_interval_seconds: float = 5.0
    maintenance_interval_seconds: float = 300.0
    background_jobs_enabled: bool = True

    def sqlalchemy_url(self) -> str:
        if self.database_url is not None:
            return self.database_url.get_secret_value()
        auth = quote(self.db_user, safe="")
        if self.db_password is not None and not self.db_iam_auth:
            auth += ":" + quote(self.db_password.get_secret_value(), safe="")
        return f"postgresql+asyncpg://{auth}@{self.db_host}:{self.db_port}/{self.db_name}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
