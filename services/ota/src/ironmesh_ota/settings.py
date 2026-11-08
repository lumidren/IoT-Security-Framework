"""Service configuration from ``OTA_*`` environment variables.

Names follow the deployment contract in ``deploy/helm/ironmesh`` (``values.yaml`` ota block and
the README env-var table) and ``deploy/k8s/base/services/ota.yaml``. The chart renders unset keys
as empty strings, so an empty value always means "use the default".
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Self
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_core import PydanticUseDefault
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class ArtifactStoreKind(StrEnum):
    FILESYSTEM = "filesystem"
    S3 = "s3"


class SigningProvider(StrEnum):
    FILE = "file"
    KMS_WRAPPED = "kms-wrapped"


class DatabaseBackend(StrEnum):
    POSTGRES = "postgres"
    MEMORY = "memory"


class Settings(BaseSettings):
    """``OTA_*`` settings. Secrets are :class:`SecretStr` and never logged."""

    model_config = SettingsConfigDict(env_prefix="OTA_", extra="ignore", frozen=True)

    env: Environment = Environment.DEV
    service_name: str = "ota"
    log_level: str = "info"
    log_format: str = "json"
    # container port behind the ingress/ALB; bind address is configurable
    listen_host: str = "0.0.0.0"  # noqa: S104  # nosec B104
    listen_port: int = 8001

    # --- database (OTA_DB_*; OTA_DATABASE_URL overrides) ------------------------------------
    database_backend: DatabaseBackend = DatabaseBackend.POSTGRES
    database_url: SecretStr | None = None
    db_host: str | None = None
    db_port: int = 5432
    db_name: str = "ota"
    db_user: str = "ota_app"
    db_sslmode: str | None = None
    db_iam_auth: bool = False
    db_password: SecretStr | None = None
    db_pool_size: int = 10
    aws_region: str | None = None

    # --- artifact storage -----------------------------------------------------------------
    artifact_store: ArtifactStoreKind = ArtifactStoreKind.FILESYSTEM
    artifact_path: Path = Path("var/artifacts")
    artifact_bucket: str | None = None
    s3_kms_key_arn: str | None = None
    s3_region: str | None = None
    s3_endpoint_url: str | None = None
    s3_object_lock_mode: str | None = Field(default=None, pattern="^(GOVERNANCE|COMPLIANCE)$")
    s3_object_lock_days: int = Field(default=3650, ge=1)
    public_base_url: str = "http://localhost:8001"
    download_url_ttl_s: int = Field(default=900, ge=30, le=86_400)
    download_hmac_secret: SecretStr | None = None

    # --- firmware signing -----------------------------------------------------------------
    signing_provider: SigningProvider = SigningProvider.FILE
    signing_kek_key_id: str = "alias/ironmesh-firmware-kek"
    signing_key_secret_arn: str | None = None
    signing_key_id: str | None = None
    """Informational key name written into manifest field 9 (defaults to the key id hex)."""
    pq_signing_enabled: bool = False
    require_pq: bool = False
    """The service's own pre-notify verification requires the ML-DSA-65 signature."""
    signing_private_key_pem: SecretStr | None = None
    signing_key_file: Path | None = None
    signing_key_generate_if_missing: bool = False
    signing_keyring_file: Path | None = None
    signing_passphrase: SecretStr | None = None

    # --- tenant command keys (OtaNotify signing) ------------------------------------------
    tenant_keys_provider: SigningProvider = SigningProvider.FILE
    tenant_keys_dir: Path | None = None
    tenant_keys_passphrase: SecretStr | None = None
    tenant_key_secret_prefix: str = "ironmesh/tenant-cmd/"  # noqa: S105 - a name
    tenant_keys_kek_key_id: str = "alias/ironmesh-tenant-kek"

    # --- upload limits --------------------------------------------------------------------
    max_image_bytes: int = Field(default=512 * 1024 * 1024, ge=1)
    max_metadata_bytes: int = Field(default=16 * 1024, ge=256)

    # --- authentication -------------------------------------------------------------------
    oidc_issuer: str | None = None
    oidc_audience: str = "ironmesh-api"
    oidc_jwks_url: str | None = None
    oidc_algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
    internal_token: SecretStr | None = None
    """Shared bearer token accepted on ``/internal/*`` (chart secret ``OTA_INTERNAL_TOKEN``)."""
    service_public_keys_dir: Path | None = None
    """ES256 service-JWT verification keys ``<service>.pem`` (``aud=ota``)."""
    service_audience: str = "ota"
    internal_allowed_services: tuple[str, ...] = ("registry", "anomaly", "bridge")
    service_token_key_file: Path | None = None
    service_token_issuer: str = "ota"  # noqa: S105 - a name

    # --- peers ----------------------------------------------------------------------------
    registry_url: str | None = None
    pki_url: str | None = None
    emqx_api_url: str | None = None
    emqx_api_key: SecretStr | None = None
    emqx_api_secret: SecretStr | None = None
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    tls_ca_file: Path | None = None
    http_timeout_s: float = 10.0

    # --- direct MQTT (alternative to the EMQX HTTP publish API) ---------------------------
    mqtt_host: str | None = None
    mqtt_port: int = 8883
    mqtt_client_id: str = "svc-ota"

    # --- Kafka / Redpanda -----------------------------------------------------------------
    kafka_brokers: str | None = None
    kafka_topic_ingest: str = "im.ingest"
    kafka_topic_commands: str = "im.commands"
    kafka_topic_audit: str = "im.audit"
    kafka_topic_campaigns: str = "im.campaigns"
    kafka_consumer_group: str = "ota-status"
    kafka_sasl_mechanism: str | None = None
    kafka_sasl_username: str | None = None
    kafka_sasl_password: SecretStr | None = None
    kafka_tls_enabled: bool = False

    # --- rollout controller ---------------------------------------------------------------
    controller_enabled: bool = True
    controller_interval_s: float = Field(default=5.0, gt=0)
    device_timeout_s: int = Field(default=7200, ge=60)
    notify_refresh_s: int = Field(default=240, ge=10, le=290)
    """Re-sign retained OtaNotify messages before devices would reject them (ts skew 300 s)."""
    halt_min_sample: int = Field(default=5, ge=1)
    four_eyes_min_dwell_s: int = Field(default=3600, ge=0)
    leader_lock_key: int = 0x4F544101  # "OTA\x01"

    # --- observability --------------------------------------------------------------------
    otel_enabled: bool = False
    otel_endpoint: str | None = None

    @field_validator("*", mode="before")
    @classmethod
    def _empty_is_default(cls, value: Any) -> Any:
        if isinstance(value, str) and value.strip() in ("", "none"):
            raise PydanticUseDefault()
        return value

    @field_validator("artifact_store", mode="before")
    @classmethod
    def _store_alias(cls, value: Any) -> Any:
        return "filesystem" if value == "local" else value

    @field_validator("signing_provider", "tenant_keys_provider", mode="before")
    @classmethod
    def _provider_alias(cls, value: Any) -> Any:
        return "kms-wrapped" if value == "kms" else value

    # --- derived --------------------------------------------------------------------------
    def sqlalchemy_url(self) -> str | None:
        if self.database_url is not None:
            return self.database_url.get_secret_value()
        if not self.db_host:
            return None
        password = (
            f":{quote(self.db_password.get_secret_value(), safe='')}"
            if self.db_password is not None and not self.db_iam_auth
            else ""
        )
        url = (
            f"postgresql+asyncpg://{quote(self.db_user, safe='')}{password}@{self.db_host}:"
            f"{self.db_port}/{quote(self.db_name, safe='')}"
        )
        if self.db_sslmode:
            url += f"?ssl={quote(self.db_sslmode, safe='')}"
        return url

    @property
    def kafka_enabled(self) -> bool:
        return bool(self.kafka_brokers)

    @model_validator(mode="after")
    def _check_production(self) -> Self:
        if self.env is not Environment.PROD:
            return self
        checks = (
            ("OTA_DB_HOST or OTA_DATABASE_URL", self.sqlalchemy_url() is not None),
            ("OTA_ARTIFACT_STORE=s3", self.artifact_store is ArtifactStoreKind.S3),
            ("OTA_ARTIFACT_BUCKET", self.artifact_bucket is not None),
            (
                "OTA_SIGNING_PROVIDER=kms-wrapped",
                self.signing_provider is SigningProvider.KMS_WRAPPED,
            ),
            ("OTA_SIGNING_KEY_SECRET_ARN", self.signing_key_secret_arn is not None),
            (
                "OTA_TENANT_KEYS_PROVIDER=kms-wrapped",
                self.tenant_keys_provider is SigningProvider.KMS_WRAPPED,
            ),
            (
                "OTA_OIDC_ISSUER or OTA_OIDC_JWKS_URL",
                self.oidc_issuer is not None or self.oidc_jwks_url is not None,
            ),
            (
                "OTA_EMQX_API_URL or OTA_MQTT_HOST",
                self.emqx_api_url is not None or self.mqtt_host is not None,
            ),
            ("OTA_KAFKA_BROKERS", self.kafka_enabled),
            ("OTA_REGISTRY_URL", self.registry_url is not None),
            ("OTA_PKI_URL", self.pki_url is not None),
            ("OTA_DATABASE_BACKEND=postgres", self.database_backend is DatabaseBackend.POSTGRES),
        )
        missing = [name for name, ok in checks if not ok]
        if missing:
            raise ValueError("production profile requires: " + ", ".join(missing))
        return self
