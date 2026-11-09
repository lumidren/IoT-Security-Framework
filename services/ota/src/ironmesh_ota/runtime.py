"""Build a production/dev :class:`Container` from :class:`Settings`."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from .auth import JtiReplayCache, JwksTokenVerifier, StaticKeyTokenVerifier, TokenVerifier
from .container import Container
from .integrations.device_keys import (
    DeviceKeyResolver,
    PkiDeviceKeyResolver,
    StaticDeviceKeyResolver,
)
from .integrations.events import EventPublisher, KafkaEventPublisher, LoggingEventPublisher
from .integrations.http import ServiceTokenMinter, build_http_client
from .integrations.leader import FakeLeaderLock, FakeLockServer, LeaderLock, PostgresAdvisoryLock
from .integrations.mqtt import (
    AiomqttPublisher,
    EmqxApiPublisher,
    LoggingPublisher,
    MqttPublisher,
)
from .integrations.pki import FakePkiPolicy, HttpPkiPolicyClient, PkiPolicyClient
from .integrations.registry import FakeRegistry, HttpRegistryClient, RegistryClient
from .observability import Metrics, configure_logging, configure_tracing, get_logger
from .repository.base import Database
from .repository.memory import MemoryDatabase
from .repository.sql import SqlDatabase
from .settings import (
    ArtifactStoreKind,
    DatabaseBackend,
    Environment,
    Settings,
    SigningProvider,
)
from .signing import (
    KeyringSigner,
    SigningError,
    generate_pem_key,
    load_file_signer,
    load_kms_signer,
    load_pem_signer,
)
from .storage import ArtifactStore, DownloadSigner, LocalArtifactStore, S3ArtifactStore

log = get_logger("ironmesh.ota.runtime")


class ConfigurationError(Exception):
    pass


def _boto(service: str, settings: Settings, **kwargs: Any) -> Any:
    import boto3

    kwargs.setdefault("region_name", settings.aws_region)
    return boto3.client(service, **kwargs)  # type: ignore[call-overload]


def _secret(value: Any) -> bytes | None:
    return value.get_secret_value().encode() if value is not None else None


def build_signer(settings: Settings, *, boto: Callable[..., Any] = _boto) -> KeyringSigner:
    name = settings.signing_key_id
    if settings.signing_provider is SigningProvider.KMS_WRAPPED:
        if not settings.signing_key_secret_arn:
            raise ConfigurationError("OTA_SIGNING_KEY_SECRET_ARN is required for kms-wrapped")
        return load_kms_signer(
            boto("secretsmanager", settings),
            boto("kms", settings),
            secret_id=settings.signing_key_secret_arn,
            key_id=settings.signing_kek_key_id,
            pq_enabled=settings.pq_signing_enabled,
            key_name=name,
        )
    passphrase = _secret(settings.signing_passphrase)
    if settings.env is Environment.PROD:
        raise ConfigurationError("the file signing provider is for development only")
    if settings.signing_keyring_file is not None:
        if passphrase is None:
            raise ConfigurationError("OTA_SIGNING_PASSPHRASE is required for the key ring file")
        return load_file_signer(
            settings.signing_keyring_file,
            passphrase,
            pq_enabled=settings.pq_signing_enabled,
            key_name=name,
        )
    if settings.signing_private_key_pem is not None:
        pem = settings.signing_private_key_pem.get_secret_value().encode()
        return load_pem_signer(pem, passphrase, key_name=name)
    if settings.signing_key_file is not None:
        path = settings.signing_key_file
        if not path.exists():
            if not settings.signing_key_generate_if_missing:
                raise ConfigurationError(f"signing key file {path} does not exist")
            generate_pem_key(path, passphrase)
            log.warning(
                "generated a development firmware signing key",
                path=str(path),
                encrypted=passphrase is not None,
            )
        if passphrase is None:
            log.warning("firmware signing key file is not passphrase-encrypted (dev only)")
        return load_pem_signer(path.read_bytes(), passphrase, key_name=name)
    raise SigningError(
        "no signing key configured: set OTA_SIGNING_KEYRING_FILE, OTA_SIGNING_PRIVATE_KEY_PEM "
        "or OTA_SIGNING_KEY_FILE (file provider) or use OTA_SIGNING_PROVIDER=kms-wrapped"
    )


def build_store(settings: Settings, *, boto: Callable[..., Any] = _boto) -> ArtifactStore:
    if settings.artifact_store is ArtifactStoreKind.S3:
        if not settings.artifact_bucket:
            raise ConfigurationError("OTA_ARTIFACT_BUCKET is required for the s3 store")
        from botocore.config import Config

        client = boto(
            "s3",
            settings,
            region_name=settings.s3_region or settings.aws_region,
            endpoint_url=settings.s3_endpoint_url,
            config=Config(signature_version="s3v4", retries={"mode": "standard"}),
        )
        return S3ArtifactStore(
            client,
            settings.artifact_bucket,
            object_lock_mode=settings.s3_object_lock_mode,
            object_lock_days=settings.s3_object_lock_days,
            kms_key_id=settings.s3_kms_key_arn,
        )
    secret = _secret(settings.download_hmac_secret)
    if secret is None:
        secret = secrets.token_bytes(32)
        log.warning(
            "OTA_DOWNLOAD_HMAC_SECRET unset: download links are valid for this process only"
        )
    return LocalArtifactStore(
        settings.artifact_path, settings.public_base_url, DownloadSigner(secret)
    )


def _load_public_keys(directory: Path) -> list[PublicKeyTypes]:
    return [
        serialization.load_pem_public_key(path.read_bytes())
        for path in sorted(directory.glob("*.pem"))
    ]


def _discover_jwks(issuer: str, timeout: float) -> str:  # pragma: no cover - network I/O
    resp = httpx.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=timeout)
    resp.raise_for_status()
    return str(json.loads(resp.text)["jwks_uri"])


def build_user_verifier(settings: Settings) -> TokenVerifier:
    jwks = settings.oidc_jwks_url
    if jwks is None and settings.oidc_issuer:  # pragma: no cover - network I/O
        jwks = _discover_jwks(settings.oidc_issuer, settings.http_timeout_s)
    if jwks is None:
        log.warning("no OIDC issuer configured: every public API call will be rejected")
        return StaticKeyTokenVerifier([], audience=settings.oidc_audience)
    return JwksTokenVerifier(
        jwks,
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        algorithms=settings.oidc_algorithms,
    )


def _registry_token(settings: Settings) -> Callable[[str], str]:
    """``OTA_REGISTRY_TOKEN`` (the registry's ``ota`` internal token) or a service JWT."""
    if settings.registry_token is not None:
        token = settings.registry_token.get_secret_value()
        return lambda _audience: token
    if settings.service_token_key_file is not None:
        minter = ServiceTokenMinter.from_file(
            settings.service_token_key_file, settings.service_token_issuer
        )
        return minter.mint
    raise ConfigurationError("registry calls need OTA_REGISTRY_TOKEN or OTA_SERVICE_TOKEN_KEY_FILE")


def _token_source(settings: Settings) -> Callable[[str], str]:
    if settings.service_token_key_file is not None:
        minter = ServiceTokenMinter.from_file(
            settings.service_token_key_file, settings.service_token_issuer
        )
        return minter.mint
    if settings.internal_token is not None:
        token = settings.internal_token.get_secret_value()
        return lambda _audience: token
    raise ConfigurationError(
        "outgoing service calls need OTA_SERVICE_TOKEN_KEY_FILE or OTA_INTERNAL_TOKEN"
    )


def build_container(settings: Settings) -> Container:
    configure_logging(settings)
    configure_tracing(settings)
    closers: list[Callable[[], Any]] = []

    db: Database
    leader: LeaderLock
    if settings.database_backend is DatabaseBackend.MEMORY:
        db = MemoryDatabase()
        leader = FakeLeaderLock(FakeLockServer(), "local")
    else:
        url = settings.sqlalchemy_url()
        if url is None:
            raise ConfigurationError("set OTA_DB_HOST (or OTA_DATABASE_URL)")
        sql = SqlDatabase.from_url(url, pool_size=settings.db_pool_size)
        if settings.db_iam_auth:  # pragma: no cover - needs RDS
            _install_iam_auth(sql, settings)
        db = sql
        leader = PostgresAdvisoryLock(sql.engine, settings.leader_lock_key)

    registry: RegistryClient
    device_keys: DeviceKeyResolver
    pki: PkiPolicyClient
    if settings.registry_url:
        http = build_http_client(settings, settings.registry_url)
        closers.append(http.aclose)
        registry = HttpRegistryClient(http, _registry_token(settings))
    else:
        log.warning("OTA_REGISTRY_URL unset: in-memory registry, notifies are not delivered")
        registry = FakeRegistry()
    if settings.pki_url:
        token = _token_source(settings)
        http = build_http_client(settings, settings.pki_url)
        closers.append(http.aclose)
        device_keys = PkiDeviceKeyResolver(http, token)
        pki = HttpPkiPolicyClient(http, token)
    else:
        log.warning("OTA_PKI_URL unset: firmware keys are not pushed to the PKI")
        device_keys = StaticDeviceKeyResolver()
        pki = FakePkiPolicy()

    publisher: MqttPublisher
    if settings.emqx_api_url and settings.emqx_api_key and settings.emqx_api_secret:
        publisher = EmqxApiPublisher(
            build_http_client(settings, settings.emqx_api_url),
            settings.emqx_api_key.get_secret_value(),
            settings.emqx_api_secret.get_secret_value(),
        )
    elif settings.mqtt_host:  # pragma: no cover - needs a broker
        publisher = AiomqttPublisher(settings)
    else:
        log.warning("no broker configured: retained notify clears are logged, not published")
        publisher = LoggingPublisher()

    events: EventPublisher
    if settings.kafka_enabled:  # pragma: no cover - needs Redpanda
        events = KafkaEventPublisher(settings.kafka_brokers or "", ssl=settings.kafka_tls_enabled)
    else:
        events = LoggingEventPublisher()

    service_verifier: TokenVerifier | None = None
    if settings.service_public_keys_dir is not None:
        service_verifier = StaticKeyTokenVerifier(
            _load_public_keys(settings.service_public_keys_dir),
            audience=settings.service_audience,
            algorithms=("ES256",),
        )

    return Container(
        settings=settings,
        db=db,
        store=build_store(settings),
        signer=build_signer(settings),
        registry=registry,
        publisher=publisher,
        events=events,
        pki=pki,
        device_keys=device_keys,
        metrics=Metrics(),
        user_verifier=build_user_verifier(settings),
        service_verifier=service_verifier,
        leader=leader,
        closers=closers,
        service_replay=JtiReplayCache(settings.service_jwt_replay_cache_size)
        if settings.service_jwt_single_use
        else None,
    )


def _install_iam_auth(db: SqlDatabase, settings: Settings) -> None:  # pragma: no cover - RDS
    """Fresh RDS IAM auth token as the password on every new connection."""
    from sqlalchemy import event

    rds = _boto("rds", settings)

    @event.listens_for(db.engine.sync_engine, "do_connect")
    def _token(_dialect: Any, _conn_rec: Any, _cargs: Any, cparams: dict[str, Any]) -> None:
        cparams["password"] = rds.generate_db_auth_token(
            DBHostname=settings.db_host,
            Port=settings.db_port,
            DBUsername=settings.db_user,
            Region=settings.aws_region or os.environ.get("AWS_REGION"),
        )
