"""Application factory: ``uvicorn app.main:create_app --factory``."""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, Request, Response

from . import __version__
from .api.routes import health, internal_v1, v1
from .auth import (
    SYSTEM,
    HttpJwks,
    OidcConfig,
    OidcVerifier,
    ServiceJwtVerifier,
    ServiceTokenMinter,
)
from .context import AppContext
from .crypto import TenantKeyring
from .integrations.bus import EventBus, InMemoryEventBus, KafkaEventBus
from .integrations.kms import AwsKmsKeyWrapper, KeyWrapper, LocalKeyWrapper
from .integrations.mqtt import FakeMqttPublisher, MqttPublisher, MqttTls, PahoMqttPublisher
from .integrations.services import (
    HttpEmqxClient,
    HttpOtaClient,
    HttpPkiClient,
    build_http_client,
)
from .observability import Metrics, configure_logging, configure_tracing
from .problems import install_problem_handlers
from .repo.base import Repository
from .repo.memory import MemoryRepository
from .services import admin, commands, devices, tenant_policy
from .services.ingest import Ingest
from .settings import BusBackend, KmsBackend, MqttBackend, RepoBackend, Settings, get_settings
from .ws import Hub, TicketStore

log = structlog.get_logger("app.main")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _repo(settings: Settings) -> Repository:
    if settings.repo_backend is RepoBackend.MEMORY:
        return MemoryRepository()
    from .repo.sql import SqlRepository

    return SqlRepository(
        settings.sqlalchemy_url(),
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        connect_args=db_connect_args(settings),
    )


def db_connect_args(settings: Settings) -> dict[str, Any]:
    args: dict[str, Any] = {"server_settings": {"application_name": "ironmesh-registry"}}
    if settings.db_sslmode:
        args["ssl"] = settings.db_sslmode
    if settings.db_iam_auth:  # pragma: no cover - needs AWS credentials (RDS IAM auth)
        import boto3

        rds = boto3.client("rds", region_name=settings.kms_aws_region)

        def token() -> str:
            return str(
                rds.generate_db_auth_token(
                    DBHostname=settings.db_host, Port=settings.db_port, DBUsername=settings.db_user
                )
            )

        args["password"] = token
    return args


def _bus(settings: Settings) -> EventBus:
    if settings.bus_backend is BusBackend.MEMORY:
        return InMemoryEventBus()
    security: dict[str, Any] = {
        "tls": settings.kafka_tls_enabled,
        "ssl_cafile": settings.tls_ca_file,
        "ssl_certfile": settings.tls_cert_file,
        "ssl_keyfile": settings.tls_key_file,
        "sasl_mechanism": settings.kafka_sasl_mechanism,
        "region": settings.kms_aws_region,
        "sasl_username": settings.kafka_sasl_username,
        "sasl_password": settings.kafka_sasl_password.get_secret_value()
        if settings.kafka_sasl_password
        else None,
    }
    return KafkaEventBus(settings.kafka_brokers, settings.kafka_consumer_group, security)


def _mqtt(settings: Settings) -> MqttPublisher:
    if settings.mqtt_backend is MqttBackend.MEMORY:
        return FakeMqttPublisher()
    tls = MqttTls(settings.tls_ca_file, settings.tls_cert_file, settings.tls_key_file)
    return PahoMqttPublisher(  # pragma: no cover - needs a broker
        settings.mqtt_host, settings.mqtt_port, settings.mqtt_client_id, tls
    )


def _kms(settings: Settings) -> KeyWrapper:
    if settings.kms_backend is KmsBackend.AWS:  # pragma: no cover - needs AWS
        if not settings.kms_aws_key_id:
            raise ValueError("REGISTRY_KMS_AWS_KEY_ID is required for the aws KMS backend")
        return AwsKmsKeyWrapper.create(settings.kms_aws_key_id, settings.kms_aws_region)
    return LocalKeyWrapper.from_file(
        settings.kms_local_kek_file, create=settings.environment not in ("prod", "production")
    )


def build_context(settings: Settings) -> tuple[AppContext, list[httpx.AsyncClient]]:
    metrics = Metrics()
    mesh = build_http_client(
        settings.http_timeout_seconds,
        settings.tls_ca_file,
        settings.tls_cert_file,
        settings.tls_key_file,
    )
    plain = httpx.AsyncClient(timeout=settings.http_timeout_seconds)
    minter = ServiceTokenMinter.from_file(
        settings.service_jwt_issuer, settings.service_jwt_private_key_file
    )
    ctx = AppContext(
        settings=settings,
        repo=_repo(settings),
        bus=_bus(settings),
        mqtt=_mqtt(settings),
        pki=HttpPkiClient(settings.pki_url, mesh, minter, settings.pki_cert_cache_seconds),
        ota=HttpOtaClient(settings.ota_url, mesh, minter),
        emqx=HttpEmqxClient(
            settings.emqx_api_url,
            plain,
            settings.emqx_api_key.get_secret_value() if settings.emqx_api_key else None,
            settings.emqx_api_secret.get_secret_value() if settings.emqx_api_secret else None,
        ),
        keyring=TenantKeyring(_kms(settings)),
        hub=Hub(metrics),
        tickets=TicketStore(settings.ws_ticket_ttl_seconds),
        metrics=metrics,
        oidc=OidcVerifier(
            OidcConfig(
                issuer=settings.oidc_issuer,
                audience=settings.oidc_audience,
                algorithms=settings.oidc_algorithms,
                tenant_claim=settings.oidc_tenant_claim,
                role_claim=settings.oidc_role_claim,
                platform_roles_claim=settings.oidc_platform_roles_claim,
                leeway=settings.oidc_leeway_seconds,
            ),
            HttpJwks(
                settings.oidc_issuer,
                settings.oidc_jwks_url,
                plain,
                ttl=settings.oidc_jwks_cache_seconds,
            ),
        ),
        service_jwt=ServiceJwtVerifier.from_pem(
            settings.service_jwt_audience,
            settings.service_jwt_trusted_keys,
            single_use=settings.service_jwt_single_use,
            replay_cache_size=settings.service_jwt_replay_cache_size,
        ),
    )
    return ctx, [mesh, plain]


async def _loop(name: str, interval: float, job: Callable[[], Awaitable[object]]) -> None:
    while True:
        try:
            await job()
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception as exc:
            log.error("background_job_failed", job=name, error=repr(exc))
        await asyncio.sleep(interval)


async def _once(name: str, job: Callable[[], Awaitable[object]]) -> None:
    try:
        await job()
    except Exception as exc:
        log.error("background_job_failed", job=name, error=repr(exc))


async def sweep_once(ctx: AppContext) -> None:
    await commands.sweep(ctx, SYSTEM)
    await devices.run_pending_actions(ctx, SYSTEM)
    await admin.flush_health(ctx, SYSTEM)


async def reconcile_once(ctx: AppContext) -> int:
    """Startup reconciliation: push every tenant's command key + enrollment policy to the PKI
    (failures become outbox actions retried by the sweeper)."""
    count = await tenant_policy.reconcile(ctx, SYSTEM)
    log.info("pki_tenant_policy_reconciled", tenants=count)
    return count


async def maintain_once(ctx: AppContext) -> None:
    s = ctx.settings
    await ctx.repo.ensure_partitions(s.telemetry_partitions_ahead_days)
    await ctx.repo.drop_partitions(s.telemetry_retention_days)
    await admin.refresh_device_gauge(ctx, SYSTEM)


def create_app(
    settings: Settings | None = None,
    ctx: AppContext | None = None,
    *,
    ws_ping_interval: float = 30.0,
) -> FastAPI:
    settings = settings or (ctx.settings if ctx else get_settings())
    configure_logging(settings.log_level, settings.log_format)
    configure_tracing()
    clients: list[httpx.AsyncClient] = []
    if ctx is None:
        ctx, clients = build_context(settings)
    context = ctx

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if settings.ingest_enabled:
            Ingest(context).register()
        await context.bus.start()
        await context.mqtt.start()
        tasks: list[asyncio.Task[None]] = []
        if settings.background_jobs_enabled:
            tasks = [
                asyncio.create_task(
                    _loop("sweeper", settings.sweeper_interval_seconds, lambda: sweep_once(context))
                ),
                asyncio.create_task(
                    _loop(
                        "maintenance",
                        settings.maintenance_interval_seconds,
                        lambda: maintain_once(context),
                    )
                ),
                asyncio.create_task(_once("pki_reconcile", lambda: reconcile_once(context))),
            ]
        log.info("registry_started", version=__version__)
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await context.bus.stop()
            await context.mqtt.stop()
            await context.repo.close()
            for client in clients:
                await client.aclose()

    servers = [{"url": settings.public_base_url}] if settings.public_base_url else None
    app = FastAPI(
        title="IronMesh Registry",
        version=__version__,
        description="Device Registry & Fleet Service (API_CONTRACT.md §1)",
        lifespan=lifespan,
        servers=servers,
    )
    app.state.ctx = context

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            from fastapi.openapi.utils import get_openapi

            spec = get_openapi(
                title=app.title,
                version=app.version,
                description=app.description,
                routes=app.routes,
                servers=servers,
            )
            for item in spec.get("paths", {}).values():
                for op in item.values():
                    for code, resp in op.get("responses", {}).items():
                        content = resp.get("content", {})
                        if code[:1] in ("4", "5") and "application/json" in content:
                            resp["content"] = {
                                "application/problem+json": content["application/json"]
                            }
            app.openapi_schema = spec
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
    app.state.ws_ping_interval = ws_ping_interval
    install_problem_handlers(app)
    app.include_router(v1)
    app.include_router(internal_v1)
    app.include_router(health)

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if REQUEST_ID_RE.fullmatch(incoming) else str(uuid.uuid4())
        request.state.request_id = request_id
        structlog.contextvars.bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            route = request.scope.get("route")
            template = getattr(route, "path", "unmatched")
            context.metrics.http_requests.labels(
                route=template, method=request.method, code=str(status)
            ).inc()
            context.metrics.http_latency.labels(route=template, method=request.method).observe(
                time.perf_counter() - started
            )
            structlog.contextvars.unbind_contextvars("request_id")
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.path.startswith(("/v1", "/internal")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
        engine = getattr(context.repo, "engine", None)
        if engine is not None:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

            SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
    except Exception as exc:  # pragma: no cover - instrumentation is best effort
        log.warning("otel_instrumentation_failed", error=repr(exc))
    return app
