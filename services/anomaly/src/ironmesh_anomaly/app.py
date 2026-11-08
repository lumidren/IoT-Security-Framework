"""Application wiring: component construction, FastAPI app, lifecycle of the streaming tasks."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from . import __version__
from .alerting import AlertManager
from .api import router
from .audit import AuditPublisher
from .auth import TokenVerifier, build_verifier
from .bus import EventBus, KafkaEventBus, kafka_client_options
from .clients import (
    DeviceDirectory,
    HttpCertKeyProvider,
    HttpDeviceDirectory,
    HttpKnownHashesProvider,
    HttpQuarantineClient,
    KnownHashesProvider,
    QuarantineClient,
    ServiceTokenSigner,
    build_http_client,
)
from .config import Settings
from .engine import Engine, EngineConfig
from .geo import GeoIPProvider, build_geoip_provider
from .ingest import IngestDecoder
from .metrics import HTTP_REQUESTS
from .ml import LocalModelStore, ModelManager, ModelStore, S3ModelStore
from .models import TenantSettings
from .quarantine import CircuitBreaker, QuarantinePolicy
from .repository import InMemoryRepository, Repository
from .siem import SiemDispatcher, Sink, SyslogSink, WebhookSink

log = structlog.get_logger(__name__)


@dataclass(slots=True)
class Components:
    settings: Settings
    engine: Engine
    verifier: TokenVerifier | None
    closers: list[Any] = field(default_factory=list)


async def _iam_password(settings: Settings) -> str:  # pragma: no cover - needs AWS
    import boto3  # type: ignore[import-not-found,unused-ignore]

    client = boto3.client("rds", region_name=settings.db_region)
    token: str = await asyncio.to_thread(
        client.generate_db_auth_token,
        DBHostname=settings.db_host,
        Port=settings.db_port or 5432,
        DBUsername=settings.db_user,
    )
    return token


async def build_components(settings: Settings) -> Components:  # pragma: no cover - needs infra
    """Production wiring (Kafka, Postgres, upstream HTTP services)."""
    from .pg_repository import PostgresRepository, migrate

    static_tokens: dict[str, str] = {}
    if settings.internal_token is not None:
        static_tokens["registry"] = settings.internal_token.get_secret_value()
    signer = ServiceTokenSigner.from_file(
        settings.jwt_key_file(), settings.service_jwt_kid, static_tokens
    )
    http = build_http_client(
        settings.http_timeout_s, settings.tls_ca_file, settings.tls_cert_file, settings.tls_key_file
    )
    repo: Repository
    dsn = settings.database_dsn()
    if dsn is not None:
        if settings.database_migrate_url is not None:
            await migrate(settings.database_migrate_url.get_secret_value())

        async def iam() -> str:
            return await _iam_password(settings)

        repo = await PostgresRepository.connect(
            dsn, settings.db_pool_max, password=iam if settings.db_iam_auth else None
        )
    else:
        log.warning("no database configured: using the in-memory repository")
        repo = InMemoryRepository()
    topics = [settings.kafka_topic_ingest, settings.kafka_topic_auth]
    if settings.kafka_consume_audit:
        topics.append(settings.kafka_topic_audit)
    bus = KafkaEventBus(
        settings.kafka_brokers,
        settings.kafka_consumer_group,
        topics,
        **kafka_client_options(
            tls_enabled=settings.kafka_tls_enabled,
            sasl_mechanism=settings.kafka_sasl_mechanism,
            sasl_username=settings.kafka_sasl_username,
            sasl_password=(
                settings.kafka_sasl_password.get_secret_value()
                if settings.kafka_sasl_password
                else None
            ),
            ca_file=settings.tls_ca_file,
            region=settings.db_region,
        ),
    )
    store: ModelStore
    if settings.model_s3_bucket:
        import boto3  # type: ignore[import-not-found,unused-ignore]

        store = S3ModelStore(boto3.client("s3"), settings.model_s3_bucket, settings.model_s3_prefix)
    else:
        store = LocalModelStore(settings.model_dir)
    siem_http = httpx.AsyncClient(timeout=settings.http_timeout_s)
    sinks: list[Sink] = [
        SyslogSink(
            transport=settings.siem_syslog_transport,
            facility=settings.siem_syslog_facility,
            ca_file=settings.siem_syslog_ca_file,
            allow_private=settings.siem_allow_private_targets,
        )
    ]
    if settings.siem_webhook_secret is not None:
        secret = settings.siem_webhook_secret.get_secret_value().encode()
        sinks.append(
            WebhookSink(siem_http, secret, allow_private=settings.siem_allow_private_targets)
        )
        if settings.siem_webhook_url is not None:
            sinks.append(
                WebhookSink(
                    siem_http,
                    secret,
                    fixed_url=settings.siem_webhook_url.get_secret_value(),
                    name="webhook_platform",
                )
            )
    elif settings.siem_webhook_url is not None:
        log.error("ANOMALY_SIEM_WEBHOOK_URL ignored: ANOMALY_SIEM_WEBHOOK_SECRET is required")
    directory = HttpDeviceDirectory(
        http, settings.registry_url, signer, settings.device_cache_ttl_s
    )
    engine = assemble_engine(
        settings,
        repo=repo,
        bus=bus,
        decoder=IngestDecoder(
            HttpCertKeyProvider(
                http,
                settings.pki_url,
                signer,
                settings.pki_key_cache_ttl_s,
                settings.pki_negative_cache_ttl_s,
            ),
            directory,
            settings.max_clock_skew_s,
        ),
        directory=directory,
        known_hashes=HttpKnownHashesProvider(
            http, settings.ota_url, signer, settings.known_hashes_ttl_s
        ),
        quarantine_client=HttpQuarantineClient(
            http,
            settings.registry_url,
            signer,
            settings.quarantine_retry_attempts,
            settings.quarantine_retry_base_s,
        ),
        model_store=store,
        siem=SiemDispatcher(
            sinks,
            max_attempts=settings.siem_max_attempts,
            backoff_base_s=settings.siem_backoff_base_s,
            backoff_max_s=settings.siem_backoff_max_s,
            dlq_max=settings.siem_dlq_max,
            queue_max=settings.siem_queue_max,
        ),
    )
    verifier = build_verifier(
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        algorithms=settings.oidc_algorithms,
        jwks_url=settings.oidc_jwks_url,
        public_key_file=settings.oidc_public_key_file,
        leeway_s=settings.oidc_leeway_s,
    )
    return Components(
        settings, engine, verifier, closers=[http.aclose, siem_http.aclose, repo.close]
    )


def assemble_engine(
    settings: Settings,
    *,
    repo: Repository,
    bus: EventBus,
    decoder: IngestDecoder,
    directory: DeviceDirectory,
    known_hashes: KnownHashesProvider,
    quarantine_client: QuarantineClient,
    model_store: ModelStore,
    siem: SiemDispatcher | None,
    clock: Callable[[], float] = time.time,
    geoip: GeoIPProvider | None = None,
) -> Engine:
    audit = AuditPublisher(bus, settings.kafka_topic_audit)
    alerts = AlertManager(
        repo,
        bus,
        settings.kafka_topic_alerts,
        dedup_window_s=settings.dedup_window_s,
        escalate_after=settings.escalate_after,
        fp_suppression_s=settings.fp_suppression_s,
        fp_suppression_max_s=settings.fp_suppression_max_s,
    )
    breaker = CircuitBreaker(
        settings.quarantine_max_per_hour, settings.quarantine_breaker_cooldown_s, clock
    )
    return Engine(
        repo=repo,
        bus=bus,
        decoder=decoder,
        directory=directory,
        known_hashes=known_hashes,
        models=ModelManager(model_store, seed=settings.training_seed),
        alerts=alerts,
        quarantine=QuarantinePolicy(quarantine_client, repo, audit, breaker),
        audit=audit,
        siem=siem,
        geoip=geoip or build_geoip_provider(settings.geoip_db_path),
        config=EngineConfig(
            topic_ingest=settings.kafka_topic_ingest,
            topic_auth=settings.kafka_topic_auth,
            topic_audit=settings.kafka_topic_audit,
            store_events=settings.store_events,
            event_retention_days=settings.event_retention_days,
            training_seed=settings.training_seed,
            default_settings=TenantSettings(
                auto_quarantine=settings.auto_quarantine,
                quarantine_min_severity=settings.quarantine_min_severity,
            ),
        ),
    )


def _problem(
    status: int, detail: Any, instance: str, errors: list[Any] | None = None
) -> JSONResponse:
    title = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "Error"
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail if isinstance(detail, str) else (detail or {}).get("message", title),
        "instance": instance,
    }
    if errors is not None:
        body["errors"] = errors
    elif isinstance(detail, dict) and "errors" in detail:
        body["errors"] = detail["errors"]
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def create_app(components: Components) -> FastAPI:
    settings = components.settings
    engine = components.engine
    tasks: list[asyncio.Task[Any]] = []

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.run_pipeline:
            await engine.bus.start()
            restored = await engine.restore()
            log.info("state restored", devices=restored)
            if engine.siem is not None:
                engine.siem.start()
            tasks.append(
                asyncio.create_task(engine.run(settings.poll_max_records, settings.poll_timeout_ms))
            )
            tasks.append(
                asyncio.create_task(
                    engine.periodic(engine.snapshot, settings.snapshot_interval_s, "snapshot")
                )
            )
            tasks.append(
                asyncio.create_task(
                    engine.periodic(engine.train, settings.training_interval_s, "train")
                )
            )
            tasks.append(asyncio.create_task(engine.periodic(engine.purge, 3600.0, "purge")))
            tasks.append(
                asyncio.create_task(engine.periodic(engine.refresh_metrics, 30.0, "metrics"))
            )
        app.state.ready = True
        try:
            yield
        finally:
            app.state.ready = False
            engine.stop()
            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
            if settings.run_pipeline:
                with contextlib.suppress(Exception):
                    await engine.flush()
                    await engine.snapshot()
                if engine.siem is not None:
                    await engine.siem.stop()
                await engine.bus.stop()
            for close in components.closers:
                with contextlib.suppress(Exception):
                    await close()

    app = FastAPI(
        title="IronMesh Anomaly",
        version=__version__,
        lifespan=lifespan,
        openapi_url="/openapi.json",
    )
    app.state.engine = engine
    app.state.verifier = components.verifier
    app.state.allow_private_siem = settings.siem_allow_private_targets
    app.state.ready = False
    app.include_router(router)

    @app.middleware("http")
    async def count_requests(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        route = request.scope.get("route")
        template = getattr(route, "path", "unmatched")
        HTTP_REQUESTS.labels(
            route=template, method=request.method, code=str(response.status_code)
        ).inc()
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        resp = _problem(exc.status_code, exc.detail, request.url.path)
        for k, v in (exc.headers or {}).items():
            resp.headers[k] = v
        return resp

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e.get("loc", [])), "msg": str(e.get("msg")), "type": e.get("type")}
            for e in exc.errors()
        ]
        return _problem(422, "request validation failed", request.url.path, errors)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> Response:
        if not request.app.state.ready:
            return JSONResponse({"status": "starting"}, status_code=503)
        return JSONResponse({"status": "ready", "devices": len(engine.state)})

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    if settings.otlp_endpoint:  # pragma: no cover - needs a collector
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    return app
