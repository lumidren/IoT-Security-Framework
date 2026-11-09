"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response

from . import __version__, problems
from .api import campaigns, firmware, internal, system
from .bundle import ServiceBundle
from .container import Container
from .ingest import IngestConsumer
from .observability import get_logger
from .pagination import InvalidCursor

log = get_logger("ironmesh.ota.app")


def create_app(
    container: Container,
    *,
    run_controller: bool | None = None,
    run_consumer: bool | None = None,
) -> FastAPI:
    bundle = ServiceBundle.build(container)
    controller_on = (
        container.settings.controller_enabled if run_controller is None else run_controller
    )
    consumer_on = container.settings.kafka_enabled if run_consumer is None else run_consumer

    async def initial_key_sync() -> None:
        """Startup: re-push every tenant's firmware keys to the PKI (outbox, retried)."""
        try:
            marked = await bundle.key_sync.request_all()
            pushed = await bundle.key_sync.run_due()
            log.info("pki firmware keys reconciled", tenants=marked, pushed=pushed)
        except Exception:
            log.exception("pki firmware key reconciliation failed; the controller retries")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        consumer: IngestConsumer | None = None
        key_task = asyncio.create_task(initial_key_sync(), name="ota-pki-key-sync")
        if controller_on:
            bundle.controller.start()
        if consumer_on:  # pragma: no cover - needs Redpanda
            consumer = IngestConsumer(container, bundle.ingestor)
            consumer.start()
        log.info(
            "ota service started",
            version=__version__,
            controller=controller_on,
            consumer=consumer_on,
            signing_key=container.signer.active_key_id,
            pq=container.signer.pq_enabled,
        )
        try:
            yield
        finally:
            key_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await key_task
            if consumer is not None:  # pragma: no cover
                await consumer.stop()
            if controller_on:
                await bundle.controller.stop()
            await container.publisher.close()
            await container.events.close()
            for close in container.closers:
                result = close()
                if inspect.isawaitable(result):
                    await result
            await container.db.close()

    app = FastAPI(
        title="IronMesh OTA",
        version=__version__,
        description="Firmware artifacts, hybrid manifest signing, delta patches and staged "
        "rollout campaigns (docs/API_CONTRACT.md §2).",
        lifespan=lifespan,
    )
    app.state.container = container
    app.state.services = bundle
    problems.install(app)

    async def on_cursor(request: Request, _exc: Exception) -> Response:
        return problems.problem_response(request, problems.Problem(400, "invalid cursor"))

    app.add_exception_handler(InvalidCursor, on_cursor)

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        structlog.contextvars.clear_contextvars()
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    if container.settings.otel_enabled:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")

    app.include_router(system.router)
    app.include_router(firmware.router)
    app.include_router(campaigns.router)
    app.include_router(internal.router)
    return app
