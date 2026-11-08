"""Health, readiness and Prometheus metrics on the service port."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .deps import container_of, services_of

router = APIRouter(tags=["system"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    c = container_of(request)
    checks = {
        "database": await c.db.ping(),
        "artifact_store": await c.store.ping(),
        "signing_key": bool(c.signer.active_key_id),
    }
    ok = all(checks.values())
    body = {
        "status": "ok" if ok else "unavailable",
        "checks": checks,
        "controller_leader": services_of(request).controller.is_leader,
    }
    return JSONResponse(body, status_code=200 if ok else 503)


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    return Response(
        generate_latest(container_of(request).metrics.registry), media_type=CONTENT_TYPE_LATEST
    )
