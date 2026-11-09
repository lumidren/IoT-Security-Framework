"""FastAPI dependencies: container access, authentication, RBAC, pagination, idempotency."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

import structlog
from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..auth import Principal, ServicePrincipal, authenticate, authenticate_service, require_role
from ..bundle import ServiceBundle
from ..container import Container
from ..domain import IdempotencyRecord, Role
from ..problems import Problem
from ..repository.base import RepositoryConflict


def container_of(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def services_of(request: Request) -> ServiceBundle:
    bundle: ServiceBundle = request.app.state.services
    return bundle


async def current_principal(request: Request) -> Principal:
    principal = await authenticate(request, container_of(request).user_verifier)
    structlog.contextvars.bind_contextvars(
        tenant_id=str(principal.tenant_id), request_id=principal.request_id
    )
    return principal


async def internal_caller(request: Request) -> ServicePrincipal:
    c = container_of(request)
    token = c.settings.internal_token.get_secret_value() if c.settings.internal_token else None
    return await authenticate_service(
        request,
        c.service_verifier,
        c.settings.internal_allowed_services,
        token,
        c.service_replay,
    )


Viewer = Annotated[Principal, Depends(require_role(Role.VIEWER, current_principal))]
Operator = Annotated[Principal, Depends(require_role(Role.OPERATOR, current_principal))]
Admin = Annotated[Principal, Depends(require_role(Role.ADMIN, current_principal))]
Internal = Annotated[ServicePrincipal, Depends(internal_caller)]
Cursor = Annotated[str | None, Query(max_length=512)]
Limit = Annotated[int, Query(ge=1, le=200)]

IDEMPOTENCY_HEADER = "idempotency-key"


async def idempotent(
    request: Request,
    principal: Principal,
    status_code: int,
    run: Callable[[], Awaitable[BaseModel]],
) -> JSONResponse:
    """Replay the stored response for a repeated ``Idempotency-Key`` (API_CONTRACT §0)."""
    c = container_of(request)
    key = request.headers.get(IDEMPOTENCY_HEADER)
    if key is None:
        result = await run()
        return JSONResponse(result.model_dump(mode="json"), status_code=status_code)
    if not 1 <= len(key) <= 128:
        raise Problem(422, errors=[{"field": "Idempotency-Key", "message": "1..128 characters"}])
    actor = principal.actor.ref
    async with c.db.tenant(principal.tenant_id) as repo:
        stored = await repo.get_idempotency(key, actor)
    if stored is not None:
        if stored.method != request.method or stored.path != request.url.path:
            raise Problem(
                422,
                "Idempotency-Key was already used for a different request",
                errors=[{"field": "Idempotency-Key", "message": "key reused"}],
            )
        return JSONResponse(
            stored.body, status_code=stored.status_code, headers={"Idempotency-Replayed": "true"}
        )
    result = await run()
    body = result.model_dump(mode="json")
    record = IdempotencyRecord(
        tenant_id=principal.tenant_id,
        key=key,
        actor=actor,
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        body=body,
        created_at=c.clock(),
    )
    try:
        async with c.db.tenant(principal.tenant_id) as repo:
            await repo.put_idempotency(record)
    except RepositoryConflict:  # pragma: no cover - concurrent duplicate; first one wins
        pass
    return JSONResponse(body, status_code=status_code)
