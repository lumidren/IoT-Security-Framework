"""Internal service-to-service endpoints (service JWT ``aud=ota`` or ``OTA_INTERNAL_TOKEN``)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Request

from ironmesh_wire import OtaState, ids

from ..ingest import StatusInput
from ..models import OtaStatusIn, StatusResult
from ..problems import validation
from .deps import Internal, container_of, services_of

router = APIRouter(prefix="/internal/v1", tags=["internal"])


@router.post("/ota/status", response_model=StatusResult)
async def ingest_status(request: Request, caller: Internal, body: OtaStatusIn) -> StatusResult:
    status = StatusInput(
        tenant_id=uuid.UUID(body.tenant_id),
        device_id=body.device_id,
        campaign_id=uuid.UUID(body.campaign_id),
        state=OtaState(body.state),
        progress_pct=body.progress_pct,
        error=body.error,
        fw_hash=bytes.fromhex(body.fw_hash_hex) if body.fw_hash_hex else None,
        seq=body.seq,
    )
    return await services_of(request).ingestor.submit(status, caller.actor)


@router.get("/firmware/known-hashes", response_model=list[str])
async def known_hashes(
    request: Request,
    _caller: Internal,
    product: Annotated[str | None, Query(max_length=64)] = None,
    tenant_id: Annotated[str | None, Query()] = None,
) -> list[str]:
    """SHA-256 hex of every signed image; tenant-scoped (RLS) when ``tenant_id`` is given."""
    c = container_of(request)
    if tenant_id is None:
        return await c.db.known_hashes(product)
    if not ids.is_tenant_id(tenant_id):
        raise validation([{"field": "tenant_id", "message": "must be a lower-case UUIDv4"}])
    async with c.db.tenant(uuid.UUID(tenant_id)) as repo:
        return [h.hex() for h in await repo.firmware_hashes(product)]
