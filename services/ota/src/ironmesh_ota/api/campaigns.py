"""``/v1/campaigns`` (API_CONTRACT §2)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Query, Request
from fastapi.responses import JSONResponse

from ..domain import CampaignState, DeviceState
from ..models import (
    AuditEventOut,
    AuditPage,
    CampaignCreateIn,
    CampaignDeviceOut,
    CampaignDevicePage,
    CampaignOut,
    CampaignPage,
    OptionalReasonIn,
    ReasonIn,
)
from ..problems import validation
from .deps import Admin, Cursor, Limit, Operator, Viewer, idempotent, services_of

router = APIRouter(tags=["campaigns"])


def _states(raw: str | None) -> list[CampaignState] | None:
    if not raw:
        return None
    states: list[CampaignState] = []
    for part in raw.split(","):
        try:
            states.append(CampaignState(part.strip()))
        except ValueError as exc:
            raise validation([{"field": "state", "message": f"unknown state {part!r}"}]) from exc
    return states


@router.post("/v1/campaigns", status_code=201, response_model=CampaignOut)
async def create_campaign(
    request: Request, principal: Operator, body: CampaignCreateIn
) -> JSONResponse:
    service = services_of(request).campaigns
    return await idempotent(request, principal, 201, lambda: service.create(principal, body))


@router.get("/v1/campaigns", response_model=CampaignPage)
async def list_campaigns(
    request: Request,
    principal: Viewer,
    state: Annotated[str | None, Query(max_length=200)] = None,
    cursor: Cursor = None,
    limit: Limit = 50,
) -> CampaignPage:
    page = await services_of(request).campaigns.list_page(
        principal.tenant_id, _states(state), cursor, limit
    )
    return CampaignPage(items=page.items, next_cursor=page.next_cursor)


@router.get("/v1/campaigns/{campaign_id}", response_model=CampaignOut)
async def get_campaign(request: Request, principal: Viewer, campaign_id: str) -> CampaignOut:
    return await services_of(request).campaigns.get(principal.tenant_id, campaign_id)


@router.post("/v1/campaigns/{campaign_id}/start", response_model=CampaignOut)
async def start_campaign(request: Request, principal: Operator, campaign_id: str) -> JSONResponse:
    service = services_of(request).campaigns
    return await idempotent(request, principal, 200, lambda: service.start(principal, campaign_id))


@router.post("/v1/campaigns/{campaign_id}/pause", response_model=CampaignOut)
async def pause_campaign(request: Request, principal: Operator, campaign_id: str) -> JSONResponse:
    service = services_of(request).campaigns
    return await idempotent(request, principal, 200, lambda: service.pause(principal, campaign_id))


@router.post("/v1/campaigns/{campaign_id}/resume", response_model=CampaignOut)
async def resume_campaign(request: Request, principal: Operator, campaign_id: str) -> JSONResponse:
    service = services_of(request).campaigns
    return await idempotent(request, principal, 200, lambda: service.resume(principal, campaign_id))


@router.post("/v1/campaigns/{campaign_id}/cancel", response_model=CampaignOut)
async def cancel_campaign(
    request: Request,
    principal: Operator,
    campaign_id: str,
    body: Annotated[OptionalReasonIn | None, Body()] = None,
) -> JSONResponse:
    service = services_of(request).campaigns
    reason = body.reason if body else None
    return await idempotent(
        request, principal, 200, lambda: service.cancel(principal, campaign_id, reason)
    )


@router.post("/v1/campaigns/{campaign_id}/halt", response_model=CampaignOut)
async def halt_campaign(
    request: Request, principal: Operator, campaign_id: str, body: ReasonIn
) -> JSONResponse:
    service = services_of(request).campaigns
    return await idempotent(
        request, principal, 200, lambda: service.halt(principal, campaign_id, body.reason)
    )


@router.post("/v1/campaigns/{campaign_id}/approve", response_model=CampaignOut)
async def approve_campaign(request: Request, principal: Operator, campaign_id: str) -> JSONResponse:
    """Second-operator approval required for ``security`` campaigns with a canary dwell < 1 h."""
    service = services_of(request).campaigns
    return await idempotent(
        request, principal, 200, lambda: service.approve(principal, campaign_id)
    )


@router.post("/v1/campaigns/{campaign_id}/rollback", status_code=201, response_model=CampaignOut)
async def rollback_campaign(
    request: Request, principal: Admin, campaign_id: str, body: ReasonIn
) -> JSONResponse:
    service = services_of(request).campaigns
    return await idempotent(
        request, principal, 201, lambda: service.rollback(principal, campaign_id, body.reason)
    )


@router.get("/v1/campaigns/{campaign_id}/devices", response_model=CampaignDevicePage)
async def campaign_devices(
    request: Request,
    principal: Viewer,
    campaign_id: str,
    state: DeviceState | None = None,
    cursor: Cursor = None,
    limit: Limit = 50,
) -> CampaignDevicePage:
    page = await services_of(request).campaigns.devices(
        principal.tenant_id, campaign_id, state, cursor, limit
    )
    return CampaignDevicePage(
        items=[CampaignDeviceOut.of(d) for d in page.items], next_cursor=page.next_cursor
    )


@router.get("/v1/campaigns/{campaign_id}/audit", response_model=AuditPage)
async def campaign_audit(
    request: Request, principal: Viewer, campaign_id: str, cursor: Cursor = None, limit: Limit = 50
) -> AuditPage:
    page = await services_of(request).campaigns.audit(
        principal.tenant_id, campaign_id, cursor, limit
    )
    return AuditPage(items=[AuditEventOut.of(e) for e in page.items], next_cursor=page.next_cursor)
