"""HTTP + WebSocket routes of API_CONTRACT.md §1 (public ``/v1``, ``/internal/v1``, health)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from starlette.websockets import WebSocketDisconnect

from .. import models as m
from ..auth import Principal
from ..domain import AuditFilter, DeviceFilter
from ..problems import unprocessable
from ..services import admin, commands, config, devices, twin
from ..ws import Connection, frame, heartbeat
from .deps import get_ctx, internal, require

PROBLEMS: dict[int | str, dict[str, Any]] = {
    code: {"model": m.ProblemDetails, "description": text}
    for code, text in (
        (401, "Authentication required"),
        (403, "Forbidden"),
        (404, "Not found"),
        (409, "Conflict"),
        (422, "Validation error"),
    )
}

v1 = APIRouter(prefix="/v1", responses=PROBLEMS)
internal_v1 = APIRouter(prefix="/internal/v1", tags=["internal"], responses=PROBLEMS)
health = APIRouter(tags=["health"])

DevicePath = Annotated[str, Path(max_length=64)]
Limit = Annotated[int | None, Query(ge=1, le=200)]
Cursor = Annotated[str | None, Query(max_length=512)]


class Page[T](BaseModel):
    items: list[T]
    next_cursor: str | None


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


# ------------------------------------------------------------------------------------------------
# §1.1 Tenant
# ------------------------------------------------------------------------------------------------


@v1.get("/tenants/me", response_model=m.Tenant, tags=["tenant"], operation_id="getTenant")
async def get_tenant(request: Request, p: Principal = Depends(require("tenant.read"))) -> m.Tenant:
    return await admin.get_tenant(get_ctx(request), p)


@v1.patch(
    "/tenants/me/settings",
    response_model=m.Tenant,
    tags=["tenant"],
    operation_id="updateTenantSettings",
)
async def patch_settings(
    request: Request,
    body: m.TenantSettingsPatch,
    p: Principal = Depends(require("tenant.settings")),
) -> m.Tenant:
    return await admin.update_settings(get_ctx(request), p, body)


# ------------------------------------------------------------------------------------------------
# §1.2 Devices
# ------------------------------------------------------------------------------------------------


@v1.get(
    "/devices", response_model=Page[m.DeviceSummary], tags=["devices"], operation_id="listDevices"
)
async def list_devices(
    request: Request,
    state: m.DeviceStateT | None = None,
    group: str | None = None,
    tag: str | None = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
    connected: bool | None = None,
    assurance: m.AssuranceT | None = None,
    cursor: Cursor = None,
    limit: Limit = None,
    p: Principal = Depends(require("device.read")),
) -> Page[m.DeviceSummary]:
    tag_filter = None
    if tag:
        key, sep, value = tag.partition(":")
        if not sep or not key:
            raise unprocessable("tag must be k:v")
        tag_filter = (key, value)
    flt = DeviceFilter(
        state=state, group=group, tag=tag_filter, q=q, connected=connected, assurance=assurance
    )
    items, nxt = await devices.list_devices(get_ctx(request), p, flt, cursor, limit)
    return Page[m.DeviceSummary](items=items, next_cursor=nxt)


@v1.post(
    "/devices",
    response_model=m.DeviceDetail,
    status_code=201,
    tags=["devices"],
    operation_id="createDevice",
)
async def create_device(
    request: Request, body: m.CreateDeviceInput, p: Principal = Depends(require("device.create"))
) -> m.DeviceDetail:
    return await devices.create_device(get_ctx(request), p, body)


@v1.get(
    "/devices/{device_id}",
    response_model=m.DeviceDetail,
    tags=["devices"],
    operation_id="getDevice",
)
async def get_device(
    request: Request, device_id: DevicePath, p: Principal = Depends(require("device.read"))
) -> m.DeviceDetail:
    return await devices.get_device(get_ctx(request), p, device_id)


@v1.patch(
    "/devices/{device_id}",
    response_model=m.DeviceDetail,
    tags=["devices"],
    operation_id="updateDevice",
)
async def update_device(
    request: Request,
    device_id: DevicePath,
    body: m.UpdateDeviceInput,
    p: Principal = Depends(require("device.edit")),
) -> m.DeviceDetail:
    return await devices.update_device(get_ctx(request), p, device_id, body)


@v1.post(
    "/devices/{device_id}/quarantine",
    response_model=m.DeviceDetail,
    tags=["devices"],
    operation_id="quarantineDevice",
)
async def quarantine_device(
    request: Request,
    device_id: DevicePath,
    body: m.ReasonInput,
    p: Principal = Depends(require("device.quarantine")),
) -> m.DeviceDetail:
    return await devices.quarantine(get_ctx(request), p, device_id, body.reason)


@v1.post(
    "/devices/{device_id}/release",
    response_model=m.DeviceDetail,
    tags=["devices"],
    operation_id="releaseDevice",
)
async def release_device(
    request: Request,
    device_id: DevicePath,
    body: m.NoteInput,
    p: Principal = Depends(require("device.release")),
) -> m.DeviceDetail:
    return await devices.release(get_ctx(request), p, device_id, body.note)


@v1.post(
    "/devices/{device_id}/decommission",
    response_model=m.DeviceDetail,
    tags=["devices"],
    operation_id="decommissionDevice",
)
async def decommission_device(
    request: Request,
    device_id: DevicePath,
    body: m.ReasonInput,
    p: Principal = Depends(require("device.decommission")),
) -> m.DeviceDetail:
    return await devices.decommission(get_ctx(request), p, device_id, body.reason)


@v1.get(
    "/devices/{device_id}/timeline",
    response_model=Page[m.TimelineEvent],
    tags=["devices"],
    operation_id="getDeviceTimeline",
)
async def device_timeline(
    request: Request,
    device_id: DevicePath,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    kinds: str | None = None,
    cursor: Cursor = None,
    limit: Limit = None,
    p: Principal = Depends(require("device.read")),
) -> Page[m.TimelineEvent]:
    items, nxt = await devices.timeline(
        get_ctx(request), p, device_id, _utc(from_), _utc(to), _csv(kinds), cursor, limit
    )
    return Page[m.TimelineEvent](items=items, next_cursor=nxt)


@v1.get(
    "/devices/{device_id}/telemetry",
    response_model=m.TelemetrySeries,
    tags=["devices"],
    operation_id="getDeviceTelemetry",
)
async def device_telemetry(
    request: Request,
    device_id: DevicePath,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    metrics: str | None = None,
    step: str = "60s",
    p: Principal = Depends(require("device.read")),
) -> m.TelemetrySeries:
    return await devices.telemetry(
        get_ctx(request), p, device_id, _utc(from_), _utc(to), _csv(metrics), step
    )


@v1.get(
    "/devices/{device_id}/certificates",
    response_model=list[m.Certificate],
    tags=["devices"],
    operation_id="getDeviceCertificates",
)
async def device_certificates(
    request: Request, device_id: DevicePath, p: Principal = Depends(require("device.read"))
) -> list[m.Certificate]:
    return await devices.certificates(get_ctx(request), p, device_id)


# ------------------------------------------------------------------------------------------------
# §1.3 Groups
# ------------------------------------------------------------------------------------------------


@v1.get("/groups", response_model=list[m.Group], tags=["groups"], operation_id="listGroups")
async def list_groups(
    request: Request, p: Principal = Depends(require("group.read"))
) -> list[m.Group]:
    return await admin.list_groups(get_ctx(request), p)


@v1.post(
    "/groups", response_model=m.Group, status_code=201, tags=["groups"], operation_id="createGroup"
)
async def create_group(
    request: Request, body: m.CreateGroupInput, p: Principal = Depends(require("group.write"))
) -> m.Group:
    return await admin.create_group(get_ctx(request), p, body)


@v1.patch("/groups/{slug}", response_model=m.Group, tags=["groups"], operation_id="updateGroup")
async def update_group(
    request: Request,
    slug: str,
    body: m.UpdateGroupInput,
    p: Principal = Depends(require("group.write")),
) -> m.Group:
    return await admin.update_group(get_ctx(request), p, slug, body)


@v1.delete("/groups/{slug}", status_code=204, tags=["groups"], operation_id="deleteGroup")
async def delete_group(
    request: Request, slug: str, p: Principal = Depends(require("group.delete"))
) -> Response:
    await admin.delete_group(get_ctx(request), p, slug)
    return Response(status_code=204)


@v1.put(
    "/groups/{slug}/members",
    response_model=m.GroupMembersResult,
    tags=["groups"],
    operation_id="setGroupMembers",
)
async def group_members(
    request: Request,
    slug: str,
    body: m.GroupMembersInput,
    p: Principal = Depends(require("group.write")),
) -> m.GroupMembersResult:
    return await admin.set_members(get_ctx(request), p, slug, body)


# ------------------------------------------------------------------------------------------------
# §1.4 Twin
# ------------------------------------------------------------------------------------------------


@v1.get("/devices/{device_id}/twin", response_model=m.Twin, tags=["twin"], operation_id="getTwin")
async def get_twin(
    request: Request, device_id: DevicePath, p: Principal = Depends(require("twin.read"))
) -> m.Twin:
    return await twin.get_twin(get_ctx(request), p, device_id)


@v1.patch(
    "/devices/{device_id}/twin/desired",
    response_model=m.Twin,
    tags=["twin"],
    operation_id="patchTwinDesired",
)
async def patch_twin(
    request: Request,
    device_id: DevicePath,
    body: m.TwinPatchInput,
    p: Principal = Depends(require("twin.write")),
) -> m.Twin:
    return await twin.patch_desired(get_ctx(request), p, device_id, body)


@v1.delete(
    "/devices/{device_id}/twin/desired/{path:path}",
    response_model=m.Twin,
    tags=["twin"],
    operation_id="deleteTwinDesiredPath",
)
async def delete_twin_path(
    request: Request,
    device_id: DevicePath,
    path: str,
    p: Principal = Depends(require("twin.write")),
) -> m.Twin:
    return await twin.delete_desired(get_ctx(request), p, device_id, path)


# ------------------------------------------------------------------------------------------------
# §1.5 Commands
# ------------------------------------------------------------------------------------------------

IdemHeader = Annotated[str | None, Header(alias="Idempotency-Key", max_length=128)]


@v1.post(
    "/devices/{device_id}/commands",
    response_model=m.Command,
    status_code=202,
    tags=["commands"],
    operation_id="sendCommand",
)
async def send_command(
    request: Request,
    device_id: DevicePath,
    body: m.SendCommandInput,
    idempotency_key: IdemHeader = None,
    p: Principal = Depends(require("command.send")),
) -> JSONResponse:
    created = await commands.create_command(get_ctx(request), p, device_id, body, idempotency_key)
    headers = {"Idempotency-Replayed": "true"} if created.replayed else {}
    return JSONResponse(created.command.model_dump(mode="json"), status_code=202, headers=headers)


@v1.get(
    "/devices/{device_id}/commands",
    response_model=Page[m.Command],
    tags=["commands"],
    operation_id="listDeviceCommands",
)
async def list_commands(
    request: Request,
    device_id: DevicePath,
    status: m.CommandStatusT | None = None,
    cursor: Cursor = None,
    limit: Limit = None,
    p: Principal = Depends(require("command.read")),
) -> Page[m.Command]:
    items, nxt = await commands.list_commands(get_ctx(request), p, device_id, status, cursor, limit)
    return Page[m.Command](items=items, next_cursor=nxt)


@v1.get(
    "/commands/{cmd_id}", response_model=m.Command, tags=["commands"], operation_id="getCommand"
)
async def get_command(
    request: Request, cmd_id: str, p: Principal = Depends(require("command.read"))
) -> m.Command:
    return await commands.get_command(get_ctx(request), p, cmd_id)


@v1.post(
    "/groups/{slug}/commands",
    response_model=m.CommandBatch,
    status_code=202,
    tags=["commands"],
    operation_id="sendGroupCommand",
)
async def send_group_command(
    request: Request,
    slug: str,
    body: m.SendCommandInput,
    idempotency_key: IdemHeader = None,
    p: Principal = Depends(require("command.send")),
) -> JSONResponse:
    batch, replayed = await commands.create_group_command(
        get_ctx(request), p, slug, body, idempotency_key
    )
    headers = {"Idempotency-Replayed": "true"} if replayed else {}
    return JSONResponse(batch.model_dump(mode="json"), status_code=202, headers=headers)


# ------------------------------------------------------------------------------------------------
# §1.6 Config
# ------------------------------------------------------------------------------------------------


@v1.get(
    "/devices/{device_id}/config",
    response_model=m.DeviceConfig,
    tags=["config"],
    operation_id="getDeviceConfig",
)
async def get_config(
    request: Request, device_id: DevicePath, p: Principal = Depends(require("config.read"))
) -> m.DeviceConfig:
    return await config.get_config(get_ctx(request), p, device_id)


@v1.put(
    "/devices/{device_id}/config",
    response_model=m.PutConfigResult,
    tags=["config"],
    operation_id="putDeviceConfig",
)
async def put_config(
    request: Request,
    device_id: DevicePath,
    body: m.PutConfigInput,
    p: Principal = Depends(require("config.write")),
) -> m.PutConfigResult:
    return await config.put_config(get_ctx(request), p, device_id, body)


# ------------------------------------------------------------------------------------------------
# §1.7 Provisioning
# ------------------------------------------------------------------------------------------------


@v1.get(
    "/provisioning",
    response_model=Page[m.ProvisioningItem],
    tags=["provisioning"],
    operation_id="listProvisioning",
)
async def list_provisioning(
    request: Request,
    state: m.ProvisioningStateT | None = None,
    cursor: Cursor = None,
    limit: Limit = None,
    p: Principal = Depends(require("provisioning.read")),
) -> Page[m.ProvisioningItem]:
    items, nxt = await devices.list_provisioning(get_ctx(request), p, state, cursor, limit)
    return Page[m.ProvisioningItem](items=items, next_cursor=nxt)


@v1.post(
    "/provisioning/{device_id}/approve",
    response_model=m.DeviceSummary,
    tags=["provisioning"],
    operation_id="approveProvisioning",
)
async def approve(
    request: Request, device_id: DevicePath, p: Principal = Depends(require("provisioning.review"))
) -> m.DeviceSummary:
    return await devices.approve(get_ctx(request), p, device_id)


@v1.post(
    "/provisioning/{device_id}/reject",
    response_model=m.DeviceSummary,
    tags=["provisioning"],
    operation_id="rejectProvisioning",
)
async def reject(
    request: Request,
    device_id: DevicePath,
    body: m.ReasonInput,
    p: Principal = Depends(require("provisioning.review")),
) -> m.DeviceSummary:
    return await devices.reject(get_ctx(request), p, device_id, body.reason)


# ------------------------------------------------------------------------------------------------
# §1.8 Fleet
# ------------------------------------------------------------------------------------------------


@v1.get(
    "/fleet/summary", response_model=m.FleetSummary, tags=["fleet"], operation_id="getFleetSummary"
)
async def fleet_summary(
    request: Request, p: Principal = Depends(require("fleet.read"))
) -> m.FleetSummary:
    return await admin.fleet_summary(get_ctx(request), p)


@v1.get(
    "/fleet/health", response_model=m.FleetHealth, tags=["fleet"], operation_id="getFleetHealth"
)
async def fleet_health(
    request: Request, window: str = "1h", p: Principal = Depends(require("fleet.read"))
) -> m.FleetHealth:
    return await admin.fleet_health(get_ctx(request), p, window)


# ------------------------------------------------------------------------------------------------
# §1.9 Audit
# ------------------------------------------------------------------------------------------------


@v1.get("/audit", response_model=Page[m.AuditEvent], tags=["audit"], operation_id="listAudit")
async def list_audit(
    request: Request,
    actor: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    cursor: Cursor = None,
    limit: Limit = None,
    p: Principal = Depends(require("audit.read")),
) -> Page[m.AuditEvent]:
    flt = AuditFilter(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        from_=_utc(from_),
        to=_utc(to),
    )
    items, nxt = await admin.list_audit(get_ctx(request), p, flt, cursor, limit)
    return Page[m.AuditEvent](items=items, next_cursor=nxt)


@v1.get(
    "/audit/export",
    tags=["audit"],
    operation_id="exportAudit",
    responses={200: {"content": {"application/x-ndjson": {}}}},
)
async def export_audit(
    request: Request,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    format: str = "ndjson",
    p: Principal = Depends(require("audit.export")),
) -> StreamingResponse:
    if format != "ndjson":
        raise unprocessable("only format=ndjson is supported")
    stream: AsyncIterator[bytes] = await admin.export_audit(
        get_ctx(request), p, _utc(from_), _utc(to)
    )
    return StreamingResponse(stream, media_type="application/x-ndjson")


@v1.get(
    "/audit/verify", response_model=m.AuditVerifyResult, tags=["audit"], operation_id="verifyAudit"
)
async def verify_audit(
    request: Request, p: Principal = Depends(require("audit.verify"))
) -> m.AuditVerifyResult:
    return await admin.verify_audit(get_ctx(request), p)


# ------------------------------------------------------------------------------------------------
# §1.10 Users & API keys
# ------------------------------------------------------------------------------------------------


@v1.get("/users", response_model=list[m.User], tags=["users"], operation_id="listUsers")
async def list_users(
    request: Request, p: Principal = Depends(require("users.read"))
) -> list[m.User]:
    return await admin.list_users(get_ctx(request), p)


@v1.put("/users/{user_id}/role", response_model=m.User, tags=["users"], operation_id="setUserRole")
async def set_role(
    request: Request,
    user_id: str,
    body: m.SetRoleInput,
    p: Principal = Depends(require("users.role")),
) -> m.User:
    return await admin.set_role(get_ctx(request), p, user_id, body.role)


@v1.get("/api-keys", response_model=list[m.ApiKey], tags=["users"], operation_id="listApiKeys")
async def list_api_keys(
    request: Request, p: Principal = Depends(require("apikeys.manage"))
) -> list[m.ApiKey]:
    return await admin.list_api_keys(get_ctx(request), p)


@v1.post(
    "/api-keys",
    response_model=m.CreatedApiKey,
    status_code=201,
    tags=["users"],
    operation_id="createApiKey",
)
async def create_api_key(
    request: Request, body: m.CreateApiKeyInput, p: Principal = Depends(require("apikeys.manage"))
) -> JSONResponse:
    created = await admin.create_api_key(get_ctx(request), p, body)
    return JSONResponse(
        created.model_dump(mode="json"), status_code=201, headers={"Cache-Control": "no-store"}
    )


@v1.delete("/api-keys/{key_id}", status_code=204, tags=["users"], operation_id="deleteApiKey")
async def delete_api_key(
    request: Request, key_id: str, p: Principal = Depends(require("apikeys.manage"))
) -> Response:
    await admin.delete_api_key(get_ctx(request), p, key_id)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------------------
# §1.11 WebSocket
# ------------------------------------------------------------------------------------------------


@v1.post("/ws/ticket", response_model=m.WsTicket, tags=["ws"], operation_id="createWsTicket")
async def ws_ticket(
    request: Request, p: Principal = Depends(require("ws.connect"))
) -> JSONResponse:
    ctx = get_ctx(request)
    ticket = ctx.tickets.issue(p)
    body = m.WsTicket(ticket=ticket, expires_in=ctx.tickets.ttl).model_dump()
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@v1.websocket("/ws")
async def ws(websocket: WebSocket, ticket: str | None = None) -> None:
    ctx = websocket.app.state.ctx
    principal = ctx.tickets.redeem(ticket)
    if principal is None:
        await websocket.close(code=4401, reason="invalid or expired ticket")
        return
    await websocket.accept()
    conn = Connection(principal=principal, send=websocket.send_json)
    ctx.hub.register(conn)
    tasks = [
        asyncio.create_task(conn.writer()),
        asyncio.create_task(heartbeat(conn, websocket.app.state.ws_ping_interval)),
    ]
    try:
        while True:
            text = await websocket.receive_text()
            if len(text) > 16_384:
                reply = frame("error", {"detail": "frame too large"})
            else:
                try:
                    message = json.loads(text)
                except ValueError:
                    message = None
                reply = ctx.hub.handle_client_message(conn, message)
            if reply is not None:
                with contextlib.suppress(asyncio.QueueFull):
                    conn.queue.put_nowait(reply)
    except WebSocketDisconnect:
        pass
    finally:
        ctx.hub.unregister(conn)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


# ------------------------------------------------------------------------------------------------
# §1.12 Internal
# ------------------------------------------------------------------------------------------------


@internal_v1.get(
    "/devices/{device_id}/lifecycle",
    response_model=m.Lifecycle,
    operation_id="internalGetLifecycle",
)
async def internal_lifecycle(
    request: Request, device_id: DevicePath, p: Principal = Depends(internal("policy"))
) -> m.Lifecycle:
    return await devices.lifecycle(get_ctx(request), p, device_id)


@internal_v1.post(
    "/devices/{device_id}/enrolled",
    response_model=m.DeviceDetail,
    operation_id="internalDeviceEnrolled",
)
async def internal_enrolled(
    request: Request,
    device_id: DevicePath,
    body: m.EnrolledInput,
    p: Principal = Depends(internal("pki")),
) -> m.DeviceDetail:
    return await devices.enrolled(get_ctx(request), p, device_id, body)


@internal_v1.post(
    "/devices/{device_id}/quarantine",
    response_model=m.DeviceDetail,
    operation_id="internalQuarantine",
)
async def internal_quarantine(
    request: Request,
    device_id: DevicePath,
    body: m.InternalQuarantineInput,
    p: Principal = Depends(internal("anomaly")),
) -> m.DeviceDetail:
    ctx = get_ctx(request)
    tenant = await devices.resolve_tenant(ctx, device_id)
    return await devices.quarantine(
        ctx, p, device_id, body.reason, tenant_id=tenant, alert_id=body.alert_id
    )


@internal_v1.get(
    "/tenants/{tenant_id}/devices/{device_id}",
    response_model=m.PkiDevice,
    operation_id="internalGetTenantDevice",
)
async def internal_tenant_device(
    request: Request, tenant_id: str, device_id: DevicePath, p: Principal = Depends(internal("pki"))
) -> m.PkiDevice:
    return await devices.pki_device(get_ctx(request), p, tenant_id, device_id)


@internal_v1.post(
    "/tenants/{tenant_id}/devices/{device_id}/assurance",
    status_code=204,
    operation_id="internalRecordAssurance",
)
async def internal_assurance(
    request: Request,
    tenant_id: str,
    device_id: DevicePath,
    body: m.AssuranceInput,
    p: Principal = Depends(internal("pki")),
) -> Response:
    await devices.record_assurance(get_ctx(request), p, tenant_id, device_id, body.assurance_level)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------------------
# Health & metrics
# ------------------------------------------------------------------------------------------------


@health.get("/healthz", response_model=m.Health, operation_id="healthz")
async def healthz() -> m.Health:
    return m.Health(status="ok")


@health.get("/readyz", response_model=m.Health, operation_id="readyz")
async def readyz(request: Request) -> JSONResponse:
    ctx = get_ctx(request)
    checks = {"database": await ctx.repo.ping()}
    ok = all(checks.values())
    body = m.Health(status="ok" if ok else "unavailable", checks=checks).model_dump()
    return JSONResponse(body, status_code=200 if ok else 503)


@health.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> PlainTextResponse:
    data = generate_latest(get_ctx(request).metrics.registry)
    return PlainTextResponse(data.decode(), media_type=CONTENT_TYPE_LATEST)
