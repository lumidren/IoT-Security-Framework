"""HTTP API (API_CONTRACT section 3). All routes are tenant-scoped by the caller's token."""

from __future__ import annotations

import base64
import binascii
import json
import math
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ironmesh_wire import ids

from .alerting import AlertNotFound, InvalidTransition
from .audit import Actor, audit_event
from .auth import Principal, require
from .engine import Engine
from .features import FEATURE_NAMES
from .models import (
    AlertState,
    RuleName,
    RuleOverride,
    Severity,
    SiemSettings,
    TenantSettings,
    from_ts,
    parse_rfc3339,
    to_rfc3339,
)
from .repository import AlertFilter, Cursor
from .rules import InvalidRuleParams, RuleSet, build_rule
from .siem import UnsafeTarget, validate_host, validate_webhook_url

router = APIRouter(prefix="/v1")

MAX_DRY_RUN_WINDOW = timedelta(days=31)


# --------------------------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------------------------


class ActionOut(BaseModel):
    type: Literal["quarantine", "notify", "none"]
    at: str
    result: str


class AlertOut(BaseModel):
    id: str
    tenant_id: str
    device_id: str
    rule: RuleName
    severity: Severity
    score: float
    features: dict[str, Any]
    explanation: str
    created_at: str
    state: AlertState
    acked_by: str | None
    resolved_by: str | None
    actions: list[ActionOut]


class AlertPage(BaseModel):
    items: list[AlertOut]
    next_cursor: str | None


class RuleOut(BaseModel):
    name: RuleName
    enabled: bool
    severity: Severity
    params: dict[str, Any]
    description: str
    dry_run: bool


class DryRunOut(BaseModel):
    would_fire: int
    sample: list[AlertOut]


class BaselineOut(BaseModel):
    device_class: str
    samples: int
    trained_at: str | None
    score_threshold: float
    feature_means: dict[str, float | None]
    recent_scores: list[tuple[str, float]]


class QuarantineOut(BaseModel):
    device_id: str
    quarantined_at: str
    reason: str
    alert_id: str | None
    by: str


class QuarantinePage(BaseModel):
    items: list[QuarantineOut]
    next_cursor: str | None


class SiemOut(BaseModel):
    ecs_webhook_url: str | None
    syslog_host: str | None
    syslog_port: int | None
    enabled: bool


class SettingsOut(BaseModel):
    auto_quarantine: bool
    quarantine_min_severity: Severity
    siem: SiemOut


class NoteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field("", max_length=4000)


class ResolveBody(NoteBody):
    false_positive: bool = False


class RulePut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    severity: Severity | None = None
    params: dict[str, Any] | None = None
    dry_run: bool | None = None


class DryRunBody(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    from_: datetime = Field(alias="from")
    to: datetime
    params: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _window(self) -> DryRunBody:
        if self.from_.tzinfo is None or self.to.tzinfo is None:
            raise ValueError("from/to must carry a UTC offset (RFC 3339)")
        if self.to <= self.from_:
            raise ValueError("to must be after from")
        if self.to - self.from_ > MAX_DRY_RUN_WINDOW:
            raise ValueError("dry-run window is limited to 31 days")
        return self


class SiemPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ecs_webhook_url: str | None = Field(None, max_length=2048)
    syslog_host: str | None = Field(None, max_length=253)
    syslog_port: int | None = Field(None, ge=1, le=65535)
    enabled: bool | None = None


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    auto_quarantine: bool | None = None
    quarantine_min_severity: Severity | None = None
    siem: SiemPatch | None = None


# --------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------


def engine_of(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


def encode_cursor(cursor: Cursor | None) -> str | None:
    if cursor is None:
        return None
    raw = json.dumps([to_rfc3339(cursor[0]), cursor[1]]).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(value: str | None) -> Cursor | None:
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        at, key = json.loads(raw)
        if not isinstance(at, str) or not isinstance(key, str):
            raise TypeError
        return parse_rfc3339(at), key
    except (ValueError, TypeError, binascii.Error) as exc:
        raise HTTPException(422, "invalid cursor") from exc


def check_device_id(device_id: str) -> str:
    if not ids.is_device_id(device_id):
        raise HTTPException(422, "device id must match ^dev-[0-9a-f]{16}$")
    return device_id


def check_alert_id(alert_id: str) -> str:
    try:
        return str(uuid.UUID(alert_id))
    except ValueError as exc:
        raise HTTPException(404, "alert not found") from exc


async def write_audit(
    request: Request,
    principal: Principal,
    action: str,
    target_type: str,
    target_id: str,
    details: dict[str, Any],
) -> None:
    engine = engine_of(request)
    details = {**details, "via": "api"}
    if principal.impersonating:
        details["platform_admin_impersonation"] = True
    await engine.audit.publish(
        audit_event(
            tenant_id=principal.tenant_id,
            actor=Actor("user", principal.subject, principal.name),
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip=request.client.host if request.client else None,
            request_id=request.headers.get("x-request-id") or str(uuid.uuid4()),
        )
    )


Viewer = Annotated[Principal, Depends(require("viewer"))]
Operator = Annotated[Principal, Depends(require("operator"))]
Admin = Annotated[Principal, Depends(require("admin"))]


# --------------------------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------------------------


@router.get("/alerts", response_model=AlertPage)
async def list_alerts(
    request: Request,
    principal: Viewer,
    state: AlertState | None = None,
    severity: Severity | None = None,
    rule: RuleName | None = None,
    device_id: str | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    if device_id is not None:
        check_device_id(device_id)
    flt = AlertFilter(state, severity, rule, device_id, from_, to)
    items, nxt = await engine_of(request).repo.list_alerts(
        principal.tenant_id, flt, decode_cursor(cursor), limit
    )
    return {"items": [a.to_api() for a in items], "next_cursor": encode_cursor(nxt)}


@router.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_alert(request: Request, principal: Viewer, alert_id: str) -> dict[str, Any]:
    alert = await engine_of(request).repo.get_alert(principal.tenant_id, check_alert_id(alert_id))
    if alert is None:
        raise HTTPException(404, "alert not found")
    return alert.to_api()


@router.post("/alerts/{alert_id}/ack", response_model=AlertOut)
async def ack_alert(
    request: Request,
    principal: Operator,
    alert_id: str,
    body: Annotated[NoteBody, Body()] = NoteBody(),  # noqa: B008
) -> dict[str, Any]:
    engine = engine_of(request)
    try:
        alert = await engine.alerts.ack(
            principal.tenant_id, check_alert_id(alert_id), f"user:{principal.subject}"
        )
    except AlertNotFound as exc:
        raise HTTPException(404, "alert not found") from exc
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc)) from exc
    await write_audit(request, principal, "alert.ack", "alert", alert.id, {"note": body.note})
    return alert.to_api()


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut)
async def resolve_alert(
    request: Request,
    principal: Operator,
    alert_id: str,
    body: Annotated[ResolveBody, Body()] = ResolveBody(),  # noqa: B008
) -> dict[str, Any]:
    engine = engine_of(request)
    try:
        alert = await engine.alerts.resolve(
            principal.tenant_id,
            check_alert_id(alert_id),
            f"user:{principal.subject}",
            false_positive=body.false_positive,
        )
    except AlertNotFound as exc:
        raise HTTPException(404, "alert not found") from exc
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc)) from exc
    await write_audit(
        request,
        principal,
        "alert.resolve",
        "alert",
        alert.id,
        {"note": body.note, "false_positive": body.false_positive, "rule": alert.rule.value},
    )
    return alert.to_api()


# --------------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------------


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(request: Request, principal: Viewer) -> list[dict[str, Any]]:
    overrides = await engine_of(request).repo.get_rule_overrides(principal.tenant_id)
    return [r.describe() for r in RuleSet(overrides)]


def _rule_name(name: str) -> RuleName:
    try:
        return RuleName(name)
    except ValueError as exc:
        raise HTTPException(404, f"unknown rule {name!r}") from exc


@router.put("/rules/{name}", response_model=RuleOut)
async def put_rule(
    request: Request, principal: Admin, name: Annotated[str, Path()], body: RulePut
) -> dict[str, Any]:
    rule_name = _rule_name(name)
    engine = engine_of(request)
    overrides = await engine.repo.get_rule_overrides(principal.tenant_id)
    current = overrides.get(rule_name, RuleOverride())
    params = dict(current.params)
    if body.params is not None:
        params.update(body.params)
    updated = RuleOverride(
        enabled=body.enabled if body.enabled is not None else current.enabled,
        severity=body.severity if body.severity is not None else current.severity,
        params=params,
        dry_run=body.dry_run if body.dry_run is not None else current.dry_run,
    )
    try:
        rule = build_rule(rule_name, updated)
    except InvalidRuleParams as exc:
        raise HTTPException(422, {"message": str(exc), "errors": exc.errors}) from exc
    updated.params = rule.params.model_dump(exclude_defaults=True)
    await engine.repo.put_rule_override(principal.tenant_id, rule_name, updated)
    engine.invalidate(principal.tenant_id)
    await write_audit(
        request,
        principal,
        "anomaly.rule.update",
        "rule",
        rule_name.value,
        {"change": body.model_dump(exclude_none=True), "effective": rule.describe()},
    )
    return rule.describe()


@router.post("/rules/{name}/dry-run", response_model=DryRunOut)
async def dry_run_rule(
    request: Request, principal: Operator, name: str, body: DryRunBody
) -> dict[str, Any]:
    rule_name = _rule_name(name)
    try:
        result = await engine_of(request).dry_run(
            principal.tenant_id, rule_name, body.from_, body.to, body.params
        )
    except InvalidRuleParams as exc:
        raise HTTPException(422, {"message": str(exc), "errors": exc.errors}) from exc
    return {"would_fire": result.would_fire, "sample": result.sample}


# --------------------------------------------------------------------------------------------
# Devices, quarantine, settings
# --------------------------------------------------------------------------------------------


@router.get("/devices/{device_id}/baseline", response_model=BaselineOut)
async def device_baseline(request: Request, principal: Viewer, device_id: str) -> dict[str, Any]:
    engine = engine_of(request)
    st = engine.state.get(principal.tenant_id, check_device_id(device_id))
    if st is None:
        raise HTTPException(404, "no baseline for this device")
    model = engine.models.get(principal.tenant_id, st.device_class)
    means: dict[str, float | None] = {}
    rows = [f for _, f in st.features]
    for i, feature in enumerate(FEATURE_NAMES):
        values = [r[i] for r in rows if not math.isnan(r[i])]
        means[feature] = round(sum(values) / len(values), 6) if values else None
    return {
        "device_class": st.device_class,
        "samples": st.sample_count,
        "trained_at": to_rfc3339(from_ts(model.trained_at)) if model else None,
        "score_threshold": 0.5,
        "feature_means": means,
        "recent_scores": [(to_rfc3339(from_ts(t)), s) for t, s in st.scores],
    }


@router.get("/quarantine", response_model=QuarantinePage)
async def list_quarantine(
    request: Request,
    principal: Viewer,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    items, nxt = await engine_of(request).repo.list_quarantine(
        principal.tenant_id, decode_cursor(cursor), limit
    )
    return {"items": [r.to_api() for r in items], "next_cursor": encode_cursor(nxt)}


@router.get("/settings", response_model=SettingsOut)
async def get_settings(request: Request, principal: Admin) -> dict[str, Any]:
    settings = await engine_of(request).tenant_settings(principal.tenant_id)
    return settings.to_api()


@router.patch("/settings", response_model=SettingsOut)
async def patch_settings(request: Request, principal: Admin, body: SettingsPatch) -> dict[str, Any]:
    engine = engine_of(request)
    current = await engine.tenant_settings(principal.tenant_id)
    allow_private: bool = request.app.state.allow_private_siem
    siem = current.siem
    if body.siem is not None:
        patch = body.siem.model_dump(exclude_unset=True)
        siem = SiemSettings(
            ecs_webhook_url=patch.get("ecs_webhook_url", siem.ecs_webhook_url),
            syslog_host=patch.get("syslog_host", siem.syslog_host),
            syslog_port=patch.get("syslog_port", siem.syslog_port),
            enabled=siem.enabled if patch.get("enabled") is None else bool(patch["enabled"]),
        )
        try:
            if siem.ecs_webhook_url:
                validate_webhook_url(siem.ecs_webhook_url, allow_private=allow_private)
            if siem.syslog_host:
                validate_host(siem.syslog_host, allow_private=allow_private)
        except UnsafeTarget as exc:
            raise HTTPException(422, f"unsafe SIEM target: {exc}") from exc
    updated = TenantSettings(
        auto_quarantine=(
            body.auto_quarantine if body.auto_quarantine is not None else current.auto_quarantine
        ),
        quarantine_min_severity=body.quarantine_min_severity or current.quarantine_min_severity,
        siem=siem,
    )
    await engine.repo.put_settings(principal.tenant_id, updated)
    engine.invalidate(principal.tenant_id)
    await write_audit(
        request,
        principal,
        "anomaly.settings.update",
        "tenant",
        principal.tenant_id,
        {"before": current.to_api(), "after": updated.to_api()},
    )
    return updated.to_api()
