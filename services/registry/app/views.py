"""Record -> API model conversion."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, cast

from . import models as m
from .domain import (
    ApiKeyRecord,
    AuditRecord,
    CertificateRecord,
    CommandRecord,
    DeviceRecord,
    GroupRecord,
    TenantRecord,
    TimelineRecord,
    TwinRecord,
    UserRecord,
)
from .jsonutil import compute_delta

EXPIRING_WINDOW = timedelta(hours=72)


def cert_status(d: DeviceRecord, now: datetime) -> str:
    if not d.cert_serial_hex or d.cert_not_after is None:
        return "none"
    if d.cert_revoked:
        return "revoked"
    if d.cert_not_after <= now:
        return "expired"
    if d.cert_not_after <= now + EXPIRING_WINDOW:
        return "expiring"
    return "valid"


def _summary_fields(
    d: DeviceRecord, groups: list[str], open_alerts: int, now: datetime
) -> dict[str, Any]:
    return {
        "id": d.id,
        "tenant_id": d.tenant_id,
        "product": d.product,
        "hw_revision": d.hw_revision,
        "state": d.state,
        "assurance_level": d.assurance_level,
        "se_type": d.se_type,
        "groups": groups,
        "tags": d.tags,
        "connected": d.connected,
        "last_seen_at": d.last_seen_at,
        "fw_version": d.fw_version,
        "fw_hash_hex": d.fw_hash_hex,
        "cert": m.DeviceCert(
            serial_hex=d.cert_serial_hex, not_after=d.cert_not_after, status=cert_status(d, now)
        ),
        "location": m.Location(lat=d.lat, lon=d.lon)
        if d.lat is not None and d.lon is not None
        else None,
        "open_alerts": open_alerts,
    }


def device_summary(
    d: DeviceRecord, groups: list[str], open_alerts: int, now: datetime
) -> m.DeviceSummary:
    return m.DeviceSummary(**_summary_fields(d, groups, open_alerts, now))


def certificate(c: CertificateRecord) -> m.Certificate:
    return m.Certificate(
        serial_hex=c.serial_hex,
        not_before=c.not_before,
        not_after=c.not_after,
        revoked_at=c.revoked_at,
        revocation_reason=c.revocation_reason,
        issuer=c.issuer,
    )


def device_detail(
    d: DeviceRecord,
    groups: list[str],
    open_alerts: int,
    now: datetime,
    twin_version: int,
    certs: list[CertificateRecord],
) -> m.DeviceDetail:
    return m.DeviceDetail(
        **_summary_fields(d, groups, open_alerts, now),
        bootstrap_serial_hex=d.bootstrap_serial_hex,
        created_at=d.created_at,
        provisioned_at=d.provisioned_at,
        activated_at=d.activated_at,
        quarantined_at=d.quarantined_at,
        quarantine_reason=d.quarantine_reason,
        decommissioned_at=d.decommissioned_at,
        twin_version=twin_version,
        last_telemetry=m.TelemetrySample.model_validate(d.last_telemetry)
        if d.last_telemetry
        else None,
        certificates=[certificate(c) for c in certs],
    )


def tenant(t: TenantRecord) -> m.Tenant:
    return m.Tenant(
        id=t.id, name=t.name, settings=m.TenantSettings(**t.settings), created_at=t.created_at
    )


def group(g: GroupRecord) -> m.Group:
    return m.Group(
        slug=g.slug,
        name=g.name,
        description=g.description,
        hardware_only=g.hardware_only,
        member_count=g.member_count,
        created_at=g.created_at,
    )


def twin(t: TwinRecord) -> m.Twin:
    return m.Twin(
        device_id=t.device_id,
        version=t.version,
        desired=t.desired,
        reported=t.reported,
        delta=compute_delta(t.desired, t.reported),
        desired_updated_at=t.desired_updated_at,
        reported_updated_at=t.reported_updated_at,
    )


def command(c: CommandRecord) -> m.Command:
    return m.Command(
        cmd_id=c.cmd_id,
        device_id=c.device_id,
        name=c.name,
        args=c.args,
        idempotency_key=c.idempotency_key,
        status=cast(Any, c.status),
        created_by=c.created_by,
        created_at=c.created_at,
        sent_at=c.sent_at,
        acked_at=c.acked_at,
        expires_at=c.expires_at,
        result=c.result,
        error=c.error,
    )


def timeline(e: TimelineRecord) -> m.TimelineEvent:
    return m.TimelineEvent(id=e.id, at=e.at, kind=cast(Any, e.kind), summary=e.summary, data=e.data)


def audit(a: AuditRecord) -> m.AuditEvent:
    body = json.loads(a.body)
    return m.AuditEvent(
        id=a.id,
        at=a.at,
        tenant_id=a.tenant_id,
        actor=m.AuditActor(type=cast(Any, a.actor_type), id=a.actor_id, name=a.actor_name),
        action=a.action,
        target=m.AuditTarget(type=a.target_type, id=a.target_id),
        outcome=cast(Any, a.outcome),
        ip=a.ip,
        request_id=a.request_id,
        details=body.get("details") or None,
    )


def user(u: UserRecord) -> m.User:
    return m.User(
        id=u.id, email=u.email, name=u.name, role=cast(Any, u.role), last_login_at=u.last_login_at
    )


def api_key(k: ApiKeyRecord) -> m.ApiKey:
    return m.ApiKey(
        id=k.id,
        name=k.name,
        prefix=k.prefix,
        role=cast(Any, k.role),
        scopes=k.scopes,
        created_at=k.created_at,
        last_used_at=k.last_used_at,
        expires_at=k.expires_at,
    )
