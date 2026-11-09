"""Devices: CRUD, listing, timeline, telemetry, certificates, lifecycle orchestration."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any

import structlog
from ironmesh_wire import ids
from ironmesh_wire.ids import TopicClass

from .. import models as m
from .. import views
from ..auth import Principal
from ..context import AppContext, Unit
from ..crypto import PKI_TENANT_POLICY
from ..domain import (
    TELEMETRY_METRICS,
    ActionRecord,
    CertificateRecord,
    DeviceFilter,
    DeviceRecord,
    TwinRecord,
)
from ..integrations.bus import TOPIC_COMMANDS
from ..integrations.services import UpstreamError, normalize_serial
from ..jsonutil import JsonObject, decode_cursor, encode_cursor
from ..lifecycle import (
    ENROLLABLE,
    DeviceState,
    TransitionError,
    check_transition,
    timestamp_field,
)
from ..problems import ProblemError, conflict, not_found, unprocessable
from ..repo.base import DuplicateError
from .common import (
    add_timeline,
    clamp_limit,
    detail,
    device_topics,
    require_device,
    summary,
    topic,
)

log = structlog.get_logger("app.devices")

MAX_TELEMETRY_POINTS = 2000
ACTION_RETRY_MAX = 20
PKI_REVOKE_ALL = "pki_revoke_all"
PKI_RELEASE = "pki_release"


# ------------------------------------------------------------------------------------------------
# Queries
# ------------------------------------------------------------------------------------------------


async def list_devices(
    app: AppContext, p: Principal, flt: DeviceFilter, cursor: str | None, limit: int | None
) -> tuple[list[m.DeviceSummary], str | None]:
    limit = clamp_limit(limit)
    after = decode_cursor(cursor, 1)
    async with app.unit(p) as u:
        rows = await u.tx.list_devices(flt, str(after[0]) if after else None, limit + 1)
        page, more = rows[:limit], len(rows) > limit
        ids_ = [d.id for d in page]
        groups = await u.tx.device_groups(ids_)
        alerts = await u.tx.open_alert_counts(ids_)
        items = [views.device_summary(d, groups[d.id], alerts[d.id], u.now()) for d in page]
    return items, encode_cursor([page[-1].id]) if more and page else None


async def get_device(app: AppContext, p: Principal, device_id: str) -> m.DeviceDetail:
    async with app.unit(p) as u:
        return await detail(u, await require_device(u, device_id))


async def timeline(
    app: AppContext,
    p: Principal,
    device_id: str,
    from_: datetime | None,
    to: datetime | None,
    kinds: list[str] | None,
    cursor: str | None,
    limit: int | None,
) -> tuple[list[m.TimelineEvent], str | None]:
    limit = clamp_limit(limit)
    after = decode_cursor(cursor, 2)
    after_key = (datetime.fromisoformat(str(after[0])), str(after[1])) if after else None
    async with app.unit(p) as u:
        await require_device(u, device_id)
        rows = await u.tx.list_timeline(device_id, from_, to, kinds, after_key, limit + 1)
    page = rows[:limit]
    nxt = encode_cursor([page[-1].at.isoformat(), page[-1].id]) if len(rows) > limit else None
    return [views.timeline(e) for e in page], nxt


def parse_step(step: str) -> int:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(step) < 2 or step[-1] not in units or not step[:-1].isdigit():
        raise unprocessable("step must look like 60s, 5m, 1h")
    seconds = int(step[:-1]) * units[step[-1]]
    if not 1 <= seconds <= 86400:
        raise unprocessable("step must be between 1s and 1d")
    return seconds


async def telemetry(
    app: AppContext,
    p: Principal,
    device_id: str,
    from_: datetime | None,
    to: datetime | None,
    metrics: list[str] | None,
    step: str,
) -> m.TelemetrySeries:
    wanted = metrics or list(TELEMETRY_METRICS)
    unknown = [x for x in wanted if x not in TELEMETRY_METRICS]
    if unknown:
        raise unprocessable(f"unknown metrics: {', '.join(unknown)}")
    end = to or app.clock()
    start = from_ or end - timedelta(hours=1)
    if start >= end:
        raise unprocessable("from must be before to")
    step_s = parse_step(step)
    span = (end - start).total_seconds()
    if span / step_s > MAX_TELEMETRY_POINTS:  # widen the step to honour the 2 000-point cap
        step_s = int(-(-span // MAX_TELEMETRY_POINTS))
    async with app.unit(p) as u:
        await require_device(u, device_id)
        buckets = await u.tx.telemetry_buckets(device_id, start, end, wanted, step_s)
    return m.TelemetrySeries(
        series=[
            m.TelemetrySeriesItem(metric=x, points=list(buckets.get(x, []))[:MAX_TELEMETRY_POINTS])
            for x in wanted
        ]
    )


async def certificates(app: AppContext, p: Principal, device_id: str) -> list[m.Certificate]:
    async with app.unit(p) as u:
        await require_device(u, device_id)
        local = await u.tx.list_certificates(device_id)
    try:
        remote = await app.pki.device_certificates(device_id)
    except UpstreamError as exc:
        log.warning("pki_unavailable_using_local_certificates", device_id=device_id, error=str(exc))
        return [views.certificate(c) for c in local]
    return [
        m.Certificate(
            serial_hex=c.serial_hex,
            not_before=c.not_before,
            not_after=c.not_after,
            revoked_at=c.revoked_at,
            revocation_reason=c.revocation_reason,
            issuer=c.issuer,
        )
        for c in remote
        if c.tenant_id in ("", p.tenant_id)
    ]


# ------------------------------------------------------------------------------------------------
# Mutations
# ------------------------------------------------------------------------------------------------


async def create_device(app: AppContext, p: Principal, body: m.CreateDeviceInput) -> m.DeviceDetail:
    device_id = body.id or "dev-" + secrets.token_hex(8)
    async with app.unit(p) as u:
        tenant = await u.tx.get_tenant()
        if tenant is None:
            raise not_found("tenant")
        if body.se_type == "software" and not tenant.settings.get("allow_software_keys", False):
            log.info("software_key_device_created_while_disallowed", device_id=device_id)
        now = u.now()
        dev = DeviceRecord(
            tenant_id=u.tenant_id,
            id=device_id,
            product=body.product,
            hw_revision=body.hw_revision,
            state=DeviceState.MANUFACTURED.value,
            created_at=now,
            se_type=body.se_type,
            bootstrap_serial_hex=normalize_serial(body.bootstrap_serial_hex),
            tags=dict(body.tags or {}),
        )
        try:
            await u.tx.insert_device(dev)
        except DuplicateError as exc:
            raise conflict(f"device {device_id} already exists") from exc
        await u.tx.save_twin(TwinRecord(tenant_id=u.tenant_id, device_id=device_id))
        default_group = tenant.settings.get("default_group")
        if default_group and await u.tx.get_group(str(default_group)) is not None:
            await u.tx.add_member(str(default_group), device_id)
        await add_timeline(u, device_id, "lifecycle", "Device manufactured", {"state": dev.state})
        await u.audit(
            "device.created",
            "device",
            device_id,
            {"product": dev.product, "hw_revision": dev.hw_revision, "se_type": dev.se_type},
        )
        out = await detail(u, dev)
        u.emit("provisioning.updated", {"device_id": device_id, "state": dev.state}, {"fleet"})
        return out


async def update_device(
    app: AppContext, p: Principal, device_id: str, body: m.UpdateDeviceInput
) -> m.DeviceDetail:
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state == DeviceState.DECOMMISSIONED:
            raise conflict("device is decommissioned")
        changes: JsonObject = {}
        if body.tags is not None:
            changes["tags"] = {"from": dev.tags, "to": body.tags}
            dev.tags = dict(body.tags)
            await u.tx.save_device(dev)
        if body.groups is not None:
            current = set((await u.tx.device_groups([dev.id]))[dev.id])
            target = set(body.groups)
            for slug in sorted(target - current):
                grp = await u.tx.get_group(slug)
                if grp is None:
                    raise unprocessable(f"group {slug} does not exist")
                if grp.hardware_only and dev.assurance_level == "software":
                    raise unprocessable(f"group {slug} accepts hardware-backed devices only")
                await u.tx.add_member(slug, dev.id)
            for slug in sorted(current - target):
                await u.tx.remove_member(slug, dev.id)
            changes["groups"] = {
                "added": sorted(target - current),
                "removed": sorted(current - target),
            }
        await u.audit("device.updated", "device", dev.id, changes)
        u.emit(
            "device.state_changed", {"device_id": dev.id, "state": dev.state}, device_topics(dev.id)
        )
        return await detail(u, dev)


async def transition(
    u: Unit, dev: DeviceRecord, target: DeviceState, reason: str | None = None
) -> DeviceState:
    """Validate and apply a lifecycle transition (timestamps, timeline, audit, WS, metrics)."""
    current = DeviceState(dev.state)
    check_transition(current, target)
    dev.state = target.value
    stamp = timestamp_field(target)
    if stamp is not None:
        setattr(dev, stamp, u.now())
    await u.tx.save_device(dev)
    data: JsonObject = {"from": current.value, "to": target.value}
    if reason:
        data["reason"] = reason
    await add_timeline(u, dev.id, "lifecycle", f"{current.value} -> {target.value}", data)
    await u.audit("device.lifecycle", "device", dev.id, data)
    u.app.metrics.lifecycle_transitions.labels(
        from_state=current.value, to_state=target.value
    ).inc()
    u.emit(
        "device.state_changed",
        {"device_id": dev.id, "state": target.value, "previous_state": current.value},
        device_topics(dev.id),
    )
    return current


async def _revoke_credentials(
    app: AppContext, p: Principal, tenant_id: str, device_id: str, reason: str, cause: str
) -> None:
    """PKI revoke-all (which drives the policy cache deny and the EMQX kick), with retries.

    On final failure a compensation is recorded: an outbox action retried by the background job,
    and an audit event with outcome ``failure`` so the gap is visible.
    """
    try:
        count = await app.retry(PKI_REVOKE_ALL, lambda: app.pki.revoke_all(device_id, reason))
    except Exception as exc:
        async with app.unit(p, tenant_id) as u:
            now = u.now()
            action = ActionRecord(
                tenant_id=tenant_id,
                id=str(uuid.uuid4()),
                kind=PKI_REVOKE_ALL,
                device_id=device_id,
                payload={"reason": reason, "cause": cause},
                created_at=now,
                next_attempt_at=now + timedelta(seconds=30),
                attempts=app.settings.orchestration_attempts,
                last_error=str(exc),
            )
            await u.tx.insert_action(action)
            await u.audit(
                "device.credentials_revoke_failed",
                "device",
                device_id,
                {
                    "cause": cause,
                    "error": str(exc),
                    "compensation": "retry_scheduled",
                    "action_id": action.id,
                },
                outcome="failure",
            )
        # Containment while the revocation is pending: kick the live session directly.
        try:
            kicked = await app.emqx.kick(device_id)
            outcome, details = "success", {"kicked": kicked, "cause": cause}
        except Exception as kick_exc:
            outcome, details = "failure", {"error": str(kick_exc), "cause": cause}
        async with app.unit(p, tenant_id) as u:
            await u.audit("device.session_kick", "device", device_id, details, outcome=outcome)
        return
    async with app.unit(p, tenant_id) as u:
        await _record_revocation(u, device_id, reason, count, cause)


async def _record_revocation(u: Unit, device_id: str, reason: str, count: int, cause: str) -> None:
    now = u.now()
    await u.tx.mark_certificates_revoked(device_id, now, reason)
    dev = await u.tx.get_device(device_id, for_update=True)
    if dev is not None and dev.cert_serial_hex:
        dev.cert_revoked = True
        await u.tx.save_device(dev)
    await add_timeline(
        u, device_id, "revoke", f"{count} certificate(s) revoked", {"reason": reason}
    )
    await u.audit(
        "device.credentials_revoked", "device", device_id, {"count": count, "cause": cause}
    )


async def _cancel_pending_releases(u: Unit, device_id: str, cause: str) -> None:
    """Drop queued PKI releases of a device that is being quarantined or decommissioned again, so
    a late release can never lift the new device-level deny."""
    for action in await u.tx.pending_device_actions(device_id, (PKI_RELEASE,)):
        action.status = "cancelled"
        await u.tx.save_action(action)
        await u.audit(
            f"action.{PKI_RELEASE}.cancelled",
            "device",
            device_id,
            {"action_id": action.id, "cause": cause},
        )


async def quarantine(
    app: AppContext,
    p: Principal,
    device_id: str,
    reason: str,
    *,
    tenant_id: str | None = None,
    alert_id: str | None = None,
) -> m.DeviceDetail:
    tenant = tenant_id or p.tenant_id
    async with app.unit(p, tenant) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state == DeviceState.QUARANTINED:
            await u.audit(
                "device.quarantine",
                "device",
                dev.id,
                {"reason": reason, "noop": True, "alert_id": alert_id},
            )
            return await detail(u, dev)
        if dev.state == DeviceState.DECOMMISSIONED:
            raise TransitionError(DeviceState.DECOMMISSIONED, DeviceState.QUARANTINED)
        dev.quarantine_reason = reason
        await transition(u, dev, DeviceState.QUARANTINED, reason)
        await _cancel_pending_releases(u, dev.id, "quarantine")
        await u.audit(
            "device.quarantine", "device", dev.id, {"reason": reason, "alert_id": alert_id}
        )
    await _revoke_credentials(app, p, tenant, device_id, reason, "quarantine")
    async with app.unit(p, tenant) as u:
        return await detail(u, await require_device(u, device_id))


async def _complete_pending_revocations(
    app: AppContext, p: Principal, tenant_id: str, device_id: str, pending: list[ActionRecord]
) -> None:
    """Finish the quarantine's revoke-all before a release (its deny must predate the release).

    Raises 503 when the PKI still cannot revoke: releasing first would let the queued revoke-all
    deny (and revoke the re-enrolled certificate of) the released device later.
    """
    reason = str(pending[0].payload.get("reason", "retry"))
    try:
        count = await app.retry(PKI_REVOKE_ALL, lambda: app.pki.revoke_all(device_id, reason))
    except Exception as exc:
        async with app.unit(p, tenant_id) as u:
            await u.audit(
                "device.release",
                "device",
                device_id,
                {"error": str(exc), "blocked_by": [a.id for a in pending]},
                outcome="failure",
            )
        raise ProblemError(
            503,
            "the quarantine's certificate revocation is still pending at the PKI; "
            "retry the release later",
            headers={"Retry-After": "30"},
        ) from exc
    async with app.unit(p, tenant_id) as u:
        for action in pending:
            action.status = "done"
            action.attempts += 1
            await u.tx.save_action(action)
            await u.audit(
                f"action.{PKI_REVOKE_ALL}.completed",
                "device",
                device_id,
                {"action_id": action.id, "attempts": action.attempts, "trigger": "release"},
            )
        await _record_revocation(u, device_id, reason, count, str(pending[0].payload.get("cause")))


async def _pki_release(u: Unit, device_id: str, note: str) -> str:
    """PKI ``device_release`` (lifts the policy service's device-level deny), with retries.

    Called while the device row is locked, so a concurrent quarantine waits and its revoke-all
    (a newer deny) is always issued after this release. On final failure the release is queued in
    the action outbox (``pki_release``) and audited with outcome ``failure``; the device stays
    refused at CONNECT until the retry succeeds (fail closed).
    """
    app = u.app
    try:
        event_id = await app.retry(
            PKI_RELEASE, lambda: app.pki.release(device_id, u.tenant_id, note)
        )
    except Exception as exc:
        now = u.now()
        action = ActionRecord(
            tenant_id=u.tenant_id,
            id=str(uuid.uuid4()),
            kind=PKI_RELEASE,
            device_id=device_id,
            payload={"note": note},
            created_at=now,
            next_attempt_at=now + timedelta(seconds=30),
            attempts=app.settings.orchestration_attempts,
            last_error=str(exc),
        )
        await u.tx.insert_action(action)
        await u.audit(
            "device.pki_release_failed",
            "device",
            device_id,
            {"error": str(exc), "compensation": "retry_scheduled", "action_id": action.id},
            outcome="failure",
        )
        return "pending"
    await u.audit("device.pki_released", "device", device_id, {"event_id": event_id})
    return "done"


async def release(app: AppContext, p: Principal, device_id: str, note: str) -> m.DeviceDetail:
    """Quarantined -> active. Revoked certificates stay revoked (the device must re-enroll); the
    PKI ``device_release`` lifts the device-level deny the quarantine installed in policy."""
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state != DeviceState.QUARANTINED:
            raise TransitionError(DeviceState(dev.state), DeviceState.ACTIVE)
        pending = await u.tx.pending_device_actions(device_id, (PKI_REVOKE_ALL,))
    if pending:
        await _complete_pending_revocations(app, p, p.tenant_id, device_id, pending)
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state != DeviceState.QUARANTINED:  # changed while the revocation completed
            raise TransitionError(DeviceState(dev.state), DeviceState.ACTIVE)
        pki_release = await _pki_release(u, dev.id, note)
        dev.quarantine_reason = None
        await transition(u, dev, DeviceState.ACTIVE, note or None)
        await u.audit(
            "device.release",
            "device",
            dev.id,
            {"note": note, "reenroll_required": True, "pki_release": pki_release},
        )
        return await detail(u, dev)


async def decommission(
    app: AppContext, p: Principal, device_id: str, reason: str
) -> m.DeviceDetail:
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        await transition(u, dev, DeviceState.DECOMMISSIONED, reason)
        await _cancel_pending_releases(u, dev.id, "decommission")
        now = u.now()
        for status in ("pending", "sent"):
            for cmd in await u.tx.list_commands(dev.id, status, None, 1000):
                cmd.status, cmd.error, cmd.acked_at = "rejected", "device decommissioned", now
                await u.tx.save_command(cmd)
                u.publish(
                    TOPIC_COMMANDS,
                    f"{u.tenant_id}/{dev.id}",
                    {"cmd_id": cmd.cmd_id, "device_id": dev.id, "status": cmd.status, "at": now},
                )
        await u.audit("device.decommission", "device", dev.id, {"reason": reason})
    await _revoke_credentials(app, p, p.tenant_id, device_id, reason, "decommission")
    for cls in (TopicClass.SHADOW_DESIRED, TopicClass.CONFIG, TopicClass.OTA_NOTIFY):
        try:  # an empty retained publish clears the retained downlink state on the broker
            await app.mqtt.publish(topic(p.tenant_id, device_id, cls), b"", qos=1, retain=True)
        except Exception as exc:
            log.warning(
                "retained_clear_failed", device_id=device_id, topic=cls.value, error=str(exc)
            )
    async with app.unit(p) as u:
        return await detail(u, await require_device(u, device_id))


# ------------------------------------------------------------------------------------------------
# Provisioning queue
# ------------------------------------------------------------------------------------------------


async def list_provisioning(
    app: AppContext, p: Principal, state: str | None, cursor: str | None, limit: int | None
) -> tuple[list[m.ProvisioningItem], str | None]:
    if state is not None and state not in ("manufactured", "provisioned", "failed"):
        raise unprocessable("state must be manufactured, provisioned or failed")
    limit = clamp_limit(limit)
    after = decode_cursor(cursor, 1)
    async with app.unit(p) as u:
        rows = await u.tx.list_provisioning(state, str(after[0]) if after else None, limit + 1)
    page = rows[:limit]
    items = [
        m.ProvisioningItem(
            device_id=r.device.id,
            product=r.device.product,
            se_type=r.device.se_type,
            state=r.state,
            bootstrap_serial_hex=r.device.bootstrap_serial_hex,
            created_at=r.device.created_at,
            last_attempt_at=r.device.last_attempt_at,
            last_error=r.device.last_error,
            attempts=r.device.provisioning_attempts,
        )
        for r in page
    ]
    return items, encode_cursor([page[-1].device.id]) if len(rows) > limit else None


async def approve(app: AppContext, p: Principal, device_id: str) -> m.DeviceSummary:
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state != DeviceState.PROVISIONED:
            raise conflict(f"device is {dev.state}, only provisioned devices can be approved")
        dev.provisioning_status = "done"
        await transition(u, dev, DeviceState.ACTIVE, "manual approval")
        await u.audit("provisioning.approve", "device", dev.id)
        u.emit("provisioning.updated", {"device_id": dev.id, "state": dev.state}, {"fleet"})
        return await summary(u, dev)


async def reject(app: AppContext, p: Principal, device_id: str, reason: str) -> m.DeviceSummary:
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state not in (DeviceState.MANUFACTURED, DeviceState.PROVISIONED):
            raise conflict(f"device is {dev.state}, not in the provisioning queue")
        dev.provisioning_status = "failed"
        dev.last_error = reason
        dev.quarantine_reason = f"provisioning rejected: {reason}"
        await transition(u, dev, DeviceState.QUARANTINED, dev.quarantine_reason)
        await u.audit("provisioning.reject", "device", dev.id, {"reason": reason})
        u.emit("provisioning.updated", {"device_id": dev.id, "state": "failed"}, {"fleet"})
    await _revoke_credentials(app, p, p.tenant_id, device_id, reason, "provisioning_reject")
    async with app.unit(p) as u:
        return await summary(u, await require_device(u, device_id))


# ------------------------------------------------------------------------------------------------
# Internal (PKI / policy / anomaly)
# ------------------------------------------------------------------------------------------------


async def resolve_tenant(app: AppContext, device_id: str) -> str:
    if not ids.is_device_id(device_id):
        raise not_found("device")
    tenant = await app.repo.resolve_device_tenant(device_id)
    if tenant is None:
        raise not_found("device")
    return tenant


async def lifecycle(app: AppContext, p: Principal, device_id: str) -> m.Lifecycle:
    """``GET /internal/v1/devices/{id}/lifecycle`` (policy, anomaly)."""
    tenant = await resolve_tenant(app, device_id)
    async with app.unit(p, tenant) as u:
        dev = await require_device(u, device_id)
    return m.Lifecycle(
        device_id=dev.id,
        tenant_id=dev.tenant_id,
        state=dev.state,
        assurance_level=dev.assurance_level,
        product=dev.product,
    )


async def enrolled(
    app: AppContext, p: Principal, device_id: str, body: m.EnrolledInput
) -> m.DeviceDetail:
    tenant = await resolve_tenant(app, device_id)
    serial = normalize_serial(body.serial_hex)
    async with app.unit(p, tenant) as u:
        dev = await require_device(u, device_id, for_update=True)
        state = DeviceState(dev.state)
        now = u.now()
        dev.provisioning_attempts += 1
        dev.last_attempt_at = now
        if state not in ENROLLABLE:
            dev.last_error = f"enrollment refused in state {state.value}"
            await u.tx.save_device(dev)
            await u.audit(
                "device.enrolled",
                "device",
                dev.id,
                {"serial_hex": serial, "state": state.value},
                outcome="failure",
            )
            raise conflict(f"device is {state.value}; enrollment is not permitted")
        tenant_rec = await u.tx.get_tenant()
        settings: dict[str, Any] = tenant_rec.settings if tenant_rec else {}
        renewal = state == DeviceState.ACTIVE
        await u.tx.upsert_certificate(
            CertificateRecord(
                tenant_id=u.tenant_id,
                serial_hex=serial,
                device_id=dev.id,
                not_before=body.not_before,
                not_after=body.not_after,
                issuer=body.issuer,
                created_at=now,
                assurance_level=body.assurance_level,
            )
        )
        dev.cert_serial_hex, dev.cert_not_after, dev.cert_revoked = serial, body.not_after, False
        dev.se_type, dev.assurance_level = body.se_type, body.assurance_level
        if body.fw_version:
            dev.fw_version = body.fw_version
        if body.fw_hash_hex:
            dev.fw_hash_hex = body.fw_hash_hex
        dev.last_error = None
        await u.tx.save_device(dev)
        # A retained config is HPKE-wrapped to the certificate key that was current when it was
        # published. Re-wrap it to the new key (durably, through the action outbox) so a
        # superseded or leaked key cannot decrypt the configuration the broker keeps retained.
        stored_config = await u.tx.get_config(dev.id)
        if stored_config is not None:
            await u.tx.insert_action(
                ActionRecord(
                    tenant_id=u.tenant_id,
                    id=str(uuid.uuid4()),
                    kind="publish_config",
                    device_id=dev.id,
                    payload={"version": stored_config.version, "cause": "rewrap_on_enroll"},
                    created_at=now,
                    next_attempt_at=now,
                    last_error=None,
                )
            )
        kind = "renew" if renewal else "enroll"
        await add_timeline(
            u,
            dev.id,
            kind,
            f"Certificate {serial} issued",
            {
                "serial_hex": serial,
                "not_after": body.not_after.isoformat(),
                "assurance_level": body.assurance_level,
            },
        )
        await u.audit(
            "device.enrolled",
            "device",
            dev.id,
            {"serial_hex": serial, "assurance_level": body.assurance_level, "renewal": renewal},
        )
        if state == DeviceState.MANUFACTURED:
            await transition(u, dev, DeviceState.PROVISIONED, "enrolled")
            state = DeviceState.PROVISIONED
        if state == DeviceState.PROVISIONED and not settings.get("require_manual_approval"):
            dev.provisioning_status = "done"
            await transition(u, dev, DeviceState.ACTIVE, "auto-activated after enrollment")
        u.emit("provisioning.updated", {"device_id": dev.id, "state": dev.state}, {"fleet"})
        app.pki.invalidate(dev.id)
        return await detail(u, dev)


async def record_assurance(
    app: AppContext, p: Principal, tenant_id: str, device_id: str, assurance: str
) -> None:
    _check_tenant_uuid(tenant_id)
    async with app.unit(p, tenant_id) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.assurance_level != assurance:
            dev.assurance_level = assurance
            await u.tx.save_device(dev)
            await u.audit("device.assurance", "device", dev.id, {"assurance_level": assurance})


def _check_tenant_uuid(tenant_id: str) -> None:
    try:
        uuid.UUID(tenant_id)
    except ValueError as exc:
        raise not_found("device") from exc


async def pki_device(app: AppContext, p: Principal, tenant_id: str, device_id: str) -> m.PkiDevice:
    _check_tenant_uuid(tenant_id)
    async with app.unit(p, tenant_id) as u:
        dev = await require_device(u, device_id)
    return m.PkiDevice(
        device_id=dev.id,
        tenant_id=dev.tenant_id,
        state=dev.state,
        assurance_level=dev.assurance_level,
        se_type=dev.se_type,
        bootstrap_serial=dev.bootstrap_serial_hex,
    )


# ------------------------------------------------------------------------------------------------
# Outbox retries (background job)
# ------------------------------------------------------------------------------------------------


async def _retry_pki_release(
    app: AppContext, p: Principal, tenant_id: str, action: ActionRecord
) -> bool:
    """One outbox retry of a queued PKI release, with the device row locked (see ``_pki_release``).

    Returns ``False`` when the release no longer applies (cancelled by a new quarantine or
    decommission, or the device is not ``active``); raises when the PKI call fails.
    """
    async with app.unit(p, tenant_id) as u:
        dev = await u.tx.get_device(action.device_id, for_update=True)
        pending = await u.tx.pending_device_actions(action.device_id, (PKI_RELEASE,))
        if action.id not in {a.id for a in pending}:
            return False
        if dev is None or dev.state != DeviceState.ACTIVE:
            action.status = "cancelled"
            await u.tx.save_action(action)
            await u.audit(
                f"action.{PKI_RELEASE}.cancelled",
                "device",
                action.device_id,
                {"action_id": action.id, "cause": f"state {dev.state if dev else 'missing'}"},
            )
            return False
        event_id = await app.pki.release(
            action.device_id, tenant_id, str(action.payload.get("note", ""))
        )
        await u.audit(
            "device.pki_released",
            "device",
            action.device_id,
            {"event_id": event_id, "action_id": action.id},
        )
    return True


async def run_pending_actions(
    app: AppContext, p: Principal, tenant_ids: list[str] | None = None
) -> int:
    """Retry due outbox actions for every tenant (or ``tenant_ids``); returns how many completed."""
    from . import config as config_svc
    from . import tenant_policy
    from . import twin as twin_svc

    done = 0
    for tenant_id in tenant_ids or await app.repo.list_tenant_ids():
        async with app.unit(p, tenant_id) as u:
            due = await u.tx.due_actions(u.now(), 50)
        for action in due:
            # tenant-level actions (PKI policy) carry no device id
            target = ("device", action.device_id) if action.device_id else ("tenant", tenant_id)
            try:
                if action.kind == PKI_REVOKE_ALL:
                    reason = str(action.payload.get("reason", "retry"))
                    count = await app.pki.revoke_all(action.device_id, reason)
                    async with app.unit(p, tenant_id) as u:
                        await _record_revocation(
                            u, action.device_id, reason, count, str(action.payload.get("cause"))
                        )
                elif action.kind == PKI_RELEASE:
                    if not await _retry_pki_release(app, p, tenant_id, action):
                        continue  # cancelled: the device was quarantined or decommissioned again
                elif action.kind == "publish_shadow":
                    await twin_svc.republish(app, p, tenant_id, action.device_id)
                elif action.kind == "publish_config":
                    await config_svc.republish(app, p, tenant_id, action.device_id)
                elif action.kind == PKI_TENANT_POLICY:
                    await tenant_policy.push(app, p, tenant_id)
                else:
                    raise ProblemError(500, f"unknown action kind {action.kind}")
            except Exception as exc:
                async with app.unit(p, tenant_id) as u:
                    action.attempts += 1
                    action.last_error = str(exc)
                    delay = min(3600, 30 * 2 ** min(action.attempts, 10))
                    action.next_attempt_at = u.now() + timedelta(seconds=delay)
                    if action.attempts >= ACTION_RETRY_MAX:
                        action.status = "failed"
                        await u.audit(
                            f"action.{action.kind}.abandoned",
                            *target,
                            {"action_id": action.id, "error": str(exc)},
                            outcome="failure",
                        )
                    await u.tx.save_action(action)
                continue
            async with app.unit(p, tenant_id) as u:
                action.status = "done"
                action.attempts += 1
                await u.tx.save_action(action)
                await u.audit(
                    f"action.{action.kind}.completed",
                    *target,
                    {"action_id": action.id, "attempts": action.attempts},
                )
            done += 1
    return done
