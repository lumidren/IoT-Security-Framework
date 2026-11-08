"""Tenant settings, groups, users, API keys, audit and fleet aggregation."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta

from .. import models as m
from .. import views
from ..auth import ALL_SCOPES, Principal, generate_api_key, role_at_most
from ..context import AppContext
from ..domain import ApiKeyRecord, AuditFilter, GroupRecord
from ..jsonutil import JsonObject, decode_cursor, encode_cursor
from ..problems import conflict, not_found, unprocessable
from ..repo.base import GENESIS_HASH, DuplicateError, chain_hash
from .common import clamp_limit

# ------------------------------------------------------------------------------------------------
# Tenant
# ------------------------------------------------------------------------------------------------


async def get_tenant(app: AppContext, p: Principal) -> m.Tenant:
    async with app.unit(p) as u:
        rec = await u.tx.get_tenant()
    if rec is None:
        raise not_found("tenant")
    return views.tenant(rec)


async def update_settings(app: AppContext, p: Principal, patch: m.TenantSettingsPatch) -> m.Tenant:
    changes = patch.model_dump(exclude_unset=True)
    async with app.unit(p) as u:
        rec = await u.tx.get_tenant()
        if rec is None:
            raise not_found("tenant")
        if changes.get("default_group") and await u.tx.get_group(changes["default_group"]) is None:
            raise unprocessable(f"group {changes['default_group']} does not exist")
        before = {k: rec.settings.get(k) for k in changes}
        rec.settings = {**rec.settings, **changes}
        m.TenantSettings(**rec.settings)  # validate the merged document
        await u.tx.save_tenant(rec)
        await u.audit("tenant.settings_updated", "tenant", rec.id, {"from": before, "to": changes})
        return views.tenant(rec)


# ------------------------------------------------------------------------------------------------
# Groups
# ------------------------------------------------------------------------------------------------


async def list_groups(app: AppContext, p: Principal) -> list[m.Group]:
    async with app.unit(p) as u:
        return [views.group(g) for g in await u.tx.list_groups()]


async def create_group(app: AppContext, p: Principal, body: m.CreateGroupInput) -> m.Group:
    async with app.unit(p) as u:
        rec = GroupRecord(
            tenant_id=u.tenant_id,
            slug=body.slug,
            name=body.name,
            created_at=u.now(),
            description=body.description,
            hardware_only=body.hardware_only,
        )
        try:
            await u.tx.insert_group(rec)
        except DuplicateError as exc:
            raise conflict(f"group {body.slug} already exists") from exc
        await u.audit("group.created", "group", body.slug, body.model_dump())
        return views.group(rec)


async def update_group(
    app: AppContext, p: Principal, slug: str, body: m.UpdateGroupInput
) -> m.Group:
    changes = body.model_dump(exclude_unset=True)
    async with app.unit(p) as u:
        rec = await u.tx.get_group(slug)
        if rec is None:
            raise not_found("group")
        if changes.get("hardware_only") and not rec.hardware_only:
            for device_id in await u.tx.group_device_ids(slug):
                dev = await u.tx.get_device(device_id)
                if dev is not None and dev.assurance_level == "software":
                    raise conflict("group has software-key members; remove them first")
        for key, value in changes.items():
            setattr(rec, key, value)
        await u.tx.save_group(rec)
        await u.audit("group.updated", "group", slug, changes)
        return views.group(rec)


async def delete_group(app: AppContext, p: Principal, slug: str) -> None:
    async with app.unit(p) as u:
        if not await u.tx.delete_group(slug):
            raise not_found("group")
        await u.audit("group.deleted", "group", slug)


async def set_members(
    app: AppContext, p: Principal, slug: str, body: m.GroupMembersInput
) -> m.GroupMembersResult:
    added: list[str] = []
    removed: list[str] = []
    rejected: list[m.RejectedMember] = []
    async with app.unit(p) as u:
        grp = await u.tx.get_group(slug)
        if grp is None:
            raise not_found("group")
        for device_id in dict.fromkeys(body.add):
            dev = await u.tx.get_device(device_id)
            if dev is None:
                rejected.append(m.RejectedMember(device_id=device_id, reason="unknown device"))
            elif dev.state == "decommissioned":
                rejected.append(m.RejectedMember(device_id=device_id, reason="decommissioned"))
            elif grp.hardware_only and dev.assurance_level == "software":
                rejected.append(
                    m.RejectedMember(device_id=device_id, reason="software keys not allowed")
                )
            elif await u.tx.add_member(slug, device_id):
                added.append(device_id)
        for device_id in dict.fromkeys(body.remove):
            if await u.tx.remove_member(slug, device_id):
                removed.append(device_id)
        await u.audit(
            "group.members_updated",
            "group",
            slug,
            {"added": added, "removed": removed, "rejected": [r.device_id for r in rejected]},
        )
    return m.GroupMembersResult(added=added, removed=removed, rejected=rejected)


# ------------------------------------------------------------------------------------------------
# Users and API keys
# ------------------------------------------------------------------------------------------------


async def list_users(app: AppContext, p: Principal) -> list[m.User]:
    async with app.unit(p) as u:
        return [views.user(x) for x in await u.tx.list_users()]


async def set_role(app: AppContext, p: Principal, user_id: str, role: str) -> m.User:
    async with app.unit(p) as u:
        rec = await u.tx.get_user(user_id)
        if rec is None:
            raise not_found("user")
        if rec.role == "owner" and role != "owner":
            owners = [x for x in await u.tx.list_users() if x.role == "owner"]
            if len(owners) <= 1:
                raise conflict("cannot demote the last owner of the tenant")
        before, rec.role = rec.role, role
        await u.tx.save_user(rec)
        await u.audit("user.role_changed", "user", user_id, {"from": before, "to": role})
    app.user_cache.pop((p.tenant_id, user_id), None)
    return views.user(rec)


async def list_api_keys(app: AppContext, p: Principal) -> list[m.ApiKey]:
    async with app.unit(p) as u:
        return [views.api_key(k) for k in await u.tx.list_api_keys()]


async def create_api_key(
    app: AppContext, p: Principal, body: m.CreateApiKeyInput
) -> m.CreatedApiKey:
    if not role_at_most(p.role, body.role):
        raise unprocessable(f"cannot create a key with role {body.role} above your own")
    scopes = sorted(set(body.scopes or []))
    unknown = [s for s in scopes if s not in ALL_SCOPES]
    if unknown:
        raise unprocessable(f"unknown scopes: {', '.join(unknown)}")
    if p.scopes is not None and not set(scopes or ALL_SCOPES) <= p.scopes:
        raise unprocessable("cannot grant scopes beyond the calling key's scopes")
    secret, prefix, digest = generate_api_key()
    async with app.unit(p) as u:
        if body.expires_at is not None and body.expires_at <= u.now():
            raise unprocessable("expires_at must be in the future")
        rec = ApiKeyRecord(
            tenant_id=u.tenant_id,
            id=str(uuid.uuid4()),
            name=body.name,
            prefix=prefix,
            key_hash=digest,
            role=body.role,
            created_at=u.now(),
            scopes=scopes,
            created_by=p.display,
            expires_at=body.expires_at,
        )
        await u.tx.insert_api_key(rec)
        await u.audit(
            "api_key.created",
            "api_key",
            rec.id,
            {"name": rec.name, "role": rec.role, "scopes": scopes, "prefix": prefix},
        )
    return m.CreatedApiKey(api_key=views.api_key(rec), secret=secret)


async def delete_api_key(app: AppContext, p: Principal, key_id: str) -> None:
    async with app.unit(p) as u:
        rec = await u.tx.get_api_key(key_id)
        if rec is None or rec.revoked_at is not None:
            raise not_found("api key")
        rec.revoked_at = u.now()
        await u.tx.save_api_key(rec)
        await u.audit("api_key.revoked", "api_key", key_id, {"prefix": rec.prefix})


# ------------------------------------------------------------------------------------------------
# Audit
# ------------------------------------------------------------------------------------------------


async def list_audit(
    app: AppContext, p: Principal, flt: AuditFilter, cursor: str | None, limit: int | None
) -> tuple[list[m.AuditEvent], str | None]:
    limit = clamp_limit(limit)
    before = decode_cursor(cursor, 1)
    async with app.unit(p) as u:
        rows = await u.tx.list_audit(flt, int(before[0]) if before else None, limit + 1)
    page = rows[:limit]
    return [views.audit(a) for a in page], encode_cursor([page[-1].seq]) if len(
        rows
    ) > limit else None


async def export_audit(
    app: AppContext, p: Principal, from_: datetime | None, to: datetime | None
) -> AsyncIterator[bytes]:
    async with app.unit(p) as u:
        await u.audit(
            "audit.exported",
            "audit",
            u.tenant_id,
            {"from": from_.isoformat() if from_ else None, "to": to.isoformat() if to else None},
        )

    async def stream() -> AsyncIterator[bytes]:
        after = 0
        while True:
            async with app.unit(p) as u:
                batch = await u.tx.audit_after(after, 500, from_, to)
            for rec in batch:
                yield views.audit(rec).model_dump_json().encode() + b"\n"
            if len(batch) < 500:
                return
            after = batch[-1].seq

    return stream()


async def verify_audit(app: AppContext, p: Principal) -> m.AuditVerifyResult:
    """Recompute the hash chain: seq continuity, prev links, hashes, body/column agreement, head."""
    import json

    checked = 0
    prev_hash, expected_seq = GENESIS_HASH, 1
    failure: tuple[int, str] | None = None
    async with app.unit(p) as u:
        head = await u.tx.audit_head()
        after = 0
        while failure is None:
            batch = await u.tx.audit_after(after, 1000)
            for rec in batch:
                checked += 1
                body = json.loads(rec.body)
                columns: JsonObject = {
                    "id": rec.id,
                    "seq": rec.seq,
                    "tenant_id": rec.tenant_id,
                    "actor": {"type": rec.actor_type, "id": rec.actor_id, "name": rec.actor_name},
                    "action": rec.action,
                    "target": {"type": rec.target_type, "id": rec.target_id},
                    "outcome": rec.outcome,
                    "ip": rec.ip,
                    "request_id": rec.request_id,
                }
                if rec.seq != expected_seq:
                    failure = (rec.seq, f"sequence gap: expected {expected_seq}")
                elif rec.prev_hash != prev_hash:
                    failure = (rec.seq, "prev_hash does not link to the previous event")
                elif chain_hash(rec.prev_hash, rec.body) != rec.hash:
                    failure = (rec.seq, "hash does not match the event content")
                elif any(body.get(k) != v for k, v in columns.items()) or (
                    body.get("at")
                    and datetime.fromisoformat(body["at"].replace("Z", "+00:00")) != rec.at
                ):
                    failure = (rec.seq, "stored columns differ from the hashed content")
                if failure:
                    break
                prev_hash, expected_seq = rec.hash, rec.seq + 1
            if len(batch) < 1000:
                break
            after = batch[-1].seq
        head_seq = head[0] if head else 0
        if (
            failure is None
            and head is not None
            and (head[0] != expected_seq - 1 or head[1] != prev_hash)
        ):
            failure = (expected_seq, "chain head does not match the last event (truncation?)")
        result = m.AuditVerifyResult(
            ok=failure is None,
            checked=checked,
            head_seq=head_seq,
            head_hash_hex=head[1].hex() if head else None,
            first_invalid_seq=failure[0] if failure else None,
            reason=failure[1] if failure else None,
        )
        await u.audit(
            "audit.verified",
            "audit",
            u.tenant_id,
            {"ok": result.ok, "checked": checked, "first_invalid_seq": result.first_invalid_seq},
            outcome="success" if result.ok else "failure",
        )
    return result


# ------------------------------------------------------------------------------------------------
# Fleet
# ------------------------------------------------------------------------------------------------


async def fleet_summary(app: AppContext, p: Principal) -> m.FleetSummary:
    async with app.unit(p) as u:
        agg = await u.tx.fleet_aggregate(u.now())
    by_state = {
        s: agg.by_state.get(s, 0)
        for s in ("manufactured", "provisioned", "active", "quarantined", "decommissioned")
    }
    return m.FleetSummary(
        devices_total=agg.devices_total,
        by_state=by_state,
        connected=agg.connected,
        disconnected=agg.devices_total - agg.connected,
        assurance=m.AssuranceCounts(hardware=agg.hardware, software=agg.software),
        certs=m.CertCounts(
            expiring_24h=agg.expiring_24h,
            expiring_7d=agg.expiring_7d,
            expired=agg.expired,
            revoked=agg.revoked,
        ),
        firmware=[m.FirmwareCount(version=v, count=n) for v, n in agg.firmware],
        alerts_open=m.AlertCounts(
            **{s: agg.alerts_open.get(s, 0) for s in ("critical", "high", "medium", "low")}
        ),
        campaigns_running=0,  # campaigns are owned by the OTA service
        map=[m.MapPoint(**pt) for pt in agg.map],
    )


def parse_window(window: str) -> timedelta:
    units = {"m": 60, "h": 3600, "d": 86400}
    if len(window) < 2 or window[-1] not in units or not window[:-1].isdigit():
        raise unprocessable("window must look like 15m, 1h or 1d")
    seconds = int(window[:-1]) * units[window[-1]]
    if not 60 <= seconds <= 7 * 86400:
        raise unprocessable("window must be between 1m and 7d")
    return timedelta(seconds=seconds)


async def fleet_health(app: AppContext, p: Principal, window: str) -> m.FleetHealth:
    span = parse_window(window)
    async with app.unit(p) as u:
        stats = await u.tx.ingest_stats_since((u.now() - span).replace(second=0, microsecond=0))
    seconds = span.total_seconds()
    return m.FleetHealth(
        connect_rate=round(stats.connects / (seconds / 60), 4),
        auth_failures=float(stats.auth_failures),
        msgs_per_s=round(stats.messages / seconds, 4),
        replay_rejected=float(stats.replay_rejected),
        p99_ingest_ms=round(stats.p99_ms, 2),
    )


async def flush_health(app: AppContext, p: Principal) -> int:
    pending = app.health.drain()
    for (tenant_id, minute), stats in pending.items():
        async with app.unit(p, tenant_id) as u:
            await u.tx.add_ingest_stats(minute, stats)
    return len(pending)


async def refresh_device_gauge(app: AppContext, p: Principal) -> dict[str, int]:
    totals: dict[str, int] = dict.fromkeys(
        ("manufactured", "provisioned", "active", "quarantined", "decommissioned"), 0
    )
    connected = 0
    for tenant_id in await app.repo.list_tenant_ids():
        async with app.unit(p, tenant_id) as u:
            agg = await u.tx.fleet_aggregate(u.now())
        connected += agg.connected
        for state, n in agg.by_state.items():
            totals[state] = totals.get(state, 0) + n
    for state, n in totals.items():
        app.metrics.devices_total.labels(state=state).set(n)
    app.metrics.connected_devices.set(connected)
    return totals
