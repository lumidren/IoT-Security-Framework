"""PostgreSQL implementation (SQLAlchemy async Core + asyncpg) with row-level security.

Every :meth:`SqlDatabase.tenant` transaction starts with
``SELECT set_config('ironmesh.tenant_id', <tenant>, true)`` - the function form of
``SET LOCAL ironmesh.tenant_id`` (it accepts a bind parameter, so no SQL is ever formatted). The
setting is transaction-local, so a pooled connection can never leak a tenant into the next
transaction. The service connects as ``ota_app``, which owns nothing and therefore cannot bypass
the ``FORCE ROW LEVEL SECURITY`` policies created by the migration.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Collection, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, bindparam, delete, func, or_, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from ..domain import (
    Actor,
    AuditEvent,
    Campaign,
    CampaignDevice,
    CampaignState,
    DeltaArtifact,
    DeviceState,
    Firmware,
    IdempotencyRecord,
    Page,
    ScheduledCampaign,
    Severity,
    Stage,
    Target,
    utcnow,
)
from ..pagination import decode_cursor, decode_time_cursor, encode_cursor, time_cursor
from . import tables as t
from .base import RepositoryConflict

SET_TENANT = text("SELECT set_config('ironmesh.tenant_id', :tenant, true)")


def _firmware(row: RowMapping) -> Firmware:
    return Firmware(
        id=row["id"],
        tenant_id=row["tenant_id"],
        product=row["product"],
        version=row["version"],
        version_code=row["version_code"],
        sha256=bytes(row["sha256"]),
        size=row["size"],
        min_version_code=row["min_version_code"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        manifest=bytes(row["manifest"]),
        signed_manifest=bytes(row["signed_manifest"]),
        signing_key_id=row["signing_key_id"],
        pq_signed=row["pq_signed"],
        notes=row["notes"],
        severity=Severity(row["severity"]),
        image_key=row["image_key"],
        manifest_key=row["manifest_key"],
        signature_key=row["signature_key"],
        rollback_of=row["rollback_of"],
    )


def _campaign(row: RowMapping) -> Campaign:
    return Campaign(
        id=row["id"],
        tenant_id=row["tenant_id"],
        name=row["name"],
        firmware_id=row["firmware_id"],
        target=Target.from_json(row["target"]),
        delta=row["delta"],
        severity=Severity(row["severity"]),
        stages=[Stage.from_json(s) for s in row["stages"]],
        current_stage=row["current_stage"],
        state=CampaignState(row["state"]),
        halt_reason=row["halt_reason"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        parent_campaign_id=row["parent_campaign_id"],
        requires_approval=row["requires_approval"],
        approved_by=row["approved_by"],
        approved_at=row["approved_at"],
        updated_at=row["updated_at"],
    )


def _campaign_values(c: Campaign) -> dict[str, Any]:
    return {
        "id": c.id,
        "tenant_id": c.tenant_id,
        "name": c.name,
        "firmware_id": c.firmware_id,
        "target": c.target.to_json(),
        "delta": c.delta,
        "severity": c.severity.value,
        "stages": [s.to_json() for s in c.stages],
        "current_stage": c.current_stage,
        "state": c.state.value,
        "halt_reason": c.halt_reason,
        "created_by": c.created_by,
        "created_at": c.created_at,
        "started_at": c.started_at,
        "finished_at": c.finished_at,
        "parent_campaign_id": c.parent_campaign_id,
        "requires_approval": c.requires_approval,
        "approved_by": c.approved_by,
        "approved_at": c.approved_at,
        "updated_at": c.updated_at,
    }


def _device(row: RowMapping) -> CampaignDevice:
    def opt(name: str) -> bytes | None:
        value = row[name]
        return None if value is None else bytes(value)

    return CampaignDevice(
        campaign_id=row["campaign_id"],
        tenant_id=row["tenant_id"],
        device_id=row["device_id"],
        stage_index=row["stage_index"],
        rank=row["rank"],
        state=DeviceState(row["state"]),
        progress_pct=row["progress_pct"],
        error=row["error"],
        notified_at=row["notified_at"],
        updated_at=row["updated_at"],
        fw_hash=opt("fw_hash"),
        from_fw_hash=opt("from_fw_hash"),
        delta_from=opt("delta_from"),
        delta_fallback=row["delta_fallback"],
        last_notified_at=row["last_notified_at"],
        notify_count=row["notify_count"],
        acknowledged=row["acknowledged"],
    )


def _device_values(d: CampaignDevice) -> dict[str, Any]:
    return {
        "tenant_id": d.tenant_id,
        "campaign_id": d.campaign_id,
        "device_id": d.device_id,
        "stage_index": d.stage_index,
        "rank": d.rank,
        "state": d.state.value,
        "progress_pct": d.progress_pct,
        "error": d.error,
        "notified_at": d.notified_at,
        "updated_at": d.updated_at,
        "fw_hash": d.fw_hash,
        "from_fw_hash": d.from_fw_hash,
        "delta_from": d.delta_from,
        "delta_fallback": d.delta_fallback,
        "last_notified_at": d.last_notified_at,
        "notify_count": d.notify_count,
        "acknowledged": d.acknowledged,
    }


def _delta(row: RowMapping) -> DeltaArtifact:
    return DeltaArtifact(
        id=row["id"],
        tenant_id=row["tenant_id"],
        firmware_id=row["firmware_id"],
        base_sha256=bytes(row["base_sha256"]),
        patch_sha256=bytes(row["patch_sha256"]),
        patch_size=row["patch_size"],
        patch_key=row["patch_key"],
        signed_manifest=bytes(row["signed_manifest"]),
        created_at=row["created_at"],
    )


def _audit(row: RowMapping) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        at=row["at"],
        tenant_id=row["tenant_id"],
        actor=Actor(row["actor_type"], row["actor_id"], row["actor_name"]),
        action=row["action"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        outcome=row["outcome"],
        ip=row["ip"],
        request_id=row["request_id"],
        details=dict(row["details"]),
    )


class SqlTenantRepository:
    def __init__(self, conn: AsyncConnection, tenant_id: UUID) -> None:
        self.tenant_id = tenant_id
        self._c = conn

    async def _insert(self, stmt: Any, conflict: str) -> None:
        try:
            async with self._c.begin_nested():
                await self._c.execute(stmt)
        except IntegrityError as exc:
            raise RepositoryConflict(conflict) from exc

    # --- firmware -------------------------------------------------------------------------
    async def lock_product(self, product: str) -> None:
        await self._c.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
            {"k": f"ota-version-code/{self.tenant_id}/{product}"},
        )

    async def add_firmware(self, firmware: Firmware) -> None:
        values = {
            "id": firmware.id,
            "tenant_id": firmware.tenant_id,
            "product": firmware.product,
            "version": firmware.version,
            "version_code": firmware.version_code,
            "sha256": firmware.sha256,
            "size": firmware.size,
            "min_version_code": firmware.min_version_code,
            "created_at": firmware.created_at,
            "created_by": firmware.created_by,
            "manifest": firmware.manifest,
            "signed_manifest": firmware.signed_manifest,
            "signing_key_id": firmware.signing_key_id,
            "pq_signed": firmware.pq_signed,
            "notes": firmware.notes,
            "severity": firmware.severity.value,
            "image_key": firmware.image_key,
            "manifest_key": firmware.manifest_key,
            "signature_key": firmware.signature_key,
            "rollback_of": firmware.rollback_of,
        }
        await self._insert(
            t.firmware.insert().values(**values),
            "firmware version or version_code already exists",
        )
        await self._c.execute(
            pg_insert(t.firmware_hash_index)
            .values(product=firmware.product, sha256_hex=firmware.sha256.hex())
            .on_conflict_do_nothing()
        )

    async def get_firmware(self, firmware_id: UUID) -> Firmware | None:
        row = (
            (await self._c.execute(select(t.firmware).where(t.firmware.c.id == firmware_id)))
            .mappings()
            .first()
        )
        return _firmware(row) if row else None

    async def get_firmware_by_hash(self, sha256: bytes) -> Firmware | None:
        row = (
            (
                await self._c.execute(
                    select(t.firmware)
                    .where(t.firmware.c.sha256 == sha256)
                    .order_by(t.firmware.c.version_code.desc())
                    .limit(1)
                )
            )
            .mappings()
            .first()
        )
        return _firmware(row) if row else None

    async def list_firmware(
        self, product: str | None, cursor: str | None, limit: int
    ) -> Page[Firmware]:
        q = select(t.firmware)
        if product is not None:
            q = q.where(t.firmware.c.product == product)
        if cursor:
            at, tie = decode_time_cursor(cursor)
            q = q.where(tuple_(t.firmware.c.created_at, t.firmware.c.id) < (at, UUID(tie)))
        q = q.order_by(t.firmware.c.created_at.desc(), t.firmware.c.id.desc()).limit(limit + 1)
        rows = [_firmware(r) for r in (await self._c.execute(q)).mappings()]
        nxt = (
            time_cursor(rows[limit - 1].created_at, str(rows[limit - 1].id))
            if len(rows) > limit
            else None
        )
        return Page(rows[:limit], nxt)

    async def max_version_code(self, product: str) -> int | None:
        value = (
            await self._c.execute(
                select(func.max(t.firmware.c.version_code)).where(t.firmware.c.product == product)
            )
        ).scalar()
        return None if value is None else int(value)

    async def version_exists(self, product: str, version: str) -> bool:
        row = (
            await self._c.execute(
                select(t.firmware.c.id).where(
                    t.firmware.c.product == product, t.firmware.c.version == version
                )
            )
        ).first()
        return row is not None

    async def firmware_hashes(self, product: str | None) -> list[bytes]:
        q = select(t.firmware.c.sha256).distinct()
        if product is not None:
            q = q.where(t.firmware.c.product == product)
        return sorted(bytes(r[0]) for r in await self._c.execute(q))

    async def firmware_by_hashes(
        self, product: str, hashes: Collection[bytes]
    ) -> dict[bytes, Firmware]:
        if not hashes:
            return {}
        q = (
            select(t.firmware)
            .where(t.firmware.c.product == product, t.firmware.c.sha256.in_(list(hashes)))
            .order_by(t.firmware.c.version_code)
        )
        result: dict[bytes, Firmware] = {}
        for row in (await self._c.execute(q)).mappings():
            fw = _firmware(row)
            result[fw.sha256] = fw
        return result

    # --- deltas ---------------------------------------------------------------------------
    async def add_delta(self, delta: DeltaArtifact) -> None:
        await self._insert(
            t.firmware_deltas.insert().values(
                id=delta.id,
                tenant_id=delta.tenant_id,
                firmware_id=delta.firmware_id,
                base_sha256=delta.base_sha256,
                patch_sha256=delta.patch_sha256,
                patch_size=delta.patch_size,
                patch_key=delta.patch_key,
                signed_manifest=delta.signed_manifest,
                created_at=delta.created_at,
            ),
            "delta already exists",
        )

    async def get_delta(self, firmware_id: UUID, base_sha256: bytes) -> DeltaArtifact | None:
        row = (
            (
                await self._c.execute(
                    select(t.firmware_deltas).where(
                        t.firmware_deltas.c.firmware_id == firmware_id,
                        t.firmware_deltas.c.base_sha256 == base_sha256,
                    )
                )
            )
            .mappings()
            .first()
        )
        return _delta(row) if row else None

    # --- campaigns ------------------------------------------------------------------------
    async def add_campaign(self, campaign: Campaign) -> None:
        await self._insert(
            t.campaigns.insert().values(**_campaign_values(campaign)), "campaign conflict"
        )

    async def get_campaign(self, campaign_id: UUID, *, for_update: bool = False) -> Campaign | None:
        q = select(t.campaigns).where(t.campaigns.c.id == campaign_id)
        if for_update:
            q = q.with_for_update()
        row = (await self._c.execute(q)).mappings().first()
        return _campaign(row) if row else None

    async def update_campaign(self, campaign: Campaign) -> None:
        values = _campaign_values(campaign)
        values.pop("id")
        values.pop("tenant_id")
        result = await self._c.execute(
            update(t.campaigns).where(t.campaigns.c.id == campaign.id).values(**values)
        )
        if result.rowcount != 1:
            raise KeyError(campaign.id)

    async def list_campaigns(
        self, states: Collection[CampaignState] | None, cursor: str | None, limit: int
    ) -> Page[Campaign]:
        q = select(t.campaigns)
        if states:
            q = q.where(t.campaigns.c.state.in_([s.value for s in states]))
        if cursor:
            at, tie = decode_time_cursor(cursor)
            q = q.where(tuple_(t.campaigns.c.created_at, t.campaigns.c.id) < (at, UUID(tie)))
        q = q.order_by(t.campaigns.c.created_at.desc(), t.campaigns.c.id.desc()).limit(limit + 1)
        rows = [_campaign(r) for r in (await self._c.execute(q)).mappings()]
        nxt = (
            time_cursor(rows[limit - 1].created_at, str(rows[limit - 1].id))
            if len(rows) > limit
            else None
        )
        return Page(rows[:limit], nxt)

    async def set_schedule(self, campaign_id: UUID, active: bool) -> None:
        if active:
            await self._c.execute(
                pg_insert(t.campaign_schedule)
                .values(campaign_id=campaign_id, tenant_id=self.tenant_id, updated_at=utcnow())
                .on_conflict_do_nothing()
            )
        else:
            await self._c.execute(
                delete(t.campaign_schedule).where(
                    t.campaign_schedule.c.campaign_id == campaign_id,
                    t.campaign_schedule.c.tenant_id == self.tenant_id,
                )
            )

    # --- campaign devices -----------------------------------------------------------------
    async def add_campaign_devices(self, devices: Sequence[CampaignDevice]) -> None:
        if not devices:
            return
        try:
            async with self._c.begin_nested():
                await self._c.execute(
                    t.campaign_devices.insert(), [_device_values(d) for d in devices]
                )
        except IntegrityError as exc:
            raise RepositoryConflict("campaign device already exists") from exc

    async def get_campaign_device(
        self, campaign_id: UUID, device_id: str, *, for_update: bool = False
    ) -> CampaignDevice | None:
        q = select(t.campaign_devices).where(
            t.campaign_devices.c.campaign_id == campaign_id,
            t.campaign_devices.c.device_id == device_id,
        )
        if for_update:
            q = q.with_for_update()
        row = (await self._c.execute(q)).mappings().first()
        return _device(row) if row else None

    async def update_campaign_devices(self, devices: Sequence[CampaignDevice]) -> None:
        if not devices:
            return
        cd = t.campaign_devices
        stmt = (
            update(cd)
            .where(
                cd.c.campaign_id == bindparam("k_campaign"), cd.c.device_id == bindparam("k_dev")
            )
            .values(
                state=bindparam("state"),
                progress_pct=bindparam("progress_pct"),
                error=bindparam("error"),
                notified_at=bindparam("notified_at"),
                updated_at=bindparam("updated_at"),
                fw_hash=bindparam("fw_hash"),
                delta_from=bindparam("delta_from"),
                delta_fallback=bindparam("delta_fallback"),
                last_notified_at=bindparam("last_notified_at"),
                notify_count=bindparam("notify_count"),
                acknowledged=bindparam("acknowledged"),
            )
        )
        params = []
        for d in devices:
            v = _device_values(d)
            params.append(
                {
                    "k_campaign": d.campaign_id,
                    "k_dev": d.device_id,
                    "state": v["state"],
                    "progress_pct": v["progress_pct"],
                    "error": v["error"],
                    "notified_at": v["notified_at"],
                    "updated_at": v["updated_at"],
                    "fw_hash": v["fw_hash"],
                    "delta_from": v["delta_from"],
                    "delta_fallback": v["delta_fallback"],
                    "last_notified_at": v["last_notified_at"],
                    "notify_count": v["notify_count"],
                    "acknowledged": v["acknowledged"],
                }
            )
        await self._c.execute(stmt, params)

    async def list_campaign_devices(
        self, campaign_id: UUID, state: DeviceState | None, cursor: str | None, limit: int
    ) -> Page[CampaignDevice]:
        cd = t.campaign_devices
        q = select(cd).where(cd.c.campaign_id == campaign_id)
        if state is not None:
            q = q.where(cd.c.state == state.value)
        if cursor:
            (after,) = decode_cursor(cursor, 1)
            q = q.where(cd.c.device_id > str(after))
        q = q.order_by(cd.c.device_id).limit(limit + 1)
        rows = [_device(r) for r in (await self._c.execute(q)).mappings()]
        nxt = encode_cursor(rows[limit - 1].device_id) if len(rows) > limit else None
        return Page(rows[:limit], nxt)

    async def find_campaign_devices(
        self,
        campaign_id: UUID,
        *,
        stage_index: int | None = None,
        states: Collection[DeviceState] | None = None,
        notified_before: datetime | None = None,
        refresh_before: datetime | None = None,
    ) -> list[CampaignDevice]:
        cd = t.campaign_devices
        conds = [cd.c.campaign_id == campaign_id]
        if stage_index is not None:
            conds.append(cd.c.stage_index == stage_index)
        if states is not None:
            conds.append(cd.c.state.in_([s.value for s in states]))
        if notified_before is not None:
            conds.append(cd.c.notified_at < notified_before)
        if refresh_before is not None:
            conds.append(
                or_(cd.c.last_notified_at.is_(None), cd.c.last_notified_at < refresh_before)
            )
        q = select(cd).where(and_(*conds)).order_by(cd.c.rank)
        return [_device(r) for r in (await self._c.execute(q)).mappings()]

    async def state_histogram(self, campaign_id: UUID) -> dict[int, dict[DeviceState, int]]:
        cd = t.campaign_devices
        q = (
            select(cd.c.stage_index, cd.c.state, func.count())
            .where(cd.c.campaign_id == campaign_id)
            .group_by(cd.c.stage_index, cd.c.state)
        )
        hist: dict[int, dict[DeviceState, int]] = {}
        for stage, state, n in await self._c.execute(q):
            hist.setdefault(int(stage), {})[DeviceState(state)] = int(n)
        return hist

    # --- audit ----------------------------------------------------------------------------
    async def add_audit(self, event: AuditEvent) -> None:
        await self._c.execute(
            t.audit_events.insert().values(
                id=event.id,
                tenant_id=event.tenant_id,
                at=event.at,
                actor_type=event.actor.type,
                actor_id=event.actor.id,
                actor_name=event.actor.name,
                action=event.action,
                target_type=event.target_type,
                target_id=event.target_id,
                outcome=event.outcome,
                ip=event.ip,
                request_id=event.request_id,
                details=event.details,
            )
        )

    async def list_audit(
        self, target_type: str, target_id: str, cursor: str | None, limit: int
    ) -> Page[AuditEvent]:
        a = t.audit_events
        q = select(a).where(a.c.target_type == target_type, a.c.target_id == target_id)
        if cursor:
            at, tie = decode_time_cursor(cursor)
            q = q.where(tuple_(a.c.at, a.c.id) < (at, UUID(tie)))
        q = q.order_by(a.c.at.desc(), a.c.id.desc()).limit(limit + 1)
        rows = [_audit(r) for r in (await self._c.execute(q)).mappings()]
        nxt = (
            time_cursor(rows[limit - 1].at, str(rows[limit - 1].id)) if len(rows) > limit else None
        )
        return Page(rows[:limit], nxt)

    # --- idempotency ----------------------------------------------------------------------
    async def get_idempotency(self, key: str, actor: str) -> IdempotencyRecord | None:
        i = t.idempotency_keys
        row = (
            (await self._c.execute(select(i).where(i.c.key == key, i.c.actor == actor)))
            .mappings()
            .first()
        )
        if row is None:
            return None
        return IdempotencyRecord(
            tenant_id=row["tenant_id"],
            key=row["key"],
            actor=row["actor"],
            method=row["method"],
            path=row["path"],
            status_code=row["status_code"],
            body=dict(row["body"]),
            created_at=row["created_at"],
        )

    async def put_idempotency(self, record: IdempotencyRecord) -> None:
        await self._insert(
            t.idempotency_keys.insert().values(
                tenant_id=record.tenant_id,
                actor=record.actor,
                key=record.key,
                method=record.method,
                path=record.path,
                status_code=record.status_code,
                body=record.body,
                created_at=record.created_at,
            ),
            "idempotency key already used",
        )

    # --- replay ---------------------------------------------------------------------------
    async def check_and_record_seq(self, device_id: str, seq: int) -> bool:
        s = t.device_seq
        insert = pg_insert(s).values(tenant_id=self.tenant_id, device_id=device_id, last_seq=seq)
        stmt = insert.on_conflict_do_update(
            index_elements=[s.c.tenant_id, s.c.device_id],
            set_={"last_seq": insert.excluded.last_seq},
            where=s.c.last_seq < insert.excluded.last_seq,
        ).returning(s.c.last_seq)
        return (await self._c.execute(stmt)).first() is not None


class SqlDatabase:
    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine

    @classmethod
    def from_url(cls, url: str, *, pool_size: int = 10) -> SqlDatabase:
        return cls(create_async_engine(url, pool_size=pool_size, pool_pre_ping=True))

    @asynccontextmanager
    async def tenant(self, tenant_id: UUID) -> AsyncIterator[SqlTenantRepository]:
        async with self.engine.begin() as conn:
            await conn.execute(SET_TENANT, {"tenant": str(tenant_id)})
            yield SqlTenantRepository(conn, tenant_id)

    async def due_campaigns(self) -> list[ScheduledCampaign]:
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                select(t.campaign_schedule.c.tenant_id, t.campaign_schedule.c.campaign_id).order_by(
                    t.campaign_schedule.c.updated_at
                )
            )
            return [ScheduledCampaign(r[0], r[1]) for r in rows]

    async def known_hashes(self, product: str | None) -> list[str]:
        q = select(t.firmware_hash_index.c.sha256_hex).distinct()
        if product is not None:
            q = q.where(t.firmware_hash_index.c.product == product)
        async with self.engine.connect() as conn:
            return sorted(r[0] for r in await conn.execute(q))

    async def ping(self) -> bool:
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception:
            return False
        return True

    async def close(self) -> None:
        await self.engine.dispose()
