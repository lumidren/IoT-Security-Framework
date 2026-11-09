"""PostgreSQL repository (SQLAlchemy 2.x async Core + asyncpg) with row-level security.

Each :meth:`SqlRepository.tenant` block is one transaction that first runs
``SELECT set_config('ironmesh.tenant_id', $1, true)`` - the parameterised form of
``SET LOCAL`` - so the RLS policies of the migration confine every statement to that tenant.
Queries additionally filter on ``tenant_id`` (defense in depth, and it lets the planner use the
tenant-leading indexes); the RLS policies are what actually enforces isolation and are tested
without those filters in ``tests/test_postgres_rls.py``.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, TypeVar

from sqlalchemy import (
    BigInteger,
    ColumnElement,
    Table,
    Text,
    and_,
    any_,
    bindparam,
    cast,
    delete,
    exists,
    func,
    insert,
    literal,
    or_,
    select,
    text,
    tuple_,
    update,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.types import DateTime

from ..domain import (
    ActionRecord,
    AlertRecord,
    ApiKeyRecord,
    AuditDraft,
    AuditFilter,
    AuditRecord,
    CertificateRecord,
    CommandRecord,
    ConfigRecord,
    DeviceFilter,
    DeviceRecord,
    FleetAggregate,
    GroupRecord,
    IngestStats,
    ProvisioningRow,
    TelemetryRecord,
    TenantKeysRecord,
    TenantRecord,
    TimelineRecord,
    TwinRecord,
    UserRecord,
)
from . import tables as t
from .base import (
    GENESIS_HASH,
    Bucket,
    CommandCursor,
    DuplicateError,
    TimelineCursor,
    build_audit_record,
)

R = TypeVar("R")
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
UNIQUE_VIOLATION = "23505"


def _rec[R](cls: type[R], row: RowMapping, **overrides: Any) -> R:
    names = {f.name for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
    values = {k: v for k, v in row.items() if k in names}
    for key, value in values.items():
        if isinstance(value, uuid.UUID):
            values[key] = str(value)
    values.update(overrides)
    return cls(**values)


def _values(rec: object, table: Table, exclude: Iterable[str] = ()) -> dict[str, Any]:
    skip = set(exclude)
    data = {f.name: getattr(rec, f.name) for f in dataclasses.fields(rec)}  # type: ignore[arg-type]
    return {c.name: data[c.name] for c in table.columns if c.name in data and c.name not in skip}


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class SqlTenantTx:
    def __init__(self, conn: AsyncConnection, tenant_id: str) -> None:
        self.conn = conn
        self.tenant_id = tenant_id

    async def _insert(self, stmt: Any) -> None:
        try:
            async with self.conn.begin_nested():
                await self.conn.execute(stmt)
        except IntegrityError as exc:
            if getattr(exc.orig, "sqlstate", None) == UNIQUE_VIOLATION or "unique" in str(exc):
                raise DuplicateError(str(exc.orig)) from exc
            raise

    async def _one(self, stmt: Any) -> RowMapping | None:
        return (await self.conn.execute(stmt)).mappings().first()

    async def _all(self, stmt: Any) -> list[RowMapping]:
        return list((await self.conn.execute(stmt)).mappings().all())

    def _mine(self, table: Table) -> ColumnElement[bool]:
        return table.c.tenant_id == self.tenant_id

    # --- tenant ---------------------------------------------------------------------------------
    async def get_tenant(self) -> TenantRecord | None:
        row = await self._one(select(t.tenants).where(self._mine(t.tenants)))
        if row is None:
            return None
        return TenantRecord(
            id=str(row["tenant_id"]),
            name=row["name"],
            settings=dict(row["settings"]),
            created_at=row["created_at"],
        )

    async def insert_tenant(self, rec: TenantRecord) -> None:
        await self._insert(
            insert(t.tenants).values(
                tenant_id=rec.id, name=rec.name, settings=rec.settings, created_at=rec.created_at
            )
        )

    async def save_tenant(self, rec: TenantRecord) -> None:
        await self.conn.execute(
            update(t.tenants)
            .where(self._mine(t.tenants))
            .values(name=rec.name, settings=rec.settings)
        )

    async def get_tenant_keys(self) -> TenantKeysRecord | None:
        row = await self._one(select(t.tenant_keys).where(self._mine(t.tenant_keys)))
        return None if row is None else _rec(TenantKeysRecord, row)

    async def insert_tenant_keys(self, rec: TenantKeysRecord) -> None:
        await self._insert(insert(t.tenant_keys).values(**_values(rec, t.tenant_keys)))

    # --- devices --------------------------------------------------------------------------------
    async def insert_device(self, rec: DeviceRecord) -> None:
        await self._insert(insert(t.devices).values(**_values(rec, t.devices)))

    async def get_device(self, device_id: str, *, for_update: bool = False) -> DeviceRecord | None:
        stmt = select(t.devices).where(self._mine(t.devices), t.devices.c.id == device_id)
        if for_update:
            stmt = stmt.with_for_update()
        row = await self._one(stmt)
        return None if row is None else _rec(DeviceRecord, row)

    async def save_device(self, rec: DeviceRecord) -> None:
        await self.conn.execute(
            update(t.devices)
            .where(self._mine(t.devices), t.devices.c.id == rec.id)
            .values(**_values(rec, t.devices, exclude=("id", "tenant_id", "created_at")))
        )

    def _device_where(self, flt: DeviceFilter) -> list[ColumnElement[bool]]:
        d = t.devices
        conds: list[ColumnElement[bool]] = [self._mine(d)]
        if flt.state:
            conds.append(d.c.state == flt.state)
        if flt.connected is not None:
            conds.append(d.c.connected.is_(flt.connected))
        if flt.assurance:
            conds.append(d.c.assurance_level == flt.assurance)
        if flt.tag:
            conds.append(d.c.tags.contains({flt.tag[0]: flt.tag[1]}))
        if flt.group:
            m = t.group_members
            conds.append(
                exists().where(
                    m.c.tenant_id == d.c.tenant_id, m.c.device_id == d.c.id, m.c.slug == flt.group
                )
            )
        if flt.q:
            pattern = _like(flt.q)
            conds.append(
                or_(
                    d.c.id.ilike(pattern, escape="\\"),
                    d.c.product.ilike(pattern, escape="\\"),
                    d.c.hw_revision.ilike(pattern, escape="\\"),
                    d.c.fw_version.ilike(pattern, escape="\\"),
                    cast(d.c.tags, Text).ilike(pattern, escape="\\"),
                )
            )
        return conds

    async def list_devices(
        self, flt: DeviceFilter, after_id: str | None, limit: int
    ) -> list[DeviceRecord]:
        conds = self._device_where(flt)
        if after_id is not None:
            conds.append(t.devices.c.id > after_id)
        rows = await self._all(
            select(t.devices).where(and_(*conds)).order_by(t.devices.c.id).limit(limit)
        )
        return [_rec(DeviceRecord, r) for r in rows]

    async def resolve_targets(
        self,
        groups: list[str],
        tags: dict[str, str],
        device_ids: list[str],
        states: list[str] | None,
        limit: int,
    ) -> list[DeviceRecord]:
        d, m = t.devices, t.group_members
        # Arrays are bound as one parameter each (= ANY($n)), so 100 000 ids stay within the
        # protocol's bind-parameter limit.
        selectors: list[ColumnElement[bool]] = []
        if groups:
            members = select(m.c.device_id).where(
                self._mine(m), m.c.slug == any_(bindparam("groups", groups, ARRAY(Text)))
            )
            selectors.append(d.c.id.in_(members))
        if device_ids:
            selectors.append(d.c.id == any_(bindparam("device_ids", device_ids, ARRAY(Text))))
        if tags:
            selectors.append(d.c.tags.contains(tags))
        if not selectors:
            return []
        conds: list[ColumnElement[bool]] = [self._mine(d), or_(*selectors)]
        if states is not None:
            conds.append(d.c.state == any_(bindparam("states", states, ARRAY(Text))))
        cols = (
            d.c.tenant_id,
            d.c.id,
            d.c.product,
            d.c.hw_revision,
            d.c.state,
            d.c.created_at,
            d.c.fw_version,
            d.c.fw_hash_hex,
            d.c.connected,
        )
        rows = await self._all(select(*cols).where(*conds).order_by(d.c.id).limit(limit))
        return [_rec(DeviceRecord, r) for r in rows]

    async def next_downlink_seq(self, device_id: str, msg_type: int, floor: int = 0) -> int:
        d, s = t.devices, t.downlink_sequences
        row = await self._one(select(d.c.downlink_seq).where(self._mine(d), d.c.id == device_id))
        if row is None:
            raise KeyError(device_id)
        ins = pg_insert(s).values(
            device_id=device_id,
            msg_type=msg_type,
            tenant_id=self.tenant_id,
            last_seq=max(int(row["downlink_seq"]) + 1, floor),
        )
        stmt = ins.on_conflict_do_update(
            index_elements=[s.c.device_id, s.c.msg_type],
            set_={"last_seq": func.greatest(s.c.last_seq + 1, literal(floor, BigInteger))},
        ).returning(s.c.last_seq)
        out = await self._one(stmt)
        assert out is not None
        return int(out["last_seq"])

    async def device_groups(self, device_ids: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {d: [] for d in device_ids}
        if not device_ids:
            return out
        m = t.group_members
        rows = await self._all(
            select(m.c.device_id, m.c.slug)
            .where(self._mine(m), m.c.device_id.in_(device_ids))
            .order_by(m.c.slug)
        )
        for r in rows:
            out[r["device_id"]].append(r["slug"])
        return out

    async def open_alert_counts(self, device_ids: list[str]) -> dict[str, int]:
        out = dict.fromkeys(device_ids, 0)
        if not device_ids:
            return out
        a = t.alerts
        rows = await self._all(
            select(a.c.device_id, func.count().label("n"))
            .where(self._mine(a), a.c.state == "open", a.c.device_id.in_(device_ids))
            .group_by(a.c.device_id)
        )
        for r in rows:
            out[r["device_id"]] = int(r["n"])
        return out

    async def list_provisioning(
        self, state: str | None, after_id: str | None, limit: int
    ) -> list[ProvisioningRow]:
        d = t.devices
        failed = d.c.provisioning_status == "failed"
        early = d.c.state.in_(("manufactured", "provisioned"))
        conds: list[ColumnElement[bool]] = [self._mine(d)]
        if state == "failed":
            conds.append(failed)
        elif state is not None:
            conds.extend([d.c.state == state, ~failed])
        else:
            conds.append(or_(failed, early))
        if after_id is not None:
            conds.append(d.c.id > after_id)
        rows = await self._all(select(d).where(and_(*conds)).order_by(d.c.id).limit(limit))
        out = []
        for r in rows:
            rec = _rec(DeviceRecord, r)
            out.append(
                ProvisioningRow(
                    device=rec, state="failed" if rec.provisioning_status == "failed" else rec.state
                )
            )
        return out

    async def fleet_aggregate(self, now: datetime) -> FleetAggregate:
        d, a = t.devices, t.alerts
        agg = FleetAggregate()
        for r in await self._all(
            select(d.c.state, func.count().label("n")).where(self._mine(d)).group_by(d.c.state)
        ):
            agg.by_state[r["state"]] = int(r["n"])
        agg.devices_total = sum(agg.by_state.values())
        has_cert = and_(d.c.cert_serial_hex.is_not(None), d.c.cert_not_after.is_not(None))
        live = and_(has_cert, d.c.cert_revoked.is_(False), d.c.cert_not_after > now)
        row = await self._one(
            select(
                func.count().filter(d.c.connected.is_(True)).label("connected"),
                func.count().filter(d.c.assurance_level == "hardware").label("hardware"),
                func.count().filter(d.c.assurance_level == "software").label("software"),
                func.count().filter(and_(has_cert, d.c.cert_revoked.is_(True))).label("revoked"),
                func.count()
                .filter(and_(has_cert, d.c.cert_revoked.is_(False), d.c.cert_not_after <= now))
                .label("expired"),
                func.count()
                .filter(and_(live, d.c.cert_not_after <= now + timedelta(hours=24)))
                .label("e24"),
                func.count()
                .filter(and_(live, d.c.cert_not_after <= now + timedelta(days=7)))
                .label("e7"),
            ).where(self._mine(d))
        )
        assert row is not None
        agg.connected, agg.hardware, agg.software = (
            int(row["connected"]),
            int(row["hardware"]),
            int(row["software"]),
        )
        agg.revoked, agg.expired = int(row["revoked"]), int(row["expired"])
        agg.expiring_24h, agg.expiring_7d = int(row["e24"]), int(row["e7"])
        n = func.count().label("n")
        agg.firmware = [
            (r["fw_version"], int(r["n"]))
            for r in await self._all(
                select(d.c.fw_version, n)
                .where(self._mine(d), d.c.fw_version.is_not(None))
                .group_by(d.c.fw_version)
                .order_by(n.desc(), d.c.fw_version)
            )
        ]
        for r in await self._all(
            select(a.c.severity, func.count().label("n"))
            .where(self._mine(a), a.c.state == "open")
            .group_by(a.c.severity)
        ):
            agg.alerts_open[r["severity"]] = int(r["n"])
        open_count = (
            select(func.count())
            .where(a.c.tenant_id == d.c.tenant_id, a.c.device_id == d.c.id, a.c.state == "open")
            .scalar_subquery()
        )
        agg.map = [
            {
                "device_id": r["id"],
                "lat": r["lat"],
                "lon": r["lon"],
                "state": r["state"],
                "open_alerts": int(r["open_alerts"]),
            }
            for r in await self._all(
                select(d.c.id, d.c.lat, d.c.lon, d.c.state, open_count.label("open_alerts"))
                .where(self._mine(d), d.c.lat.is_not(None), d.c.lon.is_not(None))
                .order_by(d.c.id)
                .limit(10_000)
            )
        ]
        return agg

    # --- certificates ---------------------------------------------------------------------------
    async def upsert_certificate(self, rec: CertificateRecord) -> None:
        values = _values(rec, t.certificates)
        stmt = pg_insert(t.certificates).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[t.certificates.c.serial_hex],
            set_={k: stmt.excluded[k] for k in values if k not in ("serial_hex", "tenant_id")},
        )
        await self._insert(stmt)

    async def list_certificates(self, device_id: str) -> list[CertificateRecord]:
        c = t.certificates
        rows = await self._all(
            select(c)
            .where(self._mine(c), c.c.device_id == device_id)
            .order_by(c.c.not_before.desc())
        )
        return [_rec(CertificateRecord, r) for r in rows]

    async def mark_certificates_revoked(self, device_id: str, at: datetime, reason: str) -> int:
        c = t.certificates
        result = await self.conn.execute(
            update(c)
            .where(self._mine(c), c.c.device_id == device_id, c.c.revoked_at.is_(None))
            .values(revoked_at=at, revocation_reason=reason)
        )
        return int(result.rowcount)

    # --- groups ---------------------------------------------------------------------------------
    def _group_select(self) -> Any:
        g, m = t.groups, t.group_members
        count = (
            select(func.count())
            .where(m.c.tenant_id == g.c.tenant_id, m.c.slug == g.c.slug)
            .scalar_subquery()
        )
        return select(g, count.label("member_count")).where(self._mine(g))

    async def list_groups(self) -> list[GroupRecord]:
        rows = await self._all(self._group_select().order_by(t.groups.c.slug))
        return [_rec(GroupRecord, r) for r in rows]

    async def get_group(self, slug: str) -> GroupRecord | None:
        row = await self._one(self._group_select().where(t.groups.c.slug == slug))
        return None if row is None else _rec(GroupRecord, row)

    async def insert_group(self, rec: GroupRecord) -> None:
        await self._insert(insert(t.groups).values(**_values(rec, t.groups)))

    async def save_group(self, rec: GroupRecord) -> None:
        await self.conn.execute(
            update(t.groups)
            .where(self._mine(t.groups), t.groups.c.slug == rec.slug)
            .values(name=rec.name, description=rec.description, hardware_only=rec.hardware_only)
        )

    async def delete_group(self, slug: str) -> bool:
        result = await self.conn.execute(
            delete(t.groups).where(self._mine(t.groups), t.groups.c.slug == slug)
        )
        return bool(result.rowcount)

    async def add_member(self, slug: str, device_id: str) -> bool:
        m = t.group_members
        result = await self.conn.execute(
            pg_insert(m)
            .values(tenant_id=self.tenant_id, slug=slug, device_id=device_id)
            .on_conflict_do_nothing()
        )
        return bool(result.rowcount)

    async def remove_member(self, slug: str, device_id: str) -> bool:
        m = t.group_members
        result = await self.conn.execute(
            delete(m).where(self._mine(m), m.c.slug == slug, m.c.device_id == device_id)
        )
        return bool(result.rowcount)

    async def group_device_ids(self, slug: str) -> list[str]:
        m = t.group_members
        rows = await self._all(
            select(m.c.device_id).where(self._mine(m), m.c.slug == slug).order_by(m.c.device_id)
        )
        return [r["device_id"] for r in rows]

    # --- twin -----------------------------------------------------------------------------------
    async def get_twin(self, device_id: str, *, for_update: bool = False) -> TwinRecord | None:
        stmt = select(t.twins).where(self._mine(t.twins), t.twins.c.device_id == device_id)
        if for_update:
            stmt = stmt.with_for_update()
        row = await self._one(stmt)
        return None if row is None else _rec(TwinRecord, row)

    async def save_twin(self, rec: TwinRecord) -> None:
        values = _values(rec, t.twins)
        stmt = pg_insert(t.twins).values(**values)
        await self.conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[t.twins.c.device_id],
                set_={k: stmt.excluded[k] for k in values if k not in ("device_id", "tenant_id")},
            )
        )

    # --- commands -------------------------------------------------------------------------------
    async def insert_command(self, rec: CommandRecord) -> None:
        await self._insert(insert(t.commands).values(**_values(rec, t.commands)))

    async def get_command(self, cmd_id: str, *, for_update: bool = False) -> CommandRecord | None:
        try:
            uuid.UUID(cmd_id)
        except ValueError:
            return None
        stmt = select(t.commands).where(self._mine(t.commands), t.commands.c.cmd_id == cmd_id)
        if for_update:
            stmt = stmt.with_for_update()
        row = await self._one(stmt)
        return None if row is None else _rec(CommandRecord, row)

    async def get_command_by_key(self, device_id: str, key: str) -> CommandRecord | None:
        c = t.commands
        row = await self._one(
            select(c).where(self._mine(c), c.c.device_id == device_id, c.c.idempotency_key == key)
        )
        return None if row is None else _rec(CommandRecord, row)

    async def save_command(self, rec: CommandRecord) -> None:
        await self.conn.execute(
            update(t.commands)
            .where(self._mine(t.commands), t.commands.c.cmd_id == rec.cmd_id)
            .values(**_values(rec, t.commands, exclude=("cmd_id", "tenant_id")))
        )

    async def list_commands(
        self, device_id: str, status: str | None, after: CommandCursor | None, limit: int
    ) -> list[CommandRecord]:
        c = t.commands
        conds: list[ColumnElement[bool]] = [self._mine(c), c.c.device_id == device_id]
        if status:
            conds.append(c.c.status == status)
        if after is not None:
            conds.append(
                tuple_(c.c.created_at, c.c.cmd_id)
                < tuple_(literal(after[0], c.c.created_at.type), literal(after[1], c.c.cmd_id.type))
            )
        rows = await self._all(
            select(c)
            .where(and_(*conds))
            .order_by(c.c.created_at.desc(), c.c.cmd_id.desc())
            .limit(limit)
        )
        return [_rec(CommandRecord, r) for r in rows]

    async def expired_commands(self, now: datetime, limit: int) -> list[CommandRecord]:
        c = t.commands
        rows = await self._all(
            select(c)
            .where(self._mine(c), c.c.status.in_(("pending", "sent")), c.c.expires_at <= now)
            .order_by(c.c.expires_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return [_rec(CommandRecord, r) for r in rows]

    async def unsent_commands(self, now: datetime, limit: int) -> list[CommandRecord]:
        c = t.commands
        rows = await self._all(
            select(c)
            .where(self._mine(c), c.c.status == "pending", c.c.expires_at > now)
            .order_by(c.c.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return [_rec(CommandRecord, r) for r in rows]

    # --- config ---------------------------------------------------------------------------------
    async def get_config(self, device_id: str, *, for_update: bool = False) -> ConfigRecord | None:
        c = t.device_configs
        stmt = select(c).where(self._mine(c), c.c.device_id == device_id)
        if for_update:
            stmt = stmt.with_for_update()
        row = await self._one(stmt)
        return None if row is None else _rec(ConfigRecord, row)

    async def save_config(self, rec: ConfigRecord) -> None:
        values = _values(rec, t.device_configs)
        stmt = pg_insert(t.device_configs).values(**values)
        await self.conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[t.device_configs.c.device_id],
                set_={k: stmt.excluded[k] for k in values if k not in ("device_id", "tenant_id")},
            )
        )

    # --- timeline & telemetry -------------------------------------------------------------------
    async def insert_timeline(self, rec: TimelineRecord) -> None:
        await self.conn.execute(insert(t.timeline_events).values(**_values(rec, t.timeline_events)))

    async def list_timeline(
        self,
        device_id: str,
        from_: datetime | None,
        to: datetime | None,
        kinds: list[str] | None,
        after: TimelineCursor | None,
        limit: int,
    ) -> list[TimelineRecord]:
        e = t.timeline_events
        conds: list[ColumnElement[bool]] = [self._mine(e), e.c.device_id == device_id]
        if from_ is not None:
            conds.append(e.c.at >= from_)
        if to is not None:
            conds.append(e.c.at <= to)
        if kinds:
            conds.append(e.c.kind.in_(kinds))
        if after is not None:
            conds.append(
                tuple_(e.c.at, e.c.id)
                < tuple_(literal(after[0], e.c.at.type), literal(after[1], e.c.id.type))
            )
        rows = await self._all(
            select(e).where(and_(*conds)).order_by(e.c.at.desc(), e.c.id.desc()).limit(limit)
        )
        return [_rec(TimelineRecord, r) for r in rows]

    async def insert_telemetry(self, rec: TelemetryRecord) -> None:
        values: dict[str, Any] = {
            "tenant_id": rec.tenant_id,
            "device_id": rec.device_id,
            "at": rec.at,
            "extra": rec.extra,
        }
        for metric, value in rec.values.items():
            values[metric] = None if value is None else float(value)
        await self.conn.execute(insert(t.telemetry_samples).values(**values))

    async def telemetry_buckets(
        self,
        device_id: str,
        from_: datetime,
        to: datetime,
        metrics: list[str],
        step_seconds: int,
    ) -> dict[str, list[Bucket]]:
        s = t.telemetry_samples
        bucket = func.date_bin(
            func.make_interval(0, 0, 0, 0, 0, 0, float(step_seconds)),
            s.c.at,
            literal(EPOCH, DateTime(timezone=True)),
        ).label("bucket")
        cols = [func.avg(s.c[m]).label(m) for m in metrics]
        rows = await self._all(
            select(bucket, *cols)
            .where(self._mine(s), s.c.device_id == device_id, s.c.at >= from_, s.c.at < to)
            .group_by(bucket)
            .order_by(bucket)
        )
        out: dict[str, list[Bucket]] = {m: [] for m in metrics}
        for r in rows:
            for m in metrics:
                if r[m] is not None:
                    out[m].append((r["bucket"], float(r[m])))
        return out

    async def check_and_record_seq(self, device_id: str, direction: str, seq: int) -> bool:
        r = t.device_replay
        ins = pg_insert(r).values(
            device_id=device_id,
            direction=direction,
            tenant_id=self.tenant_id,
            last_seq=Decimal(seq),
        )
        cas = ins.on_conflict_do_update(
            index_elements=[r.c.device_id, r.c.direction],
            set_={"last_seq": ins.excluded.last_seq},
            where=r.c.last_seq < ins.excluded.last_seq,
        ).returning(r.c.last_seq)
        return (await self._one(cas)) is not None

    # --- alerts ---------------------------------------------------------------------------------
    async def upsert_alert(self, rec: AlertRecord) -> AlertRecord | None:
        a = t.alerts
        row = await self._one(select(a).where(self._mine(a), a.c.id == rec.id).with_for_update())
        previous = None if row is None else _rec(AlertRecord, row)
        values = _values(rec, a)
        stmt = pg_insert(a).values(**values)
        await self._insert(
            stmt.on_conflict_do_update(
                index_elements=[a.c.id],
                set_={k: stmt.excluded[k] for k in values if k not in ("id", "tenant_id")},
            )
        )
        return previous

    # --- audit ----------------------------------------------------------------------------------
    async def append_audit(self, draft: AuditDraft) -> AuditRecord:
        h = t.audit_heads
        await self.conn.execute(
            pg_insert(h)
            .values(tenant_id=self.tenant_id, last_seq=0, last_hash=GENESIS_HASH)
            .on_conflict_do_nothing()
        )
        head = await self._one(select(h).where(self._mine(h)).with_for_update())
        assert head is not None
        rec = build_audit_record(
            draft, str(uuid.uuid4()), int(head["last_seq"]) + 1, bytes(head["last_hash"])
        )
        await self.conn.execute(insert(t.audit_events).values(**_values(rec, t.audit_events)))
        await self.conn.execute(
            update(h).where(self._mine(h)).values(last_seq=rec.seq, last_hash=rec.hash)
        )
        return rec

    def _audit(self, row: RowMapping) -> AuditRecord:
        return _rec(AuditRecord, row, prev_hash=bytes(row["prev_hash"]), hash=bytes(row["hash"]))

    async def list_audit(
        self, flt: AuditFilter, before_seq: int | None, limit: int
    ) -> list[AuditRecord]:
        e = t.audit_events
        conds: list[ColumnElement[bool]] = [self._mine(e)]
        if before_seq is not None:
            conds.append(e.c.seq < before_seq)
        if flt.actor:
            conds.append(e.c.actor_id == flt.actor)
        if flt.action:
            conds.append(e.c.action == flt.action)
        if flt.target_type:
            conds.append(e.c.target_type == flt.target_type)
        if flt.target_id:
            conds.append(e.c.target_id == flt.target_id)
        if flt.from_:
            conds.append(e.c.at >= flt.from_)
        if flt.to:
            conds.append(e.c.at <= flt.to)
        rows = await self._all(select(e).where(and_(*conds)).order_by(e.c.seq.desc()).limit(limit))
        return [self._audit(r) for r in rows]

    async def audit_after(
        self, after_seq: int, limit: int, from_: datetime | None = None, to: datetime | None = None
    ) -> list[AuditRecord]:
        e = t.audit_events
        conds: list[ColumnElement[bool]] = [self._mine(e), e.c.seq > after_seq]
        if from_:
            conds.append(e.c.at >= from_)
        if to:
            conds.append(e.c.at <= to)
        rows = await self._all(select(e).where(and_(*conds)).order_by(e.c.seq).limit(limit))
        return [self._audit(r) for r in rows]

    async def audit_head(self) -> tuple[int, bytes] | None:
        h = t.audit_heads
        row = await self._one(select(h).where(self._mine(h)))
        return None if row is None else (int(row["last_seq"]), bytes(row["last_hash"]))

    # --- users & API keys -----------------------------------------------------------------------
    async def get_user(self, user_id: str) -> UserRecord | None:
        u = t.users
        row = await self._one(select(u).where(self._mine(u), u.c.id == user_id))
        return None if row is None else _rec(UserRecord, row)

    async def save_user(self, rec: UserRecord) -> None:
        values = _values(rec, t.users)
        stmt = pg_insert(t.users).values(**values)
        await self.conn.execute(
            stmt.on_conflict_do_update(
                index_elements=[t.users.c.tenant_id, t.users.c.id],
                set_={k: stmt.excluded[k] for k in ("email", "name", "role", "last_login_at")},
            )
        )

    async def list_users(self) -> list[UserRecord]:
        u = t.users
        rows = await self._all(select(u).where(self._mine(u)).order_by(u.c.email))
        return [_rec(UserRecord, r) for r in rows]

    def _key(self, row: RowMapping) -> ApiKeyRecord:
        return _rec(ApiKeyRecord, row, key_hash=bytes(row["key_hash"]), scopes=list(row["scopes"]))

    async def list_api_keys(self) -> list[ApiKeyRecord]:
        k = t.api_keys
        rows = await self._all(
            select(k).where(self._mine(k), k.c.revoked_at.is_(None)).order_by(k.c.created_at)
        )
        return [self._key(r) for r in rows]

    async def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        try:
            uuid.UUID(key_id)
        except ValueError:
            return None
        k = t.api_keys
        row = await self._one(select(k).where(self._mine(k), k.c.id == key_id))
        return None if row is None else self._key(row)

    async def insert_api_key(self, rec: ApiKeyRecord) -> None:
        await self._insert(insert(t.api_keys).values(**_values(rec, t.api_keys)))

    async def save_api_key(self, rec: ApiKeyRecord) -> None:
        k = t.api_keys
        await self.conn.execute(
            update(k)
            .where(self._mine(k), k.c.id == rec.id)
            .values(**_values(rec, k, exclude=("id", "tenant_id", "key_hash", "created_at")))
        )

    # --- outbox & stats -------------------------------------------------------------------------
    async def insert_action(self, rec: ActionRecord) -> None:
        await self.conn.execute(insert(t.pending_actions).values(**_values(rec, t.pending_actions)))

    async def due_actions(self, now: datetime, limit: int) -> list[ActionRecord]:
        p = t.pending_actions
        rows = await self._all(
            select(p)
            .where(self._mine(p), p.c.status == "pending", p.c.next_attempt_at <= now)
            .order_by(p.c.next_attempt_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return [_rec(ActionRecord, r) for r in rows]

    async def pending_device_actions(
        self, device_id: str, kinds: tuple[str, ...]
    ) -> list[ActionRecord]:
        p = t.pending_actions
        rows = await self._all(
            select(p)
            .where(
                self._mine(p),
                p.c.status == "pending",
                p.c.device_id == device_id,
                p.c.kind.in_(kinds),
            )
            .order_by(p.c.created_at, p.c.id)
            .with_for_update()
        )
        return [_rec(ActionRecord, r) for r in rows]

    async def save_action(self, rec: ActionRecord) -> None:
        p = t.pending_actions
        await self.conn.execute(
            update(p)
            .where(self._mine(p), p.c.id == rec.id)
            .values(**_values(rec, p, exclude=("id", "tenant_id")))
        )

    async def add_ingest_stats(self, minute: datetime, stats: IngestStats) -> None:
        s = t.ingest_stats
        stmt = pg_insert(s).values(
            tenant_id=self.tenant_id,
            minute=minute,
            messages=stats.messages,
            rejected=stats.rejected,
            replay_rejected=stats.replay_rejected,
            auth_failures=stats.auth_failures,
            connects=stats.connects,
            p99_ms=stats.p99_ms,
        )
        counters = ("messages", "rejected", "replay_rejected", "auth_failures", "connects")
        set_: dict[str, Any] = {k: s.c[k] + stmt.excluded[k] for k in counters}
        set_["p99_ms"] = func.greatest(s.c.p99_ms, stmt.excluded.p99_ms)
        await self.conn.execute(
            stmt.on_conflict_do_update(index_elements=[s.c.tenant_id, s.c.minute], set_=set_)
        )

    async def ingest_stats_since(self, since: datetime) -> IngestStats:
        s = t.ingest_stats
        row = await self._one(
            select(
                func.coalesce(func.sum(s.c.messages), 0).label("messages"),
                func.coalesce(func.sum(s.c.rejected), 0).label("rejected"),
                func.coalesce(func.sum(s.c.replay_rejected), 0).label("replay_rejected"),
                func.coalesce(func.sum(s.c.auth_failures), 0).label("auth_failures"),
                func.coalesce(func.sum(s.c.connects), 0).label("connects"),
                func.coalesce(func.max(s.c.p99_ms), 0).label("p99_ms"),
            ).where(self._mine(s), s.c.minute >= since)
        )
        assert row is not None
        return IngestStats(
            messages=int(row["messages"]),
            rejected=int(row["rejected"]),
            replay_rejected=int(row["replay_rejected"]),
            auth_failures=int(row["auth_failures"]),
            connects=int(row["connects"]),
            p99_ms=float(row["p99_ms"]),
        )


class SqlRepository:
    def __init__(
        self,
        url: str,
        *,
        pool_size: int = 10,
        max_overflow: int = 10,
        connect_args: dict[str, Any] | None = None,
    ) -> None:
        self.engine: AsyncEngine = create_async_engine(
            url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,
            connect_args=connect_args or {},
        )

    @classmethod
    def from_engine(cls, engine: AsyncEngine) -> SqlRepository:
        repo = cls.__new__(cls)
        repo.engine = engine
        return repo

    @asynccontextmanager
    async def tenant(self, tenant_id: str) -> AsyncIterator[SqlTenantTx]:
        tenant_id = str(uuid.UUID(tenant_id))
        async with self.engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('ironmesh.tenant_id', :tenant, true)"),
                {"tenant": tenant_id},
            )
            yield SqlTenantTx(conn, tenant_id)

    async def _scalar(self, sql: str, params: dict[str, Any]) -> Any:
        async with self.engine.begin() as conn:
            return (await conn.execute(text(sql), params)).scalar()

    async def resolve_device_tenant(self, device_id: str) -> str | None:
        value = await self._scalar("SELECT registry_device_tenant(:d)", {"d": device_id})
        return None if value is None else str(value)

    async def lookup_api_key(self, key_hash: bytes) -> ApiKeyRecord | None:
        async with self.engine.begin() as conn:
            row = (
                (
                    await conn.execute(
                        text("SELECT * FROM registry_api_key_lookup(:h)"), {"h": key_hash}
                    )
                )
                .mappings()
                .first()
            )
        if row is None:
            return None
        return _rec(ApiKeyRecord, row, key_hash=bytes(row["key_hash"]), scopes=list(row["scopes"]))

    async def list_tenant_ids(self) -> list[str]:
        async with self.engine.begin() as conn:
            rows = (await conn.execute(text("SELECT registry_tenant_ids()"))).scalars().all()
        return [str(r) for r in rows]

    async def ensure_partitions(self, days_ahead: int) -> int:
        return int(
            await self._scalar("SELECT registry_ensure_telemetry_partitions(:n)", {"n": days_ahead})
        )

    async def drop_partitions(self, retain_days: int) -> int:
        return int(
            await self._scalar("SELECT registry_drop_telemetry_partitions(:n)", {"n": retain_days})
        )

    async def ping(self) -> bool:
        try:
            return bool(await self._scalar("SELECT 1", {}))
        except Exception:
            return False

    async def close(self) -> None:
        await self.engine.dispose()
