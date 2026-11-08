"""PostgreSQL :class:`~.repository.Repository` (asyncpg) with row-level security per transaction."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import asyncpg
from asyncpg.pool import PoolConnectionProxy

from .models import (
    Alert,
    DeviceEvent,
    ModelMeta,
    QuarantineRecord,
    RuleName,
    RuleOverride,
    Severity,
    Suppression,
    TenantSettings,
    event_from_dict,
    event_to_dict,
    from_ts,
)
from .repository import AlertFilter, Cursor

type Conn = asyncpg.Connection[Any] | PoolConnectionProxy[Any]


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


def migration_sql() -> str:
    return (resources.files("ironmesh_anomaly") / "migrations" / "001_init.sql").read_text("utf-8")


async def migrate(dsn: str) -> None:
    """Apply the schema (run with the owner/migration role, never the app role)."""
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(migration_sql())
    finally:
        await conn.close()


class PostgresRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @classmethod
    async def connect(
        cls,
        dsn: str,
        max_size: int = 10,
        password: Callable[[], Awaitable[str]] | None = None,
    ) -> PostgresRepository:
        """``password`` (e.g. an RDS IAM token minter) is called for every new connection."""
        kwargs: dict[str, Any] = {"password": password} if password is not None else {}
        pool = await asyncpg.create_pool(
            dsn, min_size=1, max_size=max_size, init=_init_connection, **kwargs
        )
        return cls(pool)

    async def close(self) -> None:
        await self._pool.close()

    @asynccontextmanager
    async def _tx(self, tenant_id: str) -> AsyncIterator[Conn]:
        async with self._pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", tenant_id)
            yield conn

    async def _touch(self, conn: Conn, tenant_id: str) -> None:
        await conn.execute(
            "INSERT INTO anomaly_tenants (tenant_id) VALUES ($1::uuid) ON CONFLICT DO NOTHING",
            tenant_id,
        )

    # -- alerts ------------------------------------------------------------------------------
    @staticmethod
    def _alert_args(a: Alert) -> tuple[Any, ...]:
        return (
            a.tenant_id,
            a.id,
            a.device_id,
            a.rule.value,
            a.severity.value,
            a.state.value,
            a.created_at,
            a.last_seen_at or a.created_at,
            a.to_record(),
        )

    async def insert_alert(self, alert: Alert) -> None:
        async with self._tx(alert.tenant_id) as conn:
            await self._touch(conn, alert.tenant_id)
            await conn.execute(
                "INSERT INTO alerts (tenant_id, id, device_id, rule, severity, state, created_at,"
                " last_seen_at, record) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)",
                *self._alert_args(alert),
            )

    async def update_alert(self, alert: Alert) -> None:
        async with self._tx(alert.tenant_id) as conn:
            status = await conn.execute(
                "UPDATE alerts SET device_id=$3, rule=$4, severity=$5, state=$6, created_at=$7,"
                " last_seen_at=$8, record=$9 WHERE tenant_id=$1::uuid AND id=$2::uuid",
                *self._alert_args(alert),
            )
            if status.endswith(" 0"):
                raise KeyError(alert.id)

    async def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None:
        async with self._tx(tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT record FROM alerts WHERE tenant_id=$1::uuid AND id=$2::uuid",
                tenant_id,
                alert_id,
            )
        return Alert.from_record(row["record"]) if row else None

    async def find_active_alert(
        self, tenant_id: str, device_id: str, rule: RuleName, since: datetime
    ) -> Alert | None:
        async with self._tx(tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT record FROM alerts WHERE tenant_id=$1::uuid AND device_id=$2 AND rule=$3"
                " AND state <> 'resolved' AND last_seen_at >= $4"
                " ORDER BY created_at DESC LIMIT 1",
                tenant_id,
                device_id,
                rule.value,
                since,
            )
        return Alert.from_record(row["record"]) if row else None

    async def list_alerts(
        self, tenant_id: str, flt: AlertFilter, cursor: Cursor | None, limit: int
    ) -> tuple[list[Alert], Cursor | None]:
        where = ["tenant_id = $1::uuid"]
        args: list[Any] = [tenant_id]

        def add(clause: str, value: Any) -> None:
            args.append(value)
            where.append(clause.replace("?", f"${len(args)}"))

        if flt.state is not None:
            add("state = ?", flt.state.value)
        if flt.severity is not None:
            add("severity = ?", flt.severity.value)
        if flt.rule is not None:
            add("rule = ?", flt.rule.value)
        if flt.device_id is not None:
            add("device_id = ?", flt.device_id)
        if flt.from_ is not None:
            add("created_at >= ?", flt.from_)
        if flt.to is not None:
            add("created_at <= ?", flt.to)
        if cursor is not None:
            args.extend([cursor[0], cursor[1]])
            where.append(f"(created_at, id) < (${len(args) - 1}, ${len(args)}::uuid)")
        args.append(limit + 1)
        sql = (
            "SELECT record FROM alerts WHERE "  # noqa: S608 constant clauses  # nosec B608
            + " AND ".join(where)
            + f" ORDER BY created_at DESC, id DESC LIMIT ${len(args)}"
        )
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(sql, *args)
        alerts = [Alert.from_record(r["record"]) for r in rows[:limit]]
        nxt = (alerts[-1].created_at, alerts[-1].id) if len(rows) > limit and alerts else None
        return alerts, nxt

    async def alerts_since(self, tenant_id: str, since: datetime) -> list[Alert]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT record FROM alerts WHERE tenant_id=$1::uuid AND"
                " (state <> 'resolved' OR created_at >= $2)",
                tenant_id,
                since,
            )
        return [Alert.from_record(r["record"]) for r in rows]

    async def open_alert_counts(self, tenant_id: str) -> dict[Severity, int]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT severity, count(*) AS n FROM alerts WHERE tenant_id=$1::uuid"
                " AND state <> 'resolved' GROUP BY severity",
                tenant_id,
            )
        counts = dict.fromkeys(Severity, 0)
        for r in rows:
            counts[Severity(r["severity"])] = int(r["n"])
        return counts

    # -- rules / settings -------------------------------------------------------------------
    async def get_rule_overrides(self, tenant_id: str) -> dict[RuleName, RuleOverride]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT name, override FROM rule_overrides WHERE tenant_id=$1::uuid", tenant_id
            )
        return {
            RuleName(r["name"]): RuleOverride.from_dict(r["override"])
            for r in rows
            if r["name"] in RuleName._value2member_map_
        }

    async def put_rule_override(
        self, tenant_id: str, name: RuleName, override: RuleOverride
    ) -> None:
        async with self._tx(tenant_id) as conn:
            await self._touch(conn, tenant_id)
            await conn.execute(
                "INSERT INTO rule_overrides (tenant_id, name, override) VALUES ($1::uuid, $2, $3)"
                " ON CONFLICT (tenant_id, name) DO UPDATE SET override=EXCLUDED.override,"
                " updated_at=now()",
                tenant_id,
                name.value,
                override.to_dict(),
            )

    async def get_settings(self, tenant_id: str) -> TenantSettings | None:
        async with self._tx(tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT settings FROM tenant_settings WHERE tenant_id=$1::uuid", tenant_id
            )
        return TenantSettings.from_api(row["settings"]) if row else None

    async def put_settings(self, tenant_id: str, settings: TenantSettings) -> None:
        async with self._tx(tenant_id) as conn:
            await self._touch(conn, tenant_id)
            await conn.execute(
                "INSERT INTO tenant_settings (tenant_id, settings) VALUES ($1::uuid, $2)"
                " ON CONFLICT (tenant_id) DO UPDATE SET settings=EXCLUDED.settings,"
                " updated_at=now()",
                tenant_id,
                settings.to_api(),
            )

    # -- quarantine / suppression -----------------------------------------------------------
    async def add_quarantine(self, record: QuarantineRecord) -> None:
        async with self._tx(record.tenant_id) as conn:
            await self._touch(conn, record.tenant_id)
            await conn.execute(
                "INSERT INTO quarantine_records (tenant_id, device_id, quarantined_at, reason,"
                " alert_id, by_actor) VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6)"
                " ON CONFLICT (tenant_id, device_id) DO UPDATE SET"
                " quarantined_at=EXCLUDED.quarantined_at, reason=EXCLUDED.reason,"
                " alert_id=EXCLUDED.alert_id, by_actor=EXCLUDED.by_actor",
                record.tenant_id,
                record.device_id,
                record.quarantined_at,
                record.reason,
                record.alert_id,
                record.by,
            )

    async def remove_quarantine(self, tenant_id: str, device_id: str) -> None:
        async with self._tx(tenant_id) as conn:
            await conn.execute(
                "DELETE FROM quarantine_records WHERE tenant_id=$1::uuid AND device_id=$2",
                tenant_id,
                device_id,
            )

    async def list_quarantine(
        self, tenant_id: str, cursor: Cursor | None, limit: int
    ) -> tuple[list[QuarantineRecord], Cursor | None]:
        args: list[Any] = [tenant_id]
        clause = ""
        if cursor is not None:
            args.extend([cursor[0], cursor[1]])
            clause = " AND (quarantined_at, device_id) < ($2, $3)"
        args.append(limit + 1)
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT device_id, quarantined_at, reason, alert_id::text AS alert_id, by_actor"  # noqa: S608 constant  # nosec B608
                " FROM quarantine_records WHERE tenant_id=$1::uuid"
                + clause
                + f" ORDER BY quarantined_at DESC, device_id DESC LIMIT ${len(args)}",
                *args,
            )
        records = [
            QuarantineRecord(
                tenant_id=tenant_id,
                device_id=r["device_id"],
                quarantined_at=r["quarantined_at"],
                reason=r["reason"],
                alert_id=r["alert_id"],
                by=r["by_actor"],
            )
            for r in rows[:limit]
        ]
        nxt = (
            (records[-1].quarantined_at, records[-1].device_id)
            if len(rows) > limit and records
            else None
        )
        return records, nxt

    async def quarantined_devices(self, tenant_id: str) -> set[str]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT device_id FROM quarantine_records WHERE tenant_id=$1::uuid", tenant_id
            )
        return {r["device_id"] for r in rows}

    async def get_suppression(
        self, tenant_id: str, device_id: str, rule: RuleName
    ) -> Suppression | None:
        async with self._tx(tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT until, count, created_by FROM suppressions WHERE tenant_id=$1::uuid"
                " AND device_id=$2 AND rule=$3",
                tenant_id,
                device_id,
                rule.value,
            )
        if row is None:
            return None
        return Suppression(
            tenant_id=tenant_id,
            device_id=device_id,
            rule=rule,
            until=row["until"],
            count=row["count"],
            created_by=row["created_by"],
        )

    async def put_suppression(self, suppression: Suppression) -> None:
        async with self._tx(suppression.tenant_id) as conn:
            await conn.execute(
                "INSERT INTO suppressions (tenant_id, device_id, rule, until, count, created_by)"
                " VALUES ($1::uuid, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, device_id, rule)"
                " DO UPDATE SET until=EXCLUDED.until, count=EXCLUDED.count,"
                " created_by=EXCLUDED.created_by",
                suppression.tenant_id,
                suppression.device_id,
                suppression.rule.value,
                suppression.until,
                suppression.count,
                suppression.created_by,
            )

    # -- events / states / models -----------------------------------------------------------
    async def store_events(self, events: list[DeviceEvent]) -> None:
        by_tenant: dict[str, list[DeviceEvent]] = {}
        for e in events:
            by_tenant.setdefault(e.tenant_id, []).append(e)
        for tenant_id, items in by_tenant.items():
            async with self._tx(tenant_id) as conn:
                await self._touch(conn, tenant_id)
                await conn.executemany(
                    "INSERT INTO device_events (tenant_id, ts, device_id, kind, data)"
                    " VALUES ($1::uuid, $2, $3, $4, $5)",
                    [
                        (tenant_id, from_ts(e.ts), e.device_id, e.kind, event_to_dict(e))
                        for e in items
                    ],
                )

    async def events_between(
        self, tenant_id: str, start: datetime, end: datetime, limit: int
    ) -> list[DeviceEvent]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT data FROM device_events WHERE tenant_id=$1::uuid AND ts >= $2 AND ts <= $3"
                " ORDER BY ts LIMIT $4",
                tenant_id,
                start,
                end,
                limit,
            )
        return [event_from_dict(r["data"]) for r in rows]

    async def purge_events(self, before: datetime) -> int:
        removed = 0
        for tenant_id in await self.tenants():
            async with self._tx(tenant_id) as conn:
                status = await conn.execute(
                    "DELETE FROM device_events WHERE tenant_id=$1::uuid AND ts < $2",
                    tenant_id,
                    before,
                )
            removed += int(status.split()[-1])
        return removed

    async def save_states(self, tenant_id: str, states: list[dict[str, Any]]) -> None:
        if not states:
            return
        async with self._tx(tenant_id) as conn:
            await self._touch(conn, tenant_id)
            await conn.executemany(
                "INSERT INTO device_states (tenant_id, device_id, state) VALUES ($1::uuid, $2, $3)"
                " ON CONFLICT (tenant_id, device_id) DO UPDATE SET state=EXCLUDED.state,"
                " updated_at=now()",
                [(tenant_id, s["device_id"], s) for s in states],
            )

    async def load_states(self, tenant_id: str) -> list[dict[str, Any]]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT state FROM device_states WHERE tenant_id=$1::uuid", tenant_id
            )
        return [r["state"] for r in rows]

    async def tenants(self) -> list[str]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT tenant_id::text AS t FROM anomaly_tenants ORDER BY 1")
        return [r["t"] for r in rows]

    async def save_model_meta(self, meta: ModelMeta) -> None:
        async with self._tx(meta.tenant_id) as conn:
            await self._touch(conn, meta.tenant_id)
            await conn.execute(
                "INSERT INTO models (tenant_id, device_class, version, sha256_hex, trained_at,"
                " samples, metadata) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)",
                meta.tenant_id,
                meta.device_class,
                meta.version,
                meta.sha256_hex,
                meta.trained_at,
                meta.samples,
                meta.metadata,
            )

    async def latest_models(self, tenant_id: str) -> list[ModelMeta]:
        async with self._tx(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT ON (device_class) device_class, version, sha256_hex, trained_at,"
                " samples, metadata FROM models WHERE tenant_id=$1::uuid"
                " ORDER BY device_class, trained_at DESC",
                tenant_id,
            )
        return [
            ModelMeta(
                tenant_id=tenant_id,
                device_class=r["device_class"],
                version=r["version"],
                sha256_hex=r["sha256_hex"],
                trained_at=r["trained_at"].astimezone(UTC),
                samples=r["samples"],
                metadata=r["metadata"],
            )
            for r in rows
        ]


__all__ = ["PostgresRepository", "migrate", "migration_sql"]
