"""PostgreSQL repository with row-level security (pgserver locally, service container in CI).

Set ``IRONMESH_TEST_PG_DSN`` to an owner/superuser DSN to use an existing server; otherwise the
pip ``pgserver`` package provides a throwaway server. Tests are skipped when neither works.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from ironmesh_anomaly.models import (
    Alert,
    AlertState,
    AuthEvent,
    AuthKind,
    DeviceEvent,
    ModelMeta,
    QuarantineRecord,
    RuleName,
    RuleOverride,
    Severity,
    SiemSettings,
    Suppression,
    TenantSettings,
    from_ts,
    utcnow,
)
from ironmesh_anomaly.pg_repository import PostgresRepository, migrate
from ironmesh_anomaly.repository import AlertFilter
from tests.support import OTHER_TENANT, T0, TENANT, telemetry_event

pytestmark = pytest.mark.postgres
DEV = "dev-00000000000000aa"


@pytest.fixture(scope="module")
def admin_dsn() -> Iterator[str]:
    dsn = os.environ.get("IRONMESH_TEST_PG_DSN")
    if dsn:
        yield dsn
        return
    try:
        import pgserver
    except ImportError:  # pragma: no cover
        pytest.skip("pgserver not installed and IRONMESH_TEST_PG_DSN not set")
    tmp = tempfile.mkdtemp(prefix="anomaly-pg-")
    try:
        server = pgserver.get_server(tmp, cleanup_mode="stop")  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"pgserver unavailable: {exc}")
    yield server.get_uri()
    server.cleanup()


def app_dsn(admin: str, db: str) -> str:
    parts = urlsplit(admin)
    host = parts.hostname or "127.0.0.1"
    netloc = f"anomaly_app:app-pw@{host}:{parts.port or 5432}"
    return urlunsplit((parts.scheme, netloc, f"/{db}", parts.query, ""))


@pytest.fixture
async def repo(admin_dsn: str) -> AsyncIterator[PostgresRepository]:
    db = f"anomaly_{uuid.uuid4().hex[:8]}"
    conn = await asyncpg.connect(admin_dsn)
    await conn.execute(f'CREATE DATABASE "{db}"')
    await conn.close()
    parts = urlsplit(admin_dsn)
    db_admin = urlunsplit((parts.scheme, parts.netloc, f"/{db}", parts.query, ""))
    await migrate(db_admin)
    await migrate(db_admin)  # idempotent
    conn = await asyncpg.connect(db_admin)
    await conn.execute("ALTER ROLE anomaly_app LOGIN PASSWORD 'app-pw'")
    await conn.close()
    r = await PostgresRepository.connect(app_dsn(admin_dsn, db), max_size=2)
    try:
        yield r
    finally:
        await r.close()
        conn = await asyncpg.connect(admin_dsn)
        await conn.execute(f'DROP DATABASE "{db}" WITH (FORCE)')
        await conn.close()


def alert(
    tenant: str = TENANT, device: str = DEV, rule: RuleName = RuleName.AUTH_BURST, offset: float = 0
) -> Alert:
    now = utcnow() + timedelta(seconds=offset)
    return Alert(
        str(uuid.uuid4()),
        tenant,
        device,
        rule,
        Severity.HIGH,
        0.5,
        {"n": 1},
        "x",
        now,
        last_seen_at=now,
    )


async def test_alert_crud_filters_pagination(repo: PostgresRepository) -> None:
    alerts = [alert(device=f"dev-{i:016x}", offset=i) for i in range(5)]
    for a in alerts:
        await repo.insert_alert(a)
    await repo.insert_alert(alert(OTHER_TENANT))
    got = await repo.get_alert(TENANT, alerts[0].id)
    assert got is not None and got.to_api() == alerts[0].to_api()
    page, cur = await repo.list_alerts(TENANT, AlertFilter(), None, 2)
    assert [a.id for a in page] == [alerts[4].id, alerts[3].id] and cur is not None
    page2, cur2 = await repo.list_alerts(TENANT, AlertFilter(), cur, 10)
    assert [a.id for a in page2] == [a.id for a in reversed(alerts[:3])] and cur2 is None
    flt = AlertFilter(
        AlertState.OPEN,
        Severity.HIGH,
        RuleName.AUTH_BURST,
        alerts[1].device_id,
        alerts[0].created_at,
        alerts[4].created_at,
    )
    assert [a.id for a in (await repo.list_alerts(TENANT, flt, None, 10))[0]] == [alerts[1].id]
    a = alerts[1]
    a.state = AlertState.RESOLVED
    a.resolved_at = utcnow()
    await repo.update_alert(a)
    assert (
        await repo.find_active_alert(
            TENANT, a.device_id, a.rule, a.created_at - timedelta(minutes=1)
        )
        is None
    )
    active = await repo.find_active_alert(
        TENANT,
        alerts[2].device_id,
        RuleName.AUTH_BURST,
        alerts[2].created_at - timedelta(minutes=1),
    )
    assert active is not None and active.id == alerts[2].id
    assert len(await repo.alerts_since(TENANT, utcnow() - timedelta(days=1))) == 5
    counts = await repo.open_alert_counts(TENANT)
    assert counts[Severity.HIGH] == 4
    ghost = alert()
    with pytest.raises(KeyError):
        await repo.update_alert(ghost)


async def test_row_level_security_isolates_tenants(repo: PostgresRepository) -> None:
    mine = alert()
    await repo.insert_alert(mine)
    assert await repo.get_alert(OTHER_TENANT, mine.id) is None
    assert (await repo.list_alerts(OTHER_TENANT, AlertFilter(), None, 10))[0] == []
    # the app role cannot bypass RLS even with a hand-written query
    async with repo._pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM alerts") == 0  # no tenant set -> no rows
        async with conn.transaction():
            await conn.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", OTHER_TENANT)
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    "INSERT INTO alerts (tenant_id, id, device_id, rule, severity, state, created_at, last_seen_at, record)"
                    " VALUES ($1::uuid, $2::uuid, 'd', 'r', 's', 'open', now(), now(), '{}'::jsonb)",
                    TENANT,
                    str(uuid.uuid4()),
                )
        assert (
            await conn.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
            is False
        )


async def test_settings_rules_quarantine_suppression(repo: PostgresRepository) -> None:
    assert await repo.get_settings(TENANT) is None
    s = TenantSettings(
        True, Severity.CRITICAL, SiemSettings("https://siem.example.com", "h", 6514, True)
    )
    await repo.put_settings(TENANT, s)
    await repo.put_settings(TENANT, s)
    assert await repo.get_settings(TENANT) == s
    assert await repo.get_settings(OTHER_TENANT) is None
    await repo.put_rule_override(
        TENANT, RuleName.AUTH_BURST, RuleOverride(enabled=False, params={"threshold": 3})
    )
    await repo.put_rule_override(
        TENANT, RuleName.AUTH_BURST, RuleOverride(dry_run=True, params={"threshold": 4})
    )
    ov = await repo.get_rule_overrides(TENANT)
    assert ov[RuleName.AUTH_BURST].params == {"threshold": 4} and ov[RuleName.AUTH_BURST].dry_run
    assert await repo.get_rule_overrides(OTHER_TENANT) == {}
    for i in range(3):
        await repo.add_quarantine(
            QuarantineRecord(TENANT, f"dev-{i:016x}", from_ts(T0 + i), "r", None, "auto")
        )
    await repo.add_quarantine(
        QuarantineRecord(
            TENANT, "dev-0000000000000000", from_ts(T0 + 10), "again", str(uuid.uuid4()), "user:1"
        )
    )
    page, cur = await repo.list_quarantine(TENANT, None, 2)
    assert [r.device_id for r in page] == ["dev-0000000000000000", "dev-0000000000000002"] and cur
    rest, cur2 = await repo.list_quarantine(TENANT, cur, 2)
    assert [r.device_id for r in rest] == ["dev-0000000000000001"] and cur2 is None
    await repo.remove_quarantine(TENANT, "dev-0000000000000001")
    assert await repo.quarantined_devices(TENANT) == {
        "dev-0000000000000000",
        "dev-0000000000000002",
    }
    assert await repo.get_suppression(TENANT, DEV, RuleName.BEACONING) is None
    sup = Suppression(TENANT, DEV, RuleName.BEACONING, utcnow(), 1, "user:1")
    await repo.put_suppression(sup)
    sup.count = 2
    await repo.put_suppression(sup)
    got = await repo.get_suppression(TENANT, DEV, RuleName.BEACONING)
    assert got is not None and got.count == 2


async def test_events_states_models(repo: PostgresRepository) -> None:
    events: list[DeviceEvent] = [telemetry_event(DEV, T0 + i, seq=i) for i in range(3)]
    events.append(AuthEvent(OTHER_TENANT, DEV, T0, AuthKind.CONNECTED, "1.1.1.1"))
    await repo.store_events(events)
    got = await repo.events_between(TENANT, from_ts(T0), from_ts(T0 + 10), 10)
    assert got == events[:3]
    assert await repo.events_between(OTHER_TENANT, from_ts(T0), from_ts(T0 + 10), 10) == events[3:]
    assert await repo.purge_events(from_ts(T0 + 1.5)) == 3
    await repo.save_states(TENANT, [])
    await repo.save_states(TENANT, [{"device_id": DEV, "tenant_id": TENANT, "x": 1}])
    await repo.save_states(TENANT, [{"device_id": DEV, "tenant_id": TENANT, "x": 2}])
    assert await repo.load_states(TENANT) == [{"device_id": DEV, "tenant_id": TENANT, "x": 2}]
    assert set(await repo.tenants()) == {TENANT, OTHER_TENANT}
    for i, v in enumerate(("v1", "v2")):
        await repo.save_model_meta(
            ModelMeta(TENANT, "gateway-rpi", v, "a" * 64, from_ts(T0 + i), 100, {"devices": 3})
        )
    latest = await repo.latest_models(TENANT)
    assert [(m.version, m.metadata) for m in latest] == [("v2", {"devices": 3})]
    with pytest.raises(asyncpg.CheckViolationError):
        await repo.save_model_meta(ModelMeta(TENANT, "c", "v", "not-hex", from_ts(T0), 1))
