"""Database-level tenancy: RLS policies, grants, append-only audit, definer functions, partitions.

These run as ``registry_app`` with raw SQL and **no** ``tenant_id`` filters, so they prove that
the policies themselves (not the repository's defensive filters) isolate tenants.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import asyncpg
import pytest

from app.auth import hash_api_key
from app.repo.base import Repository

from .conftest import PgUrls

pytestmark = pytest.mark.postgres

TABLES = (
    "tenants",
    "tenant_keys",
    "devices",
    "certificates",
    "groups",
    "group_members",
    "twins",
    "commands",
    "device_configs",
    "timeline_events",
    "telemetry_samples",
    "device_replay",
    "alerts",
    "audit_events",
    "audit_heads",
    "users",
    "api_keys",
    "pending_actions",
    "ingest_stats",
    "downlink_sequences",
)


@pytest.fixture
async def db(pg: PgUrls | None) -> AsyncIterator[tuple[asyncpg.Connection, asyncpg.Connection]]:
    if pg is None:
        pytest.skip("PostgreSQL not available")
    app_conn = await asyncpg.connect(pg.app)
    owner_conn = await asyncpg.connect(pg.owner)
    yield app_conn, owner_conn
    await app_conn.close()
    await owner_conn.close()


async def _seed_tenant(conn: asyncpg.Connection, tenant: str) -> str:
    device = "dev-" + uuid.uuid4().hex[:16]
    async with conn.transaction():
        await conn.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", tenant)
        await conn.execute(
            "INSERT INTO tenants (tenant_id, name) VALUES ($1, 'x')", uuid.UUID(tenant)
        )
        await conn.execute(
            "INSERT INTO devices (id, tenant_id, product, hw_revision, state) "
            "VALUES ($1, $2, 'p', '1', 'active')",
            device,
            uuid.UUID(tenant),
        )
        await conn.execute(
            "INSERT INTO audit_events (tenant_id, seq, id, at, actor_type, actor_id, action, "
            "target_type, target_id, outcome, body, prev_hash, hash) VALUES ($1, 1, $2, now(), "
            "'system', 's', 'a', 't', 'i', 'success', '{}', '\\x00', '\\x00')",
            uuid.UUID(tenant),
            uuid.uuid4(),
        )
        await conn.execute(
            "INSERT INTO api_keys (id, tenant_id, name, prefix, key_hash, role) "
            "VALUES ($1, $2, 'k', 'imk_', $3, 'viewer')",
            uuid.uuid4(),
            uuid.UUID(tenant),
            hash_api_key(f"imk_{tenant}"),
        )
    return device


async def test_policies_forced_on_every_tenant_table(db: tuple[asyncpg.Connection, ...]) -> None:
    _, owner = db
    rows = await owner.fetch(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relname = ANY($1::text[]) AND relkind IN ('r', 'p')",
        list(TABLES),
    )
    assert {r["relname"] for r in rows} == set(TABLES)
    assert all(r["relrowsecurity"] and r["relforcerowsecurity"] for r in rows)
    policies = await owner.fetch(
        "SELECT tablename, qual, roles FROM pg_policies WHERE policyname = 'tenant_isolation'"
    )
    assert {p["tablename"] for p in policies} == set(TABLES)
    for p in policies:
        assert "current_setting('ironmesh.tenant_id'::text)" in p["qual"]
        assert list(p["roles"]) == ["registry_app"]
    role = await owner.fetchrow(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'registry_app'"
    )
    assert role is not None and not role["rolsuper"] and not role["rolbypassrls"]


async def test_rls_isolates_tenants(db: tuple[asyncpg.Connection, ...]) -> None:
    app, _ = db
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    dev_a = await _seed_tenant(app, a)
    dev_b = await _seed_tenant(app, b)
    async with app.transaction():
        await app.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", a)
        visible = {r["id"] for r in await app.fetch("SELECT id FROM devices")}
        assert dev_a in visible and dev_b not in visible
        assert await app.fetchval("SELECT count(*) FROM tenants") == 1
        assert (
            await app.fetchval(
                "SELECT count(*) FROM audit_events WHERE tenant_id = $1", uuid.UUID(b)
            )
            == 0
        )
        # updates/deletes of B's rows silently affect nothing
        assert (
            await app.execute("UPDATE devices SET state = 'quarantined' WHERE id = $1", dev_b)
            == "UPDATE 0"
        )
        assert (
            await app.execute("DELETE FROM api_keys WHERE tenant_id = $1", uuid.UUID(b))
            == "DELETE 0"
        )
    # writing a row for B while scoped to A violates WITH CHECK
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with app.transaction():
            await app.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", a)
            await app.execute(
                "INSERT INTO groups (tenant_id, slug, name) VALUES ($1, 'evil', 'x')", uuid.UUID(b)
            )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with app.transaction():
            await app.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", a)
            await app.execute(
                "UPDATE devices SET tenant_id = $1 WHERE id = $2", uuid.UUID(b), dev_a
            )


async def test_unset_tenant_fails_closed(db: tuple[asyncpg.Connection, ...]) -> None:
    app, _ = db
    with pytest.raises(asyncpg.PostgresError):
        await app.fetch("SELECT * FROM devices")
    # after a SET LOCAL transaction the setting is '' on this session: still fails closed
    async with app.transaction():
        await app.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", str(uuid.uuid4()))
    with pytest.raises(asyncpg.PostgresError):
        await app.fetch("SELECT * FROM devices")


async def test_audit_is_append_only(db: tuple[asyncpg.Connection, ...]) -> None:
    app, owner = db
    t = str(uuid.uuid4())
    await _seed_tenant(app, t)
    for sql in (
        "UPDATE audit_events SET action = 'x'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with app.transaction():
                await app.execute("SELECT set_config('ironmesh.tenant_id', $1, true)", t)
                await app.execute(sql)
    # the trigger also blocks the owner unless explicitly disabled
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        await owner.execute(
            "UPDATE audit_events SET action = 'x' WHERE tenant_id = $1", uuid.UUID(t)
        )


async def test_security_definer_functions(
    db: tuple[asyncpg.Connection, ...], pg_repo: Repository | None
) -> None:
    app, _ = db
    t = str(uuid.uuid4())
    device = await _seed_tenant(app, t)
    assert str(await app.fetchval("SELECT registry_device_tenant($1)", device)) == t
    assert await app.fetchval("SELECT registry_device_tenant('dev-0000000000000000')") is None
    row = await app.fetchrow("SELECT * FROM registry_api_key_lookup($1)", hash_api_key(f"imk_{t}"))
    assert row is not None and str(row["tenant_id"]) == t
    assert t in {str(x[0]) for x in await app.fetch("SELECT * FROM registry_tenant_ids()")}
    assert pg_repo is not None
    assert await pg_repo.resolve_device_tenant(device) == t
    assert await pg_repo.ensure_partitions(5) >= 0
    assert await pg_repo.drop_partitions(30) >= 0
    assert await pg_repo.ping() is True


async def test_tampering_with_db_rows_is_detected(
    db: tuple[asyncpg.Connection, ...], pg_repo: Repository | None
) -> None:
    from app.auth import Principal
    from app.domain import AuditDraft
    from app.jsonutil import utcnow
    from app.services import admin

    from .conftest import build_env

    _, owner = db
    assert pg_repo is not None
    t = str(uuid.uuid4())
    async with pg_repo.tenant(t) as tx:
        from app.domain import TenantRecord

        await tx.insert_tenant(TenantRecord(id=t, name="x", settings={}, created_at=utcnow()))
        for i in range(3):
            await tx.append_audit(
                AuditDraft(
                    tenant_id=t,
                    at=utcnow(),
                    actor_type="system",
                    actor_id="s",
                    actor_name=None,
                    action=f"a{i}",
                    target_type="t",
                    target_id=str(i),
                )
            )
    import tempfile
    from pathlib import Path

    env = build_env("postgres", pg_repo, Path(tempfile.mkdtemp()))
    p = Principal(tenant_id=t, actor_type="user", actor_id="admin", role="admin")
    assert (await admin.verify_audit(env.ctx, p)).ok is True
    await owner.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update")
    try:
        await owner.execute(
            "UPDATE audit_events SET body = replace(body, 'a1', 'zz') "
            "WHERE tenant_id = $1 AND seq = 2",
            uuid.UUID(t),
        )
    finally:
        await owner.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update")
    result = await admin.verify_audit(env.ctx, p)
    assert result.ok is False and result.first_invalid_seq == 2
    await env.client.aclose()
