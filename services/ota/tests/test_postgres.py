"""PostgreSQL: migrations, FORCE RLS isolation under the ``ota_app`` role, the SQL repository
contract (shared with the in-memory fake) and the advisory-lock leader election.

Runs against ``OTA_TEST_DATABASE_URL`` (CI service container, owner role) or a throw-away local
server from the ``pgserver`` wheel; skipped when neither is available.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import create_async_engine

from ironmesh_ota import migrate
from ironmesh_ota.domain import (
    Actor,
    AuditEvent,
    Campaign,
    CampaignDevice,
    CampaignState,
    DeltaArtifact,
    DeviceState,
    Firmware,
    IdempotencyRecord,
    Severity,
    Stage,
    Target,
)
from ironmesh_ota.integrations.leader import PostgresAdvisoryLock
from ironmesh_ota.pagination import InvalidCursor
from ironmesh_ota.repository.base import Database, RepositoryConflict
from ironmesh_ota.repository.memory import MemoryDatabase
from ironmesh_ota.repository.sql import SqlDatabase

from .conftest import Clock, Keys, device_id, image_bytes, make_env, new_tenant, pg_available

pytestmark = pytest.mark.postgres


def _asyncpg(url: str) -> str:
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


@pytest.fixture(scope="session")
def pg_urls(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, str]]:
    """``(owner_url, app_url)`` for a freshly migrated database."""
    if not pg_available():
        pytest.skip("no PostgreSQL available (set OTA_TEST_DATABASE_URL or install pgserver)")
    server = None
    base = os.environ.get("OTA_TEST_DATABASE_URL")
    if base is None:
        import pgserver

        server = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")  # type: ignore[attr-defined]
        base = server.get_uri()
    owner = _asyncpg(base)
    db_name = f"ota_test_{uuid.uuid4().hex[:8]}"

    import asyncio

    async def prepare() -> None:
        engine = create_async_engine(owner, isolation_level="AUTOCOMMIT")
        async with engine.connect() as conn:
            await conn.execute(text(f'CREATE DATABASE "{db_name}"'))
        await engine.dispose()

    owner_db = owner.rsplit("/", 1)[0] + f"/{db_name}"
    # Per-session password: a server with password auth on TCP (the CI service container) needs
    # one, a trust-auth server (pgserver) ignores it. Hex only, so it is safe inside the SQL.
    app_password = secrets.token_hex(16)

    async def grant_login() -> None:
        engine = create_async_engine(owner_db, isolation_level="AUTOCOMMIT")
        async with engine.connect() as conn:
            await conn.execute(text(f"ALTER ROLE ota_app LOGIN PASSWORD '{app_password}'"))
            await conn.execute(text(f'GRANT CONNECT ON DATABASE "{db_name}" TO ota_app'))
        await engine.dispose()

    def setup() -> None:  # own thread: the fixture may be requested from a running loop
        asyncio.run(prepare())
        migrate.upgrade(owner_db)
        asyncio.run(grant_login())

    with ThreadPoolExecutor(1) as pool:
        pool.submit(setup).result()
    host = owner_db.split("@", 1)[1]
    app = f"postgresql+asyncpg://ota_app:{app_password}@{host}"
    yield owner_db, app
    if server is not None:
        server.cleanup()


@pytest.fixture
async def sql_db(pg_urls: tuple[str, str]) -> AsyncIterator[SqlDatabase]:
    db = SqlDatabase.from_url(pg_urls[1], pool_size=2)
    yield db
    await db.close()


@pytest.fixture(params=["memory", "sql"])
async def any_db(request: pytest.FixtureRequest) -> AsyncIterator[Database]:
    if request.param == "memory":
        yield MemoryDatabase()
        return
    pg_urls = request.getfixturevalue("pg_urls")
    db = SqlDatabase.from_url(pg_urls[1], pool_size=2)
    yield db
    await db.close()


def _fw(tenant: uuid.UUID, code: int, sha: bytes, *, product: str = "gw", at: datetime) -> Firmware:
    return Firmware(
        id=uuid.uuid4(),
        tenant_id=tenant,
        product=product,
        version=f"1.0.{code}",
        version_code=code,
        sha256=sha,
        size=10,
        min_version_code=0,
        created_at=at,
        created_by="user:x",
        manifest=b"m",
        signed_manifest=b"s",
        signing_key_id="k",
        pq_signed=False,
        notes=None,
        severity=Severity.NORMAL,
        image_key="i",
        manifest_key="m",
        signature_key="s",
    )


async def test_repository_contract(any_db: Database) -> None:
    tenant, other = new_tenant(), new_tenant()
    now = datetime.now(UTC).replace(microsecond=0)
    sha = [bytes([i]) * 32 for i in range(4)]
    async with any_db.tenant(tenant) as repo:
        await repo.lock_product("gw")
        assert await repo.max_version_code("gw") is None
        fws = [_fw(tenant, c, sha[c], at=now + timedelta(seconds=c)) for c in range(1, 4)]
        for fw in fws:
            await repo.add_firmware(fw)
        assert await repo.max_version_code("gw") == 3
        assert await repo.version_exists("gw", "1.0.2")
        assert not await repo.version_exists("gw", "9.9.9")
        got = await repo.get_firmware(fws[0].id)
        assert got is not None and got.sha256 == sha[1]
        by_hash = await repo.get_firmware_by_hash(sha[2])
        assert by_hash is not None and by_hash.version_code == 2
        assert await repo.get_firmware_by_hash(b"\xff" * 32) is None
        assert await repo.firmware_hashes("gw") == sorted(sha[1:])
        assert len(await repo.firmware_hashes(None)) == 3
        assert set(await repo.firmware_by_hashes("gw", [sha[1], sha[3]])) == {sha[1], sha[3]}
        assert await repo.firmware_by_hashes("gw", []) == {}
        page = await repo.list_firmware("gw", None, 2)
        assert [f.version_code for f in page.items] == [3, 2] and page.next_cursor
        page2 = await repo.list_firmware(None, page.next_cursor, 2)
        assert [f.version_code for f in page2.items] == [1] and page2.next_cursor is None

        delta = DeltaArtifact(
            uuid.uuid4(), tenant, fws[2].id, sha[1], b"\x09" * 32, 5, "p", b"sig", now
        )
        await repo.add_delta(delta)
        stored = await repo.get_delta(fws[2].id, sha[1])
        assert stored is not None and stored.patch_size == 5
        assert await repo.get_delta(fws[2].id, sha[2]) is None

        campaign = Campaign(
            id=uuid.uuid4(),
            tenant_id=tenant,
            name="c",
            firmware_id=fws[2].id,
            target=Target(groups=["g"]),
            delta=True,
            severity=Severity.SECURITY,
            stages=[Stage(0, 50, 60, 0.1), Stage(1, 100, 0, 0.1)],
            current_stage=0,
            state=CampaignState.DRAFT,
            halt_reason=None,
            created_by="user:x",
            created_at=now,
            started_at=None,
            finished_at=None,
            parent_campaign_id=None,
            requires_approval=True,
            updated_at=now,
        )
        await repo.add_campaign(campaign)
        campaign.state = CampaignState.RUNNING
        campaign.stages[0].dwell_started_at = now
        await repo.update_campaign(campaign)
        loaded = await repo.get_campaign(campaign.id, for_update=True)
        assert loaded is not None and loaded.state is CampaignState.RUNNING
        assert loaded.stages[0].dwell_started_at == now and loaded.target.groups == ["g"]
        assert await repo.get_campaign(uuid.uuid4()) is None
        listed = await repo.list_campaigns([CampaignState.RUNNING], None, 10)
        assert [c.id for c in listed.items] == [campaign.id]
        assert (await repo.list_campaigns([CampaignState.DRAFT], None, 10)).items == []
        await repo.set_schedule(campaign.id, True)
        await repo.set_schedule(campaign.id, True)

        devices = [
            CampaignDevice(
                campaign.id,
                tenant,
                device_id(i),
                i % 2,
                i,
                DeviceState.PENDING,
                0,
                None,
                None,
                now,
                from_fw_hash=sha[1],
            )
            for i in range(6)
        ]
        await repo.add_campaign_devices(devices)
        await repo.add_campaign_devices([])
        notified = [  # queued for the registry, not yet delivered
            replace(d, state=DeviceState.NOTIFIED, notified_at=now, notify_count=1)
            for d in devices[:3]
        ]
        await repo.update_campaign_devices(notified)
        await repo.update_campaign_devices([])
        hist = await repo.state_histogram(campaign.id)
        assert sum(hist[0].values()) == 3 and hist[0].get(DeviceState.NOTIFIED) == 2
        dev = await repo.get_campaign_device(campaign.id, device_id(0), for_update=True)
        assert dev is not None and dev.state is DeviceState.NOTIFIED and dev.from_fw_hash == sha[1]
        assert await repo.get_campaign_device(campaign.id, "dev-ffffffffffffffff") is None
        later = now + timedelta(seconds=1)
        found = await repo.find_campaign_devices(
            campaign.id,
            stage_index=0,
            states={DeviceState.NOTIFIED},
            notified_before=later,
            undelivered_before=later,
        )
        assert [d.device_id for d in found] == [device_id(0), device_id(2)]
        assert await repo.find_campaign_devices(campaign.id, notified_before=now) == []
        assert (
            await repo.find_campaign_devices(
                campaign.id, states={DeviceState.NOTIFIED}, undelivered_before=now
            )
            == []
        )
        await repo.mark_notified(campaign.id, [device_id(0), "dev-ffffffffffffffff"], later)
        await repo.mark_notified(campaign.id, [], later)
        undelivered = await repo.find_campaign_devices(
            campaign.id, states={DeviceState.NOTIFIED}, undelivered_before=later
        )
        assert [d.device_id for d in undelivered] == [device_id(1), device_id(2)]
        marked = await repo.get_campaign_device(campaign.id, device_id(0))
        assert marked is not None and marked.last_notified_at == later
        assert len(await repo.find_campaign_devices(campaign.id, undelivered_before=later)) == 5
        dpage = await repo.list_campaign_devices(campaign.id, None, None, 4)
        assert len(dpage.items) == 4 and dpage.next_cursor
        rest = await repo.list_campaign_devices(campaign.id, None, dpage.next_cursor, 4)
        assert len(rest.items) == 2 and rest.next_cursor is None
        only = await repo.list_campaign_devices(campaign.id, DeviceState.PENDING, None, 10)
        assert len(only.items) == 3

        for i in range(3):
            await repo.add_audit(
                AuditEvent(
                    uuid.uuid4(),
                    now + timedelta(seconds=i),
                    tenant,
                    Actor("user", "x"),
                    f"a{i}",
                    "campaign",
                    str(campaign.id),
                    "success",
                    None,
                    None,
                    {"i": i},
                )
            )
        audit = await repo.list_audit("campaign", str(campaign.id), None, 2)
        assert [e.action for e in audit.items] == ["a2", "a1"] and audit.next_cursor
        audit2 = await repo.list_audit("campaign", str(campaign.id), audit.next_cursor, 2)
        assert [e.action for e in audit2.items] == ["a0"]

        rec = IdempotencyRecord(tenant, "k", "user:x", "POST", "/p", 200, {"a": 1}, now)
        await repo.put_idempotency(rec)
        got_rec = await repo.get_idempotency("k", "user:x")
        assert got_rec is not None and got_rec.body == {"a": 1}
        assert await repo.get_idempotency("k", "user:y") is None

        assert await repo.check_and_record_seq(device_id(1), 5)
        assert not await repo.check_and_record_seq(device_id(1), 5)
        assert await repo.check_and_record_seq(device_id(1), 2**64 - 1)
        assert not await repo.check_and_record_seq(device_id(1), 6)

    refs = await any_db.due_campaigns()
    assert any(r.campaign_id == campaign.id and r.tenant_id == tenant for r in refs)

    # firmware-key sync outbox: add_firmware registered the tenant; due until the PKI accepted
    # the current key-set digest, back-off on failure, everything again after a restart
    soon = now + timedelta(days=1)
    assert tenant in await any_db.due_key_syncs("digest-1", soon, 10_000)
    await any_db.finish_key_sync(
        tenant, digest="digest-1", now=now, error="boom", retry_at=now + timedelta(days=2)
    )
    assert tenant not in await any_db.due_key_syncs("digest-1", soon, 10_000)
    await any_db.finish_key_sync(tenant, digest="digest-1", now=now)
    assert tenant not in await any_db.due_key_syncs("digest-1", now + timedelta(days=3), 10_000)
    assert tenant in await any_db.due_key_syncs("digest-2", now + timedelta(days=3), 10_000)
    assert await any_db.request_key_sync_all(soon) >= 1
    assert tenant in await any_db.due_key_syncs("digest-1", soon, 10_000)
    assert await any_db.due_key_syncs("digest-1", now - timedelta(days=1), 10_000) == []
    assert sha[1].hex() in await any_db.known_hashes("gw")
    assert await any_db.ping()

    # uniqueness violations surface as RepositoryConflict and roll the transaction back
    for attempt in ("version_code", "delta", "device", "idempotency"):
        with pytest.raises(RepositoryConflict):
            async with any_db.tenant(tenant) as repo:
                if attempt == "version_code":
                    await repo.add_firmware(_fw(tenant, 3, sha[0], at=now))
                elif attempt == "delta":
                    await repo.add_delta(replace(delta, id=uuid.uuid4()))
                elif attempt == "device":
                    await repo.add_campaign_devices([devices[0]])
                else:
                    await repo.put_idempotency(rec)
    with pytest.raises(KeyError):
        async with any_db.tenant(tenant) as repo:
            await repo.update_campaign(replace(campaign, id=uuid.uuid4()))
    with pytest.raises(InvalidCursor):
        async with any_db.tenant(tenant) as repo:
            await repo.list_firmware(None, "garbage!!", 2)

    # a different tenant sees none of it
    async with any_db.tenant(other) as repo:
        assert await repo.get_firmware(fws[0].id) is None
        assert await repo.get_campaign(campaign.id) is None
        assert (await repo.list_campaign_devices(campaign.id, None, None, 10)).items == []
        assert await repo.state_histogram(campaign.id) == {}
        assert await repo.max_version_code("gw") is None
        assert (await repo.list_audit("campaign", str(campaign.id), None, 10)).items == []
        assert await repo.get_idempotency("k", "user:x") is None
        assert await repo.check_and_record_seq(device_id(1), 1)  # independent counters
        await repo.add_firmware(_fw(other, 3, sha[0], at=now))  # same code, other tenant
    async with any_db.tenant(tenant) as repo:
        await repo.set_schedule(campaign.id, False)


async def test_migration_enables_forced_rls(pg_urls: tuple[str, str]) -> None:
    engine = create_async_engine(pg_urls[0])
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relname IN ('firmware', 'firmware_deltas', 'campaigns', 'campaign_devices', "
                    "'audit_events', 'idempotency_keys', 'device_seq')"
                )
            )
        ).all()
        assert len(rows) == 7 and all(r[1] and r[2] for r in rows)
        role = (
            await conn.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'ota_app'")
            )
        ).one()
        assert role == (False, False)
        owners = (
            await conn.execute(
                text("SELECT DISTINCT tableowner FROM pg_tables WHERE tablename = 'firmware'")
            )
        ).scalar()
        assert owners != "ota_app"
        # the firmware-key sync outbox is identifier-only (no RLS) and writable by the service
        sync = (
            await conn.execute(
                text(
                    "SELECT relrowsecurity, has_table_privilege('ota_app', 'pki_key_sync', "
                    "'UPDATE') FROM pg_class WHERE relname = 'pki_key_sync'"
                )
            )
        ).one()
        assert sync == (False, True)
    await engine.dispose()


async def test_rls_blocks_cross_tenant_access_at_sql_level(sql_db: SqlDatabase) -> None:
    tenant_a, tenant_b = new_tenant(), new_tenant()
    now = datetime.now(UTC)
    fw = _fw(tenant_a, 1, b"\x01" * 32, at=now)
    async with sql_db.tenant(tenant_a) as repo:
        await repo.add_firmware(fw)
    engine = sql_db.engine
    async with engine.begin() as conn:  # no tenant set at all
        assert (await conn.execute(text("SELECT count(*) FROM firmware"))).scalar() == 0
    async with engine.begin() as conn:
        await conn.execute(
            text("SELECT set_config('ironmesh.tenant_id', :t, true)"), {"t": str(tenant_b)}
        )
        assert (await conn.execute(text("SELECT count(*) FROM firmware"))).scalar() == 0
    # writing a row for another tenant violates the WITH CHECK clause
    with pytest.raises(DBAPIError):
        async with sql_db.tenant(tenant_b) as repo:
            await repo.add_firmware(_fw(tenant_a, 2, b"\x02" * 32, at=now))
    # released firmware and the audit trail are append-only for ota_app
    for statement in (
        "UPDATE firmware SET notes = 'x'",
        "DELETE FROM audit_events",
        "DELETE FROM firmware",
    ):
        with pytest.raises(ProgrammingError):
            async with engine.begin() as conn:
                await conn.execute(
                    text("SELECT set_config('ironmesh.tenant_id', :t, true)"), {"t": str(tenant_a)}
                )
                await conn.execute(text(statement))
    # ota_app cannot switch RLS off
    with pytest.raises(ProgrammingError):
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE firmware DISABLE ROW LEVEL SECURITY"))


async def test_api_flow_on_postgres(
    tmp_path: Path, keys: Keys, clock: Clock, sql_db: SqlDatabase
) -> None:
    async for env in make_env(tmp_path, keys, clock, db=sql_db):
        tenant, intruder = new_tenant(), new_tenant()
        good, bad = image_bytes(1, blocks=8), image_bytes(2, blocks=8)
        await env.upload(tenant, good, version="1.0.0", version_code=10)
        fw = await env.upload(tenant, bad, version="1.1.0", version_code=11)
        await env.upload(tenant, image_bytes(3), version="0.9.0", version_code=9, expect=422)
        devices = env.add_devices(tenant, 6, fw=good)
        campaign = await env.create_campaign(
            tenant,
            fw["id"],
            delta=True,
            stages=[
                {"percent": 50, "dwell_s": 10, "max_failure_rate": 1.0},
                {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
            ],
        )
        cid = campaign["id"]
        await env.action(tenant, cid, "start")
        first = [d["device_id"] for d in await env.devices(tenant, cid, "notified")]
        assert len(first) == 3
        for dev in first:
            await env.status(tenant, cid, dev, 5)
            env.set_device_fw(tenant, dev, bad)
        clock.advance(11)
        await env.tick()
        assert (await env.campaign(tenant, cid))["current_stage"] == 1
        resp = await env.client.get(f"/v1/campaigns/{cid}", headers=env.auth(intruder))
        assert resp.status_code == 404
        child = await env.action(tenant, cid, "rollback", body={"reason": "bad"}, expect=201)
        assert child["firmware"]["version_code"] == 12
        assert sorted(child["target"]["device_ids"]) == sorted(first)
        assert set(devices) >= set(first)
        audit = await env.client.get(
            f"/v1/campaigns/{cid}/audit?limit=200", headers=env.auth(tenant)
        )
        assert any(a["action"] == "campaign.rollback" for a in audit.json()["items"])
        ready = await env.client.get("/readyz")
        assert ready.status_code == 200 and ready.json()["checks"]["database"] is True


async def test_advisory_lock_leader_election(pg_urls: tuple[str, str]) -> None:
    key = 0x0BADF00D
    engine_a = create_async_engine(pg_urls[1])
    engine_b = create_async_engine(pg_urls[1])
    a, b = PostgresAdvisoryLock(engine_a, key), PostgresAdvisoryLock(engine_b, key)
    try:
        assert await a.acquire()
        assert await a.acquire()  # re-validated on the same session
        assert not await b.acquire()
        await a.release()
        assert await b.acquire()
        assert not await a.acquire()
        # the leader's session dies: Postgres frees the lock, the standby takes over
        conn: Any = b._conn
        assert conn is not None
        await conn.invalidate()
        assert not await b.acquire()
        assert await a.acquire()
        await b.release()
        await a.release()
        await a.release()  # releasing twice is harmless
    finally:
        await engine_a.dispose()
        await engine_b.dispose()


async def test_sql_ping_reports_failure() -> None:
    db = SqlDatabase.from_url("postgresql+asyncpg://nobody@127.0.0.1:1/none", pool_size=1)
    assert await db.ping() is False
    await db.close()
