"""The registry signs OtaNotify; this service pushes its firmware keys to the PKI policy."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from ironmesh_ota.app import create_app
from ironmesh_ota.container import deliver_notifies
from ironmesh_ota.integrations.registry import Downlink
from ironmesh_ota.repository.memory import MemoryTenantRepository
from ironmesh_ota.signing import KeyringSigner
from ironmesh_wire import envelope

from .conftest import Env, image_bytes, new_tenant

ONE_STAGE = [{"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0}]


async def test_firmware_keys_pushed_for_tenants_with_firmware(env: Env) -> None:
    tenant, idle = new_tenant(), new_tenant()
    env.add_devices(idle, 2)  # a tenant without firmware is never pushed
    await env.upload(tenant, image_bytes(1))
    env.pki.fail = 1
    await env.tick()
    assert tenant not in env.pki.firmware_keys
    await env.tick()  # back-off: not retried immediately
    assert env.pki.calls == []
    env.clock.advance(61)
    await env.tick()
    expected = sorted(env.container.signer.trusted_public_keys())
    assert env.pki.firmware_keys[tenant] == expected
    assert sorted(len(k) for k in expected) == [32, 1952]  # Ed25519 + ML-DSA-65
    assert idle not in env.pki.firmware_keys
    await env.tick()
    assert env.pki.calls == [tenant]  # synced: no repeat while the key set is unchanged

    # a second image for the same tenant does not re-push
    await env.upload(tenant, image_bytes(2), version="1.1.0", version_code=110)
    await env.tick()
    assert env.pki.calls == [tenant]

    # signing-key rotation: the new key set is pushed on the next tick
    now = datetime.now(UTC)
    old = env.container.signer
    assert isinstance(old, KeyringSigner)
    rotated = KeyringSigner(
        [(ed25519.Ed25519PrivateKey.generate(), now, True)],
        extra_trusted_mldsa=[(k, now) for k in old.trusted_public_keys() if len(k) == 1952],
    )
    env.container.signer = rotated
    await env.tick()
    assert env.pki.calls == [tenant, tenant]
    assert env.pki.firmware_keys[tenant] == sorted(rotated.trusted_public_keys())


async def test_startup_pushes_every_tenant(env: Env) -> None:
    a, b = new_tenant(), new_tenant()
    await env.upload(a, image_bytes(1))
    await env.upload(b, image_bytes(2))
    await env.tick()
    assert sorted(env.pki.calls, key=str) == sorted([a, b], key=str)
    app = create_app(env.container, run_controller=False, run_consumer=False)
    async with app.router.lifespan_context(app):
        for _ in range(50):
            if len(env.pki.calls) == 4:
                break
            await asyncio.sleep(0.01)
    assert sorted(env.pki.calls[2:], key=str) == sorted([a, b], key=str)


async def test_startup_key_sync_failure_is_contained(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(now: Any) -> int:
        raise RuntimeError("db down")

    monkeypatch.setattr(env.container.db, "request_key_sync_all", broken)
    app = create_app(env.container, run_controller=False, run_consumer=False)
    async with app.router.lifespan_context(app):
        pass  # the app still starts and stops


async def test_controller_survives_key_sync_errors(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken() -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr(env.services.controller.key_sync, "run_due", broken)
    assert await env.tick() == 0


async def test_notifies_go_through_the_registry(env: Env) -> None:
    tenant = new_tenant()
    old, new = image_bytes(1), image_bytes(2)
    await env.upload(tenant, old, version="1.0.0", version_code=100)
    fw = await env.upload(tenant, new, version="1.1.0", version_code=110)
    devices = env.add_devices(tenant, 3, fw=old)
    campaign = await env.create_campaign(tenant, fw["id"], stages=ONE_STAGE)
    await env.action(tenant, campaign["id"], "start")
    assert {d.device_id for d in env.registry.downlinks} == set(devices)
    assert all(d.retain for d in env.registry.downlinks)
    assert all(d.tenant_id == tenant for d in env.registry.downlinks)
    # this service never publishes a signed payload itself: the only direct publishes are the
    # (empty) retained clears
    await env.action(tenant, campaign["id"], "cancel", body={"reason": "stop"})
    direct = [m for m in env.publisher.messages if not m.payload]
    assert len(direct) == 3 and env.publisher.retained == {}
    rows = await env.devices(tenant, campaign["id"])
    assert all(r["notified_at"] for r in rows)


async def test_paused_campaigns_do_not_redeliver(env: Env) -> None:
    tenant = new_tenant()
    old, new = image_bytes(1), image_bytes(2)
    await env.upload(tenant, old, version="1.0.0", version_code=100)
    fw = await env.upload(tenant, new, version="1.1.0", version_code=110)
    env.add_devices(tenant, 4, fw=old)
    campaign = await env.create_campaign(tenant, fw["id"], stages=ONE_STAGE)
    env.registry.fail = 4
    await env.action(tenant, campaign["id"], "start")
    await env.action(tenant, campaign["id"], "pause")
    env.clock.advance(3600)
    await env.tick()
    assert env.registry.downlinks == []
    await env.action(tenant, campaign["id"], "resume")
    assert len(env.registry.downlinks) == 4


async def test_delivery_bookkeeping_failure_is_logged(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*args: Any) -> None:
        raise RuntimeError("db down")

    monkeypatch.setattr(MemoryTenantRepository, "mark_notified", broken)
    body = envelope.OtaNotify(
        campaign_id=str(uuid.uuid4()), manifest=b"m", url="https://a", delta_from=None
    )
    downlink = Downlink(new_tenant(), uuid.uuid4(), "dev-0000000000000001", body)
    assert await deliver_notifies(env.container, [downlink]) == 1
