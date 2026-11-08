"""``im.ingest`` decoding of device-signed OtaStatus and controller leader election."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ironmesh_ota.controller import RolloutController
from ironmesh_ota.integrations.device_keys import StaticDeviceKeyResolver
from ironmesh_ota.integrations.leader import FakeLeaderLock, FakeLockServer
from ironmesh_wire import OtaState, envelope

from .conftest import Env, image_bytes, new_tenant

SERIAL = 0x3FA1B2C3D4E5F607


def _record(
    tenant: uuid.UUID,
    device: str,
    body: envelope.Body,
    key: ec.EllipticCurvePrivateKey,
    *,
    seq: int = 1,
    ts: int | None = None,
    msg_class: str = "ota_status",
) -> tuple[bytes, list[tuple[str, bytes]]]:
    message = envelope.Message(seq=seq, ts=ts or int(time.time()), body=body)
    value = envelope.encode(message, envelope.SigningIdentity.device(key, SERIAL))
    headers = [
        ("mqtt_topic", f"im/v1/{tenant}/{device}/ota/status".encode()),
        ("tenant_id", str(tenant).encode()),
        ("device_id", device.encode()),
        ("msg_class", msg_class.encode()),
    ]
    return value, headers


async def _running(env: Env) -> tuple[uuid.UUID, str, str, bytes]:
    tenant = new_tenant()
    image = image_bytes(3)
    fw = await env.upload(tenant, image)
    env.add_devices(tenant, 2)
    campaign = await env.create_campaign(
        tenant, fw["id"], stages=[{"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0}]
    )
    await env.action(tenant, campaign["id"], "start")
    device = (await env.devices(tenant, campaign["id"], "notified"))[0]["device_id"]
    return tenant, campaign["id"], device, image


async def test_ingest_record_verifies_device_signature_and_applies(env: Env) -> None:
    tenant, cid, device, image = await _running(env)
    key = ec.generate_private_key(ec.SECP256R1())
    resolver = env.container.device_keys
    assert isinstance(resolver, StaticDeviceKeyResolver)
    from ironmesh_wire import ids

    resolver.add(tenant, device, ids.kid_from_serial(SERIAL), key.public_key())
    ingestor = env.services.ingestor

    downloading = envelope.OtaStatus(cid, int(OtaState.DOWNLOADING), 40)
    result = await ingestor.handle_record(*_record(tenant, device, downloading, key, seq=1))
    assert result is not None and result.device_state.value == "downloading"

    # replayed seq is dropped and counted
    again = await ingestor.handle_record(*_record(tenant, device, downloading, key, seq=1))
    assert again is None
    metrics = (await env.client.get("/metrics")).text
    assert "ironmesh_replay_rejected_total 1.0" in metrics

    done = envelope.OtaStatus(
        cid, int(OtaState.SUCCESS), 100, fw_hash=hashlib.sha256(image).digest()
    )
    result = await ingestor.handle_record(*_record(tenant, device, done, key, seq=2))
    assert result is not None and result.device_state.value == "success"

    # other message classes are ignored
    assert (
        await ingestor.handle_record(
            *_record(tenant, device, done, key, seq=3, msg_class="telemetry")
        )
        is None
    )


@pytest.mark.parametrize(
    "case",
    [
        "forged",
        "unknown_kid",
        "other_device",
        "stale",
        "wrong_type",
        "bad_headers",
        "unknown_campaign",
    ],
)
async def test_ingest_rejections(env: Env, case: str) -> None:
    tenant, cid, device, image = await _running(env)
    key = ec.generate_private_key(ec.SECP256R1())
    resolver = env.container.device_keys
    assert isinstance(resolver, StaticDeviceKeyResolver)
    from ironmesh_wire import ids

    kid = ids.kid_from_serial(SERIAL)
    resolver.add(tenant, device, kid, key.public_key())
    body: envelope.Body = envelope.OtaStatus(cid, int(OtaState.SUCCESS), 100)
    sign_key = key
    kwargs: dict[str, Any] = {}
    target_device = device
    expected_code = {
        "forged": "COSE_SIGNATURE",
        "unknown_kid": "ENV_UNKNOWN_KEY",
        "other_device": "ENV_UNKNOWN_KEY",
        "stale": "ENV_TS_SKEW",
        "wrong_type": "ENV_TYPE",
        "bad_headers": "ID_FORMAT",
        "unknown_campaign": "404",
    }[case]
    if case == "forged":
        sign_key = ec.generate_private_key(ec.SECP256R1())
    elif case == "unknown_kid":
        resolver.keys.clear()
    elif case == "other_device":
        target_device = "dev-00000000000000ff"
    elif case == "stale":
        kwargs["ts"] = int(time.time()) - 3600
    elif case == "wrong_type":
        body = envelope.Event("boot", 1, {})
    elif case == "unknown_campaign":
        body = envelope.OtaStatus(str(uuid.uuid4()), int(OtaState.SUCCESS), 100)
    value, headers = _record(tenant, target_device, body, sign_key, **kwargs)
    if case == "bad_headers":
        headers = [(k, b"bogus" if k == "tenant_id" else v) for k, v in headers]
    assert await env.services.ingestor.handle_record(value, headers) is None
    metrics = (await env.client.get("/metrics")).text
    assert f'ironmesh_ota_ingest_rejected_total{{code="{expected_code}"}} 1.0' in metrics


async def test_ingest_rejects_downlink_messages(env: Env) -> None:
    tenant, cid, device, _ = await _running(env)
    notify = env.publisher.messages[0].payload
    headers = [
        ("tenant_id", str(tenant).encode()),
        ("device_id", device.encode()),
        ("msg_class", b"ota_status"),
    ]
    assert await env.services.ingestor.handle_record(notify, headers) is None
    assert 'code="ENV_DIRECTION"' in (await env.client.get("/metrics")).text


def _leader(controller: RolloutController) -> bool:
    return controller.is_leader


async def test_only_the_leader_drives_rollouts(env: Env) -> None:
    tenant = new_tenant()
    fw = await env.upload(tenant, image_bytes(1))
    env.add_devices(tenant, 4)
    campaign = await env.create_campaign(
        tenant,
        fw["id"],
        stages=[
            {"percent": 50, "dwell_s": 60, "max_failure_rate": 1.0},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    await env.action(tenant, campaign["id"], "start")
    for d in await env.devices(tenant, campaign["id"], "notified"):
        await env.status(tenant, campaign["id"], d["device_id"], int(OtaState.SUCCESS))
    env.clock.advance(61)

    server = FakeLockServer()
    rollout = env.services.rollout
    env.container.leader = FakeLeaderLock(server, "a")
    a = RolloutController(env.container, rollout)
    container_b = type(env.container)(
        **{**env.container.__dict__, "leader": FakeLeaderLock(server, "b")}
    )
    b = RolloutController(container_b, rollout)

    assert await a.tick() == 1 and _leader(a)
    assert await b.tick() == 0 and not _leader(b)
    assert (await env.campaign(tenant, campaign["id"]))["current_stage"] == 1
    # leader's database session dies -> lock is released and the standby takes over
    server.healthy["a"] = False
    assert await a.tick() == 0 and not _leader(a)
    assert await b.tick() == 1 and _leader(b)
    server.healthy["a"] = True
    assert await a.tick() == 0  # b still holds it
    await b.stop()
    assert server.holder is None
    assert await a.tick() >= 0 and _leader(a)
    metrics = (await env.client.get("/metrics")).text
    assert "ironmesh_ota_controller_leader 1.0" in metrics
    assert 'ironmesh_ota_campaign_devices{state="notified"} 2.0' in metrics


async def test_controller_loop_start_stop_and_error_isolation(env: Env) -> None:
    tenant = new_tenant()
    fw = await env.upload(tenant, image_bytes(1))
    env.add_devices(tenant, 2)
    campaign = await env.create_campaign(tenant, fw["id"])
    await env.action(tenant, campaign["id"], "start")
    controller = env.services.controller

    calls = {"n": 0}
    original = env.services.rollout.tick

    async def flaky(*args: Any) -> None:
        calls["n"] += 1
        raise RuntimeError("boom")

    env.services.rollout.tick = flaky  # type: ignore[method-assign,assignment]
    assert await controller.tick() == 0  # failure is contained
    env.services.rollout.tick = original  # type: ignore[method-assign]
    assert calls["n"] == 1

    env.container.settings = env.container.settings.model_copy(
        update={"controller_interval_s": 0.01}
    )
    controller.start()
    controller.start()  # idempotent
    import asyncio

    await asyncio.sleep(0.05)
    await controller.stop()
    assert not _leader(controller)

    # a scheduled campaign that disappeared or finished is unscheduled
    async with env.container.db.tenant(tenant) as repo:
        await repo.set_schedule(uuid.uuid4(), True)
    await env.action(tenant, campaign["id"], "cancel")
    async with env.container.db.tenant(tenant) as repo:
        await repo.set_schedule(uuid.UUID(campaign["id"]), True)
    await controller.tick()
    assert await env.container.db.due_campaigns() == []
