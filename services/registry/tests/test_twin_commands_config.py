"""Twin reconciliation, signed downlinks, idempotent commands, encrypted config."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from ironmesh_wire import AckStatus, Direction, envelope, hpke, ids
from ironmesh_wire.errors import WireError
from ironmesh_wire.ids import TopicClass

from app.auth import SYSTEM
from app.integrations.bus import TOPIC_COMMANDS
from app.services import commands as command_svc
from app.services import devices as device_svc

from .conftest import Env


async def tenant_public_key(env: Env, tenant_id: str) -> ed25519.Ed25519PublicKey:
    async with env.repo.tenant(tenant_id) as tx:
        keys = await env.ctx.keyring.keys(tx)
    return keys.cmd_key.public_key()


def verify_downlink(
    wire: bytes, tenant_id: str, pub: ed25519.Ed25519PublicKey, now: int
) -> envelope.Message:
    return envelope.decode(
        wire,
        envelope.StaticKeyResolver({ids.tenant_kid(tenant_id): pub}),
        envelope.InMemoryReplayStore(),
        now=now,
        expected_direction=Direction.DOWNLINK,
        expected_tenant=tenant_id,
    )


async def test_twin_desired_reported_delta(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    did = dev["id"]
    url = f"/v1/devices/{did}/twin"
    r = await env.client.get(url, headers=env.auth(t, "viewer"))
    assert r.json()["version"] == 0 and r.json()["delta"] == {}

    r = await env.client.patch(
        url + "/desired",
        headers=env.auth(t, "operator"),
        json={"patch": {"led": "on", "net": {"wifi": True, "mtu": 1500}}, "expected_version": 0},
    )
    assert r.status_code == 200, r.text
    twin = r.json()
    assert twin["version"] == 1 and twin["delta"] == {
        "led": "on",
        "net": {"wifi": True, "mtu": 1500},
    }
    shadow = env.mqtt.on("shadow/desired")[-1]
    assert shadow.retain and shadow.qos == 1
    msg = verify_downlink(
        shadow.payload, t, await tenant_public_key(env, t), int(env.clock().timestamp())
    )
    assert isinstance(msg.body, envelope.ShadowDesired)
    assert msg.body.version == 1 and msg.body.state["led"] == "on"

    # version conflict
    r = await env.client.patch(
        url + "/desired",
        headers=env.auth(t, "operator"),
        json={"patch": {"led": "off"}, "expected_version": 0},
    )
    assert r.status_code == 409 and r.json()["type"].endswith("version-conflict")
    assert r.json()["errors"][0]["current_version"] == 1

    # merge-patch null removes, nested merge keeps siblings
    r = await env.client.patch(
        url + "/desired", headers=env.auth(t, "operator"), json={"patch": {"net": {"mtu": None}}}
    )
    assert r.json()["desired"] == {"led": "on", "net": {"wifi": True}} and r.json()["version"] == 2
    # no-op patch keeps version
    r = await env.client.patch(
        url + "/desired", headers=env.auth(t, "operator"), json={"patch": {"led": "on"}}
    )
    assert r.json()["version"] == 2

    # device reports partially -> delta shrinks
    res = await env.send(
        dk,
        TopicClass.SHADOW_REPORTED,
        envelope.ShadowReported(state={"led": "on", "net": {"wifi": False}}, version=2),
    )
    assert res == "accepted"
    r = await env.client.get(url, headers=env.auth(t))
    assert r.json()["delta"] == {"net": {"wifi": True}} and r.json()["reported_updated_at"]

    # delete path (slash or dot form)
    r = await env.client.delete(url + "/desired/net%2Fwifi", headers=env.auth(t, "operator"))
    assert r.status_code == 200 and r.json()["desired"] == {"led": "on", "net": {}}
    r = await env.client.delete(url + "/desired/led", headers=env.auth(t, "operator"))
    assert r.json()["desired"] == {"net": {}}
    r = await env.client.delete(url + "/desired/missing.key", headers=env.auth(t, "operator"))
    assert r.status_code == 404
    r = await env.client.patch(
        url + "/desired", headers=env.auth(t, "viewer"), json={"patch": {"a": 1}}
    )
    assert r.status_code == 403


async def test_twin_limits_and_publish_failure(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    url = f"/v1/devices/{dev['id']}/twin/desired"
    deep: dict[str, object] = {}
    node = deep
    for _ in range(12):
        node["x"] = {}
        node = node["x"]  # type: ignore[assignment]
    r = await env.client.patch(url, headers=env.auth(t), json={"patch": deep})
    assert r.status_code == 422
    r = await env.client.patch(url, headers=env.auth(t), json={"patch": {"big": "x" * 70000}})
    assert r.status_code == 422
    r = await env.client.patch(url, headers=env.auth(t), json={"patch": {"n": 2**70}})
    assert r.status_code == 422
    env.mqtt.fail = 3
    r = await env.client.patch(url, headers=env.auth(t), json={"patch": {"mode": "eco"}})
    assert r.status_code == 200
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"action": "twin.publish_failed"}
    )
    assert r.json()["items"][0]["outcome"] == "failure"
    env.clock.advance(seconds=31)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 1
    msg = env.mqtt.on("shadow/desired")[-1]
    assert verify_downlink(
        msg.payload, t, await tenant_public_key(env, t), int(env.clock().timestamp())
    ).body.state == {"mode": "eco"}  # type: ignore[attr-defined]


async def test_commands_idempotency_and_ack(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    did = dev["id"]
    url = f"/v1/devices/{did}/commands"
    body = {"name": "reboot", "args": {"delay_s": 5}, "ttl_s": 120}
    h = {**env.auth(t, "operator"), "Idempotency-Key": "key-0001"}
    r1 = await env.client.post(url, headers=h, json=body)
    assert r1.status_code == 202 and "Idempotency-Replayed" not in r1.headers
    cmd = r1.json()
    assert cmd["status"] == "sent" and cmd["idempotency_key"] == "key-0001"
    r2 = await env.client.post(url, headers=h, json=body)
    assert r2.status_code == 202 and r2.headers["Idempotency-Replayed"] == "true"
    assert r2.json()["cmd_id"] == cmd["cmd_id"]
    assert len(env.mqtt.on("cmd/req")) == 1
    r3 = await env.client.post(url, headers=h, json={**body, "args": {"delay_s": 6}})
    assert r3.status_code == 409
    r4 = await env.client.post(url, headers=h, json={**body, "idempotency_key": "other-key"})
    assert r4.status_code == 422
    # body key is accepted too
    r5 = await env.client.post(
        url, headers=env.auth(t, "operator"), json={**body, "idempotency_key": "key-0001"}
    )
    assert r5.headers.get("Idempotency-Replayed") == "true"

    # the published command is tenant-signed with a nonce
    wire = env.mqtt.on("cmd/req")[-1].payload
    msg = verify_downlink(wire, t, await tenant_public_key(env, t), int(env.clock().timestamp()))
    assert isinstance(msg.body, envelope.Command) and msg.body.cmd_id == cmd["cmd_id"]
    assert msg.nonce is not None

    # ack with the wrong nonce is rejected and does not consume the seq
    bad = envelope.CommandAck(cmd_id=cmd["cmd_id"], status=AckStatus.OK)
    assert await env.send(dk, TopicClass.CMD_ACK, bad, nonce=b"\x00" * 16, seq=50) == "ENV_NONCE"
    ok = envelope.CommandAck(cmd_id=cmd["cmd_id"], status=AckStatus.OK, result={"rebooted": True})
    assert await env.send(dk, TopicClass.CMD_ACK, ok, nonce=msg.nonce, seq=50) == "accepted"
    r = await env.client.get(f"/v1/commands/{cmd['cmd_id']}", headers=env.auth(t, "viewer"))
    acked = r.json()
    assert (
        acked["status"] == "acked" and acked["result"] == {"rebooted": True} and acked["acked_at"]
    )
    statuses = [json.loads(m.value)["status"] for m in env.bus.on(TOPIC_COMMANDS)]
    assert statuses[-3:] == ["pending", "sent", "acked"]
    # a repeated ack is a replay
    assert await env.send(dk, TopicClass.CMD_ACK, ok, nonce=msg.nonce, seq=50) == "ENV_REPLAY"
    # an ack for an unknown command
    unknown = envelope.CommandAck(cmd_id="123e4567-e89b-12d3-a456-426614174000", status=0)
    assert await env.send(dk, TopicClass.CMD_ACK, unknown, nonce=msg.nonce) == "ENV_FIELD"

    r = await env.client.get(url, headers=env.auth(t), params={"status": "acked"})
    assert [c["cmd_id"] for c in r.json()["items"]] == [cmd["cmd_id"]]
    assert (await env.client.get("/v1/commands/not-a-uuid", headers=env.auth(t))).status_code == 404
    assert (
        await env.client.get(
            "/v1/commands/123e4567-e89b-12d3-a456-426614174000", headers=env.auth(t)
        )
    ).status_code == 404


async def test_command_pagination_states_and_sweeper(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    did = dev["id"]
    url = f"/v1/devices/{did}/commands"
    for i in range(3):
        await env.client.post(
            url, headers=env.auth(t, "operator"), json={"name": f"cmd{i}", "args": {}, "ttl_s": 30}
        )
        env.clock.advance(seconds=1)
    r = await env.client.get(url, headers=env.auth(t), params={"limit": 2})
    first = r.json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    r = await env.client.get(url, headers=env.auth(t), params={"cursor": first["next_cursor"]})
    assert [c["name"] for c in r.json()["items"]] == ["cmd0"]
    # broker down: command stays pending, the sweeper republishes it
    env.mqtt.fail = 3
    r = await env.client.post(
        url, headers=env.auth(t, "operator"), json={"name": "later", "args": {}, "ttl_s": 600}
    )
    assert r.json()["status"] == "pending"
    expired, republished = await command_svc.sweep(env.ctx, SYSTEM, tenant_ids=[t])
    assert republished == 1 and expired == 0
    env.mqtt.fail = 1
    env.clock.advance(seconds=31)
    expired, _ = await command_svc.sweep(env.ctx, SYSTEM, tenant_ids=[t])
    assert expired == 3
    r = await env.client.get(url, headers=env.auth(t), params={"status": "expired"})
    assert len(r.json()["items"]) == 3
    # expired commands ignore late acks
    cmd = r.json()["items"][0]
    async with env.repo.tenant(t) as tx:
        rec = await tx.get_command(cmd["cmd_id"])
    assert rec is not None
    late = envelope.CommandAck(cmd_id=cmd["cmd_id"], status=AckStatus.FAILED, error="late")
    assert await env.send(dk, TopicClass.CMD_ACK, late, nonce=rec.nonce) == "accepted"
    r = await env.client.get(f"/v1/commands/{cmd['cmd_id']}", headers=env.auth(t))
    assert r.json()["status"] == "expired"
    # commands to a non-active device are rejected immediately
    m = await env.device(t)
    r = await env.client.post(
        f"/v1/devices/{m['id']}/commands",
        headers=env.auth(t, "operator"),
        json={"name": "reboot", "args": {}, "ttl_s": 60},
    )
    assert r.status_code == 202 and r.json()["status"] == "rejected"
    r = await env.client.post(
        url, headers=env.auth(t, "operator"), json={"name": "x", "args": {}, "ttl_s": 5}
    )
    assert r.status_code == 422


async def test_group_commands(env: Env) -> None:
    t = await env.tenant()
    await env.client.post("/v1/groups", headers=env.auth(t), json={"slug": "all", "name": "All"})
    a, _ = await env.active_device(t)
    b = await env.device(t)
    await env.client.put(
        "/v1/groups/all/members", headers=env.auth(t), json={"add": [a["id"], b["id"]]}
    )
    h = {**env.auth(t, "operator"), "Idempotency-Key": "batch-1"}
    body = {"name": "update", "args": {"v": 2}, "ttl_s": 300}
    r = await env.client.post("/v1/groups/all/commands", headers=h, json=body)
    assert r.status_code == 202
    batch = r.json()
    by_device = {c["device_id"]: c["status"] for c in batch["commands"]}
    assert by_device == {a["id"]: "sent", b["id"]: "rejected"}
    r2 = await env.client.post("/v1/groups/all/commands", headers=h, json=body)
    assert (
        r2.headers["Idempotency-Replayed"] == "true" and r2.json()["batch_id"] == batch["batch_id"]
    )
    r = await env.client.post("/v1/groups/none/commands", headers=h, json=body)
    assert r.status_code == 404


async def test_config_encrypted_hpke(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    did = dev["id"]
    url = f"/v1/devices/{did}/config"
    assert (await env.client.get(url, headers=env.auth(t))).status_code == 404
    r = await env.client.put(url, headers=env.auth(t, "operator"), json={"config": {"a": 1}})
    assert r.status_code == 403
    cfg = {"ntp": "pool.ntp.org", "telemetry_interval_s": 30, "secret": "s3cr3t"}
    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": cfg})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 1 and r.json()["published_at"]
    published = env.mqtt.on("config")[-1]
    assert published.retain and b"s3cr3t" not in published.payload
    inner = hpke.unwrap_config(published.payload, dk.key)
    msg = verify_downlink(inner, t, await tenant_public_key(env, t), int(env.clock().timestamp()))
    assert isinstance(msg.body, envelope.Config) and dict(msg.body.settings) == cfg

    # stored encrypted at rest
    async with env.repo.tenant(t) as tx:
        stored = await tx.get_config(did)
    assert stored is not None and b"s3cr3t" not in stored.ciphertext

    r = await env.client.get(url, headers=env.auth(t, "admin"))
    assert r.json()["config"] == cfg and r.json()["acked_at"] is None
    r = await env.client.get(url, headers=env.auth(t, "operator"))
    assert r.status_code == 200 and r.json()["config"] == {}

    # device acknowledges via reported state
    await env.send(
        dk,
        TopicClass.SHADOW_REPORTED,
        envelope.ShadowReported(state={"config_version": 1}, version=0),
    )
    r = await env.client.get(url, headers=env.auth(t, "admin"))
    assert r.json()["acked_at"] is not None
    # second version, ack via event
    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": {"x": 1}})
    assert r.json()["version"] == 2
    await env.send(
        dk,
        TopicClass.EVENTS,
        envelope.Event(name="config.applied", severity=1, data={"version": 2}),
    )
    r = await env.client.get(url, headers=env.auth(t, "admin"))
    assert r.json()["acked_at"] is not None and r.json()["version"] == 2

    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": {"x": "y" * 20000}})
    assert r.status_code == 422


async def test_config_requires_cert_and_handles_broker_failure(env: Env) -> None:
    t = await env.tenant()
    dev = await env.device(t)
    url = f"/v1/devices/{dev['id']}/config"
    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": {"a": 1}})
    assert r.status_code == 409
    dk = await env.enroll(t, dev["id"])
    env.pki.fail_lookup = True
    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": {"a": 1}})
    assert r.status_code == 503
    env.pki.fail_lookup = False
    env.mqtt.fail = 3
    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": {"a": 1}})
    assert r.status_code == 503 and "retry scheduled" in r.json()["detail"]
    env.clock.advance(seconds=31)
    # the config publish retry, plus the PKI push queued when the command key was created
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 2
    assert t in env.pki.command_keys
    inner = hpke.unwrap_config(env.mqtt.on("config")[-1].payload, dk.key)
    assert b"a" in inner
    r = await env.client.get(url, headers=env.auth(t, "admin"))
    assert r.json()["delivered_at"] is not None
    await env.client.post(
        f"/v1/devices/{dev['id']}/decommission",
        headers=env.auth(t, "admin"),
        json={"reason": "eol"},
    )
    r = await env.client.put(url, headers=env.auth(t, "admin"), json={"config": {"a": 2}})
    assert r.status_code == 409
    r = await env.client.patch(
        f"/v1/devices/{dev['id']}/twin/desired", headers=env.auth(t), json={"patch": {"a": 1}}
    )
    assert r.status_code == 409
    env.clock.advance(days=1)
    assert timedelta(days=1)


async def test_retained_config_rewrapped_to_new_key_on_renewal(env: Env) -> None:
    """T-48: after a certificate renewal the retained config is re-wrapped to the new key, so the
    superseded (possibly leaked) key can no longer decrypt what the broker keeps retained."""
    t = await env.tenant()
    dev, old = await env.active_device(t)
    did = dev["id"]
    cfg = {"wifi_psk": "correct horse battery staple"}
    r = await env.client.put(
        f"/v1/devices/{did}/config", headers=env.auth(t, "admin"), json={"config": cfg}
    )
    assert r.status_code == 200, r.text
    assert hpke.unwrap_config(env.mqtt.on("config")[-1].payload, old.key)

    new = await env.enroll(t, did)  # renewal: new key, new certificate
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) >= 1
    latest = env.mqtt.on("config")[-1]
    assert latest.retain
    inner = hpke.unwrap_config(latest.payload, new.key)
    msg = verify_downlink(inner, t, await tenant_public_key(env, t), int(env.clock().timestamp()))
    assert isinstance(msg.body, envelope.Config) and dict(msg.body.settings) == cfg
    with pytest.raises(WireError):
        hpke.unwrap_config(latest.payload, old.key)

    # A device without stored config queues nothing extra on enrollment.
    other, _ = await env.active_device(t)
    before = len(env.mqtt.on("config"))
    await env.enroll(t, other["id"])
    await device_svc.run_pending_actions(env.ctx, SYSTEM, [t])
    assert len(env.mqtt.on("config")) == before
