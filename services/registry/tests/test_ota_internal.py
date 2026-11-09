"""OTA-facing internal endpoints (API_CONTRACT §1.12): target resolution and signed downlinks;
lifecycle callers (policy + anomaly)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from ironmesh_wire import Direction, envelope, ids
from ironmesh_wire.constants import MessageType

from app import models
from app.services.common import seq_floor

from .conftest import ANOMALY_TOKEN, INTERNAL_TOKEN, OTA_TOKEN, Env
from .test_twin_commands_config import tenant_public_key, verify_downlink

OTA = {"Authorization": f"Bearer {OTA_TOKEN}"}


def resolve_url(tenant_id: str) -> str:
    return f"/internal/v1/tenants/{tenant_id}/devices/resolve"


def downlink_url(tenant_id: str, device_id: str) -> str:
    return f"/internal/v1/tenants/{tenant_id}/devices/{device_id}/downlink"


def notify_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "campaign_id": str(uuid.uuid4()),
        "manifest": (b"\xa1\x01\x02" * 10).hex(),
        "url": "https://artifacts.example.test/fw/image.bin?sig=abc",
        "delta_from": None,
    }
    body.update(overrides)
    return body


async def fleet(env: Env) -> tuple[str, dict[str, str]]:
    """Tenant with: a1 (group canary, tag ring=a, active), a2 (tag ring=a + site=x, active),
    a3 (manufactured, no group/tags), a4 (group canary, quarantined)."""
    t = await env.tenant()
    r = await env.client.post(
        "/v1/groups", headers=env.auth(t, "operator"), json={"slug": "canary", "name": "Canary"}
    )
    assert r.status_code == 201
    a1, _ = await env.active_device(t, product="gateway-rpi")
    a2, _ = await env.active_device(t, product="sensor-esp32", tags={"ring": "a", "site": "x"})
    a3 = await env.device(t)
    a4, _ = await env.active_device(t)
    await env.client.patch(
        f"/v1/devices/{a1['id']}",
        headers=env.auth(t, "operator"),
        json={"groups": ["canary"], "tags": {"ring": "a"}},
    )
    await env.client.patch(
        f"/v1/devices/{a4['id']}", headers=env.auth(t, "operator"), json={"groups": ["canary"]}
    )
    r = await env.client.post(
        f"/v1/devices/{a4['id']}/quarantine", headers=env.auth(t, "operator"), json={"reason": "x"}
    )
    assert r.status_code == 200
    return t, {"a1": a1["id"], "a2": a2["id"], "a3": a3["id"], "a4": a4["id"]}


async def resolved(env: Env, t: str, **body: Any) -> list[str]:
    r = await env.client.post(resolve_url(t), headers=OTA, json=body)
    assert r.status_code == 200, r.text
    return [item["device_id"] for item in r.json()["items"]]


async def test_resolve_selectors(env: Env) -> None:
    t, d = await fleet(env)
    assert await resolved(env, t) == []
    assert sorted(await resolved(env, t, groups=["canary"])) == sorted([d["a1"], d["a4"]])
    # tags: a device must carry every listed tag
    assert sorted(await resolved(env, t, tags={"ring": "a"})) == sorted([d["a1"], d["a2"]])
    assert await resolved(env, t, tags={"ring": "a", "site": "x"}) == [d["a2"]]
    assert await resolved(env, t, tags={"ring": "zzz"}) == []
    # device ids: unknown and malformed ids are ignored, duplicates collapse
    ids_ = [d["a3"], d["a3"], "dev-ffffffffffffffff", "not-a-device"]
    assert await resolved(env, t, device_ids=ids_) == [d["a3"]]
    # union of the three selectors, each device once, ordered by id
    union = await resolved(
        env, t, groups=["canary"], tags={"site": "x"}, device_ids=[d["a3"], d["a1"]]
    )
    assert union == sorted(d.values())
    # optional states filter
    active = await resolved(
        env, t, groups=["canary"], device_ids=[d["a3"]], tags={"ring": "a"}, states=["active"]
    )
    assert sorted(active) == sorted([d["a1"], d["a2"]])
    r = await env.client.post(resolve_url(t), headers=OTA, json={"device_ids": [d["a2"]]})
    item = r.json()["items"][0]
    assert item == {
        "device_id": d["a2"],
        "product": "sensor-esp32",
        "state": "active",
        "fw_version": "2.4.1",
        "fw_hash_hex": "ab" * 32,
        "connected": False,
    }
    for bad in (
        {"groups": ["Not A Slug"]},
        {"states": ["sleeping"]},
        {"tags": {"": "x"}},
        {"unknown": 1},
    ):
        r = await env.client.post(resolve_url(t), headers=OTA, json=bad)
        assert r.status_code == 422, bad


async def test_resolve_is_tenant_scoped(env: Env) -> None:
    t, d = await fleet(env)
    other, od = await fleet(env)
    # same group slug and tags exist in the other tenant; its devices never leak
    got = await resolved(
        env, t, groups=["canary"], tags={"ring": "a"}, device_ids=[od["a1"], od["a3"]]
    )
    assert set(got) == {d["a1"], d["a2"], d["a4"]}
    assert not set(got) & set(od.values())
    r = await env.client.post(resolve_url(str(uuid.uuid4())), headers=OTA, json={})
    assert r.status_code == 404
    r = await env.client.post(resolve_url("not-a-uuid"), headers=OTA, json={})
    assert r.status_code == 404
    assert other != t


async def test_resolve_limit(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    t, d = await fleet(env)
    monkeypatch.setattr(models, "MAX_RESOLVE_ITEMS", 2)
    assert len(await resolved(env, t, groups=["canary"])) == 2
    r = await env.client.post(resolve_url(t), headers=OTA, json={"device_ids": list(d.values())})
    assert r.status_code == 422 and "more than 2 devices" in r.json()["detail"]


async def test_ota_endpoints_auth_matrix(env: Env) -> None:
    t, d = await fleet(env)
    calls = [
        ("resolve", resolve_url(t), {"groups": ["canary"]}),
        (
            "downlink",
            downlink_url(t, d["a1"]),
            {"type": "ota_notify", "body": notify_body(), "retain": True},
        ),
    ]
    for name, url, body in calls:
        r = await env.client.post(url, json=body)
        assert r.status_code == 401, name
        r = await env.client.post(url, json=body, headers=env.auth(t, "owner"))
        assert r.status_code == 401, name  # user tokens are never service credentials
        r = await env.client.post(url, json=body, headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401, name
        for headers in (
            {"Authorization": f"Bearer {INTERNAL_TOKEN}"},  # policy's token
            {"Authorization": f"Bearer {ANOMALY_TOKEN}"},
            env.service("pki"),
            env.service("policy"),
            env.service("anomaly"),
        ):
            r = await env.client.post(url, json=body, headers=headers)
            assert r.status_code == 403, (name, headers)
        r = await env.client.post(url, json=body, headers=OTA)
        assert r.status_code == 200, (name, r.text)
        r = await env.client.post(url, json=body, headers=env.service("ota"))
        assert r.status_code == 200, (name, r.text)
        r = await env.client.post(url, json=body, headers=env.service("ota", aud="pki"))
        assert r.status_code == 401, name


async def test_ota_notify_downlink(env: Env) -> None:
    t, d = await fleet(env)
    dev = d["a1"]
    campaign = str(uuid.uuid4())
    base = bytes(range(32))
    body = notify_body(campaign_id=campaign, delta_from=base.hex().upper())
    before = len(env.mqtt.messages)
    r = await env.client.post(
        downlink_url(t, dev), headers=OTA, json={"type": "ota_notify", "body": body, "retain": True}
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert set(out) == {"seq", "published_at"}
    assert out["seq"] >= seq_floor(MessageType.OTA_NOTIFY, env.clock())
    published = env.mqtt.messages[before:]
    assert len(published) == 1
    msg = published[0]
    assert msg.topic == ids.build_topic(t, dev, ids.TopicClass.OTA_NOTIFY)
    assert msg.retain is True and msg.qos == 1
    pub = await tenant_public_key(env, t)
    decoded = verify_downlink(msg.payload, t, pub, int(env.clock().timestamp()))
    assert decoded.seq == out["seq"]
    assert isinstance(decoded.body, envelope.OtaNotify)
    assert decoded.body.campaign_id == campaign
    assert decoded.body.manifest == bytes.fromhex(body["manifest"])
    assert decoded.body.url == body["url"]
    assert decoded.body.delta_from == base

    # a later retained notify is still accepted (retainable type: future bound only)
    env.clock.advance(seconds=3600)
    late = envelope.decode(
        msg.payload,
        envelope.StaticKeyResolver({ids.tenant_kid(t): pub}),
        envelope.InMemoryReplayStore(),
        now=int(env.clock().timestamp()),
        expected_direction=Direction.DOWNLINK,
    )
    assert late.seq == out["seq"]

    # next notify: same type-7 stream, strictly increasing; not retained on request
    r = await env.client.post(
        downlink_url(t, dev),
        headers=OTA,
        json={"type": "ota_notify", "body": notify_body(campaign_id=campaign), "retain": False},
    )
    second = r.json()
    assert second["seq"] > out["seq"] and env.mqtt.messages[-1].retain is False

    # the registry's other downlinks use their own streams, not the type-7 sequence
    r = await env.client.patch(
        f"/v1/devices/{dev}/twin/desired",
        headers=env.auth(t, "operator"),
        json={"patch": {"led": "on"}},
    )
    assert r.status_code == 200
    shadow = env.mqtt.on("shadow/desired")[-1]
    assert verify_downlink(shadow.payload, t, pub, int(env.clock().timestamp())).seq == 1

    # timeline + audit
    r = await env.client.get(
        f"/v1/devices/{dev}/timeline", headers=env.auth(t, "viewer"), params={"kinds": "ota"}
    )
    events = r.json()["items"]
    assert len(events) == 2 and events[-1]["data"]["campaign_id"] == campaign
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"action": "device.downlink.ota_notify"}
    )
    items = r.json()["items"]
    assert len(items) == 2
    assert items[0]["actor"] == {"type": "service", "id": "ota", "name": "ota"}
    assert {i["details"]["seq"] for i in items} == {out["seq"], second["seq"]}


async def test_ota_notify_validation_and_state(env: Env) -> None:
    t, d = await fleet(env)
    url = downlink_url(t, d["a1"])
    bad_requests: list[dict[str, Any]] = [
        {"type": "command", "body": notify_body(), "retain": True},
        {"type": "shadow_desired", "body": notify_body(), "retain": True},
        {"type": "ota_notify", "body": notify_body()},  # retain is required
        {"type": "ota_notify", "body": notify_body(), "retain": True, "x": 1},
        {"type": "ota_notify", "body": notify_body(manifest=""), "retain": True},
        {"type": "ota_notify", "body": notify_body(manifest="zz"), "retain": True},
        {"type": "ota_notify", "body": notify_body(manifest="abc"), "retain": True},
        {"type": "ota_notify", "body": notify_body(delta_from="ab" * 31), "retain": True},
        {"type": "ota_notify", "body": notify_body(url=""), "retain": True},
        {"type": "ota_notify", "body": notify_body(extra=True), "retain": True},
        {"type": "ota_notify", "body": {"campaign_id": str(uuid.uuid4())}, "retain": True},
        # wire-level checks: the campaign id must be a UUIDv4
        {
            "type": "ota_notify",
            "body": notify_body(campaign_id=str(uuid.uuid1())),
            "retain": True,
        },
    ]
    for body in bad_requests:
        r = await env.client.post(url, headers=OTA, json=body)
        assert r.status_code == 422, (body, r.text)
    r = await env.client.post(
        url,
        headers=OTA,
        json={
            "type": "ota_notify",
            "body": notify_body(campaign_id=str(uuid.uuid1())),
            "retain": True,
        },
    )
    assert "campaign_id" in r.text
    ok = {"type": "ota_notify", "body": notify_body(), "retain": True}
    # device not active: manufactured / quarantined -> 409, nothing published
    before = len(env.mqtt.messages)
    for key in ("a3", "a4"):
        r = await env.client.post(downlink_url(t, d[key]), headers=OTA, json=ok)
        assert r.status_code == 409, key
    assert len(env.mqtt.messages) == before
    # unknown device, other tenant's device, malformed ids
    other, od = await fleet(env)
    r = await env.client.post(downlink_url(t, od["a1"]), headers=OTA, json=ok)
    assert r.status_code == 404
    r = await env.client.post(downlink_url(t, "dev-ffffffffffffffff"), headers=OTA, json=ok)
    assert r.status_code == 404
    r = await env.client.post(downlink_url("nope", d["a1"]), headers=OTA, json=ok)
    assert r.status_code == 404
    assert other != t


async def test_ota_notify_broker_failure(env: Env) -> None:
    t, d = await fleet(env)
    env.mqtt.fail = 3  # every retry fails
    ok = {"type": "ota_notify", "body": notify_body(), "retain": True}
    r = await env.client.post(downlink_url(t, d["a1"]), headers=OTA, json=ok)
    assert r.status_code == 503 and "broker" in r.json()["detail"]
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"action": "device.downlink.ota_notify"}
    )
    item = r.json()["items"][0]
    assert item["outcome"] == "failure" and "error" in item["details"]
    r = await env.client.post(downlink_url(t, d["a1"]), headers=OTA, json=ok)
    assert r.status_code == 200


async def test_downlink_streams_continue_from_legacy_counter(mem: Env) -> None:
    t = await mem.tenant()
    dev, _ = await mem.active_device(t)
    mem.repo.state.devices[dev["id"]].downlink_seq = 41  # type: ignore[attr-defined]
    for value in ("a", "b"):
        r = await mem.client.patch(
            f"/v1/devices/{dev['id']}/twin/desired",
            headers=mem.auth(t, "operator"),
            json={"patch": {"x": value}},
        )
        assert r.status_code == 200
    pub = await tenant_public_key(mem, t)
    seqs = [
        verify_downlink(m.payload, t, pub, int(mem.clock().timestamp())).seq
        for m in mem.mqtt.on("shadow/desired")
    ]
    assert seqs == [42, 43]


async def test_lifecycle_callers(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t, product="sensor-esp32")
    url = f"/internal/v1/devices/{dev['id']}/lifecycle"
    expected = {
        "device_id": dev["id"],
        "tenant_id": t,
        "state": "active",
        "assurance_level": "hardware",
        "product": "sensor-esp32",
    }
    for headers in (
        env.service("policy"),
        env.service("anomaly"),
        {"Authorization": f"Bearer {INTERNAL_TOKEN}"},
        {"Authorization": f"Bearer {ANOMALY_TOKEN}"},
    ):
        r = await env.client.get(url, headers=headers)
        assert r.status_code == 200 and r.json() == expected
    for headers in (env.service("pki"), env.service("ota"), OTA):
        r = await env.client.get(url, headers=headers)
        assert r.status_code == 403
