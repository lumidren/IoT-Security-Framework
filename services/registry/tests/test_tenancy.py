"""Cross-tenant isolation through every list, detail and mutation endpoint (service layer)."""

from __future__ import annotations

from typing import Any

from ironmesh_wire.ids import TopicClass

from .conftest import Env, telemetry_body


async def test_tenant_a_cannot_reach_tenant_b(env: Env) -> None:
    a = await env.tenant("a")
    b = await env.tenant("b")
    a_dev, _ = await env.active_device(a)
    b_dev, b_key = await env.active_device(b)
    bid = b_dev["id"]
    hb = env.auth(b, "owner", sub="owner-b")
    await env.client.post("/v1/groups", headers=hb, json={"slug": "bgrp", "name": "B"})
    await env.client.put("/v1/groups/bgrp/members", headers=hb, json={"add": [bid]})
    r = await env.client.post(
        f"/v1/devices/{bid}/commands", headers=hb, json={"name": "reboot", "args": {}, "ttl_s": 60}
    )
    b_cmd = r.json()["cmd_id"]
    await env.client.put(f"/v1/devices/{bid}/config", headers=hb, json={"config": {"k": "v"}})
    await env.client.patch(f"/v1/devices/{bid}/twin/desired", headers=hb, json={"patch": {"x": 1}})
    r = await env.client.post("/v1/api-keys", headers=hb, json={"name": "bk", "role": "viewer"})
    b_key_id = r.json()["api_key"]["id"]
    await env.send(b_key, TopicClass.TELEMETRY, telemetry_body())

    ha = env.auth(a, "owner", sub="owner-a")
    # lists never include B's rows
    r = await env.client.get("/v1/devices", headers=ha)
    assert [d["id"] for d in r.json()["items"]] == [a_dev["id"]]
    r = await env.client.get("/v1/devices", headers=ha, params={"q": bid})
    assert r.json()["items"] == []
    assert (await env.client.get("/v1/groups", headers=ha)).json() == []
    assert (await env.client.get("/v1/api-keys", headers=ha)).json() == []
    users = (await env.client.get("/v1/users", headers=ha)).json()
    assert "owner-a" in {u["id"] for u in users}
    assert all(b not in u["id"] and u["id"] != "owner-b" for u in users)
    r = await env.client.get("/v1/audit", headers=ha, params={"limit": 200})
    assert all(e["tenant_id"] == a for e in r.json()["items"])
    assert all(e["target"]["id"] != bid for e in r.json()["items"])
    r = await env.client.get("/v1/provisioning", headers=ha)
    assert all(i["device_id"] != bid for i in r.json()["items"])
    summary = (await env.client.get("/v1/fleet/summary", headers=ha)).json()
    assert summary["devices_total"] == 1 and all(p["device_id"] != bid for p in summary["map"])
    export = await env.client.get("/v1/audit/export", headers=ha)
    assert bid not in export.text

    # detail and mutation endpoints answer 404 for B's resources
    calls: list[tuple[str, str, dict[str, Any] | None]] = [
        ("GET", f"/v1/devices/{bid}", None),
        ("PATCH", f"/v1/devices/{bid}", {"tags": {"pwned": "1"}}),
        ("GET", f"/v1/devices/{bid}/timeline", None),
        ("GET", f"/v1/devices/{bid}/telemetry", None),
        ("GET", f"/v1/devices/{bid}/certificates", None),
        ("POST", f"/v1/devices/{bid}/quarantine", {"reason": "x"}),
        ("POST", f"/v1/devices/{bid}/release", {"note": "x"}),
        ("POST", f"/v1/devices/{bid}/decommission", {"reason": "x"}),
        ("GET", f"/v1/devices/{bid}/twin", None),
        ("PATCH", f"/v1/devices/{bid}/twin/desired", {"patch": {"x": 2}}),
        ("DELETE", f"/v1/devices/{bid}/twin/desired/x", None),
        ("GET", f"/v1/devices/{bid}/commands", None),
        ("POST", f"/v1/devices/{bid}/commands", {"name": "reboot", "args": {}, "ttl_s": 60}),
        ("GET", f"/v1/commands/{b_cmd}", None),
        ("GET", f"/v1/devices/{bid}/config", None),
        ("PUT", f"/v1/devices/{bid}/config", {"config": {"k": "evil"}}),
        ("PATCH", "/v1/groups/bgrp", {"name": "x"}),
        ("DELETE", "/v1/groups/bgrp", None),
        ("PUT", "/v1/groups/bgrp/members", {"add": [a_dev["id"]]}),
        ("POST", "/v1/groups/bgrp/commands", {"name": "reboot", "args": {}, "ttl_s": 60}),
        ("POST", f"/v1/provisioning/{bid}/approve", None),
        ("POST", f"/v1/provisioning/{bid}/reject", {"reason": "x"}),
        ("PUT", "/v1/users/owner-b/role", {"role": "viewer"}),
        ("DELETE", f"/v1/api-keys/{b_key_id}", None),
    ]
    for method, path, body in calls:
        r = await env.client.request(method, path, headers=ha, json=body)
        assert r.status_code == 404, (method, path, r.status_code, r.text)

    # A cannot add B's device to its own group either
    await env.client.post("/v1/groups", headers=ha, json={"slug": "agrp", "name": "A"})
    r = await env.client.put("/v1/groups/agrp/members", headers=ha, json={"add": [bid]})
    assert r.json()["added"] == [] and r.json()["rejected"][0]["reason"] == "unknown device"

    # B's data is untouched
    r = await env.client.get(f"/v1/devices/{bid}", headers=hb)
    d = r.json()
    assert d["state"] == "active" and "pwned" not in d["tags"] and d["groups"] == ["bgrp"]
    r = await env.client.get(f"/v1/devices/{bid}/twin", headers=hb)
    assert r.json()["desired"] == {"x": 1}
    r = await env.client.get(f"/v1/devices/{bid}/config", headers=hb)
    assert r.json()["config"] == {"k": "v"}
    assert (await env.client.get("/v1/audit/verify", headers=hb)).json()["ok"] is True

    # B's device cannot publish into A's tenant (topic/header tenant != certificate tenant)
    wire = env.wire(b_key, telemetry_body())
    assert await env.deliver(a, bid, TopicClass.TELEMETRY, wire) in ("ENV_KID", "UNKNOWN_DEVICE")
