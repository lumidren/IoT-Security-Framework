"""Audit log: listing, export, hash-chain verification and tamper detection."""

from __future__ import annotations

import json
from dataclasses import replace

from .conftest import Env


async def _events(env: Env, t: str, n: int) -> None:
    for i in range(n):
        await env.client.post(
            "/v1/groups",
            headers=env.auth(t, "owner", sub="auditor"),
            json={"slug": f"g{i}", "name": f"G{i}"},
        )


async def test_audit_list_filters_and_export(env: Env) -> None:
    t = await env.tenant()
    await _events(env, t, 4)
    h = env.auth(t, "viewer", sub="v")
    r = await env.client.get("/v1/audit", headers=h, params={"action": "group.created", "limit": 3})
    page = r.json()
    assert len(page["items"]) == 3 and page["next_cursor"]
    assert page["items"][0]["target"] == {"type": "group", "id": "g3"}
    assert page["items"][0]["actor"]["type"] == "user" and page["items"][0]["request_id"]
    r = await env.client.get(
        "/v1/audit", headers=h, params={"action": "group.created", "cursor": page["next_cursor"]}
    )
    assert [e["target"]["id"] for e in r.json()["items"]] == ["g0"]
    r = await env.client.get(
        "/v1/audit",
        headers=h,
        params={"target_type": "group", "target_id": "g1", "actor": "auditor"},
    )
    assert len(r.json()["items"]) == 1
    r = await env.client.get(
        "/v1/audit",
        headers=h,
        params={"from": "2000-01-01T00:00:00Z", "to": "2000-01-02T00:00:00Z"},
    )
    assert r.json()["items"] == []
    r = await env.client.get(
        "/v1/audit/export",
        headers=env.auth(t, "admin"),
        params={"format": "ndjson", "from": "2000-01-01T00:00:00Z"},
    )
    assert r.headers["content-type"].startswith("application/x-ndjson")
    lines = [json.loads(x) for x in r.text.splitlines()]
    assert [x["action"] for x in lines].count("group.created") == 4
    r = await env.client.get(
        "/v1/audit/export", headers=env.auth(t, "admin"), params={"format": "csv"}
    )
    assert r.status_code == 422


async def test_audit_chain_verifies(env: Env) -> None:
    t = await env.tenant()
    await _events(env, t, 3)
    r = await env.client.get("/v1/audit/verify", headers=env.auth(t, "admin"))
    body = r.json()
    assert body["ok"] is True and body["checked"] >= 4 and body["first_invalid_seq"] is None
    assert len(body["head_hash_hex"]) == 64
    # verifying is itself audited
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"action": "audit.verified"})
    assert len(r.json()["items"]) == 1


async def test_tamper_detection_memory(mem: Env) -> None:
    t = await mem.tenant()
    await _events(mem, t, 4)
    chain = mem.repo.state.audit[t]  # type: ignore[attr-defined]
    original = list(chain)

    async def verify() -> dict[str, object]:
        r = await mem.client.get("/v1/audit/verify", headers=mem.auth(t, "admin"))
        return dict(r.json())

    # 1. edit the hashed content
    chain[1] = replace(original[1], body=original[1].body.replace("g0", "gX"))
    res = await verify()
    assert res["ok"] is False and res["first_invalid_seq"] == 2
    assert "hash" in str(res["reason"])
    # 2. edit a column only (body intact)
    mem.repo.state.audit[t] = chain = list(original)  # type: ignore[attr-defined]
    chain[2] = replace(original[2], action="group.deleted")
    res = await verify()
    assert res["first_invalid_seq"] == 3 and "columns" in str(res["reason"])
    # 3. delete an event in the middle
    mem.repo.state.audit[t] = chain = [e for i, e in enumerate(original) if i != 1]  # type: ignore[attr-defined]
    res = await verify()
    assert res["first_invalid_seq"] == 3 and "gap" in str(res["reason"])
    # 4. recompute a forged event's hash but break the link to its predecessor
    from app.repo.base import chain_hash

    forged_body = original[2].body.replace('"G1"', '"GY"')  # details only
    forged = replace(
        original[2], body=forged_body, hash=chain_hash(original[2].prev_hash, forged_body)
    )
    mem.repo.state.audit[t] = chain = list(original)  # type: ignore[attr-defined]
    chain[2] = forged
    res = await verify()
    assert res["first_invalid_seq"] == 4 and "prev_hash" in str(res["reason"])
    # 5. truncate the tail
    mem.repo.state.audit[t] = list(original[:-1])  # type: ignore[attr-defined]
    head = mem.repo.state.audit_heads[t]  # type: ignore[attr-defined]
    mem.repo.state.audit_heads[t] = (original[-1].seq, original[-1].hash)  # type: ignore[attr-defined]
    res = await verify()
    assert res["ok"] is False and "head" in str(res["reason"])
    assert head is not None
