"""Registry -> PKI tenant policy (API_CONTRACT §5): command key + allow_software_keys, with
retries, an outbox for PKI outages and a startup reconciliation."""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.auth import SYSTEM, ServiceTokenMinter
from app.integrations.services import HttpPkiClient, UpstreamError
from app.main import create_app, reconcile_once
from app.services import devices as device_svc
from app.services import tenant_policy

from .conftest import Env
from .test_twin_commands_config import tenant_public_key


def raw(key: object) -> bytes:
    assert hasattr(key, "public_bytes")
    return bytes(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


async def audit(env: Env, t: str, action: str) -> list[dict[str, object]]:
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"action": action})
    return list(r.json()["items"])


async def test_command_key_creation_queues_pki_push(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    assert t not in env.pki.command_keys
    # first downlink creates the tenant command key (and the outbox row, same transaction)
    r = await env.client.patch(
        f"/v1/devices/{dev['id']}/twin/desired",
        headers=env.auth(t, "operator"),
        json={"patch": {"a": 1}},
    )
    assert r.status_code == 200
    env.pki.fail_policy = 1  # first sweep fails: the row stays pending and is retried
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0
    assert t not in env.pki.command_keys
    env.clock.advance(hours=1)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 1
    assert env.pki.command_keys[t] == raw(await tenant_public_key(env, t))
    assert len(env.pki.command_keys[t]) == 32
    assert env.pki.enrollment[t] is True
    done = await audit(env, t, "action.pki_tenant_policy.completed")
    assert done[0]["target"] == {"type": "tenant", "id": t}
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0


async def test_settings_change_pushes_enrollment(env: Env) -> None:
    t = await env.tenant()
    url = "/v1/tenants/me/settings"
    r = await env.client.patch(url, headers=env.auth(t, "admin"), json={"auto_quarantine": True})
    assert r.status_code == 200 and env.pki.policy_calls == []
    r = await env.client.patch(
        url, headers=env.auth(t, "admin"), json={"allow_software_keys": True}
    )
    assert r.status_code == 200 and env.pki.policy_calls == []  # unchanged value
    r = await env.client.patch(
        url, headers=env.auth(t, "admin"), json={"allow_software_keys": False}
    )
    assert r.status_code == 200 and r.json()["settings"]["allow_software_keys"] is False
    assert env.pki.enrollment[t] is False
    assert env.pki.command_keys[t] == raw(await tenant_public_key(env, t))
    assert (t, "enrollment") in env.pki.policy_calls


async def test_pki_outage_uses_outbox(env: Env) -> None:
    t = await env.tenant()
    env.pki.fail_policy = 100
    r = await env.client.patch(
        "/v1/tenants/me/settings", headers=env.auth(t, "admin"), json={"allow_software_keys": False}
    )
    assert r.status_code == 200  # the settings change commits regardless
    failed = await audit(env, t, "tenant.pki_policy_sync_failed")
    assert failed[0]["outcome"] == "failure"
    assert failed[0]["details"]["compensation"] == "retry_scheduled"  # type: ignore[index]
    env.pki.fail_policy = 0
    env.clock.advance(seconds=31)
    # both the sync row and the key-creation row complete; the last push wins (same state)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 2
    assert env.pki.enrollment[t] is False and t in env.pki.command_keys

    env.pki.fail_policy = 10_000
    assert not await tenant_policy.sync(env.ctx, SYSTEM, t, "test")
    for _ in range(20):
        env.clock.advance(hours=2)
        await device_svc.run_pending_actions(env.ctx, SYSTEM, [t])
    abandoned = await audit(env, t, "action.pki_tenant_policy.abandoned")
    assert abandoned and abandoned[0]["target"] == {"type": "tenant", "id": t}


async def test_startup_reconciliation(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    a, b = await env.tenant("a"), await env.tenant("b", allow_software_keys=False)
    tenants = [a, b, "8b0f3c55-3f8e-4c9e-9a0a-61d6f5f5d001"]  # the last one does not exist

    async def listed() -> list[str]:
        return tenants

    monkeypatch.setattr(env.repo, "list_tenant_ids", listed)
    count = await reconcile_once(env.ctx)
    assert count == 2
    assert env.pki.command_keys[a] == raw(await tenant_public_key(env, a))
    assert env.pki.command_keys[b] == raw(await tenant_public_key(env, b))
    assert env.pki.enrollment[a] is True and env.pki.enrollment[b] is False
    env.pki.fail_policy = 10_000
    assert await tenant_policy.reconcile(env.ctx, SYSTEM) == 0
    assert await audit(env, a, "tenant.pki_policy_sync_failed")


async def test_reconciliation_runs_in_lifespan(mem: Env) -> None:
    t = await mem.tenant()
    mem.ctx.settings.background_jobs_enabled = True
    mem.ctx.settings.sweeper_interval_seconds = 3600
    mem.ctx.settings.maintenance_interval_seconds = 3600
    app = create_app(mem.ctx.settings, mem.ctx)
    async with app.router.lifespan_context(app):
        for _ in range(100):
            if t in mem.pki.command_keys:
                break
            await asyncio.sleep(0.01)
    assert t in mem.pki.command_keys


async def test_reconcile_unknown_tenant_raises(mem: Env) -> None:
    with pytest.raises(Exception, match="tenant not found"):
        await tenant_policy.push(mem.ctx, SYSTEM, "8b0f3c55-3f8e-4c9e-9a0a-61d6f5f5d001")


async def test_http_pki_tenant_policy() -> None:
    seen: list[httpx.Request] = []
    status = {"code": 204}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status["code"])

    key = ec.generate_private_key(ec.SECP256R1())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    pki = HttpPkiClient("https://pki:8443/", client, ServiceTokenMinter("registry", key), 30)
    tenant = "8b0f3c55-3f8e-4c9e-9a0a-61d6f5f5d001"
    await pki.put_command_key(tenant, bytes(range(32)))
    await pki.put_enrollment(tenant, False)
    assert [(r.method, r.url.path) for r in seen] == [
        ("PUT", f"/v1/tenants/{tenant}/command-key"),
        ("PUT", f"/v1/tenants/{tenant}/enrollment"),
    ]
    assert json.loads(seen[0].content) == {
        "public_key_b64": base64.b64encode(bytes(range(32))).decode()
    }
    assert json.loads(seen[1].content) == {"allow_software_keys": False}
    token = seen[0].headers["authorization"].removeprefix("Bearer ")
    claims = jwt.decode(token, key.public_key(), algorithms=["ES256"], audience="pki")
    assert claims["iss"] == "registry"
    for code in (404, 409, 500, 403):
        status["code"] = code
        with pytest.raises(UpstreamError):
            await pki.put_enrollment(tenant, True)
    await client.aclose()
