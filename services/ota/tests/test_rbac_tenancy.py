"""RBAC matrix, authentication failures and cross-tenant isolation."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from .conftest import Env, image_bytes, new_tenant

ROLES = ["viewer", "factory", "operator", "admin", "owner"]
RANK = {"viewer": 0, "factory": 0, "operator": 1, "admin": 2, "owner": 3}
MIN_ROLE = {
    "upload": "admin",
    "list_firmware": "viewer",
    "get_firmware": "viewer",
    "manifest": "viewer",
    "signing_keys": "viewer",
    "create": "operator",
    "list_campaigns": "viewer",
    "get_campaign": "viewer",
    "devices": "viewer",
    "audit": "viewer",
    "start": "operator",
    "pause": "operator",
    "halt": "operator",
    "cancel": "operator",
    "rollback": "admin",
}


async def _call(env: Env, name: str, tenant: uuid.UUID, role: str, ctx: dict[str, Any]) -> int:
    headers = env.auth(tenant, role, sub=f"{role}-user")
    fid, cid = ctx["fw"]["id"], ctx["campaign"]["id"]
    client = env.client
    if name == "upload":
        resp = await client.post(
            "/v1/firmware",
            headers=headers,
            files={
                "image": (
                    "i.bin",
                    image_bytes(50 + RANK[role] + len(role)),
                    "application/octet-stream",
                )
            },
            data={
                "metadata": json.dumps(
                    {
                        "product": "gateway-rpi",
                        "version": f"9.{RANK[role]}.{len(role)}",
                        "version_code": 1000 + 10 * RANK[role] + len(role),
                    }
                )
            },
        )
    elif name == "list_firmware":
        resp = await client.get("/v1/firmware", headers=headers)
    elif name == "get_firmware":
        resp = await client.get(f"/v1/firmware/{fid}", headers=headers)
    elif name == "manifest":
        resp = await client.get(f"/v1/firmware/{fid}/manifest", headers=headers)
    elif name == "signing_keys":
        resp = await client.get("/v1/signing-keys", headers=headers)
    elif name == "create":
        resp = await client.post(
            "/v1/campaigns",
            headers=headers,
            json={
                "name": "x",
                "firmware_id": fid,
                "target": {"groups": ["fleet"], "device_ids": [], "tags": {}},
            },
        )
    elif name == "list_campaigns":
        resp = await client.get("/v1/campaigns", headers=headers)
    elif name in ("get_campaign", "devices", "audit"):
        suffix = "" if name == "get_campaign" else f"/{name}"
        resp = await client.get(f"/v1/campaigns/{cid}{suffix}", headers=headers)
    else:
        body = {"reason": "rbac"} if name in ("halt", "rollback", "cancel") else None
        resp = await client.post(f"/v1/campaigns/{cid}/{name}", headers=headers, json=body)
    return resp.status_code


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("endpoint", list(MIN_ROLE))
async def test_rbac_matrix(env: Env, endpoint: str, role: str) -> None:
    tenant = new_tenant()
    fw = await env.upload(tenant, image_bytes(1))
    env.add_devices(tenant, 3)
    campaign = await env.create_campaign(tenant, fw["id"])
    status = await _call(env, endpoint, tenant, role, {"fw": fw, "campaign": campaign})
    allowed = RANK[role] >= RANK[MIN_ROLE[endpoint]]
    if allowed:
        assert status not in (401, 403), (endpoint, role, status)
    else:
        assert status == 403, (endpoint, role, status)


@pytest.mark.parametrize(
    "header",
    [None, "Basic abc", "Bearer ", "Bearer not-a-jwt", "Bearer imk_abcdef"],
)
async def test_authentication_failures(env: Env, header: str | None) -> None:
    headers = {"Authorization": header} if header is not None else {}
    resp = await env.client.get("/v1/campaigns", headers=headers)
    assert resp.status_code == 401
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.json()["status"] == 401


async def test_token_claim_requirements(env: Env) -> None:
    tenant = new_tenant()
    cases = [
        env.token(None),  # no tenant
        env.token(tenant, role="superuser"),  # unknown role
        env.token(tenant, sub=""),  # no subject
    ]
    statuses = []
    for token in cases:
        resp = await env.client.get("/v1/campaigns", headers={"Authorization": f"Bearer {token}"})
        statuses.append(resp.status_code)
    assert statuses == [403, 403, 401]
    roles_list = env.token(tenant, role="nope", roles=["viewer", "operator"])
    resp = await env.client.get("/v1/campaigns", headers={"Authorization": f"Bearer {roles_list}"})
    assert resp.status_code == 200


async def test_cross_tenant_isolation(env: Env) -> None:
    tenant_a, tenant_b = new_tenant(), new_tenant()
    fw_a = await env.upload(tenant_a, image_bytes(1), version_code=5)
    env.add_devices(tenant_a, 4)
    env.add_devices(tenant_b, 4, start=100)
    campaign_a = await env.create_campaign(tenant_a, fw_a["id"])
    b = env.auth(tenant_b, "owner", sub="mallory")

    # tenant B sees nothing of tenant A
    assert (await env.client.get("/v1/firmware", headers=b)).json()["items"] == []
    assert (await env.client.get("/v1/campaigns", headers=b)).json()["items"] == []
    for path in (
        f"/v1/firmware/{fw_a['id']}",
        f"/v1/firmware/{fw_a['id']}/manifest",
        f"/v1/firmware/{fw_a['id']}/image",
        f"/v1/firmware/by-hash/{fw_a['sha256_hex']}",
        f"/v1/campaigns/{campaign_a['id']}",
        f"/v1/campaigns/{campaign_a['id']}/devices",
        f"/v1/campaigns/{campaign_a['id']}/audit",
    ):
        assert (await env.client.get(path, headers=b)).status_code == 404, path
    # ... and cannot act on it
    for action in ("start", "pause", "resume", "cancel", "approve"):
        resp = await env.client.post(f"/v1/campaigns/{campaign_a['id']}/{action}", headers=b)
        assert resp.status_code == 404, action
    for action in ("halt", "rollback"):
        resp = await env.client.post(
            f"/v1/campaigns/{campaign_a['id']}/{action}", headers=b, json={"reason": "x"}
        )
        assert resp.status_code == 404, action
    # nor build a campaign from A's firmware
    resp = await env.client.post(
        "/v1/campaigns",
        headers=b,
        json={
            "name": "steal",
            "firmware_id": fw_a["id"],
            "target": {"groups": ["fleet"], "device_ids": [], "tags": {}},
        },
    )
    assert resp.status_code == 422
    # nor report status into A's campaign under its own tenant id
    started = await env.action(tenant_a, campaign_a["id"], "start")
    dev = (await env.devices(tenant_a, campaign_a["id"], "notified"))[0]["device_id"]
    await env.status(tenant_b, campaign_a["id"], dev, 5, expect=404)
    assert started["state"] == "running"
    # tenant B's own version counter is independent of A's
    await env.upload(tenant_b, image_bytes(2), version_code=1)

    # the X-IronMesh-Tenant override requires platform_admin and is flagged in the audit trail
    header = {"X-IronMesh-Tenant": str(tenant_a)}
    resp = await env.client.get("/v1/campaigns", headers={**b, **header})
    assert resp.status_code == 403
    admin = env.token(tenant_b, role="viewer", sub="ops", platform_roles=["platform_admin"])
    resp = await env.client.get(
        "/v1/campaigns", headers={"Authorization": f"Bearer {admin}", **header}
    )
    assert resp.status_code == 200 and len(resp.json()["items"]) == 1
    resp = await env.client.post(
        "/v1/campaigns",
        headers={"Authorization": f"Bearer {admin}", **header},
        json={
            "name": "support",
            "firmware_id": fw_a["id"],
            "target": {"groups": ["fleet"], "device_ids": [], "tags": {}},
        },
    )
    assert resp.status_code == 201
    audit = (
        await env.client.get(f"/v1/campaigns/{resp.json()['id']}/audit", headers=env.auth(tenant_a))
    ).json()["items"]
    assert audit[0]["details"]["cross_tenant"] is True
    bad = await env.client.get(
        "/v1/campaigns",
        headers={"Authorization": f"Bearer {admin}", "X-IronMesh-Tenant": "not-a-uuid"},
    )
    assert bad.status_code == 400
    same = await env.client.get(
        "/v1/campaigns",
        headers={**env.auth(tenant_a, "viewer"), "X-IronMesh-Tenant": str(tenant_a)},
    )
    assert same.status_code == 200
