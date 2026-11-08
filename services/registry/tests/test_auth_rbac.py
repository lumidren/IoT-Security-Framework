"""Authentication (OIDC, API keys, platform admin) and the RBAC matrix for every mutation."""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from .conftest import Env

ROLES = ("owner", "admin", "operator", "viewer", "factory")
RANK = {"viewer": 0, "factory": 0, "operator": 1, "admin": 2, "owner": 3}

# (method, path, body, minimum role, extra roles allowed)
MATRIX: list[tuple[str, str, dict[str, Any] | None, str, tuple[str, ...]]] = [
    ("PATCH", "/v1/tenants/me/settings", {"auto_quarantine": False}, "admin", ()),
    (
        "POST",
        "/v1/devices",
        {"product": "p", "hw_revision": "1", "se_type": "tpm2", "bootstrap_serial_hex": "01"},
        "admin",
        ("factory",),
    ),
    ("PATCH", "/v1/devices/{dev}", {"tags": {"a": "b"}}, "operator", ()),
    ("PATCH", "/v1/devices/{dev}/twin/desired", {"patch": {"a": 1}}, "operator", ()),
    ("DELETE", "/v1/devices/{dev}/twin/desired/a", None, "operator", ()),
    (
        "POST",
        "/v1/devices/{dev}/commands",
        {"name": "noop", "args": {}, "ttl_s": 60},
        "operator",
        (),
    ),
    (
        "POST",
        "/v1/groups/{grp}/commands",
        {"name": "noop", "args": {}, "ttl_s": 60},
        "operator",
        (),
    ),
    ("PUT", "/v1/devices/{dev}/config", {"config": {"a": 1}}, "admin", ()),
    ("POST", "/v1/groups", {"slug": "g-new", "name": "n"}, "operator", ()),
    ("PATCH", "/v1/groups/{grp}", {"name": "renamed"}, "operator", ()),
    ("PUT", "/v1/groups/{grp}/members", {"add": [], "remove": []}, "operator", ()),
    ("POST", "/v1/provisioning/{new}/approve", None, "operator", ()),
    ("POST", "/v1/provisioning/{new}/reject", {"reason": "r"}, "operator", ()),
    ("POST", "/v1/devices/{dev}/quarantine", {"reason": "r"}, "operator", ()),
    ("POST", "/v1/devices/{dev}/release", {"note": "n"}, "admin", ()),
    ("PUT", "/v1/users/{user}/role", {"role": "viewer"}, "owner", ()),
    ("POST", "/v1/api-keys", {"name": "k", "role": "viewer"}, "admin", ()),
    ("DELETE", "/v1/api-keys/{key}", None, "admin", ()),
    ("DELETE", "/v1/groups/{grp}", None, "admin", ()),
    ("POST", "/v1/devices/{dev}/decommission", {"reason": "r"}, "admin", ()),
    ("POST", "/v1/ws/ticket", None, "viewer", ()),
    ("GET", "/v1/users", None, "admin", ()),
    ("GET", "/v1/api-keys", None, "admin", ()),
    ("GET", "/v1/audit/export", None, "admin", ()),
    ("GET", "/v1/audit/verify", None, "admin", ()),
    ("GET", "/v1/audit", None, "viewer", ()),
    ("GET", "/v1/devices", None, "viewer", ()),
    ("GET", "/v1/devices/{dev}/config", None, "viewer", ()),
]


def expected_allowed(role: str, min_role: str, also: tuple[str, ...]) -> bool:
    if role in also:
        return True
    if role == "factory":
        return RANK[min_role] == 0
    return RANK[role] >= RANK[min_role]


@pytest.mark.parametrize("role", ROLES)
async def test_rbac_matrix(env: Env, role: str) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    new = await env.device(t)
    await env.client.post("/v1/groups", headers=env.auth(t), json={"slug": "grp", "name": "G"})
    await env.client.get("/v1/tenants/me", headers=env.auth(t, "viewer", sub="target-user"))
    r = await env.client.post(
        "/v1/api-keys", headers=env.auth(t), json={"name": "k", "role": "viewer"}
    )
    key_id = r.json()["api_key"]["id"]
    values = {
        "dev": dev["id"],
        "grp": "grp",
        "new": new["id"],
        "user": "target-user",
        "key": key_id,
    }
    headers = env.auth(t, role, sub=f"actor-{role}")
    for method, template, body, min_role, also in MATRIX:
        path = template.format(**values)
        r = await env.client.request(method, path, headers=headers, json=body)
        allowed = expected_allowed(role, min_role, also)
        if allowed:
            assert r.status_code not in (401, 403), (role, method, path, r.status_code, r.text)
        else:
            assert r.status_code == 403, (role, method, path, r.status_code, r.text)
            assert r.headers["content-type"] == "application/problem+json"
    if role != "owner":
        r = await env.client.get(
            "/v1/audit", headers=env.auth(t, "owner"), params={"action": "authz.denied"}
        )
        assert all(a["outcome"] == "failure" for a in r.json()["items"])
        assert r.json()["items"], "denied mutations are audited"


async def test_token_validation(env: Env) -> None:
    t = await env.tenant()
    url = "/v1/tenants/me"
    r = await env.client.get(url)
    assert r.status_code == 401 and "Bearer" in r.headers["www-authenticate"]
    assert r.json()["status"] == 401 and r.json()["instance"] == url
    for token in (
        "not.a.jwt",
        env.token(t, aud="other-api"),
        env.token(t, iss="https://evil.test"),
        env.token(t, exp_in=-120),
        env.token(t, kid="unknown"),
        env.token(t, key=ec.generate_private_key(ec.SECP256R1())),
    ):
        r = await env.client.get(url, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401, token
    hs = jwt.encode(
        {
            "sub": "x",
            "aud": "ironmesh-api",
            "iss": "https://idp.test/realms/ironmesh",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "tenant_id": t,
        },
        "secret-secret-secret-secret-secret",
        algorithm="HS256",
    )
    assert (await env.client.get(url, headers={"Authorization": f"Bearer {hs}"})).status_code == 401
    r = await env.client.get(url, headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    r = await env.client.get(url, headers=env.auth(None, "owner"))
    assert r.status_code == 403
    r = await env.client.get(url, headers=env.auth(t, ["viewer", "operator"]))
    assert r.status_code == 200 and r.json()["id"] == t
    r = await env.client.get(url, headers=env.auth(t, None, sub="no-role"))
    assert r.status_code == 200
    # tenant that is not provisioned in the registry
    r = await env.client.get(url, headers=env.auth("6f6a0b55-0000-4000-8000-000000000000"))
    assert r.status_code == 403


async def test_platform_admin_tenant_override(env: Env) -> None:
    home = await env.tenant("home")
    other = await env.tenant("other")
    hdr = {**env.auth(home, "viewer", platform=True, sub="pa"), "X-IronMesh-Tenant": other}
    r = await env.client.get("/v1/tenants/me", headers=hdr)
    assert r.status_code == 200 and r.json()["id"] == other
    r = await env.client.post("/v1/groups", headers=hdr, json={"slug": "ops", "name": "Ops"})
    assert r.status_code == 201
    r = await env.client.get(
        "/v1/audit",
        headers=env.auth(other, "owner"),
        params={"action": "platform_admin.tenant_access"},
    )
    assert len(r.json()["items"]) == 2
    assert r.json()["items"][0]["details"]["home_tenant_id"] == home
    r = await env.client.get(
        "/v1/tenants/me", headers={**env.auth(home, "owner"), "X-IronMesh-Tenant": other}
    )
    assert r.status_code == 403
    r = await env.client.get("/v1/tenants/me", headers={**hdr, "X-IronMesh-Tenant": "nope"})
    assert r.status_code == 400
    missing = "11111111-1111-4111-8111-111111111111"
    r = await env.client.get("/v1/tenants/me", headers={**hdr, "X-IronMesh-Tenant": missing})
    assert r.status_code == 404
    # same tenant in the header is a no-op
    r = await env.client.get(
        "/v1/tenants/me", headers={**env.auth(home, "viewer"), "X-IronMesh-Tenant": home}
    )
    assert r.status_code == 200


async def test_api_keys(env: Env) -> None:
    t = await env.tenant()
    dev = await env.device(t)
    admin = env.auth(t, "admin")
    r = await env.client.post(
        "/v1/api-keys", headers=admin, json={"name": "owner", "role": "owner"}
    )
    assert r.status_code == 422
    r = await env.client.post(
        "/v1/api-keys", headers=admin, json={"name": "bad", "role": "viewer", "scopes": ["nope"]}
    )
    assert r.status_code == 422
    r = await env.client.post(
        "/v1/api-keys",
        headers=admin,
        json={
            "name": "past",
            "role": "viewer",
            "expires_at": (env.clock() - timedelta(1)).isoformat(),
        },
    )
    assert r.status_code == 422
    r = await env.client.post(
        "/v1/api-keys",
        headers=admin,
        json={"name": "ci", "role": "operator", "scopes": ["devices:read", "twin:write"]},
    )
    assert r.status_code == 201 and r.headers["cache-control"] == "no-store"
    created = r.json()
    secret = created["secret"]
    assert secret.startswith("imk_") and created["api_key"]["prefix"] == secret[:12]
    key_h = {"Authorization": f"Bearer {secret}"}
    assert (await env.client.get("/v1/devices", headers=key_h)).status_code == 200
    r = await env.client.patch(
        f"/v1/devices/{dev['id']}/twin/desired", headers=key_h, json={"patch": {"x": 1}}
    )
    assert r.status_code == 200
    # outside its scopes, even though the role would allow it
    r = await env.client.patch(f"/v1/devices/{dev['id']}", headers=key_h, json={"tags": {}})
    assert r.status_code == 403
    r = await env.client.post("/v1/api-keys", headers=key_h, json={"name": "x", "role": "viewer"})
    assert r.status_code == 403
    r = await env.client.get(
        "/v1/devices", headers={**key_h, "X-IronMesh-Tenant": await env.tenant()}
    )
    assert r.status_code == 403
    r = await env.client.get("/v1/api-keys", headers=admin)
    listed = r.json()
    assert [k["name"] for k in listed] == ["ci"] and listed[0]["last_used_at"] is not None
    assert "secret" not in listed[0]
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"actor": created["api_key"]["id"]}
    )
    assert r.json()["items"][0]["actor"]["type"] == "api_key"
    # scoped key cannot mint broader keys
    r = await env.client.post(
        "/v1/api-keys",
        headers=admin,
        json={"name": "admin-key", "role": "admin", "scopes": ["apikeys:write"]},
    )
    k2 = {"Authorization": f"Bearer {r.json()['secret']}"}
    r = await env.client.post("/v1/api-keys", headers=k2, json={"name": "wide", "role": "viewer"})
    assert r.status_code == 422
    r = await env.client.post(
        "/v1/api-keys",
        headers=k2,
        json={"name": "narrow", "role": "viewer", "scopes": ["apikeys:write"]},
    )
    assert r.status_code == 201
    # revoke
    assert (
        await env.client.delete(f"/v1/api-keys/{created['api_key']['id']}", headers=admin)
    ).status_code == 204
    assert (await env.client.get("/v1/devices", headers=key_h)).status_code == 401
    assert (
        await env.client.delete(f"/v1/api-keys/{created['api_key']['id']}", headers=admin)
    ).status_code == 404
    assert (await env.client.delete("/v1/api-keys/not-a-uuid", headers=admin)).status_code == 404
    assert (
        await env.client.get("/v1/devices", headers={"Authorization": "Bearer imk_nope"})
    ).status_code == 401
    # expiry
    r = await env.client.post(
        "/v1/api-keys",
        headers=admin,
        json={
            "name": "short",
            "role": "viewer",
            "expires_at": (env.clock() + timedelta(hours=1)).isoformat(),
        },
    )
    short = {"Authorization": f"Bearer {r.json()['secret']}"}
    assert (await env.client.get("/v1/devices", headers=short)).status_code == 200
    env.clock.advance(hours=2)
    assert (await env.client.get("/v1/devices", headers=short)).status_code == 401
    r = await env.client.post(
        "/v1/api-keys",
        headers=admin,
        json={"name": "naive", "role": "viewer", "expires_at": "2030-01-01T00:00:00"},
    )
    assert r.status_code == 422


async def test_users_and_roles(env: Env) -> None:
    t = await env.tenant()
    owner = env.auth(t, "owner", sub="alice")
    await env.client.get("/v1/tenants/me", headers=owner)
    await env.client.get("/v1/tenants/me", headers=env.auth(t, "operator", sub="bob"))
    r = await env.client.get("/v1/users", headers=env.auth(t, "admin", sub="carol"))
    assert {u["id"]: u["role"] for u in r.json()} == {
        "alice": "owner",
        "bob": "operator",
        "carol": "admin",
    }
    r = await env.client.put("/v1/users/bob/role", headers=owner, json={"role": "viewer"})
    assert r.status_code == 200 and r.json()["role"] == "viewer"
    # the registry role is authoritative from now on (token still says operator)
    r = await env.client.post(
        "/v1/groups", headers=env.auth(t, "operator", sub="bob"), json={"slug": "x", "name": "x"}
    )
    assert r.status_code == 403
    r = await env.client.put("/v1/users/alice/role", headers=owner, json={"role": "admin"})
    assert r.status_code == 409
    r = await env.client.put("/v1/users/ghost/role", headers=owner, json={"role": "admin"})
    assert r.status_code == 404
    r = await env.client.put("/v1/users/bob/role", headers=owner, json={"role": "root"})
    assert r.status_code == 422
    r = await env.client.patch(
        "/v1/tenants/me/settings", headers=owner, json={"default_group": "missing"}
    )
    assert r.status_code == 422
    r = await env.client.patch(
        "/v1/tenants/me/settings",
        headers=owner,
        json={"operational_cert_ttl_hours": 240, "require_manual_approval": True},
    )
    assert r.json()["settings"]["operational_cert_ttl_hours"] == 240
    r = await env.client.patch("/v1/tenants/me/settings", headers=owner, json={"bogus": 1})
    assert r.status_code == 422
    assert r.json()["errors"][0]["loc"][-1] == "bogus"
