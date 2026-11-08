"""HTTP API (API_CONTRACT section 3): auth/RBAC, alerts, rules, dry-run, baseline, quarantine, settings."""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ironmesh_anomaly.app import Components, create_app
from ironmesh_anomaly.auth import AuthError, TokenVerifier, build_verifier, principal_from_claims
from ironmesh_anomaly.config import Settings
from ironmesh_anomaly.models import (
    AlertState,
    QuarantineRecord,
    RuleName,
    Severity,
    from_ts,
    utcnow,
)
from tests.support import (
    GATEWAY,
    OTHER_TENANT,
    T0,
    TENANT,
    Harness,
    make_harness,
    sha_hex,
    telemetry_event,
)

ISSUER = "https://idp.test/realms/ironmesh"
KEY = ec.generate_private_key(ec.SECP256R1())
PUB_PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
DEV = "dev-00000000000000aa"

TokenFn = Callable[..., dict[str, str]]


def token(role: str | list[str] = "admin", tenant: str | None = TENANT, **claims: Any) -> str:
    now = int(time.time())
    body: dict[str, Any] = {
        "sub": f"user-{role}",
        "aud": ["ironmesh-api"],
        "iss": ISSUER,
        "iat": now,
        "exp": now + 300,
        "roles": role,
        "name": "Ann",
    }
    if tenant:
        body["tenant_id"] = tenant
    body.update(claims)
    return jwt.encode(body, KEY, algorithm="ES256")


def auth(role: str | list[str] = "admin", **kw: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(role, **kw)}"}


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[tuple[httpx.AsyncClient, Harness]]:
    settings = Settings(run_pipeline=False, model_dir=str(tmp_path / "m"))
    h = make_harness(tmp_path, settings=settings)
    verifier = TokenVerifier.from_public_key(
        PUB_PEM, audience="ironmesh-api", issuer=ISSUER, algorithms=["ES256"]
    )
    app = create_app(Components(settings, h.engine, verifier))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://anomaly"
    ) as client:
        yield client, h


async def seed_alert(
    h: Harness, rule: RuleName = RuleName.FW_HASH_MISMATCH, tenant: str = TENANT, device: str = DEV
) -> str:
    from ironmesh_anomaly.models import Detection

    out = await h.engine.alerts.handle(
        Detection(
            rule,
            tenant,
            device,
            Severity.CRITICAL,
            1.0,
            "bad fw",
            {"reasons": ["unknown_hash"]},
            utcnow(),
        )
    )
    assert out.alert is not None
    return out.alert.id


# ------------------------------------------------------------------------------------- auth


async def test_authentication_errors(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, _ = env
    r = await c.get("/v1/alerts")
    assert r.status_code == 401 and r.headers["content-type"] == "application/problem+json"
    assert r.json()["status"] == 401 and r.headers["www-authenticate"] == "Bearer"
    assert (
        await c.get("/v1/alerts", headers={"Authorization": "Bearer imk_abc"})
    ).status_code == 401
    assert (await c.get("/v1/alerts", headers={"Authorization": "Bearer nope"})).status_code == 401
    other = ec.generate_private_key(ec.SECP256R1())
    forged = jwt.encode(
        {
            "sub": "x",
            "aud": "ironmesh-api",
            "iss": ISSUER,
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "tenant_id": TENANT,
            "roles": "owner",
        },
        other,
        algorithm="ES256",
    )
    assert (
        await c.get("/v1/alerts", headers={"Authorization": f"Bearer {forged}"})
    ).status_code == 401
    hs = jwt.encode({"sub": "x"}, "s" * 64, algorithm="HS256")
    assert (await c.get("/v1/alerts", headers={"Authorization": f"Bearer {hs}"})).status_code == 401
    assert (await c.get("/v1/alerts", headers=auth(aud="other"))).status_code == 401
    assert (await c.get("/v1/alerts", headers=auth(exp=int(time.time()) - 3600))).status_code == 401
    assert (await c.get("/v1/alerts", headers=auth(tenant=None))).status_code == 403
    assert (await c.get("/v1/alerts", headers=auth("factory"))).status_code == 403


async def test_rbac(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    alert_id = await seed_alert(h)
    assert (await c.get("/v1/alerts", headers=auth("viewer"))).status_code == 200
    assert (
        await c.post(f"/v1/alerts/{alert_id}/ack", headers=auth("viewer"), json={})
    ).status_code == 403
    assert (
        await c.put("/v1/rules/auth_burst", headers=auth("operator"), json={})
    ).status_code == 403
    assert (await c.get("/v1/settings", headers=auth("operator"))).status_code == 403
    assert (await c.get("/v1/settings", headers=auth(["viewer", "admin"]))).status_code == 200


async def test_platform_admin_impersonation(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    await seed_alert(h, tenant=OTHER_TENANT)
    headers = {**auth("platform_admin", tenant=None), "X-IronMesh-Tenant": OTHER_TENANT}
    r = await c.get("/v1/alerts", headers=headers)
    assert r.status_code == 200 and len(r.json()["items"]) == 1
    r = await c.get("/v1/alerts", headers={**auth("admin"), "X-IronMesh-Tenant": OTHER_TENANT})
    assert r.status_code == 403
    r = await c.get("/v1/alerts", headers={**auth("admin"), "X-IronMesh-Tenant": "nope"})
    assert r.status_code == 422
    r = await c.patch("/v1/settings", headers=headers, json={"auto_quarantine": True})
    assert r.status_code == 200
    audit = [json.loads(m.value) for m in h.bus.messages("im.audit")]
    assert audit[-1]["details"]["platform_admin_impersonation"] is True
    assert audit[-1]["tenant_id"] == OTHER_TENANT


def test_principal_from_claims() -> None:
    p = principal_from_claims(
        {"sub": "u", "tenant_id": TENANT, "roles": ["viewer", "operator"]}, None
    )
    assert p.role == "operator" and p.has_role("viewer") and not p.has_role("admin")
    p = principal_from_claims(
        {"sub": "u", "tenant_id": TENANT, "role": "owner", "preferred_username": "bob"}, TENANT
    )
    assert p.role == "owner" and p.name == "bob" and not p.impersonating
    p = principal_from_claims(
        {"sub": "u", "tenant_id": TENANT, "platform_roles": ["platform_admin"]}, None
    )
    assert p.platform_admin and p.role == "admin"
    p = principal_from_claims({"sub": "u", "tenant_id": TENANT, "roles": 5}, None)
    assert p.role == "none"
    with pytest.raises(AuthError):
        principal_from_claims({"sub": "u"}, None)


def test_verifier_construction(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        TokenVerifier.from_public_key(
            PUB_PEM, audience="a", issuer=None, algorithms=["HS256", "none"]
        )
    pem = tmp_path / "pub.pem"
    pem.write_bytes(PUB_PEM)
    kw: dict[str, Any] = {"audience": "a", "issuer": None, "algorithms": ["ES256"], "leeway_s": 0}
    assert build_verifier(jwks_url=None, public_key_file=str(pem), **kw) is not None
    assert build_verifier(jwks_url="https://idp/jwks", public_key_file=None, **kw) is not None
    assert (
        build_verifier(jwks_url=None, public_key_file=None, **{**kw, "issuer": ISSUER}) is not None
    )
    assert build_verifier(jwks_url=None, public_key_file=None, **kw) is None


async def test_unconfigured_auth_is_503(tmp_path: Path) -> None:
    settings = Settings(run_pipeline=False, model_dir=str(tmp_path / "m"))
    h = make_harness(tmp_path, settings=settings)
    app = create_app(Components(settings, h.engine, None))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        assert (await c.get("/v1/rules", headers=auth())).status_code == 503


# ----------------------------------------------------------------------------------- alerts


async def test_alert_list_filters_and_pagination(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    ids_ = [await seed_alert(h, device=f"dev-{i:016x}") for i in range(5)]
    await seed_alert(h, RuleName.BEACONING)
    await seed_alert(h, tenant=OTHER_TENANT)
    r = await c.get("/v1/alerts?limit=2&rule=fw_hash_mismatch", headers=auth("viewer"))
    body = r.json()
    assert r.status_code == 200 and len(body["items"]) == 2 and body["next_cursor"]
    seen = [a["id"] for a in body["items"]]
    while body["next_cursor"]:
        body = (
            await c.get(
                f"/v1/alerts?limit=2&rule=fw_hash_mismatch&cursor={body['next_cursor']}",
                headers=auth("viewer"),
            )
        ).json()
        seen += [a["id"] for a in body["items"]]
    assert sorted(seen) == sorted(ids_)
    items = (await c.get("/v1/alerts", headers=auth("viewer"))).json()["items"]
    assert len(items) == 6 and all(a["tenant_id"] == TENANT for a in items)  # tenant isolation
    assert set(items[0]) == {
        "id",
        "tenant_id",
        "device_id",
        "rule",
        "severity",
        "score",
        "features",
        "explanation",
        "created_at",
        "state",
        "acked_by",
        "resolved_by",
        "actions",
    }
    q = "&".join(
        [
            "state=open",
            "severity=critical",
            f"device_id={DEV}",
            "from=2000-01-01T00:00:00Z",
            "to=2100-01-01T00:00:00Z",
        ]
    )
    assert len((await c.get(f"/v1/alerts?{q}", headers=auth("viewer"))).json()["items"]) == 1
    assert (await c.get("/v1/alerts?device_id=bad", headers=auth("viewer"))).status_code == 422
    assert (await c.get("/v1/alerts?cursor=%%%", headers=auth("viewer"))).status_code == 422
    assert (await c.get("/v1/alerts?limit=500", headers=auth("viewer"))).status_code == 422
    r = await c.get("/v1/alerts?severity=extreme", headers=auth("viewer"))
    assert r.status_code == 422 and r.json()["errors"]


async def test_alert_detail_ack_resolve_feedback(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    aid = await seed_alert(h)
    r = await c.get(f"/v1/alerts/{aid}", headers=auth("viewer"))
    assert r.status_code == 200 and r.json()["state"] == "open"
    assert (await c.get("/v1/alerts/not-a-uuid", headers=auth("viewer"))).status_code == 404
    assert (
        await c.get("/v1/alerts/00000000-0000-4000-8000-000000000000", headers=auth("viewer"))
    ).status_code == 404
    r = await c.post(f"/v1/alerts/{aid}/ack", headers=auth("operator"), json={"note": "looking"})
    assert (
        r.status_code == 200
        and r.json()["state"] == "acked"
        and r.json()["acked_by"] == "user:user-operator"
    )
    r = await c.post(
        f"/v1/alerts/{aid}/resolve",
        headers=auth("operator"),
        json={"note": "lab device", "false_positive": True},
    )
    assert r.status_code == 200 and r.json()["state"] == "resolved"
    assert (
        await c.post(f"/v1/alerts/{aid}/ack", headers=auth("operator"), json={})
    ).status_code == 409
    assert (
        await c.post(f"/v1/alerts/{aid}/resolve", headers=auth("operator"), json={})
    ).status_code == 409
    assert (
        await c.post(
            "/v1/alerts/00000000-0000-4000-8000-000000000000/ack", headers=auth("operator"), json={}
        )
    ).status_code == 404
    assert (
        await c.post(
            "/v1/alerts/00000000-0000-4000-8000-000000000000/resolve",
            headers=auth("operator"),
            json={},
        )
    ).status_code == 404
    assert (
        await c.post(f"/v1/alerts/{aid}/ack", headers=auth("operator"), json={"bogus": 1})
    ).status_code == 422
    sup = await h.repo.get_suppression(TENANT, DEV, RuleName.FW_HASH_MISMATCH)
    assert sup is not None  # false-positive feedback feeds suppression
    actions = [json.loads(m.value)["action"] for m in h.bus.messages("im.audit")]
    assert actions == ["alert.ack", "alert.resolve"]
    published = [json.loads(m.value)["state"] for m in h.bus.messages("im.alerts")]
    assert published == ["acked", "resolved"]
    stored = await h.repo.get_alert(TENANT, aid)
    assert stored is not None and stored.state is AlertState.RESOLVED and stored.false_positive


# ------------------------------------------------------------------------------------ rules


async def test_rules_get_put(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    rules = (await c.get("/v1/rules", headers=auth("viewer"))).json()
    assert {r["name"] for r in rules} == {r.value for r in RuleName}
    assert all(
        set(r) == {"name", "enabled", "severity", "params", "description", "dry_run"} for r in rules
    )
    r = await c.put(
        "/v1/rules/auth_burst",
        headers=auth("admin"),
        json={"params": {"threshold": 5}, "dry_run": True, "severity": "critical"},
    )
    assert r.status_code == 200
    assert (
        r.json()["params"]["threshold"] == 5
        and r.json()["dry_run"]
        and r.json()["severity"] == "critical"
    )
    r = await c.put("/v1/rules/auth_burst", headers=auth("admin"), json={"enabled": False})
    assert (
        r.json()["params"]["threshold"] == 5 and r.json()["enabled"] is False
    )  # partial update keeps params
    rs = await h.engine.rules_for(TENANT)
    assert not rs[RuleName.AUTH_BURST].enabled  # cache invalidated
    r = await c.put(
        "/v1/rules/auth_burst", headers=auth("admin"), json={"params": {"threshold": -1}}
    )
    assert r.status_code == 422 and r.json()["errors"][0]["loc"] == ["threshold"]
    assert (await c.put("/v1/rules/nope", headers=auth("admin"), json={})).status_code == 404
    assert (
        await c.put("/v1/rules/auth_burst", headers=auth("admin"), json={"unknown": 1})
    ).status_code == 422
    audit = [json.loads(m.value) for m in h.bus.messages("im.audit")]
    assert [a["action"] for a in audit] == ["anomaly.rule.update", "anomaly.rule.update"]


async def test_rule_dry_run_over_stored_events(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    h.directory.devices[DEV] = __import__(
        "ironmesh_anomaly.models", fromlist=["DeviceInfo"]
    ).DeviceInfo(DEV, TENANT, GATEWAY)
    for i in range(3):
        await h.engine.process_event(
            telemetry_event(DEV, T0 + i * 60, seq=i + 1, fw_hash=sha_hex(f"evil{i}")),
            h.directory.devices[DEV],
        )
    await h.engine.flush()
    assert len(h.repo.events) == 3
    window = {"from": "2025-10-01T00:00:00Z", "to": "2025-10-20T00:00:00Z"}
    r = await c.post("/v1/rules/fw_hash_mismatch/dry-run", headers=auth("operator"), json=window)
    assert r.status_code == 200
    body = r.json()
    assert body["would_fire"] == 1 and body["sample"][0]["rule"] == "fw_hash_mismatch"
    r = await c.post(
        "/v1/rules/fw_hash_mismatch/dry-run",
        headers=auth("operator"),
        json={
            **window,
            "params": {"check_known_hashes": False, "alert_on_unexpected_change": False},
        },
    )
    assert r.json()["would_fire"] == 0
    r = await c.post("/v1/rules/isolation_forest/dry-run", headers=auth("operator"), json=window)
    assert r.status_code == 200 and r.json()["would_fire"] == 0
    assert (
        await c.post(
            "/v1/rules/fw_hash_mismatch/dry-run",
            headers=auth("operator"),
            json={"from": "2025-10-02T00:00:00Z", "to": "2025-10-01T00:00:00Z"},
        )
    ).status_code == 422
    assert (
        await c.post(
            "/v1/rules/fw_hash_mismatch/dry-run",
            headers=auth("operator"),
            json={"from": "2025-01-01T00:00:00Z", "to": "2025-10-01T00:00:00Z"},
        )
    ).status_code == 422
    assert (
        await c.post(
            "/v1/rules/fw_hash_mismatch/dry-run",
            headers=auth("operator"),
            json={"from": "2025-10-01T00:00:00", "to": "2025-10-02T00:00:00"},
        )
    ).status_code == 422
    assert (
        await c.post(
            "/v1/rules/auth_burst/dry-run",
            headers=auth("operator"),
            json={**window, "params": {"threshold": "x"}},
        )
    ).status_code == 422
    assert (
        await c.post("/v1/rules/nope/dry-run", headers=auth("operator"), json=window)
    ).status_code == 404
    assert (
        await c.post("/v1/rules/auth_burst/dry-run", headers=auth("viewer"), json=window)
    ).status_code == 403
    assert len(h.repo.alerts) == 1  # dry-run never persists alerts (1 = the live one)


# ------------------------------------------------------------------ baseline, quarantine, settings


async def test_device_baseline(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    for i in range(5):
        await h.engine.process_event(
            telemetry_event(DEV, T0 + i * 60, seq=i + 1, tx=i * 6000, rx=i * 6000)
        )
    st = h.engine.state.get(TENANT, DEV)
    assert st is not None
    st.scores.append((T0, 0.25))
    r = await c.get(f"/v1/devices/{DEV}/baseline", headers=auth("viewer"))
    body = r.json()
    assert r.status_code == 200
    assert set(body) == {
        "device_class",
        "samples",
        "trained_at",
        "score_threshold",
        "feature_means",
        "recent_scores",
    }
    assert body["samples"] == 4 and body["trained_at"] is None and body["score_threshold"] == 0.5
    assert body["feature_means"]["cpu_pct"] == 20.0 and body["feature_means"]["rssi"] is None
    assert body["recent_scores"] == [["2025-10-09T08:53:20Z", 0.25]]
    assert (
        await c.get("/v1/devices/dev-00000000000000ff/baseline", headers=auth("viewer"))
    ).status_code == 404
    assert (await c.get("/v1/devices/bad/baseline", headers=auth("viewer"))).status_code == 422


async def test_quarantine_list(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    for i in range(3):
        await h.repo.add_quarantine(
            QuarantineRecord(TENANT, f"dev-{i:016x}", from_ts(T0 + i), "auto: x", None, "auto")
        )
    await h.repo.add_quarantine(
        QuarantineRecord(OTHER_TENANT, DEV, from_ts(T0), "x", None, "user:1")
    )
    r = await c.get("/v1/quarantine?limit=2", headers=auth("viewer"))
    body = r.json()
    assert len(body["items"]) == 2 and body["items"][0]["device_id"] == "dev-0000000000000002"
    assert set(body["items"][0]) == {"device_id", "quarantined_at", "reason", "alert_id", "by"}
    rest = (
        await c.get(f"/v1/quarantine?cursor={body['next_cursor']}", headers=auth("viewer"))
    ).json()
    assert [i["device_id"] for i in rest["items"]] == ["dev-0000000000000000"] and rest[
        "next_cursor"
    ] is None


async def test_settings_get_patch_and_ssrf(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, h = env
    r = await c.get("/v1/settings", headers=auth("admin"))
    assert r.json() == {
        "auto_quarantine": False,
        "quarantine_min_severity": "high",
        "siem": {
            "ecs_webhook_url": None,
            "syslog_host": None,
            "syslog_port": None,
            "enabled": False,
        },
    }
    r = await c.patch(
        "/v1/settings",
        headers=auth("admin"),
        json={
            "auto_quarantine": True,
            "quarantine_min_severity": "critical",
            "siem": {"ecs_webhook_url": "https://siem.example.com/x", "enabled": True},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert (
        body["auto_quarantine"]
        and body["quarantine_min_severity"] == "critical"
        and body["siem"]["enabled"]
    )
    r = await c.patch(
        "/v1/settings",
        headers=auth("admin"),
        json={"siem": {"syslog_host": "siem.example.com", "syslog_port": 6514}},
    )
    assert (
        r.json()["siem"]["ecs_webhook_url"] == "https://siem.example.com/x"
        and r.json()["siem"]["enabled"]
    )
    assert (await h.engine.settings_for(TENANT)).auto_quarantine
    for bad in (
        {"ecs_webhook_url": "https://169.254.169.254/latest"},
        {"syslog_host": "127.0.0.1"},
        {"ecs_webhook_url": "http://siem.example.com"},
    ):
        r = await c.patch("/v1/settings", headers=auth("admin"), json={"siem": bad})
        assert r.status_code == 422, bad
    assert (
        await c.patch("/v1/settings", headers=auth("admin"), json={"siem": {"syslog_port": 70000}})
    ).status_code == 422
    assert (
        await c.patch(
            "/v1/settings", headers=auth("admin"), json={"quarantine_min_severity": "extreme"}
        )
    ).status_code == 422
    audit = [json.loads(m.value) for m in h.bus.messages("im.audit")]
    assert (
        audit[0]["action"] == "anomaly.settings.update"
        and audit[0]["details"]["before"]["auto_quarantine"] is False
    )


async def test_health_metrics_openapi(env: tuple[httpx.AsyncClient, Harness]) -> None:
    c, _ = env
    assert (await c.get("/healthz")).json() == {"status": "ok"}
    assert (await c.get("/readyz")).status_code == 503  # lifespan not started
    m = await c.get("/metrics")
    assert (
        m.status_code == 200
        and "ironmesh_anomaly_alerts_total" in m.text
        and "ironmesh_http_requests_total" in m.text
    )
    spec = (await c.get("/openapi.json")).json()
    for path in (
        "/v1/alerts",
        "/v1/alerts/{alert_id}",
        "/v1/alerts/{alert_id}/ack",
        "/v1/alerts/{alert_id}/resolve",
        "/v1/rules",
        "/v1/rules/{name}",
        "/v1/rules/{name}/dry-run",
        "/v1/devices/{device_id}/baseline",
        "/v1/quarantine",
        "/v1/settings",
    ):
        assert path in spec["paths"], path
