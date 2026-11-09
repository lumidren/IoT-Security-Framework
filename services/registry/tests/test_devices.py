"""Devices, groups, provisioning, lifecycle orchestration and internal endpoints."""

from __future__ import annotations

import dataclasses
import uuid
from datetime import timedelta
from typing import Any

from app.auth import SYSTEM
from app.domain import ActionRecord
from app.integrations.bus import TOPIC_AUDIT, TOPIC_COMMANDS
from app.services import devices as device_svc

from .conftest import INTERNAL_TOKEN, Env


async def test_create_get_list_update(env: Env) -> None:
    t = await env.tenant()
    created = await env.device(t, tags={"site": "berlin"})
    assert created["state"] == "manufactured"
    assert created["id"].startswith("dev-") and len(created["id"]) == 20
    assert created["cert"] == {"serial_hex": None, "not_after": None, "status": "none"}
    assert created["bootstrap_serial_hex"] == "0a1b2c3d4e5f"
    assert created["twin_version"] == 0
    fixed = await env.device(
        t, id="dev-00000000000000a1", product="sensor-esp32", se_type="software"
    )
    assert fixed["id"] == "dev-00000000000000a1" or env.kind == "postgres"

    h = env.auth(t, "viewer")
    r = await env.client.get(f"/v1/devices/{created['id']}", headers=h)
    assert r.status_code == 200 and r.json()["tags"] == {"site": "berlin"}

    r = await env.client.get("/v1/devices", headers=h, params={"tag": "site:berlin"})
    assert [d["id"] for d in r.json()["items"]] == [created["id"]]
    r = await env.client.get("/v1/devices", headers=h, params={"q": "esp32"})
    assert [d["id"] for d in r.json()["items"]] == [fixed["id"]]
    r = await env.client.get("/v1/devices", headers=h, params={"state": "active"})
    assert r.json()["items"] == []
    r = await env.client.get("/v1/devices", headers=h, params={"tag": "nocolon"})
    assert r.status_code == 422 and r.headers["content-type"] == "application/problem+json"

    r = await env.client.post(
        "/v1/groups",
        headers=env.auth(t, "operator"),
        json={"slug": "berlin", "name": "Berlin", "hardware_only": True},
    )
    assert r.status_code == 201
    r = await env.client.patch(
        f"/v1/devices/{created['id']}",
        headers=env.auth(t, "operator"),
        json={"tags": {"site": "paris"}, "groups": ["berlin"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["groups"] == ["berlin"] and r.json()["tags"] == {"site": "paris"}
    r = await env.client.get("/v1/devices", headers=h, params={"group": "berlin"})
    assert len(r.json()["items"]) == 1
    r = await env.client.patch(
        f"/v1/devices/{created['id']}", headers=env.auth(t, "operator"), json={"groups": ["nope"]}
    )
    assert r.status_code == 422
    r = await env.client.patch(
        f"/v1/devices/{created['id']}", headers=env.auth(t, "operator"), json={"groups": []}
    )
    assert r.json()["groups"] == []
    r = await env.client.get("/v1/devices/dev-ffffffffffffffff", headers=h)
    assert r.status_code == 404 and r.json()["title"] == "Not Found"
    r = await env.client.get("/v1/devices/not-a-device", headers=h)
    assert r.status_code == 404


async def test_duplicate_device_id_conflicts(env: Env) -> None:
    t = await env.tenant()
    dev = await env.device(t)
    r = await env.client.post(
        "/v1/devices",
        headers=env.auth(t, "admin"),
        json={
            "id": dev["id"],
            "product": "gateway-rpi",
            "hw_revision": "a",
            "se_type": "tpm2",
            "bootstrap_serial_hex": "01",
        },
    )
    assert r.status_code == 409


async def test_cursor_pagination(env: Env) -> None:
    t = await env.tenant()
    ids_ = sorted([(await env.device(t))["id"] for _ in range(5)])
    seen: list[str] = []
    cursor = None
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        r = await env.client.get("/v1/devices", headers=env.auth(t), params=params)
        page = r.json()
        seen += [d["id"] for d in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == ids_
    r = await env.client.get("/v1/devices", headers=env.auth(t), params={"cursor": "%%%"})
    assert r.status_code == 422
    r = await env.client.get("/v1/devices", headers=env.auth(t), params={"limit": 500})
    assert r.status_code == 422


async def test_default_group_and_software_hardware_only(env: Env) -> None:
    t = await env.tenant(default_group="fleet")
    await env.client.post("/v1/groups", headers=env.auth(t), json={"slug": "fleet", "name": "F"})
    await env.client.post(
        "/v1/groups", headers=env.auth(t), json={"slug": "hw", "name": "HW", "hardware_only": True}
    )
    dev = await env.device(t, se_type="software")
    assert dev["groups"] == ["fleet"]
    await env.enroll(t, dev["id"], assurance="software", se_type="software")
    r = await env.client.put(
        "/v1/groups/hw/members",
        headers=env.auth(t, "operator"),
        json={"add": [dev["id"], "dev-0000000000000bad"], "remove": []},
    )
    body = r.json()
    assert body["added"] == []
    assert {x["device_id"] for x in body["rejected"]} == {dev["id"], "dev-0000000000000bad"}
    r = await env.client.patch(
        f"/v1/devices/{dev['id']}", headers=env.auth(t, "operator"), json={"groups": ["hw"]}
    )
    assert r.status_code == 422
    r = await env.client.patch(
        "/v1/groups/fleet", headers=env.auth(t, "operator"), json={"hardware_only": True}
    )
    assert r.status_code == 409
    r = await env.client.patch(
        "/v1/groups/fleet",
        headers=env.auth(t, "operator"),
        json={"name": "Fleet", "description": "all"},
    )
    assert r.json()["name"] == "Fleet" and r.json()["member_count"] == 1
    r = await env.client.put(
        "/v1/groups/fleet/members",
        headers=env.auth(t, "operator"),
        json={"add": [], "remove": [dev["id"]]},
    )
    assert r.json()["removed"] == [dev["id"]]
    r = await env.client.get("/v1/groups", headers=env.auth(t, "viewer"))
    assert [g["slug"] for g in r.json()] == ["fleet", "hw"]
    assert (
        await env.client.post("/v1/groups", headers=env.auth(t), json={"slug": "hw", "name": "x"})
    ).status_code == 409
    assert (
        await env.client.delete("/v1/groups/hw", headers=env.auth(t, "admin"))
    ).status_code == 204
    assert (
        await env.client.delete("/v1/groups/hw", headers=env.auth(t, "admin"))
    ).status_code == 404
    assert (
        await env.client.patch("/v1/groups/hw", headers=env.auth(t), json={"name": "x"})
    ).status_code == 404
    assert (
        await env.client.put("/v1/groups/hw/members", headers=env.auth(t), json={"add": []})
    ).status_code == 404


async def test_enrollment_lifecycle_and_timeline(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    r = await env.client.get(f"/v1/devices/{dev['id']}", headers=env.auth(t))
    d = r.json()
    assert d["state"] == "active" and d["assurance_level"] == "hardware"
    assert d["cert"]["serial_hex"] == dk.serial_hex and d["cert"]["status"] == "valid"
    assert d["provisioned_at"] and d["activated_at"] and d["fw_version"] == "2.4.1"
    assert [c["serial_hex"] for c in d["certificates"]] == [dk.serial_hex]

    # renewal keeps the device active and records a "renew" event
    dk2 = await env.enroll(t, dev["id"])
    r = await env.client.get(f"/v1/devices/{dev['id']}/timeline", headers=env.auth(t))
    kinds = [e["kind"] for e in r.json()["items"]]
    assert "renew" in kinds and "enroll" in kinds and "lifecycle" in kinds
    r = await env.client.get(
        f"/v1/devices/{dev['id']}/timeline",
        headers=env.auth(t),
        params={"kinds": "enroll,renew", "limit": 1},
    )
    page = r.json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    r = await env.client.get(
        f"/v1/devices/{dev['id']}/timeline",
        headers=env.auth(t),
        params={"kinds": "enroll,renew", "cursor": page["next_cursor"]},
    )
    assert len(r.json()["items"]) == 1
    r = await env.client.get(
        f"/v1/devices/{dev['id']}/timeline",
        headers=env.auth(t),
        params={
            "from": (env.clock() - timedelta(days=1)).isoformat(),
            "to": (env.clock() + timedelta(days=1)).isoformat().replace("+00:00", ""),
        },
    )
    assert r.status_code == 200 and r.json()["items"]

    r = await env.client.get(f"/v1/devices/{dev['id']}/certificates", headers=env.auth(t))
    assert {c["serial_hex"] for c in r.json()} == {dk.serial_hex, dk2.serial_hex}
    env.pki.fail_lookup = True
    r = await env.client.get(f"/v1/devices/{dev['id']}/certificates", headers=env.auth(t))
    assert {c["serial_hex"] for c in r.json()} == {dk.serial_hex, dk2.serial_hex}


async def test_manual_approval_and_reject(env: Env) -> None:
    t = await env.tenant(require_manual_approval=True)
    a = await env.device(t)
    b = await env.device(t)
    await env.enroll(t, a["id"])
    await env.enroll(t, b["id"])
    r = await env.client.get(
        "/v1/provisioning", headers=env.auth(t, "viewer"), params={"state": "provisioned"}
    )
    assert {i["device_id"] for i in r.json()["items"]} == {a["id"], b["id"]}
    assert r.json()["items"][0]["attempts"] == 1
    r = await env.client.post(
        f"/v1/provisioning/{a['id']}/approve", headers=env.auth(t, "operator")
    )
    assert r.status_code == 200 and r.json()["state"] == "active"
    r = await env.client.post(
        f"/v1/provisioning/{a['id']}/approve", headers=env.auth(t, "operator")
    )
    assert r.status_code == 409
    r = await env.client.post(
        f"/v1/provisioning/{b['id']}/reject",
        headers=env.auth(t, "operator"),
        json={"reason": "unknown batch"},
    )
    assert r.status_code == 200 and r.json()["state"] == "quarantined"
    assert env.pki.revoked[-1] == (b["id"], "unknown batch")
    r = await env.client.get("/v1/provisioning", headers=env.auth(t), params={"state": "failed"})
    assert [i["device_id"] for i in r.json()["items"]] == [b["id"]]
    assert r.json()["items"][0]["last_error"] == "unknown batch"
    r = await env.client.post(
        f"/v1/provisioning/{a['id']}/reject", headers=env.auth(t, "operator"), json={"reason": "x"}
    )
    assert r.status_code == 409
    r = await env.client.get("/v1/provisioning", headers=env.auth(t), params={"state": "bogus"})
    assert r.status_code == 422
    c = await env.device(t)
    r = await env.client.get("/v1/provisioning", headers=env.auth(t), params={"limit": 1})
    assert r.json()["next_cursor"] is not None
    r = await env.client.get(
        "/v1/provisioning", headers=env.auth(t), params={"state": "manufactured"}
    )
    assert [i["device_id"] for i in r.json()["items"]] == [c["id"]]


async def test_quarantine_release_decommission_orchestration(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    did = dev["id"]
    await env.client.post(
        f"/v1/devices/{did}/commands",
        headers=env.auth(t, "operator"),
        json={"name": "reboot", "args": {}, "ttl_s": 60},
    )
    r = await env.client.post(
        f"/v1/devices/{did}/quarantine",
        headers=env.auth(t, "operator"),
        json={"reason": "beaconing"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "quarantined" and body["quarantine_reason"] == "beaconing"
    assert body["cert"]["status"] == "revoked"
    assert env.pki.revoked == [(did, "beaconing")]
    # idempotent second quarantine
    r = await env.client.post(
        f"/v1/devices/{did}/quarantine", headers=env.auth(t, "operator"), json={"reason": "again"}
    )
    assert r.status_code == 200 and len(env.pki.revoked) == 1
    # operator cannot release (admin required)
    r = await env.client.post(
        f"/v1/devices/{did}/release", headers=env.auth(t, "operator"), json={"note": "ok"}
    )
    assert r.status_code == 403
    r = await env.client.post(
        f"/v1/devices/{did}/release", headers=env.auth(t, "admin"), json={"note": "false positive"}
    )
    assert r.status_code == 200 and r.json()["state"] == "active"
    assert r.json()["quarantine_reason"] is None
    # the PKI device_release lifts the policy service's device-level deny
    assert env.pki.released == [(did, t)]
    r = await env.client.post(
        f"/v1/devices/{did}/release", headers=env.auth(t, "admin"), json={"note": ""}
    )
    assert r.status_code == 409
    r = await env.client.post(
        f"/v1/devices/{did}/decommission",
        headers=env.auth(t, "admin"),
        json={"reason": "end of life"},
    )
    assert r.status_code == 200 and r.json()["state"] == "decommissioned"
    assert r.json()["decommissioned_at"]
    cleared = [m for m in env.mqtt.messages if m.retain and m.payload == b""]
    assert {m.topic.rsplit("/", 2)[-2] + "/" + m.topic.rsplit("/", 1)[-1] for m in cleared} >= {
        "shadow/desired"
    } or len(cleared) == 3
    r = await env.client.get(f"/v1/devices/{did}/commands", headers=env.auth(t))
    assert {c["status"] for c in r.json()["items"]} == {"rejected"}
    assert any(m.topic == TOPIC_COMMANDS for m in env.bus.published)
    # terminal state
    for path, body2 in (("quarantine", {"reason": "x"}), ("decommission", {"reason": "x"})):
        r = await env.client.post(
            f"/v1/devices/{did}/{path}", headers=env.auth(t, "admin"), json=body2
        )
        assert r.status_code == 409, path
        assert r.json()["type"].endswith("invalid-transition")
    r = await env.client.patch(f"/v1/devices/{did}", headers=env.auth(t), json={"tags": {}})
    assert r.status_code == 409
    actions = list(env.bus.on(TOPIC_AUDIT))
    assert actions, "audit events are published on im.audit"


async def test_quarantine_compensation_when_pki_down(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    env.pki.fail_revoke = 3  # all attempts fail
    r = await env.client.post(
        f"/v1/devices/{dev['id']}/quarantine",
        headers=env.auth(t, "operator"),
        json={"reason": "stolen"},
    )
    assert r.status_code == 200 and r.json()["state"] == "quarantined"
    assert env.pki.revoked == [] and env.emqx.kicked == [dev["id"]]
    assert env.sleeps, "retries back off"
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"target_id": dev["id"]})
    actions = {(a["action"], a["outcome"]) for a in r.json()["items"]}
    assert ("device.credentials_revoke_failed", "failure") in actions
    assert ("device.session_kick", "success") in actions
    # the outbox job completes the revocation later
    env.clock.advance(seconds=31)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 1
    assert env.pki.revoked == [(dev["id"], "stolen")]
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"target_id": dev["id"]})
    assert "action.pki_revoke_all.completed" in {a["action"] for a in r.json()["items"]}
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0


async def _audit_actions(env: Env, t: str, device_id: str) -> set[tuple[str, str]]:
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"target_id": device_id, "limit": 200}
    )
    return {(a["action"], a["outcome"]) for a in r.json()["items"]}


async def _quarantine(env: Env, t: str, did: str) -> None:
    r = await env.client.post(
        f"/v1/devices/{did}/quarantine", headers=env.auth(t, "operator"), json={"reason": "x"}
    )
    assert r.status_code == 200, r.text


async def _release(env: Env, t: str, did: str, note: str = "false positive") -> Any:
    return await env.client.post(
        f"/v1/devices/{did}/release", headers=env.auth(t, "admin"), json={"note": note}
    )


async def test_release_calls_pki_release(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    did = dev["id"]
    await _quarantine(env, t, did)
    r = await _release(env, t, did)
    assert r.status_code == 200 and r.json()["state"] == "active"
    assert env.pki.revoked == [(did, "x")] and env.pki.released == [(did, t)]
    actions = await _audit_actions(env, t, did)
    assert ("device.pki_released", "success") in actions
    assert ("device.release", "success") in actions
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"action": "device.release"})
    assert r.json()["items"][0]["details"]["pki_release"] == "done"
    # the device re-enrolls (new certificate) after the release
    await env.enroll(t, did)
    r = await env.client.get(f"/v1/devices/{did}", headers=env.auth(t))
    assert r.json()["state"] == "active" and r.json()["cert"]["status"] == "valid"


async def test_release_when_pki_down_is_retried_from_the_outbox(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    did = dev["id"]
    await _quarantine(env, t, did)
    env.pki.fail_release = 3  # every inline attempt fails
    r = await _release(env, t, did)
    assert r.status_code == 200 and r.json()["state"] == "active"
    assert env.pki.released == []
    actions = await _audit_actions(env, t, did)
    assert ("device.pki_release_failed", "failure") in actions
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"action": "device.release"})
    assert r.json()["items"][0]["details"]["pki_release"] == "pending"
    # not due yet
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0
    env.clock.advance(seconds=31)
    env.pki.fail_release = 1  # the first retry still fails -> backoff
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0
    assert env.pki.released == []
    env.clock.advance(hours=2)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 1
    assert env.pki.released == [(did, t)]
    actions = await _audit_actions(env, t, did)
    assert ("action.pki_release.completed", "success") in actions
    assert ("device.pki_released", "success") in actions
    env.clock.advance(hours=2)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0


async def test_requarantine_cancels_a_queued_release(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    did = dev["id"]
    await _quarantine(env, t, did)
    env.pki.fail_release = 3
    assert (await _release(env, t, did)).status_code == 200
    await _quarantine(env, t, did)  # quarantined again before the release reached the PKI
    assert ("action.pki_release.cancelled", "success") in await _audit_actions(env, t, did)
    env.clock.advance(hours=2)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0
    assert env.pki.released == []  # the new device-level deny is never lifted


async def test_queued_release_skipped_when_device_not_active(env: Env) -> None:
    t = await env.tenant()
    dev = await env.device(t)
    did = dev["id"]
    now = env.clock()
    stale = ActionRecord(
        tenant_id=t,
        id=str(uuid.uuid4()),
        kind=device_svc.PKI_RELEASE,
        device_id=did,
        payload={"note": "n"},
        created_at=now,
        next_attempt_at=now,
    )
    async with env.repo.tenant(t) as tx:
        await tx.insert_action(stale)
    # A record that is no longer pending (e.g. cancelled after the due list was read) is skipped.
    gone = dataclasses.replace(stale, id=str(uuid.uuid4()))
    assert not await device_svc._retry_pki_release(env.ctx, SYSTEM, t, gone)
    # The device is "manufactured", not active: the release is cancelled, never sent.
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0
    assert env.pki.released == []
    assert ("action.pki_release.cancelled", "success") in await _audit_actions(env, t, did)


async def test_release_waits_for_pending_revocation(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    did = dev["id"]
    env.pki.fail_revoke = 3  # quarantine's revoke-all is queued in the outbox
    await _quarantine(env, t, did)
    assert env.pki.revoked == []
    env.pki.fail_revoke = 3  # still down at release time -> refused, device stays quarantined
    r = await _release(env, t, did)
    assert r.status_code == 503 and r.headers["retry-after"] == "30"
    r = await env.client.get(f"/v1/devices/{did}", headers=env.auth(t))
    assert r.json()["state"] == "quarantined" and env.pki.released == []
    assert ("device.release", "failure") in await _audit_actions(env, t, did)
    # PKI back: the release first completes the revocation, then releases.
    r = await _release(env, t, did)
    assert r.status_code == 200 and r.json()["state"] == "active"
    assert env.pki.revoked == [(did, "x")] and env.pki.released == [(did, t)]
    assert ("action.pki_revoke_all.completed", "success") in await _audit_actions(env, t, did)
    env.clock.advance(hours=2)
    assert await device_svc.run_pending_actions(env.ctx, SYSTEM, [t]) == 0
    assert env.pki.revoked == [(did, "x")]  # the queued revoke-all is not replayed


async def test_compensation_retry_backoff_and_abandon(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    env.pki.fail_revoke = 10_000
    env.emqx.fail = True
    await env.client.post(
        f"/v1/devices/{dev['id']}/quarantine", headers=env.auth(t, "operator"), json={"reason": "x"}
    )
    for _ in range(25):
        env.clock.advance(hours=2)
        await device_svc.run_pending_actions(env.ctx, SYSTEM, [t])
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"action": "action.pki_revoke_all.abandoned"}
    )
    assert len(r.json()["items"]) == 1
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"action": "device.session_kick"}
    )
    assert r.json()["items"][0]["outcome"] == "failure"


async def test_internal_endpoints(env: Env) -> None:
    t = await env.tenant()
    dev = await env.device(t, bootstrap_serial_hex="00:AB:CD")
    did = dev["id"]
    r = await env.client.get(f"/internal/v1/devices/{did}/lifecycle", headers=env.service("policy"))
    assert r.json() == {
        "device_id": did,
        "tenant_id": t,
        "state": "manufactured",
        "assurance_level": None,
        "product": dev["product"],
    }
    r = await env.client.get(f"/internal/v1/devices/{did}/lifecycle", headers=env.service("pki"))
    assert r.status_code == 403
    r = await env.client.get(
        f"/internal/v1/devices/{did}/lifecycle",
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
    )
    assert r.status_code == 200
    # The policy service's static token identifies the policy service only: it cannot call
    # endpoints reserved for the PKI or the anomaly engine.
    r = await env.client.post(
        f"/internal/v1/devices/{did}/quarantine",
        json={"reason": "forged", "alert_id": "a-1"},
        headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"},
    )
    assert r.status_code == 403
    r = await env.client.get(
        f"/internal/v1/devices/{did}/lifecycle",
        headers={"Authorization": "Bearer not-a-configured-token"},
    )
    assert r.status_code == 401
    r = await env.client.get(f"/internal/v1/devices/{did}/lifecycle", headers=env.auth(t))
    assert r.status_code == 401
    r = await env.client.get(f"/internal/v1/devices/{did}/lifecycle")
    assert r.status_code == 401
    r = await env.client.get(
        "/internal/v1/devices/dev-1234567890abcdef/lifecycle", headers=env.service("policy")
    )
    assert r.status_code == 404
    r = await env.client.get(
        f"/internal/v1/devices/{did}/lifecycle", headers=env.service("policy", aud="pki")
    )
    assert r.status_code == 401
    r = await env.client.get(
        f"/internal/v1/devices/{did}/lifecycle", headers=env.service("policy", lifetime=3600)
    )
    assert r.status_code == 401

    # PKI EST lookups (API_CONTRACT 1.12)
    r = await env.client.get(f"/internal/v1/tenants/{t}/devices/{did}", headers=env.service("pki"))
    assert r.status_code == 200
    assert r.json() == {
        "device_id": did,
        "tenant_id": t,
        "state": "manufactured",
        "assurance_level": None,
        "se_type": "tpm2",
        "bootstrap_serial": "abcd",
    }
    other = await env.tenant()
    r = await env.client.get(
        f"/internal/v1/tenants/{other}/devices/{did}", headers=env.service("pki")
    )
    assert r.status_code == 404
    r = await env.client.get(
        f"/internal/v1/tenants/not-a-uuid/devices/{did}", headers=env.service("pki")
    )
    assert r.status_code == 404
    r = await env.client.get(
        f"/internal/v1/tenants/{t}/devices/{did}", headers=env.service("anomaly")
    )
    assert r.status_code == 403
    r = await env.client.post(
        f"/internal/v1/tenants/{t}/devices/{did}/assurance",
        headers=env.service("pki"),
        json={"assurance_level": "software"},
    )
    assert r.status_code == 204
    r = await env.client.post(
        f"/internal/v1/tenants/{other}/devices/{did}/assurance",
        headers=env.service("pki"),
        json={"assurance_level": "software"},
    )
    assert r.status_code == 404
    r = await env.client.post(
        f"/internal/v1/tenants/{t}/devices/{did}/assurance",
        headers=env.service("pki"),
        json={"assurance_level": "bogus"},
    )
    assert r.status_code == 422
    r = await env.client.get(f"/internal/v1/tenants/{t}/devices/{did}", headers=env.service("pki"))
    assert r.json()["assurance_level"] == "software"

    # anomaly quarantine
    await env.enroll(t, did)
    r = await env.client.post(
        f"/internal/v1/devices/{did}/quarantine",
        headers=env.service("anomaly"),
        json={"reason": "impossible travel", "alert_id": "a-1"},
    )
    assert r.status_code == 200 and r.json()["state"] == "quarantined"
    r = await env.client.post(
        f"/internal/v1/devices/{did}/enrolled",
        headers=env.service("pki"),
        json={
            "serial_hex": "01",
            "not_before": env.clock().isoformat(),
            "not_after": env.clock().isoformat(),
            "se_type": "tpm2",
            "assurance_level": "hardware",
        },
    )
    assert r.status_code == 409
    r = await env.client.get("/v1/audit", headers=env.auth(t), params={"actor": "anomaly"})
    assert any(a["action"] == "device.quarantine" for a in r.json()["items"])


async def test_telemetry_validation(env: Env) -> None:
    t = await env.tenant()
    dev = await env.device(t)
    url = f"/v1/devices/{dev['id']}/telemetry"
    for params in (
        {"metrics": "bogus"},
        {"step": "abc"},
        {"step": "0s"},
        {"from": env.clock().isoformat(), "to": env.clock().isoformat()},
    ):
        r = await env.client.get(url, headers=env.auth(t), params=params)
        assert r.status_code == 422, params
    r = await env.client.get(
        url,
        headers=env.auth(t),
        params={
            "step": "1s",
            "metrics": "cpu_pct",
            "from": (env.clock() - timedelta(days=1)).isoformat(),
        },
    )
    assert r.status_code == 200 and r.json() == {"series": [{"metric": "cpu_pct", "points": []}]}


async def test_internal_service_jwt_is_single_use(env: Env) -> None:
    t = await env.tenant()
    did = (await env.device(t))["id"]
    url = f"/internal/v1/devices/{did}/lifecycle"
    h = env.service("policy")
    assert (await env.client.get(url, headers=h)).status_code == 200
    replay = await env.client.get(url, headers=h)
    assert replay.status_code == 401 and "already used" in replay.json()["detail"]
    assert (await env.client.get(url, headers=env.service("policy"))).status_code == 200
    long_lived = await env.client.get(url, headers=env.service("policy", lifetime=301))
    assert long_lived.status_code == 401
