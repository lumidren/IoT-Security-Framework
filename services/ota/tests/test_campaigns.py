"""Campaign lifecycle end to end through the API, the controller and the status ingest."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from ironmesh_ota.domain import CampaignState
from ironmesh_wire import OtaState, envelope, ids
from ironmesh_wire.ids import TopicClass
from ironmesh_wire.manifest import verify_manifest

from .conftest import Env, image_bytes, new_tenant

S = OtaState
FAST = [
    {"percent": 10, "dwell_s": 600, "max_failure_rate": 0.2},
    {"percent": 50, "dwell_s": 600, "max_failure_rate": 0.2},
    {"percent": 100, "dwell_s": 0, "max_failure_rate": 0.2},
]


async def _setup(
    env: Env, n: int = 20, stages: list[dict[str, Any]] | None = None, **kw: Any
) -> tuple[uuid.UUID, dict[str, Any], dict[str, Any], list[str], bytes]:
    tenant = new_tenant()
    old, new = image_bytes(1), image_bytes(2)
    await env.upload(tenant, old, version="1.0.0", version_code=100)
    fw = await env.upload(tenant, new, version="1.1.0", version_code=110)
    devices = env.add_devices(tenant, n, fw=old)
    campaign = await env.create_campaign(tenant, fw["id"], stages=stages or FAST, **kw)
    return tenant, fw, campaign, devices, new


async def _stage_devices(env: Env, tenant: uuid.UUID, cid: str, state: str) -> list[str]:
    return [d["device_id"] for d in await env.devices(tenant, cid, state)]


async def _succeed(env: Env, tenant: uuid.UUID, cid: str, devices: list[str], image: bytes) -> None:
    for dev in devices:
        await env.status(tenant, cid, dev, S.DOWNLOADING, progress=50)
        await env.status(tenant, cid, dev, S.SUCCESS, fw_hash=hashlib.sha256(image).digest())


async def test_create_defaults_and_validation(env: Env) -> None:
    tenant = new_tenant()
    fw = await env.upload(tenant, image_bytes(1))
    created = await env.create_campaign(tenant, fw["id"])
    assert created["state"] == "draft"
    assert [s["percent"] for s in created["stages"]] == [1, 10, 100]
    assert [s["dwell_s"] for s in created["stages"]] == [3600, 3600, 0]
    assert created["severity"] == "normal" and created["requires_approval"] is False
    assert created["firmware"]["id"] == fw["id"]
    assert created["totals"]["targeted"] == 0
    resp = await env.client.post(
        "/v1/campaigns",
        json={
            "name": "x",
            "firmware_id": str(uuid.uuid4()),
            "target": {"groups": [], "device_ids": [], "tags": {}},
            "stages": [
                {"percent": 50, "dwell_s": 0, "max_failure_rate": 0.1},
                {"percent": 40, "dwell_s": 0, "max_failure_rate": 0.1},
            ],
        },
        headers=env.auth(tenant, "operator"),
    )
    assert resp.status_code == 422
    fields = {e["field"] for e in resp.json()["errors"]}
    assert {"target", "firmware_id", "stages[1].percent"} <= fields
    bad = await env.client.post(
        "/v1/campaigns",
        json={"name": "x", "firmware_id": "nope", "target": {"groups": ["Bad Slug"]}},
        headers=env.auth(tenant, "operator"),
    )
    assert bad.status_code == 422
    page = await env.client.get("/v1/campaigns?state=draft,running", headers=env.auth(tenant))
    assert [c["id"] for c in page.json()["items"]] == [created["id"]]
    assert (
        await env.client.get("/v1/campaigns?state=bogus", headers=env.auth(tenant))
    ).status_code == 422


async def test_full_rollout_through_all_stages(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 20)
    cid = campaign["id"]
    started = await env.action(tenant, cid, "start", role="operator")
    assert started["state"] == "running"
    assert [s["counts"]["targeted"] for s in started["stages"]] == [2, 8, 10]
    assert started["stages"][0]["state"] == "running"
    canary = await _stage_devices(env, tenant, cid, "notified")
    assert len(canary) == 2

    # every canary device got a tenant-signed, retained OtaNotify carrying the signed manifest
    for dev in canary:
        [notify] = env.notifies(tenant, dev)
        assert isinstance(notify.body, envelope.OtaNotify)
        assert notify.body.campaign_id == cid
        assert notify.body.delta_from is None
        verified = verify_manifest(notify.body.manifest, env.container.signer.trusted_public_keys())
        assert verified.manifest.version_code == 110
        assert notify.body.url.startswith("http://ota.test/v1/artifacts/")
    assert all(m.retain and m.qos == 1 for m in env.publisher.messages)

    await _succeed(env, tenant, cid, canary, image)
    view = await env.campaign(tenant, cid)
    assert view["stages"][0]["state"] == "dwelling"
    assert view["stages"][0]["counts"]["success"] == 2
    await env.tick()
    assert (await env.campaign(tenant, cid))["current_stage"] == 0  # dwell not over yet

    env.clock.advance(601)
    await env.tick()
    view = await env.campaign(tenant, cid)
    assert view["current_stage"] == 1 and view["stages"][0]["state"] == "passed"
    stage1 = await _stage_devices(env, tenant, cid, "notified")
    assert len(stage1) == 8 and not set(stage1) & set(canary)
    await _succeed(env, tenant, cid, stage1, image)
    env.clock.advance(601)
    await env.tick()
    stage2 = await _stage_devices(env, tenant, cid, "notified")
    assert len(stage2) == 10
    await _succeed(env, tenant, cid, stage2, image)
    done = await env.campaign(tenant, cid)
    assert done["state"] == "completed"
    assert done["totals"]["success"] == 20
    assert done["finished_at"] is not None
    # retained notifies are cleared on completion
    assert env.publisher.retained == {}
    metrics = (await env.client.get("/metrics")).text
    assert 'ironmesh_ota_result_total{result="success"} 20.0' in metrics
    assert "ironmesh_ota_campaign_stage" in metrics
    frames = env.events.of_type("campaign.updated")
    assert frames and frames[-1].value["data"]["state"] == "completed"
    assert frames[-1].topic == "im.campaigns" and frames[-1].key == str(tenant)

    audit = (
        await env.client.get(
            f"/v1/campaigns/{cid}/audit?limit=200", headers=env.auth(tenant, "viewer")
        )
    ).json()["items"]
    actions = [a["action"] for a in audit]
    for expected in (
        "campaign.create",
        "campaign.start",
        "campaign.stage.start",
        "campaign.stage.dwell",
        "campaign.stage.passed",
        "campaign.completed",
    ):
        assert expected in actions
    start = next(a for a in audit if a["action"] == "campaign.start")
    assert start["actor"] == {"type": "user", "id": "alice", "name": "Alice"}
    assert start["details"]["devices"] == 20


async def test_automatic_halt_when_failure_rate_exceeds_threshold(env: Env) -> None:
    stages = [
        {"percent": 50, "dwell_s": 0, "max_failure_rate": 0.25},
        {"percent": 100, "dwell_s": 0, "max_failure_rate": 0.25},
    ]
    tenant, fw, campaign, devices, image = await _setup(env, 16, stages)
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    stage0 = await _stage_devices(env, tenant, cid, "notified")
    assert len(stage0) == 8
    await _succeed(env, tenant, cid, stage0[:2], image)
    assert (await env.campaign(tenant, cid))["state"] == "running"  # 0/2 failures
    # 1 failure of 3 outcomes = 0.333 > 0.25 with the minimum sample (2) reached -> halt
    result = await env.status(tenant, cid, stage0[2], S.REJECTED, error="MF_ROLLBACK")
    assert result["action"] == "halted"
    view = await env.campaign(tenant, cid)
    assert view["state"] == "halted"
    assert view["halt_reason"].startswith("automatic halt: stage 0: failure rate 0.333")
    assert view["stages"][0]["state"] == "halted"
    # devices that had not started lose their retained notify; stage 1 was never notified
    remaining = await _stage_devices(env, tenant, cid, "notified")
    assert len(remaining) == 5
    for dev in remaining:
        assert (
            ids.build_topic(str(tenant), dev, TopicClass.OTA_NOTIFY) not in env.publisher.retained
        )
    assert len(await _stage_devices(env, tenant, cid, "pending")) == 8
    await env.tick()
    assert (await env.campaign(tenant, cid))["state"] == "halted"
    audit = (await env.client.get(f"/v1/campaigns/{cid}/audit", headers=env.auth(tenant))).json()
    halt = next(a for a in audit["items"] if a["action"] == "campaign.halt.auto")
    assert halt["actor"]["type"] == "system"
    assert halt["details"]["counts"]["rejected"] == 1 and halt["details"]["counts"]["success"] == 2
    # late outcomes after the halt are still recorded
    await env.status(tenant, cid, stage0[3], S.ROLLED_BACK, error="health check")
    assert (await env.campaign(tenant, cid))["totals"]["rolled_back"] == 1


async def test_canary_rollback_halts_immediately(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env,
        50,
        [
            {"percent": 10, "dwell_s": 60, "max_failure_rate": 1.0},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    canary = await _stage_devices(env, tenant, cid, "notified")
    await _succeed(env, tenant, cid, canary[:3], image)
    result = await env.status(tenant, cid, canary[3], S.ROLLED_BACK, error="boot loop")
    assert result["action"] == "halted"
    view = await env.campaign(tenant, cid)
    assert view["state"] == "halted"
    assert "rolled back" in view["halt_reason"]


async def test_resume_after_halt_evaluates_only_new_outcomes(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env,
        20,
        [
            {"percent": 50, "dwell_s": 0, "max_failure_rate": 0.3},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 0.3},
        ],
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    stage0 = await _stage_devices(env, tenant, cid, "notified")
    await env.status(tenant, cid, stage0[0], S.REJECTED, error="MF_PRODUCT")
    await env.status(tenant, cid, stage0[1], S.REJECTED, error="MF_PRODUCT")
    assert (await env.campaign(tenant, cid))["state"] == "halted"
    # operators cannot resume with a viewer token, only operator+
    await env.action(tenant, cid, "resume", role="viewer", expect=403)
    resumed = await env.action(tenant, cid, "resume", role="operator")
    assert resumed["state"] == "running" and resumed["halt_reason"] is None
    assert resumed["stages"][0]["state"] == "running"
    # the cleared retained notifies are re-sent to devices that had not started
    waiting = await _stage_devices(env, tenant, cid, "notified")
    assert all(len(env.notifies(tenant, d)) == 2 for d in waiting)
    await _succeed(env, tenant, cid, waiting, image)
    view = await env.campaign(tenant, cid)
    assert view["current_stage"] == 1 and view["state"] == "running"
    await _succeed(env, tenant, cid, await _stage_devices(env, tenant, cid, "notified"), image)
    assert (await env.campaign(tenant, cid))["state"] == "completed"


async def test_pause_resume_and_cancel(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 10)
    cid = campaign["id"]
    await env.action(tenant, cid, "pause", expect=409)
    await env.action(tenant, cid, "start")
    paused = await env.action(tenant, cid, "pause")
    assert paused["state"] == "paused"
    await env.action(tenant, cid, "start", expect=409)
    first = await _stage_devices(env, tenant, cid, "notified")
    await _succeed(env, tenant, cid, first, image)
    env.clock.advance(700)
    await env.tick()
    assert (await env.campaign(tenant, cid))["current_stage"] == 0  # paused: no advancement
    resumed = await env.action(tenant, cid, "resume")
    # the dwell (observation) timer only runs while the campaign is running
    assert resumed["current_stage"] == 0 and resumed["stages"][0]["state"] == "dwelling"
    env.clock.advance(601)
    await env.tick()
    assert (await env.campaign(tenant, cid))["current_stage"] == 1
    await env.action(tenant, cid, "halt", body={"reason": "investigating"})
    halted = await env.campaign(tenant, cid)
    assert halted["state"] == "halted" and halted["halt_reason"] == "investigating"
    await env.action(tenant, cid, "halt", body={"reason": "again"}, expect=409)
    cancelled = await env.action(tenant, cid, "cancel", body={"reason": "superseded"})
    assert cancelled["state"] == "cancelled"
    await env.action(tenant, cid, "resume", expect=409)
    await env.action(tenant, cid, "cancel", expect=409)
    assert env.publisher.retained == {}


async def test_device_timeout_counts_as_failed(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env,
        10,
        [
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    notified = await _stage_devices(env, tenant, cid, "notified")
    await _succeed(env, tenant, cid, notified[:8], image)
    await env.status(tenant, cid, notified[8], S.DOWNLOADING, progress=10)
    env.clock.advance(3601)
    await env.tick()
    view = await env.campaign(tenant, cid)
    assert view["totals"]["failed"] == 2
    assert view["state"] == "completed"
    timed_out = await env.devices(tenant, cid, "failed")
    assert {d["error"] for d in timed_out} == {"TIMEOUT"}
    # a late report from a timed-out device still records the real outcome
    late = await env.status(
        tenant, cid, notified[9], S.SUCCESS, fw_hash=hashlib.sha256(image).digest()
    )
    assert late["device_state"] == "success"


async def test_notify_refresh_resigns_unacknowledged_notifies(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env,
        10,
        [
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    notified = await _stage_devices(env, tenant, cid, "notified")
    await env.status(tenant, cid, notified[0], S.RECEIVED)
    env.clock.advance(250)
    await env.tick()
    assert len(env.notifies(tenant, notified[0])) == 1  # acknowledged: no refresh
    refreshed = env.notifies(tenant, notified[1])
    assert len(refreshed) == 2
    assert refreshed[1].seq > refreshed[0].seq and refreshed[1].ts == int(env.clock.now.timestamp())


async def test_status_edge_cases(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env,
        10,
        [
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    dev = (await _stage_devices(env, tenant, cid, "notified"))[0]
    await env.status(tenant, cid, dev, S.APPLYING, progress=90)
    stale = await env.status(tenant, cid, dev, S.DOWNLOADING, progress=10)
    assert stale["accepted"] is False and stale["action"] == "ignored_stale"
    wrong = await env.status(tenant, cid, dev, S.SUCCESS, fw_hash=b"\x01" * 32)
    assert wrong["device_state"] == "failed"
    [failed] = await env.devices(tenant, cid, "failed")
    assert failed["error"] == "FW_HASH_MISMATCH"
    again = await env.status(tenant, cid, dev, S.SUCCESS)
    assert again["action"] == "ignored_terminal"
    await env.status(tenant, str(uuid.uuid4()), dev, S.SUCCESS, expect=404)
    await env.status(tenant, cid, "dev-ffffffffffffffff", S.SUCCESS, expect=404)
    resp = await env.client.post(
        "/internal/v1/ota/status",
        headers=env.internal,
        json={"tenant_id": "x", "device_id": dev, "campaign_id": cid, "state": 9},
    )
    assert resp.status_code == 422
    # sequence numbers supplied by the caller are replay-checked
    body = {"tenant_id": str(tenant), "device_id": dev, "campaign_id": cid, "state": 5, "seq": 10}
    assert (
        await env.client.post("/internal/v1/ota/status", json=body, headers=env.internal)
    ).status_code == 200
    replay = await env.client.post("/internal/v1/ota/status", json=body, headers=env.internal)
    assert replay.status_code == 409
    assert "ironmesh_replay_rejected_total 1.0" in (await env.client.get("/metrics")).text


async def test_tampered_image_is_detected_before_notify(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 10)
    async with env.container.db.tenant(tenant) as repo:
        record = await repo.get_firmware(uuid.UUID(fw["id"]))
    assert record is not None
    path = env.container.store.path_for(record.image_key)  # type: ignore[attr-defined]
    path.chmod(0o644)
    path.write_bytes(image[:-1] + b"\x00")
    resp = await env.client.post(
        f"/v1/campaigns/{campaign['id']}/start", headers=env.auth(tenant, "operator")
    )
    assert resp.status_code == 409
    assert "MF_HASH_MISMATCH" in resp.json()["detail"]
    assert env.publisher.messages == []
    view = await env.campaign(tenant, campaign["id"])
    assert view["state"] == "draft"
    audit = (
        await env.client.get(f"/v1/campaigns/{campaign['id']}/audit", headers=env.auth(tenant))
    ).json()["items"]
    assert any(a["action"] == "campaign.start" and a["outcome"] == "failure" for a in audit)


async def test_tampering_between_stages_halts_campaign(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 10)
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    await _succeed(env, tenant, cid, await _stage_devices(env, tenant, cid, "notified"), image)
    async with env.container.db.tenant(tenant) as repo:
        record = await repo.get_firmware(uuid.UUID(fw["id"]))
    assert record is not None
    path = env.container.store.path_for(record.image_key)  # type: ignore[attr-defined]
    path.chmod(0o644)
    path.write_bytes(b"evil" + image[4:])
    before = len(env.publisher.messages)
    env.clock.advance(601)
    await env.tick()
    view = await env.campaign(tenant, cid)
    assert view["state"] == "halted"
    assert "artifact verification failed: MF_HASH_MISMATCH" in view["halt_reason"]
    assert all(not m.payload for m in env.publisher.messages[before:])


async def test_unsigned_manifest_is_detected_before_notify(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 10)
    db = env.container.db
    part = db.partitions[tenant]  # type: ignore[attr-defined]
    stored = part.firmware[uuid.UUID(fw["id"])]
    stored.signed_manifest = stored.manifest  # raw manifest without COSE_Sign
    resp = await env.client.post(
        f"/v1/campaigns/{campaign['id']}/start", headers=env.auth(tenant, "operator")
    )
    assert resp.status_code == 409
    assert "COSE_" in resp.json()["detail"] or "CBOR_" in resp.json()["detail"]
    # a manifest signed by an untrusted key is rejected the same way
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from ironmesh_wire.manifest import sign_manifest

    stored.signed_manifest = sign_manifest(stored.manifest, ed25519.Ed25519PrivateKey.generate())
    resp = await env.client.post(
        f"/v1/campaigns/{campaign['id']}/start", headers=env.auth(tenant, "operator")
    )
    assert resp.status_code == 409 and "COSE_UNKNOWN_KEY" in resp.json()["detail"]
    assert env.publisher.messages == []


async def test_start_requires_eligible_devices(env: Env) -> None:
    tenant = new_tenant()
    image = image_bytes(1)
    fw = await env.upload(tenant, image)
    env.add_devices(tenant, 2, fw=image)  # already on this image
    env.add_devices(tenant, 2, product="other", start=10)
    env.add_devices(tenant, 2, state="quarantined", start=20)
    campaign = await env.create_campaign(tenant, fw["id"])
    resp = await env.client.post(
        f"/v1/campaigns/{campaign['id']}/start", headers=env.auth(tenant, "operator")
    )
    assert resp.status_code == 409


async def test_target_by_tags_and_device_ids(env: Env) -> None:
    tenant = new_tenant()
    fw = await env.upload(tenant, image_bytes(1))
    env.add_devices(tenant, 5, group="a")
    env.add_devices(tenant, 5, group="b", start=100)
    by_id = await env.create_campaign(
        tenant,
        fw["id"],
        target={"groups": [], "device_ids": ["dev-0000000000000064"], "tags": {}},
        stages=[{"percent": 100, "dwell_s": 0, "max_failure_rate": 0.5}],
    )
    started = await env.action(tenant, by_id["id"], "start")
    assert started["totals"]["targeted"] == 1
    by_tag = await env.create_campaign(
        tenant,
        fw["id"],
        target={"groups": [], "device_ids": [], "tags": {"site": "lab"}},
        stages=[{"percent": 100, "dwell_s": 0, "max_failure_rate": 0.5}],
    )
    assert (await env.action(tenant, by_tag["id"], "start"))["totals"]["targeted"] == 10


async def test_registry_outage_returns_503(env: Env) -> None:
    tenant = new_tenant()
    fw = await env.upload(tenant, image_bytes(1))
    campaign = await env.create_campaign(tenant, fw["id"])

    async def broken(*_: Any) -> list[Any]:
        raise ConnectionError("down")

    env.registry.resolve = broken  # type: ignore[method-assign,assignment]
    resp = await env.client.post(
        f"/v1/campaigns/{campaign['id']}/start", headers=env.auth(tenant, "operator")
    )
    assert resp.status_code == 503


async def test_broker_outage_does_not_fail_start_and_refresh_recovers(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env,
        10,
        [
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    env.publisher.fail = True
    env.events.fail = True
    started = await env.action(tenant, campaign["id"], "start")
    assert started["state"] == "running"
    assert env.publisher.messages == []
    env.publisher.fail = False
    env.clock.advance(250)
    await env.tick()
    assert len(env.publisher.retained) == 10


async def test_idempotency_key_replays_response(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 5)
    headers = {**env.auth(tenant, "operator"), "Idempotency-Key": "k-1"}
    first = await env.client.post(f"/v1/campaigns/{campaign['id']}/start", headers=headers)
    assert first.status_code == 200 and "Idempotency-Replayed" not in first.headers
    second = await env.client.post(f"/v1/campaigns/{campaign['id']}/start", headers=headers)
    assert second.status_code == 200
    assert second.headers["Idempotency-Replayed"] == "true"
    assert second.json() == first.json()
    other = await env.client.post(f"/v1/campaigns/{campaign['id']}/pause", headers=headers)
    assert other.status_code == 422
    too_long = {**headers, "Idempotency-Key": "x" * 129}
    assert (
        await env.client.post(f"/v1/campaigns/{campaign['id']}/pause", headers=too_long)
    ).status_code == 422


async def test_rollback_creates_higher_version_code_and_targets_updated_devices(env: Env) -> None:
    tenant = new_tenant()
    good, bad = image_bytes(1), image_bytes(2)
    good_fw = await env.upload(tenant, good, version="2.3.0", version_code=2300)
    bad_fw = await env.upload(tenant, bad, version="2.4.0", version_code=2400)
    env.add_devices(tenant, 10, fw=good)
    campaign = await env.create_campaign(
        tenant,
        bad_fw["id"],
        stages=[
            {"percent": 50, "dwell_s": 3600, "max_failure_rate": 1.0},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0},
        ],
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    took = await _stage_devices(env, tenant, cid, "notified")
    await _succeed(env, tenant, cid, took[:4], bad)
    for dev in took[:4]:
        env.set_device_fw(tenant, dev, bad)
    await env.action(tenant, cid, "rollback", body={"reason": "x"}, role="operator", expect=403)
    child = await env.action(
        tenant, cid, "rollback", body={"reason": "watchdog resets"}, expect=201
    )
    assert child["parent_campaign_id"] == cid
    assert child["state"] == "running"
    assert child["severity"] == "security" and child["requires_approval"] is False
    assert child["firmware"]["version_code"] == 2401 > bad_fw["version_code"]
    assert child["firmware"]["version"] == "2.3.0+rollback.2401"
    assert child["firmware"]["sha256_hex"] == good_fw["sha256_hex"]
    assert child["firmware"]["rollback_of"] == good_fw["id"]
    assert sorted(child["target"]["device_ids"]) == sorted(took[:4])
    assert child["totals"]["targeted"] == 4
    parent = await env.campaign(tenant, cid)
    assert parent["state"] == "rolled_back" and parent["halt_reason"] == "watchdog resets"
    # the re-signed manifest carries the higher code and verifies with the trusted keys
    for dev in took[:4]:
        notify = env.notifies(tenant, dev)[-1]
        assert isinstance(notify.body, envelope.OtaNotify)
        m = verify_manifest(
            notify.body.manifest, env.container.signer.trusted_public_keys()
        ).manifest
        assert m.version_code == 2401 and m.image_sha256 == hashlib.sha256(good).digest()
    # devices still mid-update in the parent had their retained notify withdrawn
    for dev in took[4:]:
        assert (
            ids.build_topic(str(tenant), dev, TopicClass.OTA_NOTIFY) not in env.publisher.retained
        )
    await env.action(tenant, cid, "rollback", body={"reason": "again"}, expect=409)
    assert CampaignState(parent["state"]) is CampaignState.ROLLED_BACK


async def test_rollback_requires_updated_devices(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(env, 5)
    await env.action(tenant, campaign["id"], "start")
    await env.action(tenant, campaign["id"], "rollback", body={"reason": "x"}, expect=409)


async def test_rollback_falls_back_to_previous_release_by_version(env: Env) -> None:
    tenant = new_tenant()
    older, bad = image_bytes(1), image_bytes(2)
    older_fw = await env.upload(tenant, older, version="1.0.0", version_code=10)
    bad_fw = await env.upload(tenant, bad, version="1.1.0", version_code=11)
    env.add_devices(tenant, 3)  # registry does not know their firmware hash
    campaign = await env.create_campaign(
        tenant, bad_fw["id"], stages=[{"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0}]
    )
    await env.action(tenant, campaign["id"], "start")
    took = await _stage_devices(env, tenant, campaign["id"], "notified")
    await _succeed(env, tenant, campaign["id"], took, bad)
    child = await env.action(tenant, campaign["id"], "rollback", body={"reason": "r"}, expect=201)
    assert child["firmware"]["rollback_of"] == older_fw["id"]
    assert child["firmware"]["version_code"] == 12


async def test_four_eyes_approval_for_fast_security_campaign(env: Env) -> None:
    tenant = new_tenant()
    image = image_bytes(1)
    fw = await env.upload(tenant, image, severity="security")
    env.add_devices(tenant, 10)
    campaign = await env.create_campaign(
        tenant,
        fw["id"],
        stages=[
            {"percent": 10, "dwell_s": 600, "max_failure_rate": 0.1},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 0.1},
        ],
        sub="alice",
    )
    assert campaign["severity"] == "security" and campaign["requires_approval"] is True
    resp = await env.client.post(
        f"/v1/campaigns/{campaign['id']}/start", headers=env.auth(tenant, "operator", "alice")
    )
    assert resp.status_code == 409 and "approval" in resp.json()["detail"]
    await env.action(tenant, campaign["id"], "approve", role="operator", sub="alice", expect=403)
    await env.action(tenant, campaign["id"], "approve", role="viewer", sub="bob", expect=403)
    approved = await env.action(tenant, campaign["id"], "approve", role="operator", sub="bob")
    assert approved["approved_by"] == "user:bob" and approved["approved_at"]
    await env.action(tenant, campaign["id"], "approve", role="operator", sub="carol", expect=409)
    started = await env.action(tenant, campaign["id"], "start", role="operator", sub="alice")
    assert started["state"] == "running"
    await env.action(tenant, campaign["id"], "approve", role="operator", sub="bob", expect=409)

    # normal-severity or slow security campaigns need no second operator
    slow = await env.create_campaign(
        tenant,
        fw["id"],
        stages=[
            {"percent": 10, "dwell_s": 7200, "max_failure_rate": 0.1},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 0.1},
        ],
    )
    assert slow["requires_approval"] is False
    await env.action(tenant, slow["id"], "approve", role="operator", sub="bob", expect=409)
    normal = await env.create_campaign(
        tenant,
        fw["id"],
        severity="normal",
        stages=[{"percent": 100, "dwell_s": 0, "max_failure_rate": 0.1}],
    )
    assert normal["requires_approval"] is False


async def test_campaign_devices_and_audit_pagination(env: Env) -> None:
    tenant, fw, campaign, devices, image = await _setup(
        env, 30, [{"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0}]
    )
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"limit": 7}
        if cursor:
            params["cursor"] = cursor
        page = (
            await env.client.get(
                f"/v1/campaigns/{cid}/devices", params=params, headers=env.auth(tenant)
            )
        ).json()
        seen.extend(d["device_id"] for d in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert seen == sorted(devices)
    audit = (
        await env.client.get(f"/v1/campaigns/{cid}/audit?limit=1", headers=env.auth(tenant))
    ).json()
    assert len(audit["items"]) == 1 and audit["next_cursor"]
    nxt = (
        await env.client.get(
            f"/v1/campaigns/{cid}/audit",
            params={"limit": 50, "cursor": audit["next_cursor"]},
            headers=env.auth(tenant),
        )
    ).json()
    assert audit["items"][0]["id"] not in {a["id"] for a in nxt["items"]}
    for path in ("devices", "audit"):
        missing = await env.client.get(
            f"/v1/campaigns/{uuid.uuid4()}/{path}", headers=env.auth(tenant)
        )
        assert missing.status_code == 404
    assert (
        await env.client.get("/v1/campaigns/not-a-uuid", headers=env.auth(tenant))
    ).status_code == 404
    page = (await env.client.get("/v1/campaigns?limit=1", headers=env.auth(tenant))).json()
    assert len(page["items"]) == 1
