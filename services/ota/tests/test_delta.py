"""Delta campaigns: IMDELTA1 generation per base, signed delta manifests, device-side apply and
the full-image fallback."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from ironmesh_wire import OtaState, delta, envelope
from ironmesh_wire.manifest import accept_image, accept_patch, verify_manifest

from .conftest import Env, image_bytes, new_tenant, patched

S = OtaState
ONE_STAGE = [{"percent": 100, "dwell_s": 0, "max_failure_rate": 1.0}]


async def _download(env: Env, url: str) -> bytes:
    parts = urlsplit(url)
    resp = await env.client.get(f"{parts.path}?{parts.query}")
    assert resp.status_code == 200
    return resp.content


async def test_delta_per_base_and_device_apply_produces_exact_image(env: Env) -> None:
    tenant = new_tenant()
    base_a = image_bytes(1, blocks=8)
    base_b = patched(base_a, 2)
    target = patched(base_a, 5)
    await env.upload(tenant, base_a, version="1.0.0", version_code=100)
    await env.upload(tenant, base_b, version="1.0.1", version_code=101)
    fw = await env.upload(tenant, target, version="1.1.0", version_code=110)
    on_a = env.add_devices(tenant, 3, fw=base_a, start=1)
    on_b = env.add_devices(tenant, 2, fw=base_b, start=10)
    unknown = env.add_devices(tenant, 1, fw=image_bytes(77), start=20)  # base not in store
    blank = env.add_devices(tenant, 1, start=30)  # registry has no fw hash
    campaign = await env.create_campaign(tenant, fw["id"], delta=True, stages=ONE_STAGE)
    assert campaign["delta"] is True
    await env.action(tenant, campaign["id"], "start")

    trusted = env.container.signer.trusted_public_keys()
    patches: dict[bytes, bytes] = {}
    for base, devices in ((base_a, on_a), (base_b, on_b)):
        base_hash = hashlib.sha256(base).digest()
        for dev in devices:
            [notify] = env.notifies(tenant, dev)
            body = notify.body
            assert isinstance(body, envelope.OtaNotify)
            assert body.delta_from == base_hash
            verified = verify_manifest(body.manifest, trusted, require_pq=True)
            m = verified.manifest
            assert m.delta is not None and m.delta.base_sha256 == base_hash
            assert m.image_sha256 == hashlib.sha256(target).digest()
            # the device side: download, pre-check, apply, accept
            patch = await _download(env, body.url)
            assert accept_patch(m, patch, base_hash).accepted
            produced = delta.apply_delta(base, patch)
            assert produced == target
            assert accept_image(m, produced, 100, "gateway-rpi").accepted
            patches[base_hash] = patch
            assert len(patch) < len(target)
    assert len(patches) == 2  # one patch per distinct base hash, shared by its devices
    for dev in unknown + blank:
        [notify] = env.notifies(tenant, dev)
        assert isinstance(notify.body, envelope.OtaNotify)
        assert notify.body.delta_from is None
        assert await _download(env, notify.body.url) == target
    by_device = {d["device_id"]: d for d in await env.devices(tenant, campaign["id"])}
    assert by_device[on_a[0]]["delta_from_hex"] == hashlib.sha256(base_a).hexdigest()
    audit = [e.value["action"] for e in env.events.events if e.topic == "im.audit"]
    assert audit.count("firmware.delta.create") == 2

    # a second campaign reuses the stored patches instead of generating new ones
    again = await env.create_campaign(
        tenant,
        fw["id"],
        delta=True,
        stages=ONE_STAGE,
        target={"groups": [], "device_ids": on_a, "tags": {}},
    )
    await env.action(tenant, again["id"], "start")
    audit = [e.value["action"] for e in env.events.events if e.topic == "im.audit"]
    assert audit.count("firmware.delta.create") == 2


async def test_delta_failure_falls_back_to_full_image(env: Env) -> None:
    tenant = new_tenant()
    base = image_bytes(1, blocks=8)
    target = patched(base, 3)
    await env.upload(tenant, base, version="1.0.0", version_code=1)
    fw = await env.upload(tenant, target, version="1.0.1", version_code=2)
    [dev] = env.add_devices(tenant, 1, fw=base)
    campaign = await env.create_campaign(tenant, fw["id"], delta=True, stages=ONE_STAGE)
    cid = campaign["id"]
    await env.action(tenant, cid, "start")
    [first] = env.notifies(tenant, dev)
    assert isinstance(first.body, envelope.OtaNotify) and first.body.delta_from is not None

    result = await env.status(tenant, cid, dev, S.REJECTED, error="DELTA_BASE_HASH: flash drift")
    assert result["action"] == "delta_fallback"
    assert result["device_state"] == "notified"
    notifies = env.notifies(tenant, dev)
    assert len(notifies) == 2
    full = notifies[1].body
    assert isinstance(full, envelope.OtaNotify)
    assert full.delta_from is None
    m = verify_manifest(full.manifest, env.container.signer.trusted_public_keys()).manifest
    assert m.delta is None
    assert await _download(env, full.url) == target
    view = await env.campaign(tenant, cid)
    assert view["state"] == "running" and view["totals"]["rejected"] == 0
    # a second delta-type rejection is a real rejection (no fallback loop)
    result = await env.status(tenant, cid, dev, S.REJECTED, error="MF_HASH_MISMATCH")
    assert result["action"] in ("terminal", "halted")
    assert (await env.campaign(tenant, cid))["totals"]["rejected"] == 1


async def test_no_delta_when_patch_is_not_smaller(env: Env) -> None:
    tenant = new_tenant()
    base = image_bytes(1, blocks=2, tail=0)
    target = image_bytes(2, blocks=2, tail=0)  # nothing in common
    await env.upload(tenant, base, version="1.0.0", version_code=1)
    fw = await env.upload(tenant, target, version="2.0.0", version_code=2)
    [dev] = env.add_devices(tenant, 1, fw=base)
    campaign = await env.create_campaign(tenant, fw["id"], delta=True, stages=ONE_STAGE)
    await env.action(tenant, campaign["id"], "start")
    [notify] = env.notifies(tenant, dev)
    assert isinstance(notify.body, envelope.OtaNotify) and notify.body.delta_from is None


async def test_tampered_patch_is_detected_before_notify(env: Env) -> None:
    tenant = new_tenant()
    base = image_bytes(1, blocks=8)
    target = patched(base, 1)
    await env.upload(tenant, base, version="1.0.0", version_code=1)
    fw = await env.upload(tenant, target, version="1.0.1", version_code=2)
    env.add_devices(tenant, 2, fw=base)
    first = await env.create_campaign(tenant, fw["id"], delta=True, stages=ONE_STAGE)
    await env.action(tenant, first["id"], "start")
    root = env.tmp_path / "artifacts" / "delta"
    [patch_path] = list(root.rglob("*.imdelta"))
    patch_path.chmod(0o644)
    data = bytearray(patch_path.read_bytes())
    data[-2] ^= 0xFF
    patch_path.write_bytes(bytes(data))
    second = await env.create_campaign(tenant, fw["id"], delta=True, stages=ONE_STAGE)
    resp = await env.client.post(
        f"/v1/campaigns/{second['id']}/start", headers=env.auth(tenant, "operator")
    )
    assert resp.status_code == 409 and "MF_HASH_MISMATCH" in resp.json()["detail"]
