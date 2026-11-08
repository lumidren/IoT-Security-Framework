"""Firmware upload, signing, lookup and download endpoints."""

from __future__ import annotations

import base64
import hashlib
import json
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from ironmesh_wire import cose
from ironmesh_wire.errors import CoseError
from ironmesh_wire.manifest import accept_image, verify_manifest

from .conftest import Env, image_bytes, new_tenant


async def test_upload_signs_and_wire_library_verifies(env: Env) -> None:
    tenant = new_tenant()
    image = image_bytes(1)
    fw = await env.upload(tenant, image, version="2.4.1", version_code=2401, severity="security")
    assert fw["sha256_hex"] == hashlib.sha256(image).hexdigest()
    assert fw["size"] == len(image)
    assert fw["severity"] == "security"
    assert fw["pq_signed"] is True
    assert fw["created_by"] == "user:alice"
    signed = base64.b64decode(fw["signed_manifest_b64"])

    trusted = env.container.signer.trusted_public_keys()
    verified = verify_manifest(signed, trusted, require_pq=True)
    assert verified.pq_verified
    m = verified.manifest
    assert (m.product, m.version, m.version_code) == ("gateway-rpi", "2.4.1", 2401)
    assert m.image_sha256 == hashlib.sha256(image).digest()
    assert m.delta is None
    assert verified.ed25519_kid.hex() == fw["signing_key_id"]
    assert accept_image(m, image, 2400, "gateway-rpi").accepted

    # an untrusted key set rejects it: the signature really binds to our key
    other = cose.raw_public_key(ed25519.Ed25519PrivateKey.generate().public_key())
    with pytest.raises(CoseError) as info:
        verify_manifest(signed, [other])
    assert info.value.code == "COSE_UNKNOWN_KEY"

    # the manifest endpoint serves exactly the signed bytes
    resp = await env.client.get(f"/v1/firmware/{fw['id']}/manifest", headers=env.auth(tenant))
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/cbor"
    assert resp.content == signed

    # stored manifest.cbor / manifest.sig / image.bin are immutable artifacts
    events = [e.value["action"] for e in env.events.events if e.topic == "im.audit"]
    assert "firmware.upload" in events and "firmware.sign" in events


async def test_version_code_must_exceed_every_existing_code(env: Env) -> None:
    tenant = new_tenant()
    await env.upload(tenant, image_bytes(1), version="1.0.0", version_code=100)
    for code in (100, 99, 1):
        resp = await env.client.post(
            "/v1/firmware",
            headers=env.auth(tenant),
            files={"image": ("i.bin", image_bytes(2), "application/octet-stream")},
            data={
                "metadata": json.dumps(
                    {"product": "gateway-rpi", "version": f"1.0.{code}", "version_code": code}
                )
            },
        )
        assert resp.status_code == 422, resp.text
        problem = resp.json()
        assert resp.headers["content-type"] == "application/problem+json"
        assert problem["errors"][0]["field"] == "version_code"
        assert "exceed 100" in problem["errors"][0]["message"]
    # other products and other tenants have independent counters
    await env.upload(
        tenant, image_bytes(3), product="sensor-esp32", version="1.0.0", version_code=5
    )
    await env.upload(new_tenant(), image_bytes(4), version="1.0.0", version_code=1)
    await env.upload(tenant, image_bytes(5), version="1.1.0", version_code=101)
    # a duplicate semver with a higher code is a conflict
    await env.upload(tenant, image_bytes(6), version="1.1.0", version_code=150, expect=409)


@pytest.mark.parametrize(
    ("meta", "field"),
    [
        ({"product": "Bad_Product", "version": "1.0.0", "version_code": 1}, "product"),
        ({"product": "gw", "version": "1.0", "version_code": 1}, "version"),
        ({"product": "gw", "version": "1.0.0", "version_code": 0}, "version_code"),
        ({"product": "gw", "version": "1.0.0"}, "version_code"),
        ({"product": "gw", "version": "1.0.0", "version_code": 1, "extra": 1}, "extra"),
        (
            {"product": "gw", "version": "1.0.0", "version_code": 3, "min_version_code": 4},
            "min_version_code",
        ),
    ],
)
async def test_metadata_validation(env: Env, meta: dict[str, object], field: str) -> None:
    resp = await env.client.post(
        "/v1/firmware",
        headers=env.auth(new_tenant()),
        files={"image": ("i.bin", b"x" * 10, "application/octet-stream")},
        data={"metadata": json.dumps(meta)},
    )
    assert resp.status_code == 422, resp.text
    assert any(e["field"] == field for e in resp.json()["errors"])


async def test_metadata_must_be_json(env: Env) -> None:
    resp = await env.client.post(
        "/v1/firmware",
        headers=env.auth(new_tenant()),
        files={"image": ("i.bin", b"x", "application/octet-stream")},
        data={"metadata": "{not json"},
    )
    assert resp.status_code == 422
    assert resp.json()["errors"][0]["field"] == "metadata"


async def test_lookup_list_and_by_hash(env: Env) -> None:
    tenant = new_tenant()
    images = [image_bytes(i) for i in range(5)]
    created = []
    for i, img in enumerate(images):
        env.clock.advance(1)
        created.append(await env.upload(tenant, img, version=f"1.0.{i}", version_code=10 + i))
    await env.upload(tenant, image_bytes(99), product="other", version="9.0.0", version_code=1)
    seen: list[str] = []
    cursor = None
    while True:
        params: dict[str, str | int] = {"limit": 2, "product": "gateway-rpi"}
        if cursor:
            params["cursor"] = cursor
        resp = await env.client.get(
            "/v1/firmware", params=params, headers=env.auth(tenant, "viewer")
        )
        assert resp.status_code == 200
        page = resp.json()
        seen.extend(f["id"] for f in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert seen == [f["id"] for f in reversed(created)]

    by_hash = await env.client.get(
        f"/v1/firmware/by-hash/{created[2]['sha256_hex']}", headers=env.auth(tenant, "viewer")
    )
    assert by_hash.status_code == 200 and by_hash.json()["id"] == created[2]["id"]
    for bad in ("00" * 32, "XYZ", created[2]["sha256_hex"].upper()):
        resp = await env.client.get(f"/v1/firmware/by-hash/{bad}", headers=env.auth(tenant))
        assert resp.status_code == 404
    one = await env.client.get(f"/v1/firmware/{created[0]['id']}", headers=env.auth(tenant))
    assert one.json()["version"] == "1.0.0"
    for missing in ("not-a-uuid", "6f1c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f"):
        resp = await env.client.get(f"/v1/firmware/{missing}", headers=env.auth(tenant))
        assert resp.status_code == 404
    bad_cursor = await env.client.get("/v1/firmware?cursor=@@@", headers=env.auth(tenant))
    assert bad_cursor.status_code == 400


async def test_image_redirect_and_signed_download(env: Env) -> None:
    tenant = new_tenant()
    image = image_bytes(7)
    fw = await env.upload(tenant, image)
    resp = await env.client.get(f"/v1/firmware/{fw['id']}/image", headers=env.auth(tenant))
    assert resp.status_code == 302
    url = urlsplit(resp.headers["location"])
    assert url.path.startswith("/v1/artifacts/firmware/")
    download = await env.client.get(f"{url.path}?{url.query}")
    assert download.status_code == 200
    assert download.content == image
    # tampered or expired links are refused
    tampered = url.query.replace("sig=", "sig=A")
    assert (await env.client.get(f"{url.path}?{tampered}")).status_code == 403
    expired = await env.client.get(f"{url.path}?exp=1&sig=x")
    assert expired.status_code == 403


async def test_known_hashes_internal_endpoint(env: Env) -> None:
    tenant_a, tenant_b = new_tenant(), new_tenant()
    fa = await env.upload(tenant_a, image_bytes(1))
    fb = await env.upload(tenant_b, image_bytes(2), product="sensor-esp32")
    resp = await env.client.get("/internal/v1/firmware/known-hashes", headers=env.internal)
    assert resp.status_code == 200
    assert set(resp.json()) == {fa["sha256_hex"], fb["sha256_hex"]}
    resp = await env.client.get(
        "/internal/v1/firmware/known-hashes",
        params={"product": "sensor-esp32"},
        headers=env.internal,
    )
    assert resp.json() == [fb["sha256_hex"]]
    resp = await env.client.get(
        "/internal/v1/firmware/known-hashes",
        params={"tenant_id": str(tenant_a)},
        headers=env.internal,
    )
    assert resp.json() == [fa["sha256_hex"]]
    bad = await env.client.get(
        "/internal/v1/firmware/known-hashes", params={"tenant_id": "x"}, headers=env.internal
    )
    assert bad.status_code == 422
    # user tokens and wrong secrets are not accepted on internal endpoints
    user = await env.client.get("/internal/v1/firmware/known-hashes", headers=env.auth(tenant_a))
    assert user.status_code == 401
    nobody = await env.client.get("/internal/v1/firmware/known-hashes")
    assert nobody.status_code == 401


async def test_signing_keys_listing(env: Env) -> None:
    resp = await env.client.get("/v1/signing-keys", headers=env.auth(new_tenant(), "viewer"))
    assert resp.status_code == 200
    keys = resp.json()
    algorithms = {k["algorithm"] for k in keys}
    assert algorithms == {"Ed25519", "ML-DSA-65"}
    for k in keys:
        raw = base64.b64decode(k["public_key_b64"])
        assert k["key_id"] == hashlib.sha256(raw).digest()[:8].hex()
        assert k["active"] is True


async def test_upload_conflict_when_store_has_different_object(env: Env) -> None:
    tenant = new_tenant()
    image = image_bytes(1)
    hashlib.sha256(image).hexdigest()
    key = f"firmware/{tenant}/gateway-rpi/100/manifest.cbor"
    await env.container.store.put(key, b"squatter", "application/cbor")
    await env.upload(tenant, image, expect=409)
