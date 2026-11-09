"""Upstream clients: PKI key cache, OTA known hashes, registry directory and quarantine."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from ironmesh_anomaly.clients import (
    HttpCertKeyProvider,
    HttpDeviceDirectory,
    HttpKnownHashesProvider,
    HttpQuarantineClient,
    KeyLookupError,
    ServiceTokenSigner,
    TTLCache,
    build_http_client,
    parse_cert_view,
    serial_hex_from_kid,
    with_retries,
)
from tests.support import TENANT

DEV = "dev-00000000000000aa"


def device_cert(
    key: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
    cn: str = DEV,
    serial: int = 0xABCDEF,
) -> str:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, TENANT),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    signer = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Device CA")]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=14))
        .sign(signer, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def signer() -> tuple[ServiceTokenSigner, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    return ServiceTokenSigner(key, static_tokens={"registry": "shared-token"}), key


def test_service_token_signer(tmp_path: Path) -> None:
    s, key = signer()
    tok = s.token("pki")
    assert tok is not None and s.token("pki") == tok  # cached
    claims = jwt.decode(tok, key.public_key(), algorithms=["ES256"], audience="pki")
    # the registry and OTA identify the caller by iss/sub and allow-list "anomaly"
    assert claims["iss"] == claims["sub"] == "anomaly" and claims["exp"] - claims["iat"] == 300
    assert jwt.get_unverified_header(tok)["kid"] == "svc-anomaly"
    assert s.headers("registry") == {"Authorization": "Bearer shared-token"}
    assert ServiceTokenSigner(None).headers("pki") == {}
    pem = tmp_path / "k.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    assert ServiceTokenSigner.from_file(str(pem), "kid").token("ota") is not None
    ed = tmp_path / "ed.pem"
    ed.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    assert ServiceTokenSigner.from_file(str(ed), "kid").token("ota") is None
    assert ServiceTokenSigner.from_file(None, "kid").token("ota") is None


def test_parse_cert_view() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    view = {
        "serial": "00abcdef",
        "device_id": DEV,
        "tenant_id": TENANT,
        "status": "valid",
        "certificate_pem": device_cert(key),
    }
    ck = parse_cert_view(view)
    assert (
        ck.serial_hex == format(0xABCDEF, "032x") and ck.device_id == DEV and ck.status == "valid"
    )
    with pytest.raises(ValueError, match="CN"):
        parse_cert_view({**view, "device_id": "dev-00000000000000bb"})
    with pytest.raises(ValueError, match="PEM"):
        parse_cert_view({**view, "certificate_pem": ""})
    with pytest.raises(ValueError, match="P-256"):
        parse_cert_view(
            {**view, "certificate_pem": device_cert(ec.generate_private_key(ec.SECP384R1()))}
        )
    assert serial_hex_from_kid(b"\xab\xcd\xef") == format(0xABCDEF, "032x")


async def test_pki_provider_caching_and_errors() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = device_cert(key)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.headers["authorization"].startswith("Bearer ")
        serial = request.url.path.rsplit("/", 1)[1]
        if serial.endswith("404"):
            return httpx.Response(404)
        if serial.endswith("500"):
            return httpx.Response(500)
        if serial.endswith("bad"):
            return httpx.Response(200, json={"device_id": DEV, "certificate_pem": "junk"})
        status = "revoked" if serial.endswith("dead") else "valid"
        return httpx.Response(
            200,
            json={"device_id": DEV, "tenant_id": TENANT, "status": status, "certificate_pem": pem},
        )

    s, _ = signer()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        p = HttpCertKeyProvider(client, "https://pki:8443/", s)
        a = await p.get("00ab")
        assert a is not None and a.status == "valid"
        assert await p.get("00ab") is a and len(calls) == 1
        assert await p.get("x404") is None and await p.get("x404") is None and len(calls) == 2
        revoked = await p.get("dead")
        assert revoked is not None and revoked.status == "revoked"
        assert await p.get("xbad") is None
        with pytest.raises(KeyLookupError):
            await p.get("x500")
        p.invalidate("00ab")
        await p.get("00ab")
        assert calls.count("/v1/certificates/00ab") == 2

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as client:
        with pytest.raises(KeyLookupError):
            await HttpCertKeyProvider(client, "https://pki", s).get("00ab")


async def test_known_hashes_provider() -> None:
    h = "a" * 64
    responses = iter(
        [
            httpx.Response(200, json=[h.upper(), "short", 5]),
            httpx.Response(500),
            httpx.Response(200, json={"x": 1}),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["product"] in ("gw", "other", "third")
        return next(responses)

    s, _ = signer()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        p = HttpKnownHashesProvider(client, "https://ota", s)
        assert await p.known_hashes("gw") == frozenset({h})
        assert await p.known_hashes("gw") == frozenset({h})  # cached
        assert await p.known_hashes("other") is None  # 500 -> unavailable (fail-open on this check)
        assert await p.known_hashes("third") is None


async def test_device_directory() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        dev = request.url.path.split("/")[4]
        assert request.headers["authorization"] == "Bearer shared-token"
        if dev.endswith("0001"):
            return httpx.Response(
                200,
                json={
                    "device_id": dev,
                    "tenant_id": TENANT,
                    "state": "active",
                    "product": "gateway-rpi",
                },
            )
        if dev.endswith("0002"):
            return httpx.Response(
                200, json={"device_id": dev, "tenant_id": TENANT, "state": "quarantined"}
            )
        if dev.endswith("0003"):
            return httpx.Response(200, json={"tenant_id": "bogus"})
        if dev.endswith("0004"):
            return httpx.Response(503)
        if dev.endswith("0005"):
            raise httpx.ConnectError("down")
        return httpx.Response(404)

    s, _ = signer()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        d = HttpDeviceDirectory(client, "https://registry:8000", s)
        one = await d.lookup("dev-0000000000000001")
        assert one is not None and one.product == "gateway-rpi"
        two = await d.lookup("dev-0000000000000002")
        assert two is not None and two.product == "unknown" and two.state == "quarantined"
        for n in (3, 4, 5, 6):
            assert await d.lookup(f"dev-{n:016x}") is None
        assert await d.lookup("not-a-device") is None
        d.remember(one)
        assert await d.lookup("dev-0000000000000001") is one


async def test_quarantine_client_retries() -> None:
    statuses = [503, 502, 200]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(statuses.pop(0))

    sleeps: list[float] = []

    async def fake_sleep(x: float) -> None:
        sleeps.append(x)

    s, _ = signer()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        q = HttpQuarantineClient(
            client, "https://registry", s, attempts=4, base_s=0.1, sleep=fake_sleep
        )
        r = await q.quarantine(DEV, "auto", "a1")
        assert r.ok and len(seen) == 3 and len(sleeps) == 2
        body = json.loads(seen[0].content)
        assert body == {"reason": "auto", "alert_id": "a1"}
        assert seen[0].url.path == f"/internal/v1/devices/{DEV}/quarantine"
        assert seen[0].headers["idempotency-key"] == "anomaly-quarantine-a1"
        statuses.extend([409])
        r = await q.quarantine(DEV, "auto", "a2")
        assert not r.ok and r.status == 409
        statuses.extend([404])
        r = await q.quarantine(DEV, "auto", "a3")
        assert not r.ok and r.status == 404
        statuses.extend([500] * 4)
        r = await q.quarantine(DEV, "auto", "a4")
        assert not r.ok and r.status is None and "unavailable" in r.detail


async def test_with_retries_non_retryable() -> None:
    async def boom() -> int:
        raise ValueError("no")

    with pytest.raises(ValueError):
        await with_retries(boom, attempts=3, base_s=0, retry_if=lambda e: False)


def test_ttl_cache_expiry_and_bound() -> None:
    c: TTLCache[str, int] = TTLCache(ttl_s=-1, max_items=2)
    c.set("a", 1)
    assert c.get("a") == (False, None)
    c2: TTLCache[str, int] = TTLCache(ttl_s=60, max_items=2)
    c2.set("a", 1)
    c2.set("b", 2)
    c2.set("c", 3)
    assert c2.get("a") == (False, None) and c2.get("c") == (True, 3)


def test_build_http_client_with_tls(tmp_path: Path) -> None:
    import ssl

    from tests.test_siem import _self_signed

    cert, key = _self_signed(tmp_path)
    client = build_http_client(1.0, str(cert), str(cert), str(key))
    assert isinstance(client, httpx.AsyncClient)
    assert isinstance(ssl.create_default_context(), ssl.SSLContext)
    plain = build_http_client(1.0)
    assert isinstance(plain, httpx.AsyncClient)
