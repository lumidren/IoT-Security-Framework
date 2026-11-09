"""Pure units: lifecycle table, JSON helpers, auth primitives, KMS, HTTP adapters."""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.auth import (
    PERMISSIONS,
    HttpJwks,
    JtiReplayCache,
    OidcConfig,
    OidcVerifier,
    Principal,
    ServiceJwtVerifier,
    ServiceTokenMinter,
    StaticJwks,
    allowed,
    bearer_token,
    role_allows,
    role_at_most,
)
from app.domain import AuditRecord, DeviceRecord
from app.integrations.kms import AwsKmsKeyWrapper, KmsError, LocalKeyWrapper
from app.integrations.services import (
    HttpEmqxClient,
    HttpOtaClient,
    HttpPkiClient,
    UpstreamError,
    build_http_client,
    normalize_serial,
)
from app.jsonutil import (
    compute_delta,
    decode_cursor,
    encode_cursor,
    merge_patch,
    parse_rfc3339,
    remove_path,
    rfc3339,
)
from app.lifecycle import TERMINAL, TRANSITIONS, DeviceState, TransitionError, check_transition
from app.problems import ProblemError
from app.settings import Settings
from app.views import cert_status

from .conftest import ISSUER, OIDC_JWK, OIDC_KEY, SERVICE_KEYS, make_cert, pem_public

S = DeviceState

# ------------------------------------------------------------------------------------------------
# Lifecycle state machine: the complete transition table
# ------------------------------------------------------------------------------------------------

ALLOWED = {
    (S.MANUFACTURED, S.PROVISIONED),
    (S.MANUFACTURED, S.QUARANTINED),
    (S.MANUFACTURED, S.DECOMMISSIONED),
    (S.PROVISIONED, S.ACTIVE),
    (S.PROVISIONED, S.QUARANTINED),
    (S.PROVISIONED, S.DECOMMISSIONED),
    (S.ACTIVE, S.QUARANTINED),
    (S.ACTIVE, S.DECOMMISSIONED),
    (S.QUARANTINED, S.ACTIVE),
    (S.QUARANTINED, S.DECOMMISSIONED),
}


@pytest.mark.parametrize("current", list(S))
@pytest.mark.parametrize("target", list(S))
def test_transition_table(current: DeviceState, target: DeviceState) -> None:
    if (current, target) in ALLOWED:
        check_transition(current, target)
    else:
        with pytest.raises(TransitionError) as info:
            check_transition(current, target)
        assert info.value.status == 409


def test_terminal_state() -> None:
    assert {S.DECOMMISSIONED} == TERMINAL and TRANSITIONS[S.DECOMMISSIONED] == frozenset()


# ------------------------------------------------------------------------------------------------
# JSON helpers
# ------------------------------------------------------------------------------------------------


def test_merge_patch_rfc7396_examples() -> None:
    assert merge_patch({"a": "b"}, {"a": "c"}) == {"a": "c"}
    assert merge_patch({"a": "b"}, {"b": "c"}) == {"a": "b", "b": "c"}
    assert merge_patch({"a": "b"}, {"a": None}) == {}
    assert merge_patch({"a": [{"b": "c"}]}, {"a": [1]}) == {"a": [1]}
    assert merge_patch({"a": {"b": "c"}}, {"a": {"b": "d", "c": None}}) == {"a": {"b": "d"}}
    assert merge_patch(["a"], {"a": "c"}) == {"a": "c"}
    assert merge_patch({"a": "foo"}, "bar") == "bar"
    assert merge_patch({}, {"a": {"bb": {"ccc": None}}}) == {"a": {"bb": {}}}
    original = {"x": {"y": 1}}
    merge_patch(original, {"x": {"y": 2}})
    assert original == {"x": {"y": 1}}


def test_delta_and_remove_path() -> None:
    assert compute_delta({"a": 1, "b": {"c": 2, "d": 3}}, {"a": 1, "b": {"c": 2}}) == {
        "b": {"d": 3}
    }
    assert compute_delta({"a": None}, {}) == {"a": None}
    assert compute_delta({"a": {"b": 1}}, {"a": 5}) == {"a": {"b": 1}}
    doc = {"a": {"b": 1}}
    assert remove_path(doc, ["a", "x"]) is False
    assert remove_path(doc, ["z", "x"]) is False
    assert remove_path({"a": 1}, ["a", "b"]) is False
    assert remove_path(doc, ["a", "b"]) is True and doc == {"a": {}}


def test_cursors_and_time() -> None:
    c = encode_cursor(["dev-1", 5])
    assert decode_cursor(c, 2) == ["dev-1", 5] and decode_cursor(None, 1) is None
    for bad in ("!!!", encode_cursor(["a"]), encode_cursor([[1], 2]), encode_cursor([True, 1])):
        with pytest.raises(ProblemError):
            decode_cursor(bad, 2)
    import base64

    with pytest.raises(ProblemError):
        decode_cursor(base64.urlsafe_b64encode(b'{"a":1}').decode(), 1)
    assert parse_rfc3339("2026-01-01T00:00:00") == datetime(2026, 1, 1, tzinfo=UTC)
    assert rfc3339(datetime(2026, 1, 1, tzinfo=UTC)) == "2026-01-01T00:00:00Z"


def test_cert_status_and_audit_details() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    d = DeviceRecord(
        tenant_id="t",
        id="dev-1",
        product="p",
        hw_revision="1",
        state="active",
        created_at=now,
        cert_serial_hex="01",
    )
    assert cert_status(d, now) == "none"
    d.cert_not_after = now - timedelta(1)
    assert cert_status(d, now) == "expired"
    d.cert_not_after = now + timedelta(hours=10)
    assert cert_status(d, now) == "expiring"
    d.cert_revoked = True
    assert cert_status(d, now) == "revoked"
    rec = AuditRecord(
        "t",
        "i",
        1,
        now,
        "user",
        "u",
        None,
        "a",
        "t",
        "x",
        "success",
        None,
        None,
        json.dumps({"details": {"k": 1}}),
        b"",
        b"",
    )
    assert rec.details == {"k": 1}
    rec.body = json.dumps({"details": []})
    assert rec.details is None


# ------------------------------------------------------------------------------------------------
# Auth primitives
# ------------------------------------------------------------------------------------------------


def test_role_logic() -> None:
    assert role_allows("factory", PERMISSIONS["device.create"])
    assert not role_allows("factory", PERMISSIONS["device.edit"])
    assert role_allows("factory", PERMISSIONS["device.read"])
    assert not role_allows(None, PERMISSIONS["device.read"])
    assert not role_allows("root", PERMISSIONS["device.read"])
    svc = Principal(tenant_id="", actor_type="service", actor_id="pki")
    assert allowed(svc, "users.role")
    assert role_at_most("admin", "factory") and not role_at_most("operator", "factory")
    assert not role_at_most(None, "viewer") and role_at_most("owner", "owner")
    assert bearer_token("Bearer   ") is None and bearer_token("Token abc") is None
    assert bearer_token(None) is None and bearer_token("bearer abc") == "abc"


async def test_oidc_verifier_edges() -> None:
    v = OidcVerifier(
        OidcConfig(issuer=ISSUER, audience="ironmesh-api", algorithms=["ES256", "HS256"]),
        StaticJwks({"keys": [OIDC_JWK]}),
    )
    assert v.algorithms == ["ES256"]
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "ironmesh-api",
        "sub": "s",
        "iat": now,
        "exp": now + 60,
        "role": ["factory"],
        "tenant_id": "not-a-uuid",
        "name": 5,
    }
    token = jwt.encode(claims, OIDC_KEY, algorithm="ES256")  # no kid: single key is used
    ident = await v.verify(token)
    assert ident.role == "factory" and ident.tenant_id is None and ident.name is None
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ProblemError):
        await v.verify(jwt.encode(claims, rsa_key, algorithm="PS256"))
    assert await StaticJwks({"keys": [OIDC_JWK, OIDC_JWK]}).get(None) is None


async def test_http_jwks_discovery_refresh_and_outage() -> None:
    calls: list[str] = []
    state = {"fail": False, "keys": [OIDC_JWK]}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if state["fail"]:
            return httpx.Response(500)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"jwks_uri": "https://idp.test/jwks"})
        return httpx.Response(200, json={"keys": state["keys"]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    jwks = HttpJwks("https://idp.test/realms/x/", None, client, ttl=600, min_refresh_interval=0)
    assert (await jwks.get("test-key")) is not None
    assert calls == ["/realms/x/.well-known/openid-configuration", "/jwks"]
    assert await jwks.get("other", refresh=True) is None and calls[-1] == "/jwks"
    state["fail"] = True
    assert (await jwks.get("test-key", refresh=True)) is not None  # stale cache survives outage
    cold = HttpJwks("https://idp.test", "https://idp.test/jwks", client)
    with pytest.raises(ProblemError) as info:
        await cold.get("test-key")
    assert info.value.status == 503
    await client.aclose()


def _svc_token(name: str = "pki", key: str | None = None, **claims: Any) -> str:
    now = int(time.time())
    body: dict[str, Any] = {
        "iss": name,
        "aud": "registry",
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    body.update(claims)
    body = {k: v for k, v in body.items() if v is not None}
    return jwt.encode(body, SERVICE_KEYS[key or name], algorithm="ES256")


def test_service_jwt_verifier_and_minter(tmp_path: Path) -> None:
    pems = {n: pem_public(k) for n, k in SERVICE_KEYS.items()}
    v = ServiceJwtVerifier.from_pem("registry", pems)
    now = int(time.time())
    good = _svc_token()
    assert v.verify(good) == "pki"
    for token in (
        "garbage",
        jwt.encode(
            {"iss": "pki", "aud": "registry", "iat": now, "exp": now + 60, "jti": "x"},
            "k" * 32,
            algorithm="HS256",
        ),
        _svc_token("evil", key="pki"),
        _svc_token("pki", key="policy"),
    ):
        with pytest.raises(ProblemError):
            v.verify(token)
    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(ValueError, match="P-256"):
        ServiceJwtVerifier.from_pem("registry", {"x": rsa_pem})

    assert ServiceTokenMinter.from_file("registry", None).token("pki") is None
    key_path = tmp_path / "svc.pem"
    key = ec.generate_private_key(ec.SECP256R1())
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    minter = ServiceTokenMinter.from_file("registry", str(key_path))
    minted = minter.token("pki")
    assert minted is not None
    claims = jwt.decode(minted, key.public_key(), algorithms=["ES256"], audience="pki")
    assert claims["exp"] - claims["iat"] == 60 and claims["iss"] == claims["sub"] == "registry"
    rsa_path = tmp_path / "rsa.pem"
    rsa_path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="EC"):
        ServiceTokenMinter.from_file("registry", str(rsa_path))


def test_minter_issues_a_fresh_token_per_call() -> None:
    """Receivers accept each jti once, so two consecutive calls must carry different tokens."""
    key = ec.generate_private_key(ec.SECP256R1())
    minter = ServiceTokenMinter("registry", key)
    first, second = minter.token("pki"), minter.token("pki")
    assert first is not None and second is not None and first != second
    c1, c2 = (
        jwt.decode(t, key.public_key(), algorithms=["ES256"], audience="pki")
        for t in (first, second)
    )
    assert c1["jti"] != c2["jti"]
    for c in (c1, c2):
        assert c["aud"] == "pki" and c["iss"] == c["sub"] == "registry"
        assert 0 < c["exp"] - c["iat"] <= 300 and abs(c["iat"] - time.time()) < 5


def test_service_jwt_claim_rules() -> None:
    v = ServiceJwtVerifier.from_pem("registry", {"pki": pem_public(SERVICE_KEYS["pki"])})
    now = int(time.time())
    bad = {
        "missing jti": _svc_token(jti=None),
        "missing iat": _svc_token(iat=None),
        "missing exp": _svc_token(exp=None),
        "empty jti": _svc_token(jti=""),
        "numeric jti": _svc_token(jti=7),
        "long jti": _svc_token(jti="j" * 129),
        "lifetime > 300 s": _svc_token(iat=now, exp=now + 301),
        "float iat": _svc_token(iat=now + 0.5),
        "wrong audience": _svc_token(aud="pki"),
    }
    for name, token in bad.items():
        with pytest.raises(ProblemError) as info:
            v.verify(token)
        assert info.value.status == 401, name
    assert v.verify(_svc_token(iat=now, exp=now + 300)) == "pki"


def test_service_jwt_single_use() -> None:
    pems = {"pki": pem_public(SERVICE_KEYS["pki"]), "ota": pem_public(SERVICE_KEYS["ota"])}
    v = ServiceJwtVerifier.from_pem("registry", pems)
    token = _svc_token()
    assert v.verify(token) == "pki"
    with pytest.raises(ProblemError, match="already used"):
        v.verify(token)
    # The same jti from another issuer is a different token.
    jti = str(uuid.uuid4())
    assert v.verify(_svc_token("pki", jti=jti)) == "pki"
    assert v.verify(_svc_token("ota", jti=jti)) == "ota"
    # Single use can be disabled (REGISTRY_SERVICE_JWT_SINGLE_USE=false).
    lax = ServiceJwtVerifier.from_pem("registry", pems, single_use=False)
    reused = _svc_token()
    assert lax.verify(reused) == lax.verify(reused) == "pki"


def test_jti_replay_cache_bounds() -> None:
    cache = JtiReplayCache(max_entries=3)
    assert cache.use("a", forget_after=100, now=0)
    assert not cache.use("a", forget_after=100, now=50)  # replay inside the window
    assert cache.use("a", forget_after=300, now=101)  # remembered only until exp + leeway
    assert cache.use("b", forget_after=150, now=101)
    assert cache.use("c", forget_after=400, now=101)
    assert len(cache) == 3
    # Full: expired ids go first ("b" at t=200), then the oldest ("a").
    assert cache.use("d", forget_after=500, now=200) and len(cache) == 3
    assert not cache.use("a", forget_after=500, now=200)
    assert cache.use("e", forget_after=500, now=200) and len(cache) == 3
    assert cache.use("a", forget_after=500, now=200)  # "a" was evicted as the oldest
    assert JtiReplayCache(0).max_entries == 1


# ------------------------------------------------------------------------------------------------
# KMS
# ------------------------------------------------------------------------------------------------


async def test_local_kms(tmp_path: Path) -> None:
    with pytest.raises(KmsError):
        LocalKeyWrapper(b"short")
    with pytest.raises(KmsError):
        LocalKeyWrapper.from_file(str(tmp_path / "missing.bin"), create=False)
    w = LocalKeyWrapper.from_file(str(tmp_path / "sub" / "kek.bin"), create=True)
    blob = await w.wrap(b"secret", {"tenant_id": "a"})
    assert await w.unwrap(blob, {"tenant_id": "a"}) == b"secret"
    with pytest.raises(KmsError):
        await w.unwrap(blob, {"tenant_id": "b"})
    with pytest.raises(KmsError):
        await w.unwrap(b"\x02" + blob[1:], {"tenant_id": "a"})
    assert (
        LocalKeyWrapper.from_file(str(tmp_path / "sub" / "kek.bin"), create=False).key_id
        == w.key_id
    )


class FakeKmsClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def encrypt(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(kw)
        return {"CiphertextBlob": b"wrapped:" + kw["Plaintext"]}

    def decrypt(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(kw)
        if kw["EncryptionContext"].get("tenant_id") != "a":
            raise RuntimeError("InvalidCiphertextException")
        return {"Plaintext": kw["CiphertextBlob"].removeprefix(b"wrapped:")}


async def test_aws_kms_wrapper() -> None:
    client = FakeKmsClient()
    w = AwsKmsKeyWrapper(client, "arn:aws:kms:eu-west-1:1:key/abc")
    blob = await w.wrap(b"k", {"tenant_id": "a"})
    assert await w.unwrap(blob, {"tenant_id": "a"}) == b"k"
    assert client.calls[0]["KeyId"] == "arn:aws:kms:eu-west-1:1:key/abc"
    with pytest.raises(KmsError):
        await w.unwrap(blob, {"tenant_id": "b"})


# ------------------------------------------------------------------------------------------------
# HTTP adapters (PKI, OTA, EMQX) against httpx.MockTransport
# ------------------------------------------------------------------------------------------------


def _cert_view(
    serial: str,
    device: str = "dev-00000000000000aa",
    tenant: str = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11",
) -> dict[str, Any]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    return {
        "serial": serial,
        "device_id": device,
        "tenant_id": tenant,
        "issuer": "Device CA",
        "not_before": now.isoformat(),
        "not_after": (now + timedelta(days=14)).isoformat(),
        "status": "revoked",
        "revocation": {"reason": "keyCompromise", "revoked_at": now.isoformat()},
        "certificate_pem": make_cert(
            tenant, device, key, int(serial, 16), now, now + timedelta(days=14)
        ),
    }


async def test_http_pki_client() -> None:
    seen: list[tuple[str, str, str | None]] = []
    status = {"code": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.headers.get("authorization")))
        if status["code"] != 200:
            return httpx.Response(status["code"], json={})
        if request.url.path.endswith("/revoke-all"):
            return httpx.Response(200, json={"count": 2})
        if request.url.path.endswith("/release"):
            body = json.loads(request.content)
            assert body == {"tenant_id": "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", "note": "n" * 1024}
            return httpx.Response(202, json={"event_id": "ev-1", "event": "device_release"})
        if "/certificates/" in request.url.path:
            if request.url.path.endswith("/ff"):
                return httpx.Response(404, json={})
            return httpx.Response(200, json=_cert_view("0abc"))
        return httpx.Response(200, json={"certificates": [_cert_view("0abc")]})

    key = ec.generate_private_key(ec.SECP256R1())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    pki = HttpPkiClient("https://pki:8443/", client, ServiceTokenMinter("registry", key), 30)
    assert await pki.revoke_all("dev-00000000000000aa", "stolen") == 2
    tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
    assert await pki.release("dev-00000000000000aa", tenant, "n" * 2000) == "ev-1"
    assert seen[-1][:2] == ("POST", "/v1/devices/dev-00000000000000aa/release")
    certs = await pki.device_certificates("dev-00000000000000aa")
    assert certs[0].serial_hex == "0abc" and certs[0].status == "revoked"
    assert certs[0].revocation_reason == "keyCompromise" and certs[0].public_key is not None
    await pki.device_certificates("dev-00000000000000aa")  # cached
    cert = await pki.get_certificate("0A:BC")
    assert cert is not None and cert.device_id == "dev-00000000000000aa"
    await pki.get_certificate("abc")  # cached under the normalized serial
    assert await pki.get_certificate("00ff") is None
    assert sum(1 for _, p, _ in seen if p == "/v1/certificates/0abc") == 1
    assert all(a and a.startswith("Bearer ") for _, _, a in seen)
    # Every request carries its own single-use token (distinct jti, short lifetime).
    claims = [
        jwt.decode(
            a.removeprefix("Bearer "), key.public_key(), algorithms=["ES256"], audience="pki"
        )
        for _, _, a in seen
        if a
    ]
    assert len({c["jti"] for c in claims}) == len(claims) >= 3
    assert all(c["exp"] - c["iat"] <= 300 for c in claims)
    pki.invalidate("dev-00000000000000aa")
    assert pki.cert_cache.get("0abc") is None
    status["code"] = 404
    assert await pki.device_certificates("dev-00000000000000bb") == []
    for code in (500, 403, 409):
        status["code"] = code
        with pytest.raises(UpstreamError):
            await pki.revoke_all("dev-00000000000000aa", "x")
        with pytest.raises(UpstreamError):
            await pki.release("dev-00000000000000aa", tenant, "x")
        with pytest.raises(UpstreamError):
            await pki.device_certificates("dev-00000000000000cc")
        with pytest.raises(UpstreamError):
            await pki.get_certificate("1234")

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    broken = HttpPkiClient(
        "https://pki",
        httpx.AsyncClient(transport=httpx.MockTransport(boom)),
        ServiceTokenMinter("registry", None),
    )
    with pytest.raises(UpstreamError):
        await broken.get_certificate("01")
    assert normalize_serial("00:01") == "01"
    await client.aclose()


async def test_http_ota_and_emqx_clients() -> None:
    received: list[httpx.Request] = []
    codes = {"ota": 202, "emqx": 204}

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(codes["ota"] if "ota" in request.url.path else codes["emqx"])

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ota = HttpOtaClient("http://ota:8001", client, ServiceTokenMinter("registry", None))
    await ota.forward_status({"device_id": "d"})
    assert received[-1].url.path == "/internal/v1/ota/status"
    codes["ota"] = 500
    with pytest.raises(UpstreamError):
        await ota.forward_status({})
    emqx = HttpEmqxClient("http://emqx:18083", client, "key", "secret")
    assert await emqx.kick("dev-1") is True
    assert received[-1].method == "DELETE" and received[-1].url.path == "/api/v5/clients/dev-1"
    assert received[-1].headers["authorization"].startswith("Basic ")
    codes["emqx"] = 404
    assert await emqx.kick("dev-1") is False
    codes["emqx"] = 500
    with pytest.raises(UpstreamError):
        await emqx.kick("dev-1")
    with pytest.raises(UpstreamError):
        await HttpEmqxClient("http://emqx", client, None, None).kick("dev-1")

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    dead = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    with pytest.raises(UpstreamError):
        await HttpOtaClient("http://ota", dead, ServiceTokenMinter("r", None)).forward_status({})
    with pytest.raises(UpstreamError):
        await HttpEmqxClient("http://emqx", dead, "k", "s").kick("d")
    await client.aclose()
    await dead.aclose()


def test_build_http_client_and_settings(tmp_path: Path) -> None:
    assert build_http_client(1.0, None, None, None).timeout.read == 1.0
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert_pem = make_cert(
        "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11",
        "dev-00000000000000aa",
        key,
        5,
        now,
        now + timedelta(days=1),
    )
    (tmp_path / "c.pem").write_text(cert_pem)
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    client = build_http_client(1.0, None, str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    assert client is not None
    s = Settings(db_host="db", db_user="registry_app", db_password="p@ss/word", db_name="registry")
    assert s.sqlalchemy_url() == "postgresql+asyncpg://registry_app:p%40ss%2Fword@db:5432/registry"
    s = Settings(db_host="db", db_password="x", db_iam_auth=True)
    assert ":x@" not in s.sqlalchemy_url()
    s = Settings(database_url="postgresql+asyncpg://u@h/d")
    assert s.sqlalchemy_url() == "postgresql+asyncpg://u@h/d"
