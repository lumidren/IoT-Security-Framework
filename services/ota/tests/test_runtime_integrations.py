"""Settings, container wiring, auth helpers, outgoing HTTP integrations, upload parser and app
lifecycle."""

from __future__ import annotations

import base64
import json
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import SecretStr, ValidationError
from starlette.requests import Request

from ironmesh_ota import observability, runtime
from ironmesh_ota.app import create_app
from ironmesh_ota.auth import (
    JtiReplayCache,
    StaticKeyTokenVerifier,
    authenticate_service,
    principal_from_claims,
)
from ironmesh_ota.domain import Role, Target
from ironmesh_ota.integrations.device_keys import PkiDeviceKeyResolver
from ironmesh_ota.integrations.events import BusEvent, LoggingEventPublisher
from ironmesh_ota.integrations.http import ServiceTokenMinter, build_http_client
from ironmesh_ota.integrations.mqtt import (
    EmqxApiPublisher,
    LoggingPublisher,
    OutboundMessage,
    tls_context,
)
from ironmesh_ota.integrations.pki import FakePkiPolicy, HttpPkiPolicyClient, PkiPolicyError
from ironmesh_ota.integrations.registry import (
    Downlink,
    FakeRegistry,
    HttpRegistryClient,
    RegistryError,
    device_from_json,
    notify_json,
    select_eligible,
)
from ironmesh_ota.problems import Problem
from ironmesh_ota.repository.memory import MemoryDatabase
from ironmesh_ota.settings import ArtifactStoreKind, Environment, Settings, SigningProvider
from ironmesh_ota.storage import LocalArtifactStore, S3ArtifactStore
from ironmesh_ota.upload import parse_firmware_upload
from ironmesh_wire import envelope

from .conftest import Clock, Keys, build_container, new_tenant

# --- settings ----------------------------------------------------------------------------------


def test_settings_follow_the_helm_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "OTA_LISTEN_PORT": "8001",
        "OTA_DB_HOST": "db.internal",
        "OTA_DB_PORT": "",
        "OTA_DB_NAME": "ota",
        "OTA_DB_USER": "ota_app",
        "OTA_DB_SSLMODE": "verify-full",
        "OTA_DB_IAM_AUTH": "",
        "OTA_DB_PASSWORD": "p@ss/word",
        "OTA_KAFKA_BROKERS": "",
        "OTA_KAFKA_SASL_MECHANISM": "none",
        "OTA_KAFKA_TLS_ENABLED": "",
        "OTA_ARTIFACT_STORE": "s3",
        "OTA_ARTIFACT_BUCKET": "fw",
        "OTA_SIGNING_PROVIDER": "kms",
        "OTA_SIGNING_KEY_ID": "fw-ed25519-1",
        "OTA_PQ_SIGNING_ENABLED": "true",
        "OTA_LOG_LEVEL": "info",
        "OTA_OIDC_AUDIENCE": "ironmesh-api",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    s = Settings()
    assert s.db_port == 5432 and s.db_iam_auth is False and s.kafka_sasl_mechanism is None
    assert s.artifact_store is ArtifactStoreKind.S3
    assert s.signing_provider is SigningProvider.KMS_WRAPPED and s.pq_signing_enabled
    assert s.sqlalchemy_url() == (
        "postgresql+asyncpg://ota_app:p%40ss%2Fword@db.internal:5432/ota?ssl=verify-full"
    )
    assert not s.kafka_enabled


def test_database_url_building() -> None:
    assert Settings(database_url=SecretStr("postgresql+asyncpg://x/y")).sqlalchemy_url() == (
        "postgresql+asyncpg://x/y"
    )
    assert Settings(db_host="h", db_iam_auth=True, db_password=SecretStr("x")).sqlalchemy_url() == (
        "postgresql+asyncpg://ota_app@h:5432/ota"
    )
    assert Settings().sqlalchemy_url() is None
    assert Settings(artifact_store="local").artifact_store is ArtifactStoreKind.FILESYSTEM


def test_production_profile_requires_hardened_backends() -> None:
    with pytest.raises(ValidationError) as info:
        Settings(env=Environment.PROD)
    assert "OTA_SIGNING_PROVIDER=kms-wrapped" in str(info.value)
    assert "OTA_REGISTRY_TOKEN or OTA_SERVICE_TOKEN_KEY_FILE" in str(info.value)
    ok = Settings(
        env=Environment.PROD,
        db_host="db",
        artifact_store=ArtifactStoreKind.S3,
        artifact_bucket="b",
        signing_provider=SigningProvider.KMS_WRAPPED,
        signing_key_secret_arn="arn",
        registry_token=SecretStr("ota-registry-token"),
        oidc_issuer="https://idp",
        emqx_api_url="http://emqx",
        kafka_brokers="k:9092",
        registry_url="http://r",
        pki_url="https://p",
    )
    assert ok.env is Environment.PROD


# --- runtime wiring ----------------------------------------------------------------------------


def test_build_signer_variants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ironmesh_ota import signing

    key_file = tmp_path / "keys" / "fw.pem"
    s = Settings(
        signing_key_file=key_file,
        signing_key_generate_if_missing=True,
        signing_key_id="fw-ed25519-dev",
    )
    signer = runtime.build_signer(s)
    assert key_file.exists() and signer.key_name == "fw-ed25519-dev"
    assert runtime.build_signer(s).active_key_id == signer.active_key_id  # reused, not regenerated
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_signer(Settings(signing_key_file=tmp_path / "missing.pem"))
    pem = (tmp_path / "keys" / "fw.pem").read_text()
    assert runtime.build_signer(Settings(signing_private_key_pem=SecretStr(pem))).active_key_id == (
        signer.active_key_id
    )
    ring = tmp_path / "ring.json"
    ring.write_bytes(
        signing.encrypt_keyring(
            signing.keyring_document(signing.new_keyring_entries(with_mldsa=True)), b"pw", n=2**12
        )
    )
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_signer(Settings(signing_keyring_file=ring))
    pq = runtime.build_signer(
        Settings(
            signing_keyring_file=ring, signing_passphrase=SecretStr("pw"), pq_signing_enabled=True
        )
    )
    assert pq.pq_enabled
    with pytest.raises(signing.SigningError):
        runtime.build_signer(Settings())
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_signer(Settings(signing_provider=SigningProvider.KMS_WRAPPED))
    prod_like = Settings.model_construct(**{**Settings().__dict__, "env": Environment.PROD})
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_signer(prod_like)

    calls: list[str] = []

    def fake_boto(service: str, _settings: Settings, **_: Any) -> Any:
        calls.append(service)
        return object()

    def fake_load(*_: Any, **kw: Any) -> str:
        return f"kms:{kw['secret_id']}:{kw['key_id']}"

    monkeypatch.setattr(runtime, "load_kms_signer", fake_load)
    out: Any = runtime.build_signer(
        Settings(signing_provider=SigningProvider.KMS_WRAPPED, signing_key_secret_arn="arn:s"),
        boto=fake_boto,
    )
    assert out == "kms:arn:s:alias/ironmesh-firmware-kek"
    assert calls == ["secretsmanager", "kms"]


def test_build_store_variants(tmp_path: Path) -> None:
    local = runtime.build_store(Settings(artifact_path=tmp_path / "a"))
    assert isinstance(local, LocalArtifactStore)
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_store(Settings(artifact_store=ArtifactStoreKind.S3))
    seen: dict[str, Any] = {}

    def fake_boto(service: str, _settings: Settings, **kw: Any) -> Any:
        seen.update(kw, service=service)
        return object()

    s3 = runtime.build_store(
        Settings(
            artifact_store=ArtifactStoreKind.S3,
            artifact_bucket="fw",
            s3_region="eu-west-1",
            s3_kms_key_arn="arn:kms",
        ),
        boto=fake_boto,
    )
    assert isinstance(s3, S3ArtifactStore)
    assert seen["service"] == "s3" and seen["region_name"] == "eu-west-1"
    assert seen["config"].signature_version == "s3v4"


async def test_build_container_dev_profile(tmp_path: Path) -> None:
    keys_dir = tmp_path / "svc"
    keys_dir.mkdir()
    svc_key = ec.generate_private_key(ec.SECP256R1())
    (keys_dir / "registry.pem").write_bytes(
        svc_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    token_key = tmp_path / "ota-token.pem"
    token_key.write_bytes(
        svc_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings = Settings(
        database_backend="memory",
        artifact_path=tmp_path / "artifacts",
        signing_key_file=tmp_path / "fw.pem",
        signing_key_generate_if_missing=True,
        service_public_keys_dir=keys_dir,
        service_token_key_file=token_key,
        registry_url="http://registry:8000",
        pki_url="https://pki:8443",
        emqx_api_url="http://emqx:18083",
        emqx_api_key=SecretStr("k"),
        emqx_api_secret=SecretStr("s"),
        oidc_jwks_url="http://idp/jwks",
        controller_enabled=False,
    )
    container = runtime.build_container(settings)
    assert isinstance(container.db, MemoryDatabase)
    assert isinstance(container.registry, HttpRegistryClient)
    assert isinstance(container.publisher, EmqxApiPublisher)
    assert isinstance(container.pki, HttpPkiPolicyClient)
    assert container.service_verifier is not None
    app = create_app(container)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://ota") as client,
    ):
        assert (await client.get("/healthz")).json() == {"status": "ok"}
        ready = await client.get("/readyz")
        assert ready.status_code == 200
        openapi = (await client.get("/openapi.json")).json()
        for path in (
            "/v1/firmware",
            "/v1/firmware/by-hash/{sha256_hex}",
            "/v1/firmware/{firmware_id}/manifest",
            "/v1/firmware/{firmware_id}/image",
            "/v1/campaigns",
            "/v1/campaigns/{campaign_id}/approve",
            "/v1/campaigns/{campaign_id}/rollback",
            "/v1/campaigns/{campaign_id}/devices",
            "/v1/campaigns/{campaign_id}/audit",
            "/v1/signing-keys",
            "/internal/v1/ota/status",
            "/internal/v1/firmware/known-hashes",
        ):
            assert path in openapi["paths"], path
        assert (
            "multipart/form-data"
            in openapi["paths"]["/v1/firmware"]["post"]["requestBody"]["content"]
        )
        # a service JWT signed with the registry key is accepted on internal endpoints
        now = int(time.time())
        token = jwt.encode(
            {"sub": "registry", "aud": "ota", "iat": now, "exp": now + 300, "jti": "j-1"},
            svc_key,
            algorithm="ES256",
        )
        resp = await client.get(
            "/internal/v1/firmware/known-hashes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200 and resp.json() == []
        # ... but only once (OTA_SERVICE_JWT_SINGLE_USE defaults to true)
        resp = await client.get(
            "/internal/v1/firmware/known-hashes", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401


async def test_build_container_without_peers(tmp_path: Path) -> None:
    settings = Settings(
        database_backend="memory",
        artifact_path=tmp_path / "a",
        signing_key_file=tmp_path / "k.pem",
        signing_key_generate_if_missing=True,
    )
    container = runtime.build_container(settings)
    assert isinstance(container.publisher, LoggingPublisher)
    assert isinstance(container.events, LoggingEventPublisher)
    assert isinstance(container.registry, FakeRegistry)
    assert isinstance(container.pki, FakePkiPolicy)
    # the registry token alone is enough for registry calls (no service JWT key)
    with_token = runtime.build_container(
        Settings(
            database_backend="memory",
            artifact_path=tmp_path / "a",
            signing_key_file=tmp_path / "k.pem",
            registry_url="http://r",
            registry_token=SecretStr("ota-registry-token"),
        )
    )
    assert isinstance(with_token.registry, HttpRegistryClient)
    for close in with_token.closers:
        await close()
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_container(
            Settings(artifact_path=tmp_path / "a", signing_key_file=tmp_path / "k.pem")
        )
    with pytest.raises(runtime.ConfigurationError):
        runtime.build_container(
            Settings(
                database_backend="memory",
                artifact_path=tmp_path / "a",
                signing_key_file=tmp_path / "k.pem",
                registry_url="http://r",
            )
        )
    sql = runtime.build_container(
        Settings(
            database_url=SecretStr("postgresql+asyncpg://ota_app@127.0.0.1:1/ota"),
            artifact_path=tmp_path / "a",
            signing_key_file=tmp_path / "k.pem",
            registry_token=SecretStr("t" * 32),
            registry_url="http://r",
        )
    )
    assert sql.leader.__class__.__name__ == "PostgresAdvisoryLock"
    await sql.db.close()
    await LoggingPublisher().publish([OutboundMessage("t", b"x")])
    await LoggingEventPublisher().publish(BusEvent("t", "k", {}))


def test_observability_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentelemetry.exporter.otlp.proto.grpc import trace_exporter
    from opentelemetry.sdk.trace.export import SpanExportResult

    monkeypatch.setattr(
        trace_exporter.OTLPSpanExporter, "export", lambda self, spans: SpanExportResult.SUCCESS
    )
    installed: list[Any] = []
    monkeypatch.setattr("opentelemetry.trace.set_tracer_provider", installed.append)
    settings = Settings(log_level="debug", log_format="json")
    observability.configure_logging(settings)
    observability.get_logger().info("hello", tenant_id="t")
    observability.configure_logging(Settings(log_format="console"))
    assert observability.configure_tracing(Settings()) is False
    assert observability.configure_tracing(
        Settings(otel_enabled=True, otel_endpoint="http://127.0.0.1:4317")
    )
    assert observability.configure_tracing(Settings(otel_enabled=True))
    assert len(installed) == 2
    for provider in installed:
        provider.shutdown()
    from opentelemetry.sdk.trace import TracerProvider

    with TracerProvider().get_tracer("t").start_as_current_span("s"):
        event = observability._add_trace(None, "info", {})
        assert len(event["trace_id"]) == 32


# --- auth --------------------------------------------------------------------------------------


def _request(headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("10.0.0.1", 1234),
        "method": "GET",
        "path": "/",
    }
    return Request(scope)


def test_principal_from_claims_roles_and_platform_admin() -> None:
    tenant = str(new_tenant())
    p = principal_from_claims(
        {"sub": "u", "tenant_id": tenant, "roles": ["viewer", "admin"]},
        None,
        ip=None,
        request_id=None,
    )
    assert p.role is Role.ADMIN and p.has(Role.OPERATOR) and not p.has(Role.OWNER)
    key = principal_from_claims(
        {"sub": "k", "tenant_id": tenant, "role": "operator", "token_use": "api_key"},
        None,
        ip=None,
        request_id=None,
    )
    assert key.actor.type == "api_key"
    other = str(new_tenant())
    admin = principal_from_claims(
        {"sub": "a", "tenant_id": tenant, "role": "viewer", "roles": ["platform_admin"]},
        other,
        ip=None,
        request_id=None,
    )
    assert admin.cross_tenant and admin.role is Role.OWNER and str(admin.tenant_id) == other
    with pytest.raises(Problem):
        principal_from_claims(
            {"sub": "u", "tenant_id": "nope", "role": "viewer"}, None, ip=None, request_id=None
        )


async def test_service_token_rules() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    verifier = StaticKeyTokenVerifier([key.public_key()], audience="ota", algorithms=("ES256",))
    minter = ServiceTokenMinter(key, "registry", kid="k1")
    token = minter.mint("ota")
    assert minter.mint("ota") != token  # never cached: every request gets its own jti
    caller = await authenticate_service(
        _request({"Authorization": f"Bearer {token}"}), verifier, ["registry"]
    )
    assert caller.name == "registry" and caller.actor.type == "service"
    with pytest.raises(Problem) as info:
        await authenticate_service(
            _request({"Authorization": f"Bearer {token}"}), verifier, ["anomaly"]
        )
    assert info.value.status == 403
    now = int(time.time())
    long_lived = jwt.encode(
        {"sub": "registry", "aud": "ota", "iat": now, "exp": now + 3600, "jti": "j"},
        key,
        algorithm="ES256",
    )
    with pytest.raises(Problem) as info:
        await authenticate_service(
            _request({"Authorization": f"Bearer {long_lived}"}), verifier, ["registry"]
        )
    assert info.value.status == 401
    with pytest.raises(Problem):
        await authenticate_service(
            _request({"Authorization": "Bearer junk"}), verifier, ["registry"]
        )
    with pytest.raises(Problem):
        await authenticate_service(_request({"Authorization": "Bearer junk"}), None, ["x"])
    static = await authenticate_service(
        _request({"Authorization": "Bearer s" * 1 + "ecret", "X-IronMesh-Service": "bridge"}),
        None,
        [],
        "secret",
    )
    assert static.name == "bridge"
    other = StaticKeyTokenVerifier(
        [ec.generate_private_key(ec.SECP256R1()).public_key()],
        audience="ota",
        algorithms=("ES256",),
    )
    with pytest.raises(jwt.InvalidTokenError):
        await other.verify(token)
    with pytest.raises(ValueError, match="ES256"):
        ServiceTokenMinter(ec.generate_private_key(ec.SECP384R1()), "x")


def test_minter_issues_a_fresh_token_per_call() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    minter = ServiceTokenMinter(key, "ota")
    first, second = minter.mint("pki"), minter.mint("pki")
    c1, c2 = (
        jwt.decode(t, key.public_key(), algorithms=["ES256"], audience="pki")
        for t in (first, second)
    )
    assert first != second and c1["jti"] != c2["jti"]
    for c in (c1, c2):
        assert c["aud"] == "pki" and c["iss"] == c["sub"] == "ota"
        assert 0 < c["exp"] - c["iat"] <= 300 and abs(c["iat"] - time.time()) < 5


async def test_service_token_single_use_and_jti_rules() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    verifier = StaticKeyTokenVerifier([key.public_key()], audience="ota", algorithms=("ES256",))
    replay = JtiReplayCache()
    token = ServiceTokenMinter(key, "registry").mint("ota")
    auth = {"Authorization": f"Bearer {token}"}
    caller = await authenticate_service(_request(auth), verifier, ["registry"], None, replay)
    assert caller.name == "registry"
    with pytest.raises(Problem) as info:
        await authenticate_service(_request(auth), verifier, ["registry"], None, replay)
    assert info.value.status == 401 and "already used" in str(info.value.detail)
    now = int(time.time())
    for claims in (
        {"sub": "registry", "aud": "ota", "iat": now, "exp": now + 60},
        {"sub": "registry", "aud": "ota", "iat": now, "exp": now + 60, "jti": ""},
        {"sub": "registry", "aud": "ota", "iat": now, "exp": now + 60, "jti": "j" * 129},
        {"sub": "registry", "aud": "ota", "iat": now, "exp": now + 301, "jti": "long"},
    ):
        bad = jwt.encode(claims, key, algorithm="ES256")
        with pytest.raises(Problem) as info:
            await authenticate_service(
                _request({"Authorization": f"Bearer {bad}"}), verifier, ["registry"], None, replay
            )
        assert info.value.status == 401
    # Without a replay cache (OTA_SERVICE_JWT_SINGLE_USE=false) a token may be reused.
    for _ in range(2):
        await authenticate_service(_request(auth), verifier, ["registry"])


def test_jti_replay_cache_bounds() -> None:
    cache = JtiReplayCache(max_entries=2)
    assert cache.use("a", 100, now=0) and not cache.use("a", 100, now=99)
    assert cache.use("a", 300, now=100)  # forgotten after exp + leeway
    assert cache.use("b", 150, now=100) and len(cache) == 2
    assert cache.use("c", 400, now=200) and len(cache) == 2  # expired "b" dropped first
    assert cache.use("d", 400, now=200) and len(cache) == 2  # then the oldest ("a")
    assert cache.use("a", 400, now=200)
    assert JtiReplayCache(0).max_entries == 1


def test_service_token_from_file(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "k.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    minter = ServiceTokenMinter.from_file(path, "ota")
    claims = jwt.decode(
        minter.mint("registry"), key.public_key(), algorithms=["ES256"], audience="registry"
    )
    assert claims["iss"] == claims["sub"] == "ota" and claims["exp"] - claims["iat"] == 60
    from cryptography.hazmat.primitives.asymmetric import ed25519

    ed = tmp_path / "ed.pem"
    ed.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="EC P-256"):
        ServiceTokenMinter.from_file(ed, "ota")


# --- outgoing HTTP integrations ----------------------------------------------------------------


def _device(i: int, **kw: Any) -> dict[str, Any]:
    """A registry ``resolve`` item (API_CONTRACT §1.12)."""
    return {
        "device_id": f"dev-{i:016x}",
        "product": "gw",
        "state": "active",
        "fw_version": "1.0.0",
        "fw_hash_hex": "ab" * 32,
        "connected": True,
        **kw,
    }


async def test_http_registry_client_resolve_and_downlink() -> None:
    tenant = new_tenant()
    calls: list[httpx.Request] = []
    status = {"code": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer tok-registry"
        assert "X-IronMesh-Tenant" not in request.headers
        if status["code"] != 200:
            return httpx.Response(status["code"], json={"detail": "nope"})
        if request.url.path == f"/internal/v1/tenants/{tenant}/devices/resolve":
            return httpx.Response(
                200,
                json={
                    "items": [
                        _device(1),
                        _device(7, state="quarantined", fw_hash_hex="zz"),
                        _device(9, product="x", fw_hash_hex=None),
                    ]
                },
            )
        return httpx.Response(200, json={"seq": 42, "published_at": "2026-11-09T10:00:00Z"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://r")
    registry = HttpRegistryClient(client, lambda aud: f"tok-{aud}")
    target = Target(groups=["g"], device_ids=["dev-0000000000000007"], tags={"site": "lab"})
    found = await registry.resolve(tenant, target)
    assert json.loads(calls[0].content) == {
        "groups": ["g"],
        "tags": {"site": "lab"},
        "device_ids": ["dev-0000000000000007"],
    }
    assert [d.id for d in found] == [
        "dev-0000000000000001",
        "dev-0000000000000007",
        "dev-0000000000000009",
    ]
    assert found[0].fw_hash == bytes.fromhex("ab" * 32) and found[0].fw_version == "1.0.0"
    assert found[1].fw_hash is None and found[2].fw_hash is None
    eligible = select_eligible(found + [found[0]], "gw")
    assert [d.id for d in eligible.devices] == ["dev-0000000000000001"]
    assert eligible.skipped == {
        "dev-0000000000000007": "state quarantined",
        "dev-0000000000000009": "product x",
    }
    assert device_from_json({"device_id": "dev-1", "fw_hash_hex": "g" * 64}).fw_hash is None

    campaign = str(uuid.uuid4())
    body = envelope.OtaNotify(
        campaign_id=campaign, manifest=b"", url="https://a/b", delta_from=bytes(32)
    )
    receipt = await registry.ota_notify(
        Downlink(tenant, uuid.UUID(campaign), "dev-0000000000000001", body)
    )
    assert receipt.seq == 42 and receipt.published_at == datetime(2026, 11, 9, 10, tzinfo=UTC)
    sent = calls[-1]
    assert sent.url.path == (f"/internal/v1/tenants/{tenant}/devices/dev-0000000000000001/downlink")
    assert json.loads(sent.content) == {
        "type": "ota_notify",
        "body": {
            "campaign_id": campaign,
            "manifest": "0102",
            "url": "https://a/b",
            "delta_from": "00" * 32,
        },
        "retain": True,
    }
    assert notify_json(replace(body, delta_from=None))["delta_from"] is None

    status["code"] = 409
    with pytest.raises(RegistryError) as info:
        await registry.ota_notify(
            Downlink(tenant, uuid.UUID(campaign), "dev-0000000000000001", body)
        )
    assert info.value.status == 409 and info.value.detail == "nope"
    status["code"] = 502

    def plain(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="bad gateway")

    plain_client = httpx.AsyncClient(transport=httpx.MockTransport(plain), base_url="http://r")
    with pytest.raises(RegistryError, match="HTTP 502"):
        await HttpRegistryClient(plain_client, lambda aud: "t").resolve(tenant, target)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    dead = httpx.AsyncClient(transport=httpx.MockTransport(boom), base_url="http://r")
    with pytest.raises(RegistryError) as down:
        await HttpRegistryClient(dead, lambda aud: "t").resolve(tenant, target)
    assert down.value.status == 0 and "ConnectError" in str(down.value)
    for c in (client, plain_client, dead):
        await c.aclose()


async def test_http_pki_policy_client() -> None:
    tenant = new_tenant()
    seen: list[httpx.Request] = []
    status = {"code": 204}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status["code"])

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://p")
    pki = HttpPkiPolicyClient(client, lambda aud: f"tok-{aud}")
    keys = [bytes(32), b"" * 1952]
    await pki.put_firmware_keys(tenant, keys)
    assert seen[0].method == "PUT"
    assert seen[0].url.path == f"/v1/tenants/{tenant}/firmware-keys"
    assert seen[0].headers["Authorization"] == "Bearer tok-pki"
    assert json.loads(seen[0].content) == {
        "public_keys_b64": [base64.b64encode(k).decode() for k in keys]
    }
    for code in (404, 500):
        status["code"] = code
        with pytest.raises(PkiPolicyError, match=f"HTTP {code}"):
            await pki.put_firmware_keys(tenant, keys)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    dead = HttpPkiPolicyClient(
        httpx.AsyncClient(transport=httpx.MockTransport(boom), base_url="https://p"),
        lambda aud: "t",
    )
    with pytest.raises(PkiPolicyError, match="ConnectError"):
        await dead.put_firmware_keys(tenant, keys)
    await client.aclose()


def _cert(key: ec.EllipticCurvePrivateKey, cn: str) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


async def test_pki_device_key_resolver() -> None:
    tenant = new_tenant()
    key = ec.generate_private_key(ec.SECP256R1())
    pem = _cert(key, "dev-0000000000000001")
    responses = {
        "0001": {
            "status": "valid",
            "device_id": "dev-0000000000000001",
            "tenant_id": str(tenant),
            "certificate_pem": pem,
        },
        "0002": {
            "status": "revoked",
            "device_id": "dev-0000000000000001",
            "tenant_id": str(tenant),
            "certificate_pem": pem,
        },
        "0003": {
            "status": "valid",
            "device_id": "dev-0000000000000001",
            "tenant_id": str(new_tenant()),
            "certificate_pem": pem,
        },
    }
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        serial = request.url.path.rsplit("/", 1)[1]
        hits.append(serial)
        if serial not in responses:
            return httpx.Response(404)
        return httpx.Response(200, json=responses[serial])

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://pki")
    resolver = PkiDeviceKeyResolver(client, lambda aud: "t")
    dev = "dev-0000000000000001"
    got = await resolver.resolve(tenant, dev, b"\x00\x01")
    assert got is not None and got.public_numbers() == key.public_key().public_numbers()
    assert await resolver.resolve(tenant, dev, b"\x00\x01") is got  # cached
    assert hits.count("0001") == 1
    assert await resolver.resolve(tenant, dev, b"\x00\x02") is None  # revoked
    assert await resolver.resolve(tenant, dev, b"\x00\x03") is None  # other tenant
    assert await resolver.resolve(tenant, "dev-0000000000000009", b"\x00\x01") is None
    assert await resolver.resolve(tenant, dev, b"\x00\x09") is None  # unknown
    await client.aclose()


async def test_emqx_publisher_bulk_api() -> None:
    bodies: list[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v5/publish/bulk"
        assert request.headers["Authorization"] == "Basic " + base64.b64encode(b"k:s").decode()
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=[])

    publisher = EmqxApiPublisher(
        httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://emqx"), "k", "s"
    )
    messages = [
        OutboundMessage(f"t/{i}", bytes([i]), True, 1, (("traceparent", "00-x"),))
        for i in range(150)
    ]
    await publisher.publish(messages)
    assert [len(b) for b in bodies] == [100, 50]
    first = bodies[0][0]
    assert first["payload_encoding"] == "base64" and base64.b64decode(first["payload"]) == b"\x00"
    assert first["retain"] is True and first["properties"]["user_properties"] == {
        "traceparent": "00-x"
    }
    await publisher.publish([OutboundMessage("t/x", b"")])
    await publisher.close()


def test_tls_contexts(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = tmp_path / "c.pem"
    cert.write_text(_cert(key, "svc-ota"))
    key_file = tmp_path / "k.pem"
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings = Settings(tls_ca_file=cert, tls_cert_file=cert, tls_key_file=key_file)
    ctx = tls_context(settings)
    import ssl

    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_3
    client = build_http_client(settings, "https://pki")
    assert isinstance(client, httpx.AsyncClient)


# --- upload parser -----------------------------------------------------------------------------


async def _stream(body: bytes, chunk: int = 7) -> AsyncIterator[bytes]:
    for i in range(0, len(body), chunk):
        yield body[i : i + chunk]


def _multipart(parts: list[tuple[str, bytes, str | None]], boundary: str = "XyZ") -> bytes:
    out = b""
    for name, data, filename in parts:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        out += f"--{boundary}\r\nContent-Disposition: {disp}\r\n\r\n".encode() + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


CT = "multipart/form-data; boundary=XyZ"


async def test_upload_parser_streams_and_hashes() -> None:
    import hashlib

    image = bytes(range(256)) * 50
    body = _multipart([("metadata", b'{"a":1}', None), ("image", image, "fw.bin")])
    parsed = await parse_firmware_upload(
        CT, str(len(body)), _stream(body, 13), max_image=len(image), max_metadata=100
    )
    with parsed:
        assert parsed.image_sha256 == hashlib.sha256(image).digest()
        assert parsed.image_size == len(image) and parsed.filename == "fw.bin"
        assert parsed.image_path.read_bytes() == image and parsed.metadata == b'{"a":1}'
        path = parsed.image_path
    assert not path.exists()  # temp dir removed


@pytest.mark.parametrize(
    ("content_type", "body", "length", "status"),
    [
        ("application/json", b"{}", None, 415),
        ("multipart/form-data", b"", None, 415),
        (CT, _multipart([("image", b"x" * 101, "f")]), None, 413),
        (CT, _multipart([("metadata", b"m" * 101, None), ("image", b"x", "f")]), None, 413),
        (CT, b"", "999999999", 413),
        (CT, _multipart([("image", b"x", "f")]), None, 422),
        (CT, _multipart([("metadata", b"{}", None)]), None, 422),
        (
            CT,
            _multipart([("image", b"x", "f"), ("image", b"y", "f"), ("metadata", b"{}", None)]),
            None,
            422,
        ),
        (CT, b"--XyZ\r\nbroken", None, 422),
    ],
)
async def test_upload_parser_rejections(
    content_type: str, body: bytes, length: str | None, status: int
) -> None:
    with pytest.raises(Problem) as info:
        await parse_firmware_upload(
            content_type, length, _stream(body), max_image=100, max_metadata=100
        )
    assert info.value.status in (status, 400)


async def test_upload_size_limit_through_api(tmp_path: Path, keys: Keys, clock: Clock) -> None:
    from .conftest import make_env

    async for env in make_env(tmp_path, keys, clock, max_image_bytes=1000):
        resp = await env.client.post(
            "/v1/firmware",
            headers=env.auth(new_tenant()),
            files={"image": ("i.bin", b"x" * 5000, "application/octet-stream")},
            data={"metadata": json.dumps({"product": "gw", "version": "1.0.0", "version_code": 1})},
        )
        assert resp.status_code == 413
        resp = await env.client.post("/v1/firmware", headers=env.auth(new_tenant()), json={"x": 1})
        assert resp.status_code == 415


async def test_readyz_reports_failures(tmp_path: Path, keys: Keys, clock: Clock) -> None:
    container, *_ = build_container(tmp_path, keys, clock)

    async def down() -> bool:
        return False

    container.store.ping = down  # type: ignore[method-assign]
    app = create_app(container, run_controller=True, run_consumer=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://ota") as client,
    ):
        resp = await client.get("/readyz")
        assert resp.status_code == 503 and resp.json()["checks"]["artifact_store"] is False
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
    _ = uuid.uuid4()
