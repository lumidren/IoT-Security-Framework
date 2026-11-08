"""Test harness: an in-process registry with fakes for every dependency.

The ``env`` fixture runs each test against the in-memory repository and - when a PostgreSQL 16
server is available (``pgserver`` locally, ``REGISTRY_TEST_DATABASE_URL`` in CI) - again
against the real schema with row-level security, connected as ``registry_app``.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
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
from ironmesh_wire import envelope, ids
from ironmesh_wire.ids import TopicClass
from pydantic import SecretStr

from app.auth import OidcConfig, OidcVerifier, ServiceJwtVerifier, StaticJwks
from app.context import AppContext
from app.crypto import TenantKeyring
from app.domain import DEFAULT_TENANT_SETTINGS, TenantRecord
from app.integrations.bus import BusMessage, InMemoryEventBus
from app.integrations.kms import LocalKeyWrapper
from app.integrations.mqtt import FakeMqttPublisher
from app.integrations.services import FakeEmqx, FakeOta, FakePki, certificate_from_view
from app.main import create_app
from app.observability import Metrics
from app.repo.base import Repository
from app.repo.memory import MemoryRepository
from app.services.ingest import Ingest
from app.settings import Settings
from app.ws import Hub, TicketStore

ISSUER = "https://idp.test/realms/ironmesh"
AUDIENCE = "ironmesh-api"
INTERNAL_TOKEN = "internal-test-token-0123456789"
REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = REPO_ROOT / "device" / "common" / "vectors"

OIDC_KEY = ec.generate_private_key(ec.SECP256R1())
OIDC_JWK = jwt.algorithms.ECAlgorithm.to_jwk(OIDC_KEY.public_key(), as_dict=True)
OIDC_JWK.update({"kid": "test-key", "use": "sig", "alg": "ES256"})
SERVICE_KEYS = {
    name: ec.generate_private_key(ec.SECP256R1()) for name in ("pki", "policy", "anomaly")
}
CA_KEY = ec.generate_private_key(ec.SECP256R1())


def pem_public(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def new_tenant_id() -> str:
    return str(uuid.uuid4())


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@dataclass
class DeviceKey:
    tenant_id: str
    device_id: str
    key: ec.EllipticCurvePrivateKey
    serial: int
    seq: int = 0

    @property
    def serial_hex(self) -> str:
        return ids.kid_from_serial(self.serial).hex()

    def identity(self) -> envelope.SigningIdentity:
        return envelope.SigningIdentity.device(self.key, self.serial)


def make_cert(
    tenant_id: str,
    device_id: str,
    key: ec.EllipticCurvePrivateKey,
    serial: int,
    not_before: datetime,
    not_after: datetime,
) -> str:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, tenant_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IronMesh"),
        ]
    )
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IronMesh Device CA (test)")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(CA_KEY, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@dataclass
class Env:
    kind: str
    ctx: AppContext
    client: httpx.AsyncClient
    repo: Repository
    bus: InMemoryEventBus
    mqtt: FakeMqttPublisher
    pki: FakePki
    ota: FakeOta
    emqx: FakeEmqx
    clock: FakeClock
    ingest: Ingest
    app: Any
    sleeps: list[float] = field(default_factory=list)

    # --- identities ---------------------------------------------------------------------------
    def token(
        self,
        tenant_id: str | None,
        role: str | list[str] | None = "owner",
        *,
        sub: str | None = None,
        platform: bool = False,
        aud: str = AUDIENCE,
        iss: str = ISSUER,
        exp_in: int = 300,
        key: ec.EllipticCurvePrivateKey | None = None,
        kid: str = "test-key",
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": iss,
            "aud": [aud, "account"],
            "sub": sub or f"user-{role}-{tenant_id}",
            "iat": now,
            "exp": now + exp_in,
            "email": f"{role}@example.test",
            "name": f"{role}",
        }
        if tenant_id is not None:
            claims["tenant_id"] = tenant_id
        if role is not None:
            claims["role"] = role
        if platform:
            claims["platform_roles"] = ["platform_admin"]
        claims.update(extra or {})
        return jwt.encode(claims, key or OIDC_KEY, algorithm="ES256", headers={"kid": kid})

    def auth(
        self, tenant_id: str | None, role: str | list[str] | None = "owner", **kw: Any
    ) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(tenant_id, role, **kw)}"}

    def service(self, name: str, *, aud: str = "registry", lifetime: int = 300) -> dict[str, str]:
        now = int(time.time())
        token = jwt.encode(
            {"iss": name, "sub": name, "aud": aud, "iat": now, "exp": now + lifetime},
            SERVICE_KEYS[name],
            algorithm="ES256",
        )
        return {"Authorization": f"Bearer {token}"}

    # --- fixtures -----------------------------------------------------------------------------
    async def tenant(self, name: str = "acme", **settings: Any) -> str:
        tenant_id = new_tenant_id()
        async with self.repo.tenant(tenant_id) as tx:
            await tx.insert_tenant(
                TenantRecord(
                    id=tenant_id,
                    name=name,
                    settings={**DEFAULT_TENANT_SETTINGS, "allow_software_keys": True, **settings},
                    created_at=self.clock(),
                )
            )
        return tenant_id

    async def device(self, tenant_id: str, **body: Any) -> dict[str, Any]:
        payload = {
            "product": "gateway-rpi",
            "hw_revision": "rev-c",
            "se_type": "tpm2",
            "bootstrap_serial_hex": "0a1b2c3d4e5f",
            **body,
        }
        r = await self.client.post(
            "/v1/devices", json=payload, headers=self.auth(tenant_id, "admin")
        )
        assert r.status_code == 201, r.text
        return dict(r.json())

    async def enroll(
        self,
        tenant_id: str,
        device_id: str,
        *,
        assurance: str = "hardware",
        se_type: str = "tpm2",
        days: int = 14,
    ) -> DeviceKey:
        key = ec.generate_private_key(ec.SECP256R1())
        serial = int.from_bytes(os.urandom(16), "big") >> 1 | (1 << 120)
        nb = self.clock() - timedelta(minutes=5)
        na = self.clock() + timedelta(days=days)
        pem = make_cert(tenant_id, device_id, key, serial, nb, na)
        dk = DeviceKey(tenant_id, device_id, key, serial)
        self.pki.add(
            certificate_from_view(
                {
                    "serial": dk.serial_hex,
                    "device_id": device_id,
                    "tenant_id": tenant_id,
                    "issuer": "IronMesh Device CA",
                    "not_before": nb.isoformat(),
                    "not_after": na.isoformat(),
                    "status": "valid",
                    "certificate_pem": pem,
                }
            )
        )
        r = await self.client.post(
            f"/internal/v1/devices/{device_id}/enrolled",
            headers=self.service("pki"),
            json={
                "serial_hex": dk.serial_hex,
                "not_before": nb.isoformat(),
                "not_after": na.isoformat(),
                "se_type": se_type,
                "assurance_level": assurance,
                "fw_version": "2.4.1",
                "fw_hash_hex": "ab" * 32,
            },
        )
        assert r.status_code == 200, r.text
        return dk

    async def active_device(self, tenant_id: str, **body: Any) -> tuple[dict[str, Any], DeviceKey]:
        dev = await self.device(tenant_id, **body)
        return dev, await self.enroll(tenant_id, dev["id"])

    # --- device messages ----------------------------------------------------------------------
    def wire(
        self,
        dk: DeviceKey,
        body: envelope.Body,
        *,
        seq: int | None = None,
        ts: int | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        if seq is None:
            dk.seq += 1
            seq = dk.seq
        message = envelope.Message(
            seq=seq,
            ts=ts if ts is not None else int(self.clock().timestamp()),
            body=body,
            nonce=nonce,
        )
        return envelope.encode(message, dk.identity())

    async def deliver(
        self, tenant_id: str, device_id: str, cls: TopicClass, value: bytes, **headers: str
    ) -> str:
        msg = BusMessage(
            topic="im.ingest",
            key=f"{tenant_id}/{device_id}",
            value=value,
            headers={
                "mqtt_topic": ids.build_topic(tenant_id, device_id, cls),
                "tenant_id": tenant_id,
                "device_id": device_id,
                "msg_class": cls.value,
                "received_at": self.clock().isoformat(),
                **headers,
            },
        )
        return await self.ingest.on_ingest(msg)

    async def send(self, dk: DeviceKey, cls: TopicClass, body: envelope.Body, **kw: Any) -> str:
        return await self.deliver(dk.tenant_id, dk.device_id, cls, self.wire(dk, body, **kw))


def telemetry_body(**overrides: Any) -> envelope.Telemetry:
    values: dict[str, Any] = dict(
        cpu_pct=12.5,
        mem_pct=40.25,
        net_rx_bytes=1024,
        net_tx_bytes=512,
        temp_c=36.6,
        uptime_s=3600,
        auth_failures=0,
        fw_hash=bytes(32),
        fw_version="2.4.1",
        lat=52.52,
        lon=13.405,
    )
    values.update(overrides)
    return envelope.Telemetry(**values)


def build_env(kind: str, repo: Repository, tmp: Path) -> Env:
    settings = Settings(
        repo_backend="memory",
        bus_backend="memory",
        mqtt_backend="memory",
        kms_local_kek_file=str(tmp / "kek.bin"),
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        background_jobs_enabled=False,
        orchestration_backoff_seconds=0.01,
        internal_tokens={"policy": SecretStr(INTERNAL_TOKEN)},
        log_level="warning",
        service_jwt_trusted_keys={n: pem_public(k) for n, k in SERVICE_KEYS.items()},
    )
    metrics = Metrics()
    clock = FakeClock()
    sleeps: list[float] = []

    async def no_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    ctx = AppContext(
        settings=settings,
        repo=repo,
        bus=InMemoryEventBus(),
        mqtt=FakeMqttPublisher(),
        pki=FakePki(),
        ota=FakeOta(),
        emqx=FakeEmqx(),
        keyring=TenantKeyring(LocalKeyWrapper.from_file(str(tmp / "kek.bin"), create=True)),
        hub=Hub(metrics),
        tickets=TicketStore(60),
        metrics=metrics,
        oidc=OidcVerifier(
            OidcConfig(issuer=ISSUER, audience=AUDIENCE, algorithms=["ES256", "RS256"]),
            StaticJwks({"keys": [OIDC_JWK]}),
        ),
        service_jwt=ServiceJwtVerifier.from_pem("registry", settings.service_jwt_trusted_keys),
        clock=clock,
        sleep=no_sleep,
    )
    app = create_app(settings, ctx, ws_ping_interval=0.05)
    ingest = Ingest(ctx)
    ingest.register()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://registry")
    assert isinstance(ctx.bus, InMemoryEventBus)
    assert isinstance(ctx.mqtt, FakeMqttPublisher)
    assert isinstance(ctx.pki, FakePki)
    assert isinstance(ctx.ota, FakeOta)
    assert isinstance(ctx.emqx, FakeEmqx)
    return Env(
        kind,
        ctx,
        client,
        repo,
        ctx.bus,
        ctx.mqtt,
        ctx.pki,
        ctx.ota,
        ctx.emqx,
        clock,
        ingest,
        app,
        sleeps,
    )


# ------------------------------------------------------------------------------------------------
# PostgreSQL
# ------------------------------------------------------------------------------------------------


@dataclass
class PgUrls:
    owner: str
    app: str


def _asyncpg_url(url: str) -> str:
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


async def _migrate(owner_url: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
    cfg.attributes["url"] = owner_url
    await asyncio.to_thread(command.upgrade, cfg, "head")


@pytest.fixture(scope="session")
async def pg() -> AsyncIterator[PgUrls | None]:
    owner = os.environ.get("REGISTRY_TEST_DATABASE_URL")
    app_url = os.environ.get("REGISTRY_TEST_APP_DATABASE_URL")
    server = None
    if not owner:
        if os.environ.get("REGISTRY_TEST_NO_PGSERVER"):
            yield None
            return
        try:
            import pgserver
        except ImportError:
            yield None
            return
        try:
            data_dir = Path(tempfile.mkdtemp(prefix="registry-pg-"))
            get_server = pgserver.get_server  # type: ignore[attr-defined]
            server = await asyncio.to_thread(get_server, data_dir, cleanup_mode="stop")
        except Exception:
            yield None
            return
        import asyncpg

        base = server.get_uri()
        conn = await asyncpg.connect(base)
        await conn.execute("DROP DATABASE IF EXISTS registry_test")
        await conn.execute("CREATE DATABASE registry_test")
        await conn.close()
        owner = base.rsplit("/", 1)[0] + "/registry_test"
    host_part = owner.split("@", 1)[1]
    await _migrate(_asyncpg_url(owner))
    import asyncpg

    conn = await asyncpg.connect(owner)
    await conn.execute("ALTER ROLE registry_app WITH LOGIN PASSWORD 'registry-app-test'")
    await conn.close()
    urls = PgUrls(
        owner=owner, app=app_url or f"postgresql://registry_app:registry-app-test@{host_part}"
    )
    yield urls
    if server is not None:
        await asyncio.to_thread(server.cleanup)


@pytest.fixture(scope="session")
async def pg_repo(pg: PgUrls | None) -> AsyncIterator[Repository | None]:
    if pg is None:
        yield None
        return
    from app.repo.sql import SqlRepository

    repo = SqlRepository(_asyncpg_url(pg.app), pool_size=5, max_overflow=5)
    yield repo
    await repo.close()


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
async def env(
    request: pytest.FixtureRequest, pg_repo: Repository | None, tmp_path: Path
) -> AsyncIterator[Env]:
    if request.param == "postgres":
        if pg_repo is None:
            pytest.skip("PostgreSQL not available")
        repo: Repository = pg_repo
    else:
        repo = MemoryRepository()
    e = build_env(request.param, repo, tmp_path)
    yield e
    await e.client.aclose()


@pytest.fixture
async def mem(tmp_path: Path) -> AsyncIterator[Env]:
    """Memory-only environment (vectors with fixed ids, WebSocket, tamper tests)."""
    e = build_env("memory", MemoryRepository(), tmp_path)
    yield e
    await e.client.aclose()
