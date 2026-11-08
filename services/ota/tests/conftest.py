"""Shared fixtures: an OTA app wired to in-memory fakes, signed test tokens and helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi import FastAPI
from pydantic import SecretStr

from ironmesh_ota.app import create_app
from ironmesh_ota.auth import StaticKeyTokenVerifier
from ironmesh_ota.bundle import ServiceBundle
from ironmesh_ota.container import Container
from ironmesh_ota.domain import TargetDevice
from ironmesh_ota.integrations.device_keys import StaticDeviceKeyResolver
from ironmesh_ota.integrations.events import RecordingEventPublisher
from ironmesh_ota.integrations.leader import FakeLeaderLock, FakeLockServer
from ironmesh_ota.integrations.mqtt import RecordingPublisher
from ironmesh_ota.integrations.registry import FakeRegistry
from ironmesh_ota.integrations.tenant_keys import StaticTenantKeyProvider
from ironmesh_ota.observability import Metrics
from ironmesh_ota.repository.base import Database
from ironmesh_ota.repository.memory import MemoryDatabase
from ironmesh_ota.settings import DatabaseBackend, Settings
from ironmesh_ota.signing import KeyringSigner
from ironmesh_ota.storage import DownloadSigner, LocalArtifactStore
from ironmesh_wire import envelope, ids, mldsa
from ironmesh_wire.ids import TopicClass

INTERNAL_TOKEN = "test-internal-token-0123456789abcdef"
HMAC_SECRET = b"h" * 32


def new_tenant() -> uuid.UUID:
    return uuid.uuid4()


def device_id(n: int) -> str:
    return f"dev-{n:016x}"


@dataclass
class Clock:
    now: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class Keys:
    user_key: ec.EllipticCurvePrivateKey
    signer: KeyringSigner
    tenant_keys: dict[uuid.UUID, ed25519.Ed25519PrivateKey] = field(default_factory=dict)

    def tenant_key(self, tenant: uuid.UUID) -> ed25519.Ed25519PrivateKey:
        if tenant not in self.tenant_keys:
            self.tenant_keys[tenant] = ed25519.Ed25519PrivateKey.generate()
        return self.tenant_keys[tenant]


@pytest.fixture(scope="session")
def session_signer() -> KeyringSigner:
    now = datetime.now(UTC)
    return KeyringSigner(
        [(ed25519.Ed25519PrivateKey.generate(), now, True)],
        (mldsa.CryptographyMlDsa65Signer.generate(), now),
    )


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def keys(session_signer: KeyringSigner) -> Keys:
    return Keys(ec.generate_private_key(ec.SECP256R1()), session_signer)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "database_backend": DatabaseBackend.MEMORY,
        "artifact_path": tmp_path / "artifacts",
        "internal_token": SecretStr(INTERNAL_TOKEN),
        "controller_enabled": False,
        "halt_min_sample": 2,
        "device_timeout_s": 3600,
        "download_hmac_secret": SecretStr(HMAC_SECRET.decode()),
    }
    base.update(overrides)
    return Settings(**base)


@dataclass
class Env:
    """Everything a test needs to drive the service end to end."""

    app: FastAPI
    container: Container
    services: ServiceBundle
    client: httpx.AsyncClient
    keys: Keys
    clock: Clock
    registry: FakeRegistry
    publisher: RecordingPublisher
    events: RecordingEventPublisher
    tenant_keys: StaticTenantKeyProvider
    tmp_path: Path

    # --- auth -----------------------------------------------------------------------------
    def token(
        self,
        tenant: uuid.UUID | None,
        role: str = "admin",
        sub: str = "alice",
        **extra: Any,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "aud": ["ironmesh-api"],
            "iat": now,
            "exp": now + 600,
            "role": role,
            "name": sub.title(),
            **extra,
        }
        if tenant is not None:
            claims["tenant_id"] = str(tenant)
        return jwt.encode(claims, self.keys.user_key, algorithm="ES256")

    def auth(self, tenant: uuid.UUID, role: str = "admin", sub: str = "alice") -> dict[str, str]:
        if tenant not in self.tenant_keys.keys:
            self.tenant_keys.keys[tenant] = self.keys.tenant_key(tenant)
        return {"Authorization": f"Bearer {self.token(tenant, role, sub)}"}

    @property
    def internal(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {INTERNAL_TOKEN}", "X-IronMesh-Service": "registry"}

    # --- firmware -------------------------------------------------------------------------
    async def upload(
        self,
        tenant: uuid.UUID,
        image: bytes,
        *,
        product: str = "gateway-rpi",
        version: str = "1.0.0",
        version_code: int = 100,
        severity: str = "normal",
        role: str = "admin",
        expect: int = 201,
    ) -> dict[str, Any]:
        meta = {
            "product": product,
            "version": version,
            "version_code": version_code,
            "severity": severity,
            "notes": f"build {version}",
        }
        resp = await self.client.post(
            "/v1/firmware",
            headers=self.auth(tenant, role),
            files={"image": ("image.bin", image, "application/octet-stream")},
            data={"metadata": json.dumps(meta)},
        )
        assert resp.status_code == expect, resp.text
        body: dict[str, Any] = resp.json()
        return body

    # --- devices --------------------------------------------------------------------------
    def add_devices(
        self,
        tenant: uuid.UUID,
        count: int,
        *,
        fw: bytes | None = None,
        product: str = "gateway-rpi",
        group: str = "fleet",
        start: int = 1,
        state: str = "active",
    ) -> list[str]:
        ids_ = [device_id(start + i) for i in range(count)]
        self.registry.add(
            tenant,
            *[
                TargetDevice(
                    id=d,
                    product=product,
                    state=state,
                    fw_hash=hashlib.sha256(fw).digest() if fw is not None else None,
                    groups=(group,),
                    tags={"site": "lab"},
                )
                for d in ids_
            ],
        )
        return ids_

    def set_device_fw(self, tenant: uuid.UUID, device: str, fw: bytes) -> None:
        dev = self.registry.devices[tenant][device]
        self.registry.devices[tenant][device] = TargetDevice(
            id=dev.id,
            product=dev.product,
            state=dev.state,
            fw_hash=hashlib.sha256(fw).digest(),
            groups=dev.groups,
            tags=dev.tags,
        )

    # --- campaigns ------------------------------------------------------------------------
    async def create_campaign(
        self,
        tenant: uuid.UUID,
        firmware_id: str,
        *,
        stages: list[dict[str, Any]] | None = None,
        delta: bool = False,
        severity: str | None = None,
        target: dict[str, Any] | None = None,
        sub: str = "alice",
        expect: int = 201,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "name": "rollout",
            "firmware_id": firmware_id,
            "target": target or {"groups": ["fleet"], "device_ids": [], "tags": {}},
            "delta": delta,
        }
        if stages is not None:
            body["stages"] = stages
        if severity is not None:
            body["severity"] = severity
        resp = await self.client.post(
            "/v1/campaigns", json=body, headers=self.auth(tenant, "operator", sub)
        )
        assert resp.status_code == expect, resp.text
        out: dict[str, Any] = resp.json()
        return out

    async def action(
        self,
        tenant: uuid.UUID,
        campaign_id: str,
        action: str,
        *,
        body: dict[str, Any] | None = None,
        role: str = "admin",
        sub: str = "alice",
        expect: int = 200,
    ) -> dict[str, Any]:
        resp = await self.client.post(
            f"/v1/campaigns/{campaign_id}/{action}",
            json=body,
            headers=self.auth(tenant, role, sub),
        )
        assert resp.status_code == expect, resp.text
        out: dict[str, Any] = resp.json()
        return out

    async def campaign(self, tenant: uuid.UUID, campaign_id: str) -> dict[str, Any]:
        resp = await self.client.get(f"/v1/campaigns/{campaign_id}", headers=self.auth(tenant))
        assert resp.status_code == 200, resp.text
        out: dict[str, Any] = resp.json()
        return out

    async def devices(
        self, tenant: uuid.UUID, campaign_id: str, state: str | None = None
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 200}
            if state:
                params["state"] = state
            if cursor:
                params["cursor"] = cursor
            resp = await self.client.get(
                f"/v1/campaigns/{campaign_id}/devices", params=params, headers=self.auth(tenant)
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            items.extend(body["items"])
            cursor = body["next_cursor"]
            if not cursor:
                return items

    async def status(
        self,
        tenant: uuid.UUID,
        campaign_id: str,
        device: str,
        state: int,
        *,
        error: str | None = None,
        fw_hash: bytes | None = None,
        progress: int = 0,
        expect: int = 200,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "tenant_id": str(tenant),
            "device_id": device,
            "campaign_id": campaign_id,
            "state": state,
            "progress_pct": progress,
        }
        if error is not None:
            body["error"] = error
        if fw_hash is not None:
            body["fw_hash_hex"] = fw_hash.hex()
        resp = await self.client.post("/internal/v1/ota/status", json=body, headers=self.internal)
        assert resp.status_code == expect, resp.text
        out: dict[str, Any] = resp.json()
        return out

    async def tick(self) -> int:
        return await self.services.controller.tick()

    def notifies(self, tenant: uuid.UUID, device: str) -> list[envelope.Message]:
        """Decode every non-empty OtaNotify published to ``device`` with the tenant key."""
        topic = ids.build_topic(str(tenant), device, TopicClass.OTA_NOTIFY)
        key = self.keys.tenant_key(tenant).public_key()
        return [
            envelope.decode(
                msg.payload,
                envelope.StaticKeyResolver({ids.tenant_kid(str(tenant)): key}),
                envelope.InMemoryReplayStore(),
                now=int(self.clock.now.timestamp()),
                expected_tenant=str(tenant),
            )
            for msg in self.publisher.messages
            if msg.topic == topic and msg.payload
        ]


def build_container(
    tmp_path: Path,
    keys: Keys,
    clock: Clock,
    *,
    db: Database | None = None,
    **settings_overrides: Any,
) -> tuple[
    Container, FakeRegistry, RecordingPublisher, RecordingEventPublisher, StaticTenantKeyProvider
]:
    settings = make_settings(tmp_path, **settings_overrides)
    registry = FakeRegistry()
    publisher = RecordingPublisher()
    events = RecordingEventPublisher()
    tenant_keys = StaticTenantKeyProvider(keys.tenant_keys)
    tenant_keys.keys = keys.tenant_keys  # share the dict so new tenants appear
    container = Container(
        settings=settings,
        db=db or MemoryDatabase(),
        store=LocalArtifactStore(
            settings.artifact_path, "http://ota.test", DownloadSigner(HMAC_SECRET)
        ),
        signer=keys.signer,
        registry=registry,
        publisher=publisher,
        events=events,
        tenant_keys=tenant_keys,
        device_keys=StaticDeviceKeyResolver(),
        metrics=Metrics(),
        user_verifier=StaticKeyTokenVerifier(
            [keys.user_key.public_key()], audience="ironmesh-api", algorithms=("ES256",)
        ),
        service_verifier=None,
        leader=FakeLeaderLock(FakeLockServer(), "replica-1"),
        clock=clock,
    )
    return container, registry, publisher, events, tenant_keys


async def make_env(
    tmp_path: Path, keys: Keys, clock: Clock, *, db: Database | None = None, **overrides: Any
) -> AsyncIterator[Env]:
    container, registry, publisher, events, tenant_keys = build_container(
        tmp_path, keys, clock, db=db, **overrides
    )
    app = create_app(container, run_controller=False, run_consumer=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ota.test") as client:
        yield Env(
            app=app,
            container=container,
            services=app.state.services,
            client=client,
            keys=keys,
            clock=clock,
            registry=registry,
            publisher=publisher,
            events=events,
            tenant_keys=tenant_keys,
            tmp_path=tmp_path,
        )


@pytest.fixture
async def env(tmp_path: Path, keys: Keys, clock: Clock) -> AsyncIterator[Env]:
    async for e in make_env(tmp_path, keys, clock):
        yield e


@pytest.fixture
def env_factory(tmp_path: Path, keys: Keys, clock: Clock) -> Callable[..., AsyncIterator[Env]]:
    def factory(**overrides: Any) -> AsyncIterator[Env]:
        return make_env(tmp_path, keys, clock, **overrides)

    return factory


def image_bytes(seed: int, blocks: int = 6, tail: int = 123) -> bytes:
    """Deterministic pseudo-random firmware image of ``blocks`` 4 KiB blocks plus a tail."""
    out = bytearray()
    counter = 0
    while len(out) < blocks * 4096 + tail:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[: blocks * 4096 + tail])


def patched(image: bytes, block: int) -> bytes:
    """``image`` with one 4 KiB block changed - a realistic small delta."""
    out = bytearray(image)
    start = block * 4096
    out[start : start + 4096] = hashlib.sha256(b"patch").digest() * 128
    return bytes(out)


def pg_available() -> bool:
    return bool(os.environ.get("OTA_TEST_DATABASE_URL")) or _pgserver_importable()


def _pgserver_importable() -> bool:
    return importlib.util.find_spec("pgserver") is not None
