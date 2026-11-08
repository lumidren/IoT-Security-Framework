"""App factory, lifespan, health/metrics/OpenAPI, problem details, background jobs, seed."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.auth import SYSTEM
from app.main import (
    _bus,
    _loop,
    _repo,
    build_context,
    create_app,
    db_connect_args,
    maintain_once,
    sweep_once,
)
from app.observability import configure_logging
from app.problems import ProblemError
from app.repo.memory import MemoryRepository
from app.seed import main as seed_main
from app.seed import seed, tenant_uuid
from app.services import admin
from app.settings import Settings, get_settings

from .conftest import Env


def mem_settings(tmp_path: Path, **kw: Any) -> Settings:
    return Settings(
        repo_backend="memory",
        bus_backend="memory",
        mqtt_backend="memory",
        kms_local_kek_file=str(tmp_path / "kek.bin"),
        **kw,
    )


async def test_health_metrics_openapi(env: Env) -> None:
    r = await env.client.get("/healthz")
    assert r.json() == {"status": "ok", "checks": {}}
    r = await env.client.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"]["database"] is True
    r = await env.client.get("/metrics")
    text = r.text
    for name in (
        "ironmesh_replay_rejected_total",
        "ironmesh_connected_devices",
        "ironmesh_auth_failures_total",
        "ironmesh_http_requests_total",
        "ironmesh_devices_total",
    ):
        assert name in text
    assert 'route="/readyz"' in text and 'code="200"' in text
    spec = (await env.client.get("/openapi.json")).json()
    schemas = set(spec["components"]["schemas"])
    for model in (
        "Tenant",
        "DeviceSummary",
        "DeviceDetail",
        "TimelineEvent",
        "Group",
        "Twin",
        "Command",
        "CommandBatch",
        "DeviceConfig",
        "ProvisioningItem",
        "FleetSummary",
        "FleetHealth",
        "AuditEvent",
        "User",
        "ApiKey",
        "CreatedApiKey",
        "WsTicket",
        "Lifecycle",
        "PkiDevice",
        "ProblemDetails",
    ):
        assert model in schemas, model
    assert "/internal/v1/tenants/{tenant_id}/devices/{device_id}" in spec["paths"]
    assert spec["paths"]["/v1/devices"]["get"]["responses"]["422"]["content"][
        "application/problem+json"
    ]
    r = await env.client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    r = await env.client.get("/healthz", headers={"X-Request-ID": "bad id with spaces"})
    assert r.headers["x-request-id"] != "bad id with spaces"


async def test_readyz_unavailable_and_unhandled_errors(
    mem: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down() -> bool:
        return False

    monkeypatch.setattr(mem.repo, "ping", down)
    r = await mem.client.get("/readyz")
    assert r.status_code == 503 and r.json()["status"] == "unavailable"

    app: FastAPI = mem.app

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("kaput")

    @app.get("/teapot")
    async def teapot() -> None:
        raise ProblemError(418, "short and stout", headers={"X-Teapot": "1"})

    transport = httpx.ASGITransport(app=mem.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://r") as client:
        r = await client.get("/boom")
        assert r.status_code == 500 and r.json()["detail"] == "internal error"
        r = await client.get("/teapot")
        assert r.status_code == 418 and r.headers["x-teapot"] == "1"
        r = await client.get("/nope")
        assert r.status_code == 404 and r.headers["content-type"] == "application/problem+json"


async def test_factory_lifespan_and_jobs(tmp_path: Path) -> None:
    settings = mem_settings(
        tmp_path,
        sweeper_interval_seconds=0.01,
        maintenance_interval_seconds=0.01,
        log_format="console",
    )
    app = create_app(settings)
    ctx = app.state.ctx
    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.05)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://r") as client:
            assert (await client.get("/healthz")).status_code == 200
    assert ctx.metrics.registry.get_sample_value("ironmesh_devices_total", {"state": "active"}) == 0
    configure_logging("verbose")

    calls: list[int] = []

    async def flaky() -> None:
        calls.append(1)
        raise RuntimeError("x")

    task = asyncio.create_task(_loop("flaky", 0.001, flaky))
    await asyncio.sleep(0.02)
    task.cancel()
    assert len(calls) >= 2


async def test_build_context_variants(tmp_path: Path) -> None:
    ctx, clients = build_context(mem_settings(tmp_path))
    assert isinstance(ctx.repo, MemoryRepository)
    for c in clients:
        await c.aclose()
    from app.repo.sql import SqlRepository

    pg = Settings(database_url="postgresql+asyncpg://u:p@127.0.0.1:1/x", db_sslmode="require")
    repo = _repo(pg)
    assert isinstance(repo, SqlRepository)
    await repo.close()
    assert db_connect_args(pg)["ssl"] == "require"
    bus = _bus(Settings(kafka_brokers="k:9092"))
    assert type(bus).__name__ == "KafkaEventBus"


async def test_jobs_once(env: Env) -> None:
    t = await env.tenant()
    await env.active_device(t)
    await sweep_once(env.ctx)
    await maintain_once(env.ctx)
    totals = await admin.refresh_device_gauge(env.ctx, SYSTEM)
    assert totals["active"] >= 1


async def test_seed(env: Env) -> None:
    name = f"demo-{env.kind}-{tenant_uuid(str(id(env)))[:8]}"
    result = await seed(env.repo, name, 40, owner_sub="owner-1", owner_email="o@example.test")
    assert result["devices_created"] == 40
    again = await seed(env.repo, name, 40)
    assert again["devices_created"] == 0
    tenant_id = str(result["tenant_id"])
    r = await env.client.get("/v1/fleet/summary", headers=env.auth(tenant_id, "viewer"))
    summary = r.json()
    assert summary["devices_total"] == 40 and summary["map"]
    r = await env.client.get("/v1/audit/verify", headers=env.auth(tenant_id, "admin"))
    assert r.json()["ok"] is True
    assert tenant_uuid(tenant_id) == tenant_id


def test_seed_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("REGISTRY_REPO_BACKEND", "memory")
    get_settings.cache_clear()
    try:
        seed_main(["--tenant", "cli", "--devices", "3"])
    finally:
        get_settings.cache_clear()
    assert "3 devices created" in capsys.readouterr().out
