"""Registry lifecycle lookups (API_CONTRACT §1.12, callers policy + anomaly): the anomaly token
authenticates the call and the returned ``product`` selects the per-class models."""

from __future__ import annotations

import time
from pathlib import Path

import httpx
from pydantic import SecretStr

from ironmesh_anomaly.app import assemble_engine, service_signer
from ironmesh_anomaly.bus import InMemoryEventBus
from ironmesh_anomaly.clients import HttpDeviceDirectory, StaticCertKeyProvider
from ironmesh_anomaly.clients import StaticKnownHashesProvider as Hashes
from ironmesh_anomaly.config import Settings
from ironmesh_anomaly.ingest import IngestDecoder
from ironmesh_anomaly.ml import LocalModelStore
from ironmesh_anomaly.models import RuleName, RuleOverride
from ironmesh_anomaly.repository import InMemoryRepository
from tests.support import (
    GATEWAY,
    KNOWN,
    SENSOR,
    T0,
    TENANT,
    FakeQuarantineClient,
    Fleet,
    ingest_record,
)

ANOMALY_TOKEN = "anomaly-internal-token-0123456789"
REGISTRY = "https://ironmesh-registry:8000"


def test_registry_calls_use_the_anomaly_token(tmp_path: Path) -> None:
    signer = service_signer(Settings(run_pipeline=False, internal_token=SecretStr(ANOMALY_TOKEN)))
    assert signer.headers("registry") == {"Authorization": f"Bearer {ANOMALY_TOKEN}"}
    assert service_signer(Settings(run_pipeline=False)).headers("registry") == {}


async def test_lifecycle_product_drives_per_class_models(tmp_path: Path) -> None:
    fleet = Fleet(seed=11)
    devices = [fleet.add(n, GATEWAY if n % 2 else SENSOR) for n in range(1, 9)]
    by_id = {d.device_id: d for d in devices}
    calls: list[httpx.Request] = []

    def registry(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        device_id = request.url.path.split("/")[4]
        assert request.url.path == f"/internal/v1/devices/{device_id}/lifecycle"
        assert request.headers["authorization"] == f"Bearer {ANOMALY_TOKEN}"
        dev = by_id[device_id]
        return httpx.Response(
            200,
            json={
                "device_id": device_id,
                "tenant_id": TENANT,
                "state": "active",
                "assurance_level": "hardware",
                "product": dev.product,
            },
        )

    settings = Settings(
        run_pipeline=False,
        model_dir=str(tmp_path / "models"),
        internal_token=SecretStr(ANOMALY_TOKEN),
    )
    certs = StaticCertKeyProvider({d.serial_hex: d.cert_key() for d in devices})
    bus = InMemoryEventBus(["im.ingest", "im.auth", "im.audit"])
    repo = InMemoryRepository()
    async with httpx.AsyncClient(transport=httpx.MockTransport(registry)) as http:
        directory = HttpDeviceDirectory(http, REGISTRY, service_signer(settings))
        engine = assemble_engine(
            settings,
            repo=repo,
            bus=bus,
            decoder=IngestDecoder(certs, directory, settings.max_clock_skew_s),
            directory=directory,
            known_hashes=Hashes({k: set(v) for k, v in KNOWN.items()}),
            quarantine_client=FakeQuarantineClient(),
            model_store=LocalModelStore(tmp_path / "models"),
            siem=None,
            clock=time.time,
        )
        await repo.put_rule_override(
            TENANT,
            RuleName.ISOLATION_FOREST,
            RuleOverride(params={"min_train_samples": 40, "min_train_devices": 3}),
        )
        engine.invalidate(TENANT)
        for i in range(25):
            ts = T0 + i * 60.0
            for dev in devices:
                msg = fleet.telemetry(dev, ts, 60.0)
                ingest_record(bus, dev, fleet.sign(dev, msg), ts)
            while await engine.run_batch(500, 0):
                pass

        # one lookup per device (cached afterwards), each answered with the device's product
        assert len(calls) == len(devices)
        for dev in devices:
            state = engine.state.get(TENANT, dev.device_id)
            assert state is not None and state.device_class == dev.product
        assert await engine.train(now=T0 + 25 * 60.0) == 2
        gateway = engine.models.get(TENANT, GATEWAY)
        sensor = engine.models.get(TENANT, SENSOR)
        assert gateway is not None and sensor is not None and gateway is not sensor
        assert gateway.device_class == GATEWAY and sensor.device_class == SENSOR
        assert engine.models.get(TENANT, "unknown") is None
