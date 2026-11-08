"""Test support: fakes, a fleet simulator producing real signed envelopes, engine factory."""

from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from ironmesh_anomaly.app import assemble_engine
from ironmesh_anomaly.bus import BusRecord, InMemoryEventBus
from ironmesh_anomaly.clients import (
    CertKey,
    QuarantineResult,
    StaticCertKeyProvider,
    StaticDeviceDirectory,
    StaticKnownHashesProvider,
)
from ironmesh_anomaly.config import Settings
from ironmesh_anomaly.engine import Engine
from ironmesh_anomaly.geo import GeoIPProvider
from ironmesh_anomaly.ingest import IngestDecoder
from ironmesh_anomaly.ml import LocalModelStore
from ironmesh_anomaly.models import DeviceInfo, TelemetryEvent
from ironmesh_anomaly.repository import InMemoryRepository
from ironmesh_anomaly.siem import SiemDispatcher
from ironmesh_wire import envelope, ids
from ironmesh_wire.constants import OtaState

TENANT = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
OTHER_TENANT = "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
T0 = 1_760_000_000.0
GATEWAY = "gateway-rpi"
SENSOR = "sensor-esp32"


def device_id(n: int) -> str:
    return f"dev-{n:016x}"


def sha_hex(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KNOWN = {GATEWAY: {sha_hex("gw-2.4.1"), sha_hex("gw-2.4.0")}, SENSOR: {sha_hex("esp-1.3.0")}}
FW = {GATEWAY: (sha_hex("gw-2.4.1"), "2.4.1"), SENSOR: (sha_hex("esp-1.3.0"), "1.3.0")}


class FakeQuarantineClient:
    def __init__(self, ok: bool = True) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.ok = ok

    async def quarantine(self, device_id: str, reason: str, alert_id: str) -> QuarantineResult:
        self.calls.append((device_id, reason, alert_id))
        if self.ok:
            return QuarantineResult(True, 200, "quarantined")
        return QuarantineResult(False, 503, "registry unavailable")


@dataclass
class SimDevice:
    device_id: str
    product: str
    tenant_id: str = TENANT
    serial: int = 0
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    seq: int = 0
    rx: int = 0
    tx: int = 0
    auth_failures: int = 0
    uptime: int = 1000
    base: dict[str, float] = field(default_factory=dict)
    fw_hash: str = ""
    fw_version: str = ""
    lat: float | None = None
    lon: float | None = None

    @property
    def identity(self) -> envelope.SigningIdentity:
        return envelope.SigningIdentity.device(self.key, self.serial)

    @property
    def serial_hex(self) -> str:
        return format(self.serial, "032x")

    def cert_key(self, status: str = "valid") -> CertKey:
        return CertKey(
            self.serial_hex, self.device_id, self.tenant_id, self.key.public_key(), status
        )

    def info(self) -> DeviceInfo:
        return DeviceInfo(self.device_id, self.tenant_id, self.product)

    def topic(self, suffix: ids.TopicClass = ids.TopicClass.TELEMETRY) -> str:
        return ids.build_topic(self.tenant_id, self.device_id, suffix)


class Fleet:
    """Generates statistically stationary telemetry with real COSE envelopes."""

    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)
        self.devices: dict[str, SimDevice] = {}

    def add(
        self, n: int, product: str, *, tenant_id: str = TENANT, mobile: bool = False
    ) -> SimDevice:
        r = self.rng
        dev = SimDevice(device_id(n), product, tenant_id=tenant_id, serial=0x1000 + n)
        dev.base = {
            "cpu": r.uniform(10, 40),
            "mem": r.uniform(30, 60),
            "temp": r.uniform(38, 52),
            "rx": r.uniform(1500, 4000),
            "tx": r.uniform(800, 2500),
            "proc": float(r.randint(80, 160)),
            "rssi": float(r.randint(-75, -50)),
            "heap": r.uniform(120_000, 180_000),
        }
        dev.fw_hash, dev.fw_version = FW[product]
        if mobile:
            dev.lat, dev.lon = r.uniform(45, 50), r.uniform(5, 10)
        self.devices[dev.device_id] = dev
        return dev

    def telemetry(
        self,
        dev: SimDevice,
        ts: float,
        dt: float = 60.0,
        *,
        tx_factor: float = 1.0,
        overrides: dict[str, Any] | None = None,
    ) -> envelope.Message:
        r = self.rng
        b = dev.base
        dev.seq += 1
        dev.uptime += int(dt)
        dev.rx += max(0, int(r.gauss(b["rx"], b["rx"] * 0.05) * dt))
        dev.tx += max(0, int(r.gauss(b["tx"], b["tx"] * 0.05) * dt * tx_factor))
        o = overrides or {}
        if dev.lat is not None and dev.lon is not None:
            dev.lat += 0.01  # ~1.1 km per minute (~67 km/h)
        is_linux = dev.product == GATEWAY
        body = envelope.Telemetry(
            cpu_pct=float(o.get("cpu", min(100.0, max(0.0, r.gauss(b["cpu"], 3.0))))),
            mem_pct=float(o.get("mem", r.gauss(b["mem"], 1.5))),
            net_rx_bytes=dev.rx,
            net_tx_bytes=dev.tx,
            temp_c=float(o.get("temp", r.gauss(b["temp"], 0.7))),
            uptime_s=dev.uptime,
            auth_failures=dev.auth_failures,
            fw_hash=bytes.fromhex(o.get("fw_hash", dev.fw_hash)),
            fw_version=dev.fw_version,
            proc_count=int(o.get("proc", b["proc"] + r.randint(-2, 2))) if is_linux else None,
            rssi=None if is_linux else int(b["rssi"] + r.randint(-2, 2)),
            free_heap=None if is_linux else int(r.gauss(b["heap"], 800)),
            lat=dev.lat,
            lon=dev.lon,
        )
        return envelope.Message(seq=dev.seq, ts=int(ts), body=body)

    @staticmethod
    def sign(dev: SimDevice, message: envelope.Message) -> bytes:
        return envelope.encode(message, dev.identity)


def ingest_record(
    bus: InMemoryEventBus,
    dev: SimDevice,
    raw: bytes,
    ts: float,
    topic_class: ids.TopicClass = ids.TopicClass.TELEMETRY,
    **header_overrides: str,
) -> BusRecord:
    headers = {
        "mqtt_topic": dev.topic(topic_class),
        "tenant_id": dev.tenant_id,
        "device_id": dev.device_id,
        "msg_class": topic_class.value,
        "received_at": str(ts + 1),
    }
    headers.update(header_overrides)
    return bus.produce(
        "im.ingest",
        raw,
        key=f"{dev.tenant_id}/{dev.device_id}".encode(),
        headers={k: v.encode() for k, v in headers.items()},
        timestamp_ms=int((ts + 1) * 1000),
    )


def auth_record(
    bus: InMemoryEventBus,
    clientid: str,
    event: str,
    ts: float,
    peerhost: str = "198.51.100.7",
    **extra: Any,
) -> BusRecord:
    payload = {"event": event, "clientid": clientid, "peerhost": peerhost, "reason": "x", "at": ts}
    payload.update(extra)
    return bus.produce(
        "im.auth", json.dumps(payload).encode(), key=clientid.encode(), timestamp_ms=int(ts * 1000)
    )


def ota_success(dev: SimDevice, ts: float, fw_hash: str) -> envelope.Message:
    dev.seq += 1
    return envelope.Message(
        seq=dev.seq,
        ts=int(ts),
        body=envelope.OtaStatus(
            campaign_id=str(uuid.uuid4()),
            state=int(OtaState.SUCCESS),
            progress_pct=100,
            fw_hash=bytes.fromhex(fw_hash),
        ),
    )


@dataclass
class Harness:
    engine: Engine
    bus: InMemoryEventBus
    repo: InMemoryRepository
    certs: StaticCertKeyProvider
    directory: StaticDeviceDirectory
    hashes: StaticKnownHashesProvider
    quarantine: FakeQuarantineClient
    clock: list[float]

    def register(self, dev: SimDevice) -> None:
        self.certs.keys[dev.serial_hex] = dev.cert_key()
        self.directory.devices[dev.device_id] = dev.info()

    async def drain(self, batch: int = 500) -> int:
        total = 0
        while True:
            n = await self.engine.run_batch(batch, 0)
            if n == 0:
                return total
            total += n


def make_harness(
    tmp_path: Any,
    *,
    settings: Settings | None = None,
    geoip: GeoIPProvider | None = None,
    siem: SiemDispatcher | None = None,
    quarantine: FakeQuarantineClient | None = None,
) -> Harness:
    settings = settings or Settings(run_pipeline=False, model_dir=str(tmp_path / "models"))
    bus = InMemoryEventBus(["im.ingest", "im.auth", "im.audit"])
    repo = InMemoryRepository()
    certs = StaticCertKeyProvider()
    directory = StaticDeviceDirectory()
    hashes = StaticKnownHashesProvider({k: set(v) for k, v in KNOWN.items()})
    qc = quarantine or FakeQuarantineClient()
    clock = [time.time()]
    engine = assemble_engine(
        settings,
        repo=repo,
        bus=bus,
        decoder=IngestDecoder(certs, directory, settings.max_clock_skew_s),
        directory=directory,
        known_hashes=hashes,
        quarantine_client=qc,
        model_store=LocalModelStore(tmp_path / "models"),
        siem=siem,
        clock=lambda: clock[0],
        geoip=geoip,
    )
    return Harness(engine, bus, repo, certs, directory, hashes, qc, clock)


def telemetry_event(
    device: str = "dev-0000000000000001",
    ts: float = T0,
    *,
    tenant: str = TENANT,
    seq: int = 1,
    tx: int = 0,
    rx: int = 0,
    auth_failures: int = 0,
    fw_hash: str | None = None,
    lat: float | None = None,
    lon: float | None = None,
    uptime: int = 1000,
    cpu: float = 20.0,
    proc_count: int | None = 100,
) -> TelemetryEvent:
    return TelemetryEvent(
        tenant_id=tenant,
        device_id=device,
        ts=ts,
        seq=seq,
        cpu_pct=cpu,
        mem_pct=40.0,
        net_rx_bytes=rx,
        net_tx_bytes=tx,
        temp_c=45.0,
        uptime_s=uptime,
        auth_failures=auth_failures,
        fw_hash_hex=fw_hash or FW[GATEWAY][0],
        fw_version="2.4.1",
        proc_count=proc_count,
        lat=lat,
        lon=lon,
    )
