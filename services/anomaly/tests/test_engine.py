"""Engine: batch/commit semantics, transient failures, snapshots, training, audits, misc."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from prometheus_client import REGISTRY

from ironmesh_anomaly.bus import BusRecord
from ironmesh_anomaly.config import Settings
from ironmesh_anomaly.ingest import TransientError
from ironmesh_anomaly.models import (
    Alert,
    AlertState,
    DeviceInfo,
    RuleName,
    RuleOverride,
    Severity,
    SiemSettings,
    TenantSettings,
    from_ts,
    utcnow,
)
from ironmesh_anomaly.siem import Delivery, SiemDispatcher
from tests.support import (
    GATEWAY,
    T0,
    TENANT,
    Fleet,
    SimDevice,
    auth_record,
    ingest_record,
    make_harness,
    sha_hex,
    telemetry_event,
)


def metric(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


async def test_offsets_committed_only_after_processing(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    fleet = Fleet()
    dev = fleet.add(1, GATEWAY)
    h.register(dev)
    for i in range(5):
        ingest_record(h.bus, dev, fleet.sign(dev, fleet.telemetry(dev, T0 + i * 60)), T0 + i * 60)
    assert await h.engine.run_batch(3, 0) == 3
    assert h.bus.committed["im.ingest"] == 3
    assert await h.drain() == 2
    assert h.bus.committed["im.ingest"] == 5
    assert len(h.repo.events) == 5  # stored for dry-runs
    assert await h.engine.run_batch(10, 0) == 0


async def test_transient_failure_rewinds_and_redelivers(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    h.engine.config.transient_retries = 2
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    h.engine._sleep = fake_sleep
    fleet = Fleet()
    dev = fleet.add(1, GATEWAY)
    h.register(dev)
    for i in range(4):
        ingest_record(h.bus, dev, fleet.sign(dev, fleet.telemetry(dev, T0 + i * 60)), T0 + i * 60)
    calls = {"n": 0}
    real = h.certs.get

    async def flaky(serial: str) -> Any:
        calls["n"] += 1
        if 3 <= calls["n"] <= 5:
            raise __import__(
                "ironmesh_anomaly.clients", fromlist=["KeyLookupError"]
            ).KeyLookupError("down")
        return await real(serial)

    h.certs.get = flaky  # type: ignore[method-assign,assignment]
    with pytest.raises(TransientError):
        await h.engine.run_batch(10, 0)
    assert h.bus.committed["im.ingest"] == 2  # processed prefix only
    assert sleeps == [0.5]
    assert await h.drain() == 2  # re-delivered after the seek
    assert h.bus.committed["im.ingest"] == 4
    st = h.engine.state.get(TENANT, dev.device_id)
    assert st is not None and st.sample_count == 3


async def test_redelivery_after_crash_is_idempotent(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    fleet = Fleet()
    dev = fleet.add(1, GATEWAY)
    h.register(dev)
    for i in range(3):
        msg = fleet.telemetry(dev, T0 + i * 60, overrides={"fw_hash": sha_hex("implant")})
        ingest_record(h.bus, dev, fleet.sign(dev, msg), T0 + i * 60)
    await h.drain()
    assert len(h.repo.alerts) == 1
    before = metric("ironmesh_replay_rejected_total")
    h.bus.committed["im.ingest"] = 0  # simulate offsets lost (commit after crash)
    h.bus.rewind_to_committed()
    await h.drain()
    assert len(h.repo.alerts) == 1  # no duplicate alert
    assert metric("ironmesh_replay_rejected_total") - before == 3


async def test_rejected_envelopes_feed_auth_burst_and_are_audited(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    fleet = Fleet()
    dev = fleet.add(1, GATEWAY)
    h.register(dev)
    forger = SimDevice(
        dev.device_id, GATEWAY, serial=dev.serial, key=ec.generate_private_key(ec.SECP256R1())
    )
    for i in range(12):
        msg = fleet.telemetry(dev, T0 + i)
        ingest_record(h.bus, dev, fleet.sign(forger, msg), T0 + i)
    await h.drain()
    rules = {a.rule for a in h.repo.alerts.values()}
    assert rules == {RuleName.AUTH_BURST}
    audits = [json.loads(r.value) for r in h.bus.messages("im.audit")]
    rejected = [a for a in audits if a["action"] == "anomaly.envelope_rejected"]
    assert len(rejected) == 1  # rate-limited per (device, reason)
    assert (
        rejected[0]["details"]["reason"] == "bad_signature" and rejected[0]["outcome"] == "failure"
    )
    assert metric("ironmesh_anomaly_envelope_rejected_total", {"reason": "bad_signature"}) >= 12


async def test_auth_topic_and_audit_records(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    fleet = Fleet()
    dev = fleet.add(1, GATEWAY)
    h.register(dev)
    auth_record(
        h.bus,
        dev.device_id,
        "authz_denied",
        T0,
        topic=f"im/v1/{TENANT}/dev-00000000000000ff/cmd/req",
        action="subscribe",
    )
    auth_record(h.bus, "nobody", "authn_failed", T0)
    h.bus.produce(
        "im.audit",
        json.dumps(
            {
                "action": "device.quarantine",
                "tenant_id": TENANT,
                "actor": {"type": "user", "id": "u9"},
                "target": {"type": "device", "id": dev.device_id},
                "at": "2025-10-09T08:53:20Z",
            }
        ).encode(),
    )
    h.bus.produce("im.audit", b"{}")
    h.bus.produce("im.other", b"x")
    h.bus.subscribed.append("im.other")
    await h.drain()
    alerts = list(h.repo.alerts.values())
    assert [a.rule for a in alerts] == [RuleName.TOPIC_VIOLATION]
    assert alerts[0].features["classification"] == "another device's namespace"
    rec = (await h.repo.list_quarantine(TENANT, None, 10))[0]
    assert rec[0].by == "user:u9"
    st = h.engine.state.get(TENANT, dev.device_id)
    assert st is not None and st.quarantined
    h.bus.produce(
        "im.audit",
        json.dumps(
            {
                "action": "device.release",
                "tenant_id": TENANT,
                "actor": {"type": "user", "id": "u9"},
                "target": {"type": "device", "id": dev.device_id},
            }
        ).encode(),
    )
    await h.drain()
    assert await h.repo.quarantined_devices(TENANT) == set()
    assert not st.quarantined


async def test_snapshot_restore_and_model_reload(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    fleet = Fleet(seed=3)
    devs = [fleet.add(n, GATEWAY) for n in range(1, 6)]
    for d in devs:
        h.register(d)
    for i in range(60):
        for d in devs:
            ingest_record(h.bus, d, fleet.sign(d, fleet.telemetry(d, T0 + i * 60)), T0 + i * 60)
    await h.drain()
    await h.engine.repo.put_rule_override(
        TENANT, RuleName.ISOLATION_FOREST, RuleOverride(params={"min_train_samples": 50})
    )
    h.engine.invalidate(TENANT)
    assert await h.engine.train(now=T0 + 3600) == 1
    assert len(h.repo.models) == 1
    assert await h.engine.snapshot() == 5
    assert await h.engine.snapshot() == 0  # nothing dirty
    # a new process restores state, replay protection and models
    h2 = make_harness(tmp_path)
    h2.repo = h.repo
    h2.engine.repo = h.repo
    assert await h2.engine.restore() == 5
    assert h2.engine.decoder.last_seq[devs[0].device_id] == 60
    assert h2.engine.models.get(TENANT, GATEWAY) is not None
    st = h2.engine.state.get(TENANT, devs[0].device_id)
    assert st is not None and st.sample_count == 59 and st.device_class == GATEWAY
    # corrupt model blob: restore logs and continues
    meta = next(iter(h.repo.models.values()))
    meta.sha256_hex = "0" * 64
    h3 = make_harness(tmp_path)
    h3.engine.repo = h.repo
    assert await h3.engine.restore() == 5
    assert h3.engine.models.get(TENANT, GATEWAY) is None


async def test_training_excludes_alert_periods_but_keeps_false_positives(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    now = utcnow()
    open_alert = Alert(
        Alert.new_id(),
        TENANT,
        "dev-0000000000000001",
        RuleName.BEACONING,
        Severity.HIGH,
        1,
        {},
        "",
        now - timedelta(hours=1),
    )
    fp = Alert(
        Alert.new_id(),
        TENANT,
        "dev-0000000000000002",
        RuleName.BEACONING,
        Severity.HIGH,
        1,
        {},
        "",
        now - timedelta(hours=2),
        state=AlertState.RESOLVED,
        false_positive=True,
        resolved_at=now,
    )
    tp = Alert(
        Alert.new_id(),
        TENANT,
        "dev-0000000000000003",
        RuleName.BEACONING,
        Severity.HIGH,
        1,
        {},
        "",
        now - timedelta(hours=3),
        state=AlertState.RESOLVED,
        resolved_at=now - timedelta(hours=2),
    )
    for a in (open_alert, fp, tp):
        await h.repo.insert_alert(a)
    periods = await h.engine.alert_periods(TENANT, 600, now)
    assert {p.device_id for p in periods} == {"dev-0000000000000001", "dev-0000000000000003"}
    p1 = next(p for p in periods if p.device_id.endswith("1"))
    assert p1.start == pytest.approx(
        open_alert.created_at.timestamp() - 600
    ) and p1.end == pytest.approx(now.timestamp())


async def test_quarantined_device_from_registry_and_siem_notify(tmp_path: Path) -> None:
    delivered: list[Delivery] = []

    class Sink:
        name = "mem"

        def wants(self, s: TenantSettings) -> bool:
            return s.siem.enabled

        async def send(self, d: Delivery) -> None:
            delivered.append(d)

    siem = SiemDispatcher([Sink()])
    h = make_harness(tmp_path, siem=siem)
    await h.repo.put_settings(
        TENANT,
        TenantSettings(
            auto_quarantine=True,
            quarantine_min_severity=Severity.HIGH,
            siem=SiemSettings(enabled=True),
        ),
    )
    dev = "dev-00000000000000aa"
    info = DeviceInfo(dev, TENANT, GATEWAY, state="quarantined")
    await h.engine.process_event(telemetry_event(dev, T0, fw_hash=sha_hex("x")), info)
    alert = next(iter(h.repo.alerts.values()))
    assert [a.type for a in alert.actions] == ["notify"] and alert.actions[
        0
    ].result == "queued: mem"
    assert h.quarantine.calls == []  # already quarantined in the registry
    siem.start()
    await asyncio.wait_for(siem.drain(), 5)
    await siem.stop()
    assert delivered[0].alert.id == alert.id


async def test_invalid_stored_override_falls_back_to_defaults(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    await h.repo.put_rule_override(
        TENANT, RuleName.AUTH_BURST, RuleOverride(params={"threshold": -5})
    )
    rules = await h.engine.rules_for(TENANT)
    assert rules[RuleName.AUTH_BURST].params.threshold == 10
    assert await h.engine.rules_for(TENANT) is rules  # cached


async def test_disabled_rule_does_not_fire(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    await h.repo.put_rule_override(TENANT, RuleName.FW_HASH_MISMATCH, RuleOverride(enabled=False))
    await h.engine.process_event(
        telemetry_event(fw_hash=sha_hex("x")), DeviceInfo("dev-0000000000000001", TENANT, GATEWAY)
    )
    assert h.repo.alerts == {}


async def test_refresh_metrics_and_purge(tmp_path: Path) -> None:
    h = make_harness(
        tmp_path,
        settings=Settings(run_pipeline=False, model_dir=str(tmp_path / "m"), auto_quarantine=True),
    )
    await h.engine.process_event(
        telemetry_event(fw_hash=sha_hex("x")), DeviceInfo("dev-0000000000000001", TENANT, GATEWAY)
    )
    await h.engine.flush()
    auth_record(h.bus, "dev-0000000000000001", "connected", T0)
    await h.engine.refresh_metrics()
    assert metric("ironmesh_anomaly_open_alerts", {"severity": "critical"}) == 1
    assert metric("ironmesh_anomaly_auto_quarantine_enabled") == 1
    assert metric("ironmesh_anomaly_consumer_lag_messages", {"topic": "im.auth"}) == 1
    assert len(h.repo.events) == 1
    assert await h.engine.purge() == 1  # event older than the retention period


async def test_run_loop_and_periodic(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    runs: list[int] = []

    async def job() -> None:
        runs.append(1)
        if len(runs) == 2:
            raise RuntimeError("boom")  # logged, loop continues
        if len(runs) == 3:
            h.engine.stop()

    await asyncio.wait_for(h.engine.periodic(job, 0.01, "test"), 5)
    assert len(runs) == 3
    h2 = make_harness(tmp_path)
    calls = {"n": 0}

    async def bad_batch(*_: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 2:
            h2.engine.stop()
        raise RuntimeError("bus down")

    async def no_sleep(_: float) -> None:
        return None

    h2.engine.run_batch = bad_batch  # type: ignore[method-assign,assignment]
    h2.engine._sleep = no_sleep
    await asyncio.wait_for(h2.engine.run(), 5)
    assert calls["n"] == 2


async def test_unrelated_record_types(tmp_path: Path) -> None:
    h = make_harness(tmp_path)
    await h.engine.handle_record(BusRecord("im.nothing", 0, 0, None, b"", {}))
    assert h.repo.alerts == {}


async def test_ota_install_then_new_hash_is_clean(tmp_path: Path) -> None:
    from ironmesh_wire import ids
    from tests.support import ota_success

    h = make_harness(tmp_path)
    fleet = Fleet()
    dev = fleet.add(1, GATEWAY)
    h.register(dev)
    ingest_record(h.bus, dev, fleet.sign(dev, fleet.telemetry(dev, T0)), T0)
    new = sha_hex("gw-2.4.0")
    ingest_record(
        h.bus,
        dev,
        fleet.sign(dev, ota_success(dev, T0 + 30, new)),
        T0 + 30,
        ids.TopicClass.OTA_STATUS,
    )
    ingest_record(
        h.bus,
        dev,
        fleet.sign(dev, fleet.telemetry(dev, T0 + 60, overrides={"fw_hash": new})),
        T0 + 60,
    )
    await h.drain()
    assert h.repo.alerts == {}
    assert from_ts(T0).year == 2025
