"""End-to-end synthetic scenario: 200 normal devices + 3 anomalous through real signed envelopes.

Pipeline under test: im.ingest/im.auth records -> envelope verification -> state -> rules +
Isolation Forest -> alerts (persisted, published to im.alerts) -> auto-quarantine policy ->
audit to im.audit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ironmesh_anomaly.config import Settings
from ironmesh_anomaly.models import RuleName, RuleOverride, Severity, TenantSettings
from tests.support import (
    GATEWAY,
    SENSOR,
    T0,
    TENANT,
    Fleet,
    Harness,
    SimDevice,
    auth_record,
    ingest_record,
    make_harness,
    sha_hex,
)

WARMUP = 70
ATTACK = 40
DT = 60.0


@dataclass
class Scenario:
    h: Harness
    fleet: Fleet
    auth_dev: SimDevice
    beacon_dev: SimDevice
    fw_dev: SimDevice

    @property
    def anomalous(self) -> set[str]:
        return {self.auth_dev.device_id, self.beacon_dev.device_id, self.fw_dev.device_id}


def build(tmp_path: Path, settings: Settings | None = None) -> Scenario:
    h = make_harness(tmp_path, settings=settings)
    fleet = Fleet(seed=2024)
    for n in range(1, 204):
        product = GATEWAY if n % 2 else SENSOR
        dev = fleet.add(n, product, mobile=(product == SENSOR and n % 5 == 0))
        h.register(dev)
    devs = list(fleet.devices.values())
    return Scenario(h, fleet, auth_dev=devs[0], beacon_dev=devs[1], fw_dev=devs[2])


async def run_phase(sc: Scenario, start: int, count: int, *, attack: bool) -> None:
    h, fleet = sc.h, sc.fleet
    for i in range(start, start + count):
        ts = T0 + i * DT
        for dev in fleet.devices.values():
            tx_factor = 1.0
            overrides: dict[str, object] = {}
            if attack and dev is sc.beacon_dev and i % 5 == 0:
                tx_factor = 40.0
            if attack and dev is sc.fw_dev:
                overrides["fw_hash"] = sha_hex("implant")
            msg = fleet.telemetry(dev, ts, DT, tx_factor=tx_factor, overrides=overrides)
            ingest_record(h.bus, dev, fleet.sign(dev, msg), ts)
        if attack and i == start + 10:
            for k in range(25):  # credential stuffing against one device: 25 failures in 50 s
                auth_record(
                    h.bus,
                    sc.auth_dev.device_id,
                    "authn_failed",
                    ts + 2 * k,
                    peerhost="203.0.113.50",
                )
        await h.drain()


async def run_scenario(sc: Scenario) -> None:
    h = sc.h
    for dev in sc.fleet.devices.values():  # every device connects once at the start
        auth_record(h.bus, dev.device_id, "connected", T0 - 30, peerhost="198.51.100.10")
    await run_phase(sc, 0, WARMUP, attack=False)
    trained = await h.engine.train(now=T0 + WARMUP * DT)
    assert trained == 2  # one model per (tenant, device class)
    await run_phase(sc, WARMUP, ATTACK, attack=True)


def alerted_devices(sc: Scenario) -> dict[str, set[RuleName]]:
    out: dict[str, set[RuleName]] = {}
    for alert in sc.h.repo.alerts.values():
        out.setdefault(alert.device_id, set()).add(alert.rule)
    return out


def audit_decisions(sc: Scenario) -> list[dict[str, object]]:
    events = [json.loads(r.value) for r in sc.h.bus.messages("im.audit")]
    return [e for e in events if e["action"] == "anomaly.quarantine_decision"]


async def set_tenant(sc: Scenario, settings: TenantSettings) -> None:
    await sc.h.repo.put_settings(TENANT, settings)
    sc.h.engine.invalidate(TENANT)


async def test_scenario_alerts_exactly_the_anomalous_devices_and_quarantines_them(
    tmp_path: Path,
) -> None:
    sc = build(tmp_path)
    await set_tenant(
        sc, TenantSettings(auto_quarantine=True, quarantine_min_severity=Severity.HIGH)
    )
    await run_scenario(sc)

    alerted = alerted_devices(sc)
    assert set(alerted) == sc.anomalous, f"false positives: {set(alerted) - sc.anomalous}"
    assert RuleName.AUTH_BURST in alerted[sc.auth_dev.device_id]
    assert RuleName.BEACONING in alerted[sc.beacon_dev.device_id]
    assert RuleName.FW_HASH_MISMATCH in alerted[sc.fw_dev.device_id]

    # precision / recall at device level
    tp = len(set(alerted) & sc.anomalous)
    precision = tp / len(alerted)
    recall = tp / len(sc.anomalous)
    print(
        f"scenario: devices=203 alerted={sorted(alerted)} precision={precision:.2f} recall={recall:.2f}"
    )
    print({d: sorted(r.value for r in rules) for d, rules in alerted.items()})
    assert precision == 1.0 and recall == 1.0

    quarantined = {c[0] for c in sc.h.quarantine.calls}
    assert quarantined == sc.anomalous
    assert await sc.h.repo.quarantined_devices(TENANT) == sc.anomalous
    for alert in sc.h.repo.alerts.values():
        assert alert.state.value == "open"
    published = [json.loads(r.value) for r in sc.h.bus.messages("im.alerts")]
    assert {p["device_id"] for p in published} == sc.anomalous
    assert all(
        set(p)
        == {
            "id",
            "tenant_id",
            "device_id",
            "rule",
            "severity",
            "score",
            "features",
            "explanation",
            "created_at",
            "state",
            "acked_by",
            "resolved_by",
            "actions",
        }
        for p in published
    )
    decisions = audit_decisions(sc)
    taken = [d for d in decisions if d["details"]["decision"] == "quarantined"]  # type: ignore[index]
    assert {d["target"]["id"] for d in taken} == sc.anomalous  # type: ignore[index]
    # every bus record was committed
    assert sc.h.bus.committed["im.ingest"] == len(sc.h.bus.messages("im.ingest"))


async def test_scenario_dry_run_quarantines_nothing_but_audits(tmp_path: Path) -> None:
    sc = build(tmp_path)
    await set_tenant(
        sc, TenantSettings(auto_quarantine=True, quarantine_min_severity=Severity.HIGH)
    )
    for rule in RuleName:
        await sc.h.repo.put_rule_override(TENANT, rule, RuleOverride(dry_run=True))
    sc.h.engine.invalidate(TENANT)
    await run_scenario(sc)

    assert set(alerted_devices(sc)) == sc.anomalous
    assert sc.h.quarantine.calls == []
    assert await sc.h.repo.quarantined_devices(TENANT) == set()
    decisions = audit_decisions(sc)
    assert decisions
    # medium isolation_forest alerts are gated by severity first; every other decision is dry_run
    assert {d["details"]["reason"] for d in decisions} <= {"dry_run", "below_min_severity"}  # type: ignore[index]
    would = {d["target"]["id"] for d in decisions if d["details"]["reason"] == "dry_run"}  # type: ignore[index]
    assert would == sc.anomalous
    for alert in sc.h.repo.alerts.values():
        assert alert.dry_run
        if alert.severity.rank >= Severity.HIGH.rank:
            assert any(a.result.startswith("dry_run") for a in alert.actions)


async def test_scenario_auto_quarantine_disabled_is_audited(tmp_path: Path) -> None:
    sc = build(tmp_path)
    await run_scenario(sc)  # service default: auto_quarantine off
    assert sc.h.quarantine.calls == []
    reasons = {d["details"]["reason"] for d in audit_decisions(sc)}  # type: ignore[index]
    assert reasons == {"auto_quarantine_disabled"}


async def test_circuit_breaker_stops_mass_quarantine(tmp_path: Path) -> None:
    """A stale OTA known-hash list makes 60 healthy devices look tampered: at most 10 per hour."""
    settings = Settings(
        run_pipeline=False, model_dir=str(tmp_path / "m"), quarantine_max_per_hour=10
    )
    h = make_harness(tmp_path, settings=settings)
    await h.repo.put_settings(
        TENANT, TenantSettings(auto_quarantine=True, quarantine_min_severity=Severity.HIGH)
    )
    fleet = Fleet(seed=5)
    devs = [fleet.add(n, GATEWAY) for n in range(1, 61)]
    for d in devs:
        h.register(d)
    h.hashes.table[GATEWAY] = {sha_hex("gw-9.9.9")}  # OTA forgot to publish the current release
    for dev in devs:
        msg = fleet.telemetry(dev, T0)
        ingest_record(h.bus, dev, fleet.sign(dev, msg), T0)
    await h.drain()
    assert len(h.repo.alerts) == 60
    assert len(h.quarantine.calls) == 10
    decisions = [json.loads(r.value) for r in h.bus.messages("im.audit")]
    by_reason: dict[str, int] = {}
    for d in decisions:
        if d["action"] == "anomaly.quarantine_decision":
            by_reason[d["details"]["reason"]] = by_reason.get(d["details"]["reason"], 0) + 1
    assert by_reason == {"policy": 10, "rate_limited": 1, "circuit_open": 49}
    assert sum(1 for d in decisions if d["action"] == "anomaly.quarantine_breaker_opened") == 1
    assert h.engine.quarantine.breaker.is_open(TENANT)
    # after the cool-down the breaker closes again
    h.clock[0] += settings.quarantine_breaker_cooldown_s + 3601
    assert not h.engine.quarantine.breaker.is_open(TENANT)
