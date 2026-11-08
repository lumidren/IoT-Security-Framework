"""Alert dedup/escalation/suppression and the auto-quarantine policy engine."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from ironmesh_anomaly.alerting import AlertManager, AlertNotFound, InvalidTransition, NullBus
from ironmesh_anomaly.audit import AuditPublisher
from ironmesh_anomaly.bus import InMemoryEventBus
from ironmesh_anomaly.models import (
    Alert,
    AlertState,
    Detection,
    RuleName,
    Severity,
    TenantSettings,
    from_ts,
    utcnow,
)
from ironmesh_anomaly.quarantine import CircuitBreaker, QuarantinePolicy
from ironmesh_anomaly.repository import InMemoryRepository
from ironmesh_anomaly.state import DeviceState
from tests.support import TENANT, FakeQuarantineClient

DEV = "dev-00000000000000aa"


def det(
    rule: RuleName = RuleName.AUTH_BURST,
    sev: Severity = Severity.HIGH,
    *,
    at_offset: float = 0,
    score: float = 0.5,
    device: str = DEV,
) -> Detection:
    return Detection(
        rule,
        TENANT,
        device,
        sev,
        score,
        "x",
        {"n": at_offset},
        utcnow() + timedelta(seconds=at_offset),
    )


async def test_create_dedup_and_escalation() -> None:
    repo = InMemoryRepository()
    bus = InMemoryEventBus()
    am = AlertManager(repo, bus, dedup_window_s=600, escalate_after=(3, 10))
    first = await am.handle(det())
    assert first.kind == "created" and first.alert is not None
    second = await am.handle(det(at_offset=60, score=0.9))
    assert (
        second.kind == "updated" and second.alert is not None and second.alert.id == first.alert.id
    )
    assert second.alert.occurrences == 2 and second.alert.score == 0.9
    third = await am.handle(det(at_offset=120))
    assert (
        third.kind == "escalated"
        and third.alert is not None
        and third.alert.severity is Severity.CRITICAL
    )
    late = await am.handle(det(at_offset=120 + 601))  # outside dedup window -> new alert
    assert late.kind == "created"
    other_rule = await am.handle(det(RuleName.BEACONING))
    assert other_rule.kind == "created"
    assert len(repo.alerts) == 3
    await am.publish(first.alert)
    rec = bus.messages("im.alerts")[0]
    assert rec.key == f"{TENANT}/{DEV}".encode()
    assert json.loads(rec.value)["id"] == first.alert.id


async def test_detection_severity_raises_existing_alert() -> None:
    am = AlertManager(InMemoryRepository(), NullBus())
    await am.handle(det(sev=Severity.HIGH))
    out = await am.handle(det(sev=Severity.CRITICAL, at_offset=1))
    assert (
        out.kind == "escalated"
        and out.alert is not None
        and out.alert.severity is Severity.CRITICAL
    )


async def test_ack_resolve_and_false_positive_suppression() -> None:
    repo = InMemoryRepository()
    am = AlertManager(repo, NullBus(), fp_suppression_s=100, fp_suppression_max_s=250)
    a = (await am.handle(det())).alert
    assert a is not None
    acked = await am.ack(TENANT, a.id, "user:1")
    assert acked.state is AlertState.ACKED and acked.acked_by == "user:1"
    resolved = await am.resolve(TENANT, a.id, "user:2", false_positive=True)
    assert (
        resolved.state is AlertState.RESOLVED
        and resolved.resolved_by == "user:2"
        and resolved.false_positive
    )
    with pytest.raises(InvalidTransition):
        await am.ack(TENANT, a.id, "user:1")
    with pytest.raises(InvalidTransition):
        await am.resolve(TENANT, a.id, "user:1", false_positive=False)
    with pytest.raises(AlertNotFound):
        await am.ack(TENANT, "00000000-0000-4000-8000-000000000000", "u")
    sup = await repo.get_suppression(TENANT, DEV, RuleName.AUTH_BURST)
    assert sup is not None and sup.count == 1
    assert (await am.handle(det(at_offset=5))).kind == "suppressed"
    assert (await am.handle(det(RuleName.BEACONING, at_offset=5))).kind == "created"
    # second false positive doubles the period (capped)
    sup.until = utcnow() - timedelta(seconds=1)
    await repo.put_suppression(sup)
    b = (await am.handle(det(at_offset=6))).alert
    assert b is not None
    await am.resolve(TENANT, b.id, "user:2", false_positive=True)
    sup2 = await repo.get_suppression(TENANT, DEV, RuleName.AUTH_BURST)
    assert sup2 is not None and sup2.count == 2
    assert 190 < (sup2.until - utcnow()).total_seconds() <= 200
    # true positive resolution does not suppress
    c = (await am.handle(det(RuleName.TOPIC_VIOLATION))).alert
    assert c is not None
    await am.resolve(TENANT, c.id, "user:2", false_positive=False)
    assert await repo.get_suppression(TENANT, DEV, RuleName.TOPIC_VIOLATION) is None


def _alert(
    sev: Severity = Severity.CRITICAL, rule: RuleName = RuleName.FW_HASH_MISMATCH, device: str = DEV
) -> Alert:
    return Alert(Alert.new_id(), TENANT, device, rule, sev, 1.0, {}, "x", utcnow())


def _policy(
    max_per_hour: int = 3, ok: bool = True
) -> tuple[
    QuarantinePolicy, FakeQuarantineClient, InMemoryEventBus, InMemoryRepository, list[float]
]:
    bus = InMemoryEventBus()
    repo = InMemoryRepository()
    qc = FakeQuarantineClient(ok=ok)
    clock = [1000.0]
    breaker = CircuitBreaker(max_per_hour, 600, lambda: clock[0])
    return (
        QuarantinePolicy(qc, repo, AuditPublisher(bus, "im.audit"), breaker),
        qc,
        bus,
        repo,
        clock,
    )


def _reasons(bus: InMemoryEventBus) -> list[str]:
    return [json.loads(r.value)["details"].get("reason", "") for r in bus.messages("im.audit")]


ON = TenantSettings(auto_quarantine=True, quarantine_min_severity=Severity.HIGH)


async def test_policy_gates_in_order() -> None:
    policy, qc, bus, repo, _ = _policy()
    st = DeviceState(TENANT, DEV)
    d = await policy.consider(_alert(), TenantSettings(), rule_dry_run=False, state=st)
    assert (d.decision, d.reason) == ("skipped", "auto_quarantine_disabled") and d.action is None
    d = await policy.consider(_alert(Severity.MEDIUM), ON, rule_dry_run=False, state=st)
    assert d.reason == "below_min_severity"
    d = await policy.consider(_alert(), ON, rule_dry_run=True, state=st)
    assert d.reason == "dry_run" and d.action is not None and d.action.type == "none"
    alert = _alert()
    d = await policy.consider(alert, ON, rule_dry_run=False, state=st)
    assert d.decision == "quarantined" and qc.calls[0][0] == DEV
    assert alert.actions[-1].type == "quarantine" and alert.actions[-1].result == "success"
    assert st.quarantined and await repo.quarantined_devices(TENANT) == {DEV}
    rec = (await repo.list_quarantine(TENANT, None, 10))[0][0]
    assert rec.by == "auto" and rec.alert_id == alert.id
    d = await policy.consider(_alert(), ON, rule_dry_run=False, state=st)
    assert d.reason == "already_quarantined"
    assert _reasons(bus) == [
        "auto_quarantine_disabled",
        "below_min_severity",
        "dry_run",
        "policy",
        "already_quarantined",
    ]
    events = [json.loads(r.value) for r in bus.messages("im.audit")]
    assert all(
        e["actor"]["id"] == "svc-anomaly" and e["target"]["type"] == "device" for e in events
    )


async def test_policy_registry_failure_is_audited_as_failure() -> None:
    policy, _, bus, repo, _ = _policy(ok=False)
    alert = _alert()
    d = await policy.consider(alert, ON, rule_dry_run=False, state=None)
    assert d.decision == "failed" and alert.actions[-1].result.startswith("failed")
    assert json.loads(bus.messages("im.audit")[-1].value)["outcome"] == "failure"
    assert await repo.quarantined_devices(TENANT) == set()


async def test_circuit_breaker_unit() -> None:
    policy, qc, bus, _, clock = _policy(max_per_hour=2)
    results = []
    for i in range(5):
        d = await policy.consider(
            _alert(device=f"dev-{i:016x}"), ON, rule_dry_run=False, state=None
        )
        results.append(d.reason)
    assert results == ["policy", "policy", "rate_limited", "circuit_open", "circuit_open"]
    assert len(qc.calls) == 2
    status = policy.breaker.status(TENANT)
    assert status["open"] and status["attempts_last_hour"] == 2
    clock[0] += 601  # cooldown over, but the hour window still holds 2 attempts
    d = await policy.consider(
        _alert(device="dev-00000000000000f1"), ON, rule_dry_run=False, state=None
    )
    assert d.reason == "rate_limited"
    clock[0] += 3600 + 601
    d = await policy.consider(
        _alert(device="dev-00000000000000f2"), ON, rule_dry_run=False, state=None
    )
    assert d.reason == "policy"
    policy.breaker.reset(TENANT)
    assert not policy.breaker.is_open(TENANT)
    assert "anomaly.quarantine_breaker_opened" in [
        json.loads(r.value)["action"] for r in bus.messages("im.audit")
    ]


async def test_audit_publish_failure_raises() -> None:
    bus = InMemoryEventBus()
    bus.fail_publish.add("im.audit")
    pub = AuditPublisher(bus, "im.audit")
    with pytest.raises(ConnectionError):
        await pub.publish({"tenant_id": None})


def test_alert_record_roundtrip() -> None:
    a = _alert()
    a.last_seen_at = from_ts(10)
    clone = Alert.from_record(a.to_record())
    assert clone.to_api() == a.to_api() and clone.last_seen_at == a.last_seen_at
