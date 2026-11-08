"""Unit tests for each rule: positive and negative cases, params, severities."""

from __future__ import annotations

import random

import pytest

from ironmesh_anomaly.geo import GeoLocation, StaticGeoIPProvider
from ironmesh_anomaly.models import (
    AuthEvent,
    AuthKind,
    Detection,
    DeviceEvent,
    OtaStatusEvent,
    RuleName,
    RuleOverride,
    Severity,
)
from ironmesh_anomaly.rules import (
    AuthBurstParams,
    AuthBurstRule,
    BeaconingParams,
    BeaconingRule,
    FwHashMismatchRule,
    ImpossibleTravelParams,
    ImpossibleTravelRule,
    InvalidRuleParams,
    IsolationForestRule,
    RawScore,
    RuleContext,
    RuleSet,
    TopicViolationRule,
    build_rule,
)
from ironmesh_anomaly.rules.base import Rule
from ironmesh_anomaly.rules.topic_violation import classify_topic
from ironmesh_anomaly.state import DeviceState, StateStore
from tests.support import FW, GATEWAY, KNOWN, T0, TENANT, sha_hex, telemetry_event

DEV = "dev-00000000000000aa"


def run(
    rule: object,
    events: list[DeviceEvent],
    *,
    store: StateStore | None = None,
    known: frozenset[str] | None = None,
) -> list[Detection]:
    assert isinstance(rule, Rule)
    store = StateStore() if store is None else store
    out: list[Detection] = []
    for ev in events:
        obs = store.apply(ev, GATEWAY)
        st = store.get(ev.tenant_id, ev.device_id)
        assert st is not None
        det = rule.evaluate(
            ev, st, obs, RuleContext(now=ev.ts, device_class=GATEWAY, known_hashes=known)
        )
        if det is not None:
            out.append(det)
    return out


def auth(
    kind: AuthKind,
    ts: float,
    *,
    ip: str | None = "198.51.100.7",
    device: str = DEV,
    topic: str | None = None,
) -> AuthEvent:
    return AuthEvent(TENANT, device, ts, kind, peerhost=ip, topic=topic, action="publish")


# --------------------------------------------------------------------------- impossible_travel


def test_travel_gps_positive_paris_to_new_york_in_ten_minutes() -> None:
    events: list[DeviceEvent] = [
        telemetry_event(DEV, T0, lat=48.8566, lon=2.3522),
        telemetry_event(DEV, T0 + 600, seq=2, lat=40.7128, lon=-74.0060),
    ]
    dets = run(ImpossibleTravelRule(), events)
    assert len(dets) == 1
    d = dets[0]
    assert d.rule is RuleName.IMPOSSIBLE_TRAVEL and d.severity is Severity.HIGH
    assert d.features["source"] == "gps"
    assert 5800 < d.features["distance_km"] < 5900
    assert d.features["speed_kmh"] > 30000
    assert 0 < d.score < 1


def test_travel_gps_negative_realistic_drive_and_jitter() -> None:
    events: list[DeviceEvent] = [
        telemetry_event(DEV, T0, lat=48.0, lon=2.0),
        telemetry_event(DEV, T0 + 3600, seq=2, lat=48.9, lon=2.0),  # 100 km/h
        telemetry_event(DEV, T0 + 3601, seq=3, lat=48.9001, lon=2.0),  # GPS jitter, < min_distance
        telemetry_event(DEV, T0 + 3700, seq=4),  # no fix
    ]
    assert run(ImpossibleTravelRule(), events) == []


def test_travel_threshold_is_a_parameter() -> None:
    events: list[DeviceEvent] = [
        telemetry_event(DEV, T0, lat=48.0, lon=2.0),
        telemetry_event(DEV, T0 + 3600, seq=2, lat=48.9, lon=2.0),
    ]
    rule = ImpossibleTravelRule(ImpossibleTravelParams(max_speed_kmh=50))
    assert len(run(rule, events)) == 1
    assert run(ImpossibleTravelRule(ImpossibleTravelParams(use_gps=False)), events) == []


def test_travel_geoip_connects_with_accuracy_radius() -> None:
    geo = StaticGeoIPProvider(
        {
            "203.0.113.1": GeoLocation(52.52, 13.40, accuracy_km=20),  # Berlin
            "203.0.113.2": GeoLocation(-33.87, 151.21, accuracy_km=50),  # Sydney
            "203.0.113.3": GeoLocation(52.40, 13.06, accuracy_km=100),  # Potsdam (inside radius)
        }
    )
    store = StateStore(geo)
    rule = ImpossibleTravelRule()
    pos = run(
        rule,
        [
            auth(AuthKind.CONNECTED, T0, ip="203.0.113.1"),
            auth(AuthKind.CONNECTED, T0 + 1800, ip="203.0.113.2"),
        ],
        store=store,
    )
    assert len(pos) == 1
    assert pos[0].features["source"] == "geoip"
    assert pos[0].source_ip == "203.0.113.2"
    store2 = StateStore(geo)
    neg = run(
        rule,
        [
            auth(AuthKind.CONNECTED, T0, ip="203.0.113.1"),
            auth(AuthKind.CONNECTED, T0 + 60, ip="203.0.113.3"),
            auth(AuthKind.CONNECTED, T0 + 120, ip="10.0.0.1"),  # unknown to GeoIP
            auth(AuthKind.DISCONNECTED, T0 + 130, ip="203.0.113.2"),
        ],
        store=store2,
    )
    assert neg == []
    off = ImpossibleTravelRule(ImpossibleTravelParams(use_ip=False))
    assert (
        run(
            off,
            [
                auth(AuthKind.CONNECTED, T0, ip="203.0.113.1"),
                auth(AuthKind.CONNECTED, T0 + 10, ip="203.0.113.2"),
            ],
            store=StateStore(geo),
        )
        == []
    )


# --------------------------------------------------------------------------------- auth_burst


def test_auth_burst_per_device_positive_and_window() -> None:
    events: list[DeviceEvent] = [
        auth(AuthKind.AUTHN_FAILED, T0 + i * 2, ip=None) for i in range(11)
    ]
    dets = run(AuthBurstRule(), events)
    assert len(dets) == 1
    assert dets[0].features["scope"] == "device"
    assert dets[0].features["failures"] == 11


def test_auth_burst_negative_spread_out_failures() -> None:
    events: list[DeviceEvent] = [
        auth(AuthKind.AUTHN_FAILED, T0 + i * 7, ip=None) for i in range(30)
    ]
    assert run(AuthBurstRule(), events) == []  # ~8.6 failures per 60 s
    assert run(AuthBurstRule(), [auth(AuthKind.CONNECTED, T0)]) == []


def test_auth_burst_per_source_ip_across_devices() -> None:
    events: list[DeviceEvent] = [
        auth(AuthKind.AUTHN_FAILED, T0 + i, ip="203.0.113.66", device=f"dev-{i:016x}")
        for i in range(12)
    ]
    dets = run(AuthBurstRule(), events)
    assert len(dets) == 2  # the 11th and 12th failure, each attributed to the targeted device
    assert dets[0].features["scope"] == "source_ip"
    assert dets[0].source_ip == "203.0.113.66"
    assert len(dets[0].features["targeted_devices"]) == 11
    assert run(AuthBurstRule(AuthBurstParams(per_ip=False)), events) == []


def test_auth_burst_counts_rejected_envelopes_and_device_reported() -> None:
    rejected: list[DeviceEvent] = [
        auth(AuthKind.ENVELOPE_REJECTED, T0 + i, ip=None) for i in range(11)
    ]
    assert len(run(AuthBurstRule(), rejected)) == 1
    reported: list[DeviceEvent] = [
        telemetry_event(DEV, T0, auth_failures=0),
        telemetry_event(DEV, T0 + 30, seq=2, auth_failures=12),
    ]
    dets = run(AuthBurstRule(), reported)
    assert len(dets) == 1 and dets[0].features["failures"] == 12
    assert run(AuthBurstRule(AuthBurstParams(include_device_reported=False)), reported) == []


def test_auth_burst_critical_when_massive() -> None:
    events: list[DeviceEvent] = [
        auth(AuthKind.AUTHN_FAILED, T0 + i * 0.1, ip=None) for i in range(101)
    ]
    dets = run(AuthBurstRule(), events)
    assert dets[-1].severity is Severity.CRITICAL


# ---------------------------------------------------------------------------- topic_violation


def test_topic_violation_high_then_critical_when_repeated() -> None:
    other = f"im/v1/{TENANT}/dev-00000000000000bb/telemetry"
    events: list[DeviceEvent] = [auth(AuthKind.AUTHZ_DENIED, T0 + i, topic=other) for i in range(3)]
    dets = run(TopicViolationRule(), events)
    assert [d.severity for d in dets] == [Severity.HIGH, Severity.HIGH, Severity.CRITICAL]
    assert dets[0].features["classification"] == "another device's namespace"


def test_topic_violation_negative_other_events() -> None:
    events: list[DeviceEvent] = [
        auth(AuthKind.CONNECTED, T0),
        auth(AuthKind.AUTHN_FAILED, T0 + 1),
        telemetry_event(DEV, T0 + 2),
    ]
    assert run(TopicViolationRule(), events) == []


@pytest.mark.parametrize(
    ("topic", "why"),
    [
        (None, "unknown topic"),
        ("im/v1/#", "wildcard"),
        ("$SYS/brokers", "reserved topic"),
        ("foo/bar", "outside the im/v1 namespace"),
        (
            "im/v1/1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d/dev-00000000000000aa/telemetry",
            "another tenant's namespace",
        ),
        (f"im/v1/{TENANT}/{DEV}/cmd/req", "wrong direction for this topic class"),
    ],
)
def test_classify_topic(topic: str | None, why: str) -> None:
    assert classify_topic(topic, TENANT, DEV) == why


# ---------------------------------------------------------------------------- fw_hash_mismatch

KNOWN_GW = frozenset(KNOWN[GATEWAY])


def test_fw_unknown_hash_is_critical() -> None:
    dets = run(
        FwHashMismatchRule(), [telemetry_event(DEV, T0, fw_hash=sha_hex("evil"))], known=KNOWN_GW
    )
    assert len(dets) == 1
    assert dets[0].severity is Severity.CRITICAL
    assert dets[0].features["reasons"] == ["unknown_hash"]


def test_fw_known_hash_and_authorized_ota_is_clean() -> None:
    new = sha_hex("gw-2.4.0")
    events: list[DeviceEvent] = [
        telemetry_event(DEV, T0),
        OtaStatusEvent(TENANT, DEV, T0 + 10, state=5, fw_hash_hex=new),
        telemetry_event(DEV, T0 + 60, seq=3, fw_hash=new),
        telemetry_event(DEV, T0 + 120, seq=4, fw_hash=new),
    ]
    assert run(FwHashMismatchRule(), events, known=KNOWN_GW) == []
    assert (
        run(FwHashMismatchRule(), [telemetry_event(DEV, T0, fw_hash=sha_hex("x"))], known=None)
        == []
    )


def test_fw_change_to_older_known_image_without_ota() -> None:
    events: list[DeviceEvent] = [
        telemetry_event(DEV, T0),
        telemetry_event(DEV, T0 + 60, seq=2, fw_hash=sha_hex("gw-2.4.0")),
    ]
    dets = run(FwHashMismatchRule(), events, known=KNOWN_GW)
    assert len(dets) == 1 and dets[0].features["reasons"] == ["unexpected_change"]


def test_fw_differs_from_last_installed() -> None:
    events: list[DeviceEvent] = [
        OtaStatusEvent(TENANT, DEV, T0, state=5, fw_hash_hex=FW[GATEWAY][0]),
        OtaStatusEvent(TENANT, DEV, T0 + 1, state=3, fw_hash_hex=sha_hex("ignored, not success")),
        telemetry_event(DEV, T0 + 60, seq=2, fw_hash=sha_hex("gw-2.4.0")),
    ]
    dets = run(FwHashMismatchRule(), events, known=KNOWN_GW)
    assert set(dets[0].features["reasons"]) == {"differs_from_installed", "unexpected_change"}


# --------------------------------------------------------------------------------- beaconing


def tx_series(
    n: int, *, period: int | None, burst: float = 40.0, seed: int = 1, random_bursts: int = 0
) -> list[DeviceEvent]:
    rng = random.Random(seed)
    events: list[DeviceEvent] = []
    tx = 0
    spikes = set(rng.sample(range(10, n), random_bursts)) if random_bursts else set()
    for i in range(n):
        rate = rng.gauss(1000, 50)
        if (period and i % period == 0 and i > 0) or i in spikes:
            rate *= burst
        tx += int(rate * 60)
        events.append(telemetry_event(DEV, T0 + i * 60, seq=i + 1, tx=tx))
    return events


def test_beaconing_periodic_tx_bursts_positive() -> None:
    dets = run(BeaconingRule(), tx_series(80, period=5))
    assert dets, "periodic bursts must be detected"
    f = dets[-1].features
    assert f["channel"] == "tx_bursts"
    assert f["period_samples"] == 5 and abs(f["period_s"] - 300) < 1
    assert f["interval_cv"] < 0.15 and f["acf_lag"] == 5 and f["acf_peak"] > 0.4
    assert f["volume_ratio"] > 3


def test_beaconing_negatives() -> None:
    assert run(BeaconingRule(), tx_series(80, period=None)) == []  # steady traffic
    assert (
        run(BeaconingRule(), tx_series(120, period=None, random_bursts=5, seed=3)) == []
    )  # aperiodic spikes
    assert run(BeaconingRule(), tx_series(80, period=1)) == []  # level shift, not a beacon
    assert run(BeaconingRule(), tx_series(20, period=5)) == []  # not enough samples
    assert run(BeaconingRule(), tx_series(80, period=5, burst=1.5)) == []  # spikes too small


def test_beaconing_stops_when_beacon_stops() -> None:
    events = tx_series(60, period=5)
    rng = random.Random(9)
    last = events[-1]
    assert isinstance(last, type(telemetry_event()))
    tx = last.net_tx_bytes
    for i in range(60, 90):
        tx += int(rng.gauss(1000, 50) * 60)
        events.append(telemetry_event(DEV, T0 + i * 60, seq=i + 1, tx=tx))
    store = StateStore()
    dets = run(BeaconingRule(), events, store=store)
    assert dets
    st = store.get(TENANT, DEV)
    assert st is not None and BeaconingRule().analyse_tx(st) is None


def test_beaconing_periodic_reconnects() -> None:
    periodic: list[DeviceEvent] = [
        auth(AuthKind.CONNECTED, T0 + i * 120 + (i % 2)) for i in range(8)
    ]
    dets = run(BeaconingRule(), periodic)
    assert dets and dets[-1].features["channel"] == "reconnects"
    rng = random.Random(4)
    t = T0
    jittered: list[DeviceEvent] = []
    for i in range(12):  # exponential backoff with full jitter (contract section 4)
        t += rng.uniform(0, min(300, 2**i))
        jittered.append(auth(AuthKind.CONNECTED, t))
    assert run(BeaconingRule(), jittered) == []
    slow: list[DeviceEvent] = [auth(AuthKind.CONNECTED, T0 + i * 7200) for i in range(8)]
    assert run(BeaconingRule(BeaconingParams(connect_window_s=10**6)), slow) == []


def test_beaconing_params_validation() -> None:
    with pytest.raises(InvalidRuleParams):
        BeaconingRule.parse_params({"min_lag": 10, "max_lag": 5})


# -------------------------------------------------------------------------- isolation_forest


def _if_ctx(raw: RawScore | None) -> RuleContext:
    return RuleContext(now=T0, device_class=GATEWAY, scorer=lambda st, x: raw)


def test_isolation_forest_rule_gates() -> None:
    rule = IsolationForestRule()
    store = StateStore()
    events = [telemetry_event(DEV, T0 + i * 60, seq=i + 1, tx=i * 1000) for i in range(60)]
    for ev in events[:-1]:
        store.apply(ev, GATEWAY)
    ev = events[-1]
    obs = store.apply(ev, GATEWAY)
    st = store.get(TENANT, DEV)
    assert st is not None
    hot = RawScore(0.2, 9.0, {"cpu_pct": 9.0}, 0.9, T0)
    det = rule.evaluate(ev, st, obs, _if_ctx(hot))
    assert (
        det is not None
        and det.rule is RuleName.ISOLATION_FOREST
        and det.score == pytest.approx(0.9)
    )
    assert (
        rule.evaluate(ev, st, obs, _if_ctx(RawScore(-0.1, 9.0, {}, 0.4, T0))) is None
    )  # class says normal
    assert (
        rule.evaluate(ev, st, obs, _if_ctx(RawScore(0.2, 2.0, {}, 0.4, T0))) is None
    )  # device says normal
    assert (
        rule.evaluate(ev, st, obs, _if_ctx(RawScore(0.2, 9.0, {}, 0.9, None))) is None
    )  # no model
    assert rule.evaluate(ev, st, obs, _if_ctx(None)) is None
    assert rule.evaluate(ev, st, obs, RuleContext(now=T0)) is None  # no scorer
    st.sample_count = 10
    assert rule.evaluate(ev, st, obs, _if_ctx(hot)) is None  # cold start


def test_isolation_forest_min_consecutive() -> None:
    rule = build_rule(RuleName.ISOLATION_FOREST, RuleOverride(params={"min_consecutive": 2}))
    st = DeviceState(TENANT, DEV, GATEWAY, sample_count=100)
    ev = telemetry_event(DEV, T0)
    from ironmesh_anomaly.state import Observation

    obs = Observation(features=[0.0] * 10)
    hot = RawScore(0.2, 9.0, {}, 0.9, T0)
    assert rule.evaluate(ev, st, obs, _if_ctx(hot)) is None
    assert rule.evaluate(ev, st, obs, _if_ctx(hot)) is not None


# --------------------------------------------------------------------------------- rule set


def test_ruleset_overrides_and_describe() -> None:
    rs = RuleSet(
        {
            RuleName.AUTH_BURST: RuleOverride(
                enabled=False, severity=Severity.LOW, params={"threshold": 3}, dry_run=True
            )
        }
    )
    ab = rs[RuleName.AUTH_BURST]
    assert isinstance(ab, AuthBurstRule)
    assert ab.params.threshold == 3 and ab.params.window_s == 60
    d = ab.describe()
    assert d == {
        "name": "auth_burst",
        "enabled": False,
        "severity": "low",
        "params": ab.params.model_dump(),
        "description": AuthBurstRule.description,
        "dry_run": True,
    }
    assert {r.name for r in rs} == set(RuleName)
    assert rs.isolation_forest.params.contamination == 0.01


def test_invalid_params_rejected() -> None:
    with pytest.raises(InvalidRuleParams) as info:
        build_rule(RuleName.AUTH_BURST, RuleOverride(params={"threshold": 0}))
    assert info.value.errors[0]["loc"] == ["threshold"]
    with pytest.raises(InvalidRuleParams):
        build_rule(RuleName.AUTH_BURST, RuleOverride(params={"unknown": 1}))
