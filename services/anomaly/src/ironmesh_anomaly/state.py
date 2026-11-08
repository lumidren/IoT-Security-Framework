"""Per-device streaming state keyed by ``(tenant_id, device_id)``.

The store lives in memory (it is on the hot path of every event) and is snapshotted periodically
to the repository; on start-up the snapshot is restored. Every buffer is bounded so that memory
per device is O(1).

:meth:`StateStore.apply` folds one event into the state and returns an :class:`Observation`
describing the transition (previous GPS fix, previous firmware hash, the new feature vector, ...).
Rules are pure functions of ``(event, state, observation, params)``; this separation lets the
rule dry-run endpoint replay stored events through a fresh store.
"""

from __future__ import annotations

import math
from collections import OrderedDict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Final

from .features import (
    FEATURE_NAMES,
    MSG_RATE_WINDOW_S,
    counter_delta,
    log_rate,
    msg_rate_per_min,
    opt,
)
from .geo import GeoIPProvider, GeoLocation, NullGeoIPProvider, valid_coordinates
from .models import AuthEvent, AuthKind, DeviceEvent, OtaStatusEvent, TelemetryEvent

AUTH_WINDOW_MAX_S: Final = 3600.0
DENY_WINDOW_MAX_S: Final = 86400.0
MAX_AUTH_ENTRIES: Final = 4096
MAX_CONNECTS: Final = 64
MAX_TX_SERIES: Final = 256
MAX_FEATURES: Final = 256
MAX_SCORES: Final = 100
MAX_MSG_TIMES: Final = 512
MAX_IP_STATES: Final = 100_000
OTA_SUCCESS: Final = 5


@dataclass(slots=True)
class Fix:
    ts: float
    lat: float
    lon: float
    accuracy_km: float = 0.0
    source: str = "gps"  # "gps" | "ip:<addr>"

    def to_list(self) -> list[Any]:
        return [self.ts, self.lat, self.lon, self.accuracy_km, self.source]

    @classmethod
    def from_list(cls, data: list[Any] | None) -> Fix | None:
        if not data:
            return None
        return cls(float(data[0]), float(data[1]), float(data[2]), float(data[3]), str(data[4]))


@dataclass(slots=True)
class DeviceState:
    tenant_id: str
    device_id: str
    device_class: str = "unknown"
    sample_count: int = 0
    last_ts: float | None = None
    last_rx: int | None = None
    last_tx: int | None = None
    last_auth_failures: int | None = None
    last_uptime: int | None = None
    msg_times: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_MSG_TIMES))
    gps_fix: Fix | None = None
    ip_fix: Fix | None = None
    auth_failures: deque[tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=MAX_AUTH_ENTRIES)
    )
    reported_failures: deque[tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=MAX_AUTH_ENTRIES)
    )
    """Failures counted by the device itself (telemetry ``auth_failures`` deltas)."""
    denies: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_AUTH_ENTRIES))
    connects: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_CONNECTS))
    tx_series: deque[tuple[float, float]] = field(
        default_factory=lambda: deque(maxlen=MAX_TX_SERIES)
    )
    fw_last_seen: str | None = None
    fw_last_installed: str | None = None
    fw_installed_at: float | None = None
    features: deque[tuple[float, list[float]]] = field(
        default_factory=lambda: deque(maxlen=MAX_FEATURES)
    )
    scores: deque[tuple[float, float]] = field(default_factory=lambda: deque(maxlen=MAX_SCORES))
    quarantined: bool = False
    last_seq: int | None = None
    """Last accepted uplink envelope ``seq`` (replay protection across restarts)."""
    if_streak: int = 0
    """Consecutive samples the Isolation Forest rule considered anomalous."""
    dirty: bool = True

    @property
    def key(self) -> tuple[str, str]:
        return (self.tenant_id, self.device_id)

    def auth_failures_in(self, window_s: float, now: float, *, reported: bool = False) -> int:
        lo = now - window_s
        total = sum(c for t, c in self.auth_failures if lo < t <= now)
        if reported:
            total += sum(c for t, c in self.reported_failures if lo < t <= now)
        return total

    def denies_in(self, window_s: float, now: float) -> int:
        lo = now - window_s
        return sum(1 for t in self.denies if lo < t <= now)

    # -- snapshot ------------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "device_class": self.device_class,
            "sample_count": self.sample_count,
            "last_ts": self.last_ts,
            "last_rx": self.last_rx,
            "last_tx": self.last_tx,
            "last_auth_failures": self.last_auth_failures,
            "last_uptime": self.last_uptime,
            "msg_times": list(self.msg_times),
            "gps_fix": self.gps_fix.to_list() if self.gps_fix else None,
            "ip_fix": self.ip_fix.to_list() if self.ip_fix else None,
            "auth_failures": [list(x) for x in self.auth_failures],
            "reported_failures": [list(x) for x in self.reported_failures],
            "denies": list(self.denies),
            "connects": list(self.connects),
            "tx_series": [list(x) for x in self.tx_series],
            "fw_last_seen": self.fw_last_seen,
            "fw_last_installed": self.fw_last_installed,
            "fw_installed_at": self.fw_installed_at,
            "features": [[t, [None if math.isnan(v) else v for v in f]] for t, f in self.features],
            "scores": [list(x) for x in self.scores],
            "quarantined": self.quarantined,
            "last_seq": self.last_seq,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DeviceState:
        st = cls(tenant_id=d["tenant_id"], device_id=d["device_id"])
        st.device_class = d.get("device_class", "unknown")
        st.sample_count = int(d.get("sample_count", 0))
        st.last_ts = d.get("last_ts")
        st.last_rx = d.get("last_rx")
        st.last_tx = d.get("last_tx")
        st.last_auth_failures = d.get("last_auth_failures")
        st.last_uptime = d.get("last_uptime")
        st.msg_times.extend(float(x) for x in d.get("msg_times", []))
        st.gps_fix = Fix.from_list(d.get("gps_fix"))
        st.ip_fix = Fix.from_list(d.get("ip_fix"))
        st.auth_failures.extend((float(t), int(c)) for t, c in d.get("auth_failures", []))
        st.reported_failures.extend((float(t), int(c)) for t, c in d.get("reported_failures", []))
        st.denies.extend(float(x) for x in d.get("denies", []))
        st.connects.extend(float(x) for x in d.get("connects", []))
        st.tx_series.extend((float(t), float(r)) for t, r in d.get("tx_series", []))
        st.fw_last_seen = d.get("fw_last_seen")
        st.fw_last_installed = d.get("fw_last_installed")
        st.fw_installed_at = d.get("fw_installed_at")
        st.features.extend(
            (float(t), [math.nan if v is None else float(v) for v in f])
            for t, f in d.get("features", [])
        )
        st.scores.extend((float(t), float(s)) for t, s in d.get("scores", []))
        st.quarantined = bool(d.get("quarantined", False))
        st.last_seq = d.get("last_seq")
        st.dirty = False
        return st


@dataclass(slots=True)
class Observation:
    """What changed when one event was applied (input to the rules)."""

    prev_gps: Fix | None = None
    new_gps: Fix | None = None
    prev_ip_fix: Fix | None = None
    new_ip_fix: Fix | None = None
    prev_fw_seen: str | None = None
    tx_rate: float | None = None
    features: list[float] | None = None
    ip_entries: deque[tuple[float, str]] | None = None
    """Recent authentication failures from the event's source IP: ``(ts, device_id)``."""


class StateStore:
    def __init__(self, geoip: GeoIPProvider | None = None) -> None:
        self._devices: dict[tuple[str, str], DeviceState] = {}
        self._ip_failures: OrderedDict[tuple[str, str], deque[tuple[float, str]]] = OrderedDict()
        self._geoip = geoip or NullGeoIPProvider()

    def __len__(self) -> int:
        return len(self._devices)

    def __iter__(self) -> Iterator[DeviceState]:
        return iter(list(self._devices.values()))

    def get(self, tenant_id: str, device_id: str) -> DeviceState | None:
        return self._devices.get((tenant_id, device_id))

    def get_or_create(self, tenant_id: str, device_id: str, device_class: str) -> DeviceState:
        key = (tenant_id, device_id)
        st = self._devices.get(key)
        if st is None:
            st = DeviceState(tenant_id=tenant_id, device_id=device_id, device_class=device_class)
            self._devices[key] = st
        elif device_class != "unknown" and st.device_class != device_class:
            st.device_class = device_class
            st.dirty = True
        return st

    def put(self, state: DeviceState) -> None:
        self._devices[state.key] = state

    def tenants(self) -> set[str]:
        return {t for t, _ in self._devices}

    def dirty_states(self) -> list[DeviceState]:
        return [s for s in self._devices.values() if s.dirty]

    def ip_failures_in(self, tenant_id: str, ip: str, window_s: float, now: float) -> int:
        entries = self._ip_failures.get((tenant_id, ip))
        if not entries:
            return 0
        lo = now - window_s
        return sum(1 for t, _ in entries if lo < t <= now)

    # ------------------------------------------------------------------------------------
    def apply(self, event: DeviceEvent, device_class: str = "unknown") -> Observation:
        st = self.get_or_create(event.tenant_id, event.device_id, device_class)
        st.dirty = True
        if isinstance(event, TelemetryEvent):
            return self._apply_telemetry(st, event)
        if isinstance(event, AuthEvent):
            return self._apply_auth(st, event)
        return self._apply_ota(st, event)

    def _apply_telemetry(self, st: DeviceState, ev: TelemetryEvent) -> Observation:
        obs = Observation(prev_gps=st.gps_fix, prev_fw_seen=st.fw_last_seen)
        dt = ev.ts - st.last_ts if st.last_ts is not None else 0.0
        rx_delta = counter_delta(ev.net_rx_bytes, st.last_rx)
        tx_delta = counter_delta(ev.net_tx_bytes, st.last_tx)
        af_delta = counter_delta(ev.auth_failures, st.last_auth_failures)
        if st.last_uptime is not None and ev.uptime_s < st.last_uptime:
            # reboot: counters restarted from zero
            rx_delta, tx_delta, af_delta = ev.net_rx_bytes, ev.net_tx_bytes, ev.auth_failures
        st.msg_times.append(ev.ts)
        window = [t for t in st.msg_times if ev.ts - MSG_RATE_WINDOW_S <= t <= ev.ts]
        if dt > 0:
            tx_rate = tx_delta / dt
            obs.tx_rate = tx_rate
            st.tx_series.append((ev.ts, tx_rate))
            features = [
                ev.cpu_pct,
                ev.mem_pct,
                ev.temp_c,
                log_rate(rx_delta, dt),
                log_rate(tx_delta, dt),
                opt(ev.proc_count),
                float(af_delta),
                opt(ev.rssi),
                math.log1p(ev.free_heap) if ev.free_heap is not None else math.nan,
                msg_rate_per_min(window),
            ]
            assert len(features) == len(FEATURE_NAMES)
            obs.features = features
            st.features.append((ev.ts, features))
            st.sample_count += 1
        if af_delta > 0 and st.last_auth_failures is not None:
            st.reported_failures.append((ev.ts, af_delta))
        if ev.lat is not None and ev.lon is not None and valid_coordinates(ev.lat, ev.lon):
            fix = Fix(ev.ts, ev.lat, ev.lon)
            obs.new_gps = fix
            st.gps_fix = fix
        st.fw_last_seen = ev.fw_hash_hex
        st.last_ts = max(ev.ts, st.last_ts or ev.ts)
        st.last_rx, st.last_tx = ev.net_rx_bytes, ev.net_tx_bytes
        st.last_auth_failures, st.last_uptime = ev.auth_failures, ev.uptime_s
        self._prune(st, ev.ts)
        return obs

    def _apply_auth(self, st: DeviceState, ev: AuthEvent) -> Observation:
        obs = Observation(prev_ip_fix=st.ip_fix)
        if ev.event in (AuthKind.AUTHN_FAILED, AuthKind.ENVELOPE_REJECTED):
            st.auth_failures.append((ev.ts, 1))
            if ev.peerhost:
                key = (ev.tenant_id, ev.peerhost)
                entries = self._ip_failures.get(key)
                if entries is None:
                    entries = deque(maxlen=MAX_AUTH_ENTRIES)
                    self._ip_failures[key] = entries
                    while len(self._ip_failures) > MAX_IP_STATES:
                        self._ip_failures.popitem(last=False)
                else:
                    self._ip_failures.move_to_end(key)
                entries.append((ev.ts, ev.device_id))
                while entries and entries[0][0] < ev.ts - AUTH_WINDOW_MAX_S:
                    entries.popleft()
                obs.ip_entries = entries
        elif ev.event is AuthKind.AUTHZ_DENIED:
            st.denies.append(ev.ts)
        elif ev.event is AuthKind.CONNECTED:
            st.connects.append(ev.ts)
            if ev.peerhost:
                loc: GeoLocation | None = self._geoip.lookup(ev.peerhost)
                if loc is not None and valid_coordinates(loc.lat, loc.lon):
                    fix = Fix(ev.ts, loc.lat, loc.lon, loc.accuracy_km, f"ip:{ev.peerhost}")
                    obs.new_ip_fix = fix
                    st.ip_fix = fix
        self._prune(st, ev.ts)
        return obs

    def _apply_ota(self, st: DeviceState, ev: OtaStatusEvent) -> Observation:
        if ev.state == OTA_SUCCESS and ev.fw_hash_hex:
            st.fw_last_installed = ev.fw_hash_hex
            st.fw_installed_at = ev.ts
            # an authorized install legitimately changes the running hash
            st.fw_last_seen = ev.fw_hash_hex
        return Observation(prev_fw_seen=st.fw_last_seen)

    @staticmethod
    def _prune(st: DeviceState, now: float) -> None:
        for buf in (st.auth_failures, st.reported_failures):
            while buf and buf[0][0] < now - AUTH_WINDOW_MAX_S:
                buf.popleft()
        while st.denies and st.denies[0] < now - DENY_WINDOW_MAX_S:
            st.denies.popleft()
