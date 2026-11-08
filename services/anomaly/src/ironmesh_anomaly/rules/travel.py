"""``impossible_travel``: consecutive location fixes implying a speed above ``max_speed_kmh``.

Fix sources: GPS coordinates reported in telemetry (keys 14/15, mobile device classes) and the
offline GeoIP location of the broker connection's source IP (``im.auth`` ``connected`` events).
GeoIP fixes are imprecise, so the accuracy radii of both fixes are subtracted from the distance
before computing the speed (a conservative lower bound of the true distance).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from ironmesh_anomaly.geo import haversine_km
from ironmesh_anomaly.models import (
    AuthEvent,
    AuthKind,
    Detection,
    DeviceEvent,
    RuleName,
    Severity,
    TelemetryEvent,
)
from ironmesh_anomaly.state import DeviceState, Fix, Observation

from .base import Rule, RuleContext, RuleParams


class ImpossibleTravelParams(RuleParams):
    max_speed_kmh: float = Field(900.0, gt=0, le=100_000)
    min_distance_km: float = Field(5.0, ge=0, le=20_000)
    min_dt_s: float = Field(1.0, gt=0, le=3600)
    use_gps: bool = True
    use_ip: bool = True


class ImpossibleTravelRule(Rule[ImpossibleTravelParams]):
    name: ClassVar[RuleName] = RuleName.IMPOSSIBLE_TRAVEL
    description: ClassVar[str] = (
        "Haversine speed between consecutive GPS fixes or GeoIP-located connect source IPs exceeds "
        "max_speed_kmh (GeoIP accuracy radii are subtracted from the distance)."
    )
    default_severity: ClassVar[Severity] = Severity.HIGH
    params_model: ClassVar[type[RuleParams]] = ImpossibleTravelParams

    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        p = self.params
        if isinstance(event, TelemetryEvent) and p.use_gps:
            return self._check(event, obs.prev_gps, obs.new_gps, "gps", None)
        if isinstance(event, AuthEvent) and event.event is AuthKind.CONNECTED and p.use_ip:
            return self._check(event, obs.prev_ip_fix, obs.new_ip_fix, "geoip", event.peerhost)
        return None

    def _check(
        self,
        event: DeviceEvent,
        prev: Fix | None,
        new: Fix | None,
        source: str,
        source_ip: str | None,
    ) -> Detection | None:
        if prev is None or new is None:
            return None
        p = self.params
        raw_km = haversine_km(prev.lat, prev.lon, new.lat, new.lon)
        distance = max(0.0, raw_km - prev.accuracy_km - new.accuracy_km)
        if distance < p.min_distance_km:
            return None
        dt = max(abs(new.ts - prev.ts), p.min_dt_s)
        speed = distance / (dt / 3600.0)
        if speed <= p.max_speed_kmh:
            return None
        return self.detection(
            event,
            score=1.0 - p.max_speed_kmh / speed,
            explanation=(
                f"Device moved {distance:.0f} km in {dt:.0f} s ({speed:.0f} km/h > "
                f"{p.max_speed_kmh:.0f} km/h) between consecutive {source} fixes"
            ),
            features={
                "source": source,
                "distance_km": round(distance, 3),
                "elapsed_s": round(dt, 3),
                "speed_kmh": round(speed, 1),
                "max_speed_kmh": p.max_speed_kmh,
                "from": {"lat": prev.lat, "lon": prev.lon, "ts": prev.ts, "via": prev.source},
                "to": {"lat": new.lat, "lon": new.lon, "ts": new.ts, "via": new.source},
            },
            source_ip=source_ip,
        )
