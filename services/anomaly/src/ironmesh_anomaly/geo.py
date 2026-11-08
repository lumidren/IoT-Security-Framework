"""Geodesy helpers and the offline GeoIP provider protocol.

The production provider reads a MaxMind GeoLite2-City database (``.mmdb``) from a configured path
with the ``maxminddb`` reader; no network lookups are ever made. Tests use
:class:`StaticGeoIPProvider`.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol

import maxminddb

EARTH_RADIUS_KM: Final = 6371.0088  # IUGG mean Earth radius


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance (km).

    ``d = 2R * asin(sqrt(sin^2(dphi/2) + cos(phi1) cos(phi2) sin^2(dlambda/2)))``
    """
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlmb = math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))


def valid_coordinates(lat: float, lon: float) -> bool:
    return (
        math.isfinite(lat)
        and math.isfinite(lon)
        and -90.0 <= lat <= 90.0
        and -180.0 <= lon <= 180.0
    )


@dataclass(frozen=True, slots=True)
class GeoLocation:
    lat: float
    lon: float
    accuracy_km: float = 0.0
    country: str | None = None


class GeoIPProvider(Protocol):
    def lookup(self, ip: str) -> GeoLocation | None: ...


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


class NullGeoIPProvider:
    """Used when no database is configured: IP-based travel checks are disabled."""

    def lookup(self, ip: str) -> GeoLocation | None:
        return None


class StaticGeoIPProvider:
    """Dictionary-backed provider for tests and air-gapped overrides."""

    def __init__(self, table: Mapping[str, GeoLocation]) -> None:
        self._table = dict(table)

    def lookup(self, ip: str) -> GeoLocation | None:
        return self._table.get(ip)


class MaxMindGeoIPProvider:
    """Offline GeoLite2-City reader. Private/reserved addresses are never looked up."""

    def __init__(self, db_path: str) -> None:
        self._reader = maxminddb.open_database(db_path)

    def lookup(self, ip: str) -> GeoLocation | None:
        if not is_public_ip(ip):
            return None
        record = self._reader.get(ip)
        if not isinstance(record, dict):
            return None
        location = record.get("location")
        if not isinstance(location, dict):
            return None
        lat, lon = location.get("latitude"), location.get("longitude")
        if not isinstance(lat, int | float) or not isinstance(lon, int | float):
            return None
        radius = location.get("accuracy_radius")
        country = record.get("country")
        iso = country.get("iso_code") if isinstance(country, dict) else None
        return GeoLocation(
            lat=float(lat),
            lon=float(lon),
            accuracy_km=float(radius) if isinstance(radius, int | float) else 0.0,
            country=iso if isinstance(iso, str) else None,
        )

    def close(self) -> None:
        self._reader.close()


def build_geoip_provider(db_path: str | None) -> GeoIPProvider:
    if db_path:
        return MaxMindGeoIPProvider(db_path)
    return NullGeoIPProvider()
