"""Resolution of a device's certificate public key from the envelope ``kid`` (cert serial).

The PKI implementation calls ``GET /v1/certificates/{serial}`` (services/pki) and accepts the
key only when the certificate is ``valid`` and bound to the same tenant and device the bridge
reported for the MQTT topic, so a device can never report status on behalf of another.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol
from uuid import UUID

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

CACHE_TTL_S = 300.0


class DeviceKeyResolver(Protocol):
    async def resolve(
        self, tenant_id: UUID, device_id: str, kid: bytes
    ) -> ec.EllipticCurvePublicKey | None: ...


class StaticDeviceKeyResolver:
    def __init__(self) -> None:
        self.keys: dict[tuple[UUID, str, bytes], ec.EllipticCurvePublicKey] = {}

    def add(
        self, tenant_id: UUID, device_id: str, kid: bytes, key: ec.EllipticCurvePublicKey
    ) -> None:
        self.keys[(tenant_id, device_id, kid)] = key

    async def resolve(
        self, tenant_id: UUID, device_id: str, kid: bytes
    ) -> ec.EllipticCurvePublicKey | None:
        return self.keys.get((tenant_id, device_id, kid))


class PkiDeviceKeyResolver:
    def __init__(self, client: httpx.AsyncClient, token: Callable[[str], str]) -> None:
        self._http = client
        self._token = token
        self._cache: dict[tuple[UUID, str, bytes], tuple[float, ec.EllipticCurvePublicKey]] = {}

    async def resolve(
        self, tenant_id: UUID, device_id: str, kid: bytes
    ) -> ec.EllipticCurvePublicKey | None:
        cache_key = (tenant_id, device_id, kid)
        hit = self._cache.get(cache_key)
        now = time.monotonic()
        if hit is not None and hit[0] > now:
            return hit[1]
        resp = await self._http.get(
            f"/v1/certificates/{kid.hex()}",
            headers={"Authorization": f"Bearer {self._token('pki')}"},
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        body = resp.json()
        if (
            body.get("status") != "valid"
            or body.get("device_id") != device_id
            or body.get("tenant_id") != str(tenant_id)
            or not body.get("certificate_pem")
        ):
            return None
        cert = x509.load_pem_x509_certificate(str(body["certificate_pem"]).encode())
        key = cert.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return None
        self._cache[cache_key] = (now + CACHE_TTL_S, key)
        return key
