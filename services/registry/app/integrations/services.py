"""HTTP clients for the PKI and OTA services (mTLS + ES256 service JWT), with fakes for tests."""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from ironmesh_wire import ids

from ..auth import ServiceTokenMinter
from ..jsonutil import parse_rfc3339


class UpstreamError(Exception):
    """A dependency call failed (network error or unexpected status)."""


def normalize_serial(serial_hex: str) -> str:
    """Canonical serial: lower-case hex of the minimal big-endian integer (== device kid)."""
    value = int(serial_hex.replace(":", ""), 16)
    return ids.kid_from_serial(value).hex()


@dataclass(frozen=True, slots=True)
class PkiCertificate:
    serial_hex: str
    device_id: str
    tenant_id: str
    not_before: datetime
    not_after: datetime
    status: str  # valid | revoked | expired
    issuer: str
    public_key: ec.EllipticCurvePublicKey | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


def certificate_from_view(view: dict[str, Any]) -> PkiCertificate:
    """Parse the PKI ``certificateView`` JSON; the identity is taken from the X.509 subject."""
    revocation = view.get("revocation") or {}
    public_key = None
    device_id = str(view.get("device_id", ""))
    tenant_id = str(view.get("tenant_id", ""))
    pem = view.get("certificate_pem")
    if pem:
        cert = x509.load_pem_x509_certificate(str(pem).encode())
        key = cert.public_key()
        if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1":
            public_key = key
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if cn:
            device_id = str(cn[0].value)
        if ou:
            tenant_id = str(ou[0].value).removeprefix("bootstrap:")
    return PkiCertificate(
        serial_hex=normalize_serial(str(view["serial"])),
        device_id=device_id,
        tenant_id=tenant_id,
        not_before=parse_rfc3339(str(view["not_before"])),
        not_after=parse_rfc3339(str(view["not_after"])),
        status=str(view.get("status", "valid")),
        issuer=str(view.get("issuer", "")),
        public_key=public_key,
        revoked_at=parse_rfc3339(revocation["revoked_at"])
        if revocation.get("revoked_at")
        else None,
        revocation_reason=revocation.get("reason"),
    )


class PkiClient(Protocol):
    async def revoke_all(self, device_id: str, reason: str) -> int: ...
    async def device_certificates(self, device_id: str) -> list[PkiCertificate]: ...
    async def get_certificate(self, serial_hex: str) -> PkiCertificate | None: ...
    def invalidate(self, device_id: str) -> None: ...


class OtaClient(Protocol):
    async def forward_status(self, payload: dict[str, Any]) -> None: ...


def build_http_client(
    timeout: float, ca_file: str | None, cert_file: str | None, key_file: str | None
) -> httpx.AsyncClient:
    verify: ssl.SSLContext | bool = True
    if ca_file or cert_file:
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert_file and key_file:
            ctx.load_cert_chain(cert_file, key_file)
        verify = ctx
    return httpx.AsyncClient(timeout=timeout, verify=verify)


class _Cache:
    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self.items: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any:
        hit = self.items.get(key)
        if hit is None or time.monotonic() - hit[0] > self.ttl:
            return None
        return hit[1]

    def put(self, key: str, value: Any) -> None:
        self.items[key] = (time.monotonic(), value)

    def drop(self, key: str) -> None:
        self.items.pop(key, None)


class HttpPkiClient:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        minter: ServiceTokenMinter,
        cache_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.minter = minter
        self.device_cache = _Cache(cache_seconds)
        self.cert_cache = _Cache(cache_seconds)

    def _headers(self) -> dict[str, str]:
        token = self.minter.token("pki")
        return {"Authorization": f"Bearer {token}"} if token else {}

    async def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            resp = await self.client.request(
                method, self.base_url + path, headers=self._headers(), **kw
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(f"pki {method} {path}: {exc}") from exc
        if resp.status_code >= 500 or resp.status_code in (401, 403):
            raise UpstreamError(f"pki {method} {path}: HTTP {resp.status_code}")
        return resp

    async def revoke_all(self, device_id: str, reason: str) -> int:
        resp = await self._request(
            "POST", f"/v1/devices/{device_id}/revoke-all", json={"reason": reason}
        )
        if resp.status_code != 200:
            raise UpstreamError(f"pki revoke-all: HTTP {resp.status_code}")
        self.invalidate(device_id)
        return int(resp.json().get("count", 0))

    async def device_certificates(self, device_id: str) -> list[PkiCertificate]:
        cached = self.device_cache.get(device_id)
        if cached is not None:
            return list(cached)
        resp = await self._request("GET", f"/v1/devices/{device_id}/certificates")
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise UpstreamError(f"pki certificates: HTTP {resp.status_code}")
        certs = [certificate_from_view(v) for v in resp.json().get("certificates", [])]
        self.device_cache.put(device_id, certs)
        return certs

    async def get_certificate(self, serial_hex: str) -> PkiCertificate | None:
        serial = normalize_serial(serial_hex)
        cached = self.cert_cache.get(serial)
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        resp = await self._request("GET", f"/v1/certificates/{serial}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise UpstreamError(f"pki certificate: HTTP {resp.status_code}")
        cert = certificate_from_view(resp.json())
        self.cert_cache.put(serial, cert)
        return cert

    def invalidate(self, device_id: str) -> None:
        self.device_cache.drop(device_id)
        for serial, (_, cert) in list(self.cert_cache.items.items()):
            if cert.device_id == device_id:
                self.cert_cache.drop(serial)


class HttpOtaClient:
    def __init__(
        self, base_url: str, client: httpx.AsyncClient, minter: ServiceTokenMinter
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.minter = minter

    async def forward_status(self, payload: dict[str, Any]) -> None:
        token = self.minter.token("ota")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            resp = await self.client.post(
                f"{self.base_url}/internal/v1/ota/status", json=payload, headers=headers
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(f"ota status: {exc}") from exc
        if resp.status_code >= 300:
            raise UpstreamError(f"ota status: HTTP {resp.status_code}")


# ------------------------------------------------------------------------------------------------
# Fakes
# ------------------------------------------------------------------------------------------------


@dataclass
class FakePki:
    certs: dict[str, PkiCertificate] = field(default_factory=dict)
    revoked: list[tuple[str, str]] = field(default_factory=list)
    fail_revoke: int = 0
    fail_lookup: bool = False

    def add(self, cert: PkiCertificate) -> None:
        self.certs[cert.serial_hex] = cert

    async def revoke_all(self, device_id: str, reason: str) -> int:
        if self.fail_revoke > 0:
            self.fail_revoke -= 1
            raise UpstreamError("pki unavailable")
        self.revoked.append((device_id, reason))
        n = 0
        for serial, cert in list(self.certs.items()):
            if cert.device_id == device_id and cert.status != "revoked":
                self.certs[serial] = PkiCertificate(
                    **{
                        **{s: getattr(cert, s) for s in cert.__slots__},
                        "status": "revoked",
                        "revocation_reason": reason,
                    }
                )
                n += 1
        return n

    async def device_certificates(self, device_id: str) -> list[PkiCertificate]:
        if self.fail_lookup:
            raise UpstreamError("pki unavailable")
        return sorted(
            (c for c in self.certs.values() if c.device_id == device_id),
            key=lambda c: c.not_before,
            reverse=True,
        )

    async def get_certificate(self, serial_hex: str) -> PkiCertificate | None:
        if self.fail_lookup:
            raise UpstreamError("pki unavailable")
        return self.certs.get(normalize_serial(serial_hex))

    def invalidate(self, device_id: str) -> None:
        return None


@dataclass
class FakeOta:
    statuses: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    async def forward_status(self, payload: dict[str, Any]) -> None:
        if self.fail:
            raise UpstreamError("ota unavailable")
        self.statuses.append(payload)


# ------------------------------------------------------------------------------------------------
# EMQX management API (direct kick, used as containment when the PKI revocation path fails)
# ------------------------------------------------------------------------------------------------


class EmqxClient(Protocol):
    async def kick(self, client_id: str) -> bool: ...


class HttpEmqxClient:
    def __init__(
        self, base_url: str, client: httpx.AsyncClient, key: str | None, secret: str | None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.auth = (key, secret) if key and secret else None

    async def kick(self, client_id: str) -> bool:
        if self.auth is None:
            raise UpstreamError("EMQX API credentials not configured")
        try:
            resp = await self.client.delete(
                f"{self.base_url}/api/v5/clients/{client_id}", auth=self.auth
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(f"emqx kick: {exc}") from exc
        if resp.status_code == 404:
            return False
        if resp.status_code >= 300:
            raise UpstreamError(f"emqx kick: HTTP {resp.status_code}")
        return True


@dataclass
class FakeEmqx:
    kicked: list[str] = field(default_factory=list)
    fail: bool = False

    async def kick(self, client_id: str) -> bool:
        if self.fail:
            raise UpstreamError("emqx unavailable")
        self.kicked.append(client_id)
        return True
