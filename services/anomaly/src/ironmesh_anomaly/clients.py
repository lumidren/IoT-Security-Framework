"""Clients for the upstream services (PKI, OTA, Registry) with caching and retries.

Internal calls use mTLS with a Services CA certificate plus a short-lived ES256 service JWT
(``aud=<service>``; DESIGN_CONTRACT section 7), minted fresh for every request because the PKI,
policy, registry and OTA accept each ``jti`` only once. Every client is defined by a Protocol
so the engine and the tests can substitute fakes.
"""

from __future__ import annotations

import asyncio
import random
import ssl
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

import httpx
import jwt
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ironmesh_wire import ids

from .models import SERVICE_ACTOR_ID, DeviceInfo

log = structlog.get_logger(__name__)

SERVICE_JWT_TTL_S: Final = 60


# --------------------------------------------------------------------------------------------
# Service authentication
# --------------------------------------------------------------------------------------------


SERVICE_NAME = "anomaly"
"""Caller identity in service JWTs: the registry matches ``iss`` against its trusted-key map and
the ``internal("anomaly")`` allowlists, OTA checks ``sub`` against
``OTA_INTERNAL_ALLOWED_SERVICES`` and the PKI accepts ``anomaly`` or ``svc-anomaly``."""


class ServiceTokenSigner:
    """Service credentials per audience.

    A static bearer configured for an audience wins (``ANOMALY_INTERNAL_TOKEN`` for the registry:
    the ``anomaly`` entry of ``REGISTRY_INTERNAL_TOKENS``); otherwise a fresh ES256 service JWT
    (``iss = sub = anomaly``, ``kid = svc-anomaly``, ``aud = <service>``, new random ``jti``,
    ``iat`` = now, ``exp`` = now + 60 s) is minted with the Services CA key for every call. Tokens
    are never cached: the receivers reject a reused ``jti`` with 401.
    """

    def __init__(
        self,
        key: ec.EllipticCurvePrivateKey | None,
        kid: str = SERVICE_ACTOR_ID,
        static_tokens: dict[str, str] | None = None,
    ) -> None:
        self._key = key
        self._kid = kid
        self._static = dict(static_tokens or {})

    @classmethod
    def from_file(
        cls, path: str | None, kid: str, static_tokens: dict[str, str] | None = None
    ) -> ServiceTokenSigner:
        key: ec.EllipticCurvePrivateKey | None = None
        if path and Path(path).is_file():
            loaded = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
            if isinstance(loaded, ec.EllipticCurvePrivateKey):
                key = loaded
            else:
                log.warning("service JWT key is not an EC key; service JWTs disabled", path=path)
        return cls(key, kid, static_tokens)

    def token(self, audience: str) -> str | None:
        static = self._static.get(audience)
        if static:
            return static
        if self._key is None:
            return None
        now = int(time.time())
        return jwt.encode(
            {
                "iss": SERVICE_NAME,
                "sub": SERVICE_NAME,
                "aud": audience,
                "iat": now,
                "nbf": now - 5,
                "exp": now + SERVICE_JWT_TTL_S,
                "jti": str(uuid.uuid4()),
            },
            self._key,
            algorithm="ES256",
            headers={"kid": self._kid},
        )

    def headers(self, audience: str) -> dict[str, str]:
        token = self.token(audience)
        return {"Authorization": f"Bearer {token}"} if token else {}


def build_http_client(
    timeout_s: float,
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    verify: ssl.SSLContext | bool = True
    if ca_file or cert_file:
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert_file:
            ctx.load_cert_chain(cert_file, key_file)
        verify = ctx
    return httpx.AsyncClient(timeout=timeout_s, verify=verify, transport=transport)


async def with_retries[T](
    call: Callable[[], Awaitable[T]],
    *,
    attempts: int,
    base_s: float,
    max_s: float = 10.0,
    retry_if: Callable[[BaseException], bool],
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Exponential backoff with full jitter (``U(0, min(max, base * 2^i))``)."""
    for attempt in range(attempts):
        try:
            return await call()
        except Exception as exc:
            if attempt == attempts - 1 or not retry_if(exc):
                raise
            delay = random.uniform(0, min(max_s, base_s * 2**attempt))  # noqa: S311 backoff jitter, not crypto  # nosec B311
            await sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover


class TTLCache[K, V]:
    def __init__(self, ttl_s: float, max_items: int = 100_000) -> None:
        self._ttl = ttl_s
        self._max = max_items
        self._data: dict[K, tuple[V, float]] = {}

    def get(self, key: K) -> tuple[bool, V | None]:
        hit = self._data.get(key)
        if hit is None:
            return False, None
        value, expires = hit
        if expires < time.monotonic():
            self._data.pop(key, None)
            return False, None
        return True, value

    def set(self, key: K, value: V, ttl_s: float | None = None) -> None:
        if len(self._data) >= self._max:
            self._data.pop(next(iter(self._data)))
        self._data[key] = (value, time.monotonic() + (self._ttl if ttl_s is None else ttl_s))

    def invalidate(self, key: K) -> None:
        self._data.pop(key, None)


def _retryable_http(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500 or exc.response.status_code == 429
    return isinstance(exc, httpx.TransportError)


# --------------------------------------------------------------------------------------------
# PKI: device certificate keys
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CertKey:
    serial_hex: str
    device_id: str
    tenant_id: str
    public_key: ec.EllipticCurvePublicKey
    status: str  # valid | revoked | expired


class KeyLookupError(Exception):
    """The PKI could not be reached (distinct from 'certificate unknown')."""


class CertKeyProvider(Protocol):
    async def get(self, serial_hex: str) -> CertKey | None: ...


def serial_hex_from_kid(kid: bytes) -> str:
    return format(ids.serial_from_kid(kid), "032x")


def parse_cert_view(view: dict[str, Any]) -> CertKey:
    pem = view.get("certificate_pem")
    if not isinstance(pem, str) or not pem:
        raise ValueError("certificate view has no PEM")
    cert = x509.load_pem_x509_certificate(pem.encode())
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("device certificate key is not P-256")
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    device_id = str(view.get("device_id", ""))
    if not cn or cn[0].value != device_id:
        raise ValueError("certificate CN does not match the PKI record's device id")
    serial_hex = format(cert.serial_number, "032x")
    return CertKey(
        serial_hex=serial_hex,
        device_id=device_id,
        tenant_id=str(view.get("tenant_id", "")),
        public_key=key,
        status=str(view.get("status", "valid")),
    )


class HttpCertKeyProvider:
    """``GET /v1/certificates/{serial}`` on the PKI management API, cached (incl. negative)."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        signer: ServiceTokenSigner,
        ttl_s: float = 300.0,
        negative_ttl_s: float = 30.0,
    ) -> None:
        self._client, self._base, self._signer = client, base_url.rstrip("/"), signer
        self._cache: TTLCache[str, CertKey | None] = TTLCache(ttl_s)
        self._negative_ttl = negative_ttl_s

    async def get(self, serial_hex: str) -> CertKey | None:
        hit, value = self._cache.get(serial_hex)
        if hit:
            return value
        try:
            resp = await self._client.get(
                f"{self._base}/v1/certificates/{serial_hex}", headers=self._signer.headers("pki")
            )
        except httpx.TransportError as exc:
            raise KeyLookupError(str(exc)) from exc
        if resp.status_code == 404:
            self._cache.set(serial_hex, None, self._negative_ttl)
            return None
        if resp.status_code >= 400:
            raise KeyLookupError(f"PKI returned {resp.status_code}")
        try:
            key = parse_cert_view(resp.json())
        except ValueError as exc:
            log.warning("pki certificate rejected", serial=serial_hex, error=str(exc))
            self._cache.set(serial_hex, None, self._negative_ttl)
            return None
        # revoked/expired status is cached for a short time only (status can change)
        self._cache.set(serial_hex, key, None if key.status == "valid" else self._negative_ttl)
        return key

    def invalidate(self, serial_hex: str) -> None:
        self._cache.invalidate(serial_hex)


class StaticCertKeyProvider:
    def __init__(self, keys: dict[str, CertKey] | None = None) -> None:
        self.keys = dict(keys or {})
        self.fail = False

    async def get(self, serial_hex: str) -> CertKey | None:
        if self.fail:
            raise KeyLookupError("pki unavailable")
        return self.keys.get(serial_hex)


# --------------------------------------------------------------------------------------------
# OTA: known firmware hashes per product
# --------------------------------------------------------------------------------------------


class KnownHashesProvider(Protocol):
    async def known_hashes(self, product: str) -> frozenset[str] | None: ...


class HttpKnownHashesProvider:
    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        signer: ServiceTokenSigner,
        ttl_s: float = 300.0,
    ) -> None:
        self._client, self._base, self._signer = client, base_url.rstrip("/"), signer
        self._cache: TTLCache[str, frozenset[str]] = TTLCache(ttl_s)

    async def known_hashes(self, product: str) -> frozenset[str] | None:
        hit, value = self._cache.get(product)
        if hit:
            return value
        try:
            resp = await self._client.get(
                f"{self._base}/internal/v1/firmware/known-hashes",
                params={"product": product},
                headers=self._signer.headers("ota"),
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("known hashes unavailable", product=product, error=str(exc))
            return None
        if not isinstance(data, list):
            return None
        hashes = frozenset(h.lower() for h in data if isinstance(h, str) and len(h) == 64)
        self._cache.set(product, hashes)
        return hashes


class StaticKnownHashesProvider:
    def __init__(self, table: dict[str, set[str]] | None = None) -> None:
        self.table = {k: set(v) for k, v in (table or {}).items()}

    async def known_hashes(self, product: str) -> frozenset[str] | None:
        hashes = self.table.get(product)
        return frozenset(hashes) if hashes is not None else None


# --------------------------------------------------------------------------------------------
# Registry: device directory and quarantine action
# --------------------------------------------------------------------------------------------


class DeviceDirectory(Protocol):
    async def lookup(self, device_id: str) -> DeviceInfo | None: ...


class HttpDeviceDirectory:
    """``GET /internal/v1/devices/{id}/lifecycle`` (callers ``policy`` and ``anomaly``) ->
    ``{device_id, tenant_id, state, assurance_level, product}``. ``product`` is the device class
    the engine keeps per-class Isolation Forest models and known-hash sets for."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        signer: ServiceTokenSigner,
        ttl_s: float = 300.0,
    ) -> None:
        self._client, self._base, self._signer = client, base_url.rstrip("/"), signer
        self._cache: TTLCache[str, DeviceInfo | None] = TTLCache(ttl_s)

    async def lookup(self, device_id: str) -> DeviceInfo | None:
        if not ids.is_device_id(device_id):
            return None
        hit, value = self._cache.get(device_id)
        if hit:
            return value
        try:
            resp = await self._client.get(
                f"{self._base}/internal/v1/devices/{device_id}/lifecycle",
                headers=self._signer.headers("registry"),
            )
        except httpx.TransportError as exc:
            log.warning("registry lookup failed", device_id=device_id, error=str(exc))
            return None
        if resp.status_code == 404:
            self._cache.set(device_id, None, 30.0)
            return None
        if resp.status_code >= 400:
            return None
        data = resp.json()
        tenant = data.get("tenant_id")
        if not isinstance(tenant, str) or not ids.is_tenant_id(tenant):
            return None
        product = data.get("product")
        info = DeviceInfo(
            device_id=device_id,
            tenant_id=tenant,
            product=product if isinstance(product, str) and product else "unknown",
            state=str(data.get("state", "active")),
        )
        self._cache.set(device_id, info)
        return info

    def remember(self, info: DeviceInfo) -> None:
        self._cache.set(info.device_id, info)


class StaticDeviceDirectory:
    def __init__(self, devices: dict[str, DeviceInfo] | None = None) -> None:
        self.devices = dict(devices or {})

    async def lookup(self, device_id: str) -> DeviceInfo | None:
        return self.devices.get(device_id)


@dataclass(frozen=True, slots=True)
class QuarantineResult:
    ok: bool
    status: int | None
    detail: str


class QuarantineClient(Protocol):
    async def quarantine(self, device_id: str, reason: str, alert_id: str) -> QuarantineResult: ...


class HttpQuarantineClient:
    """``POST /internal/v1/devices/{id}/quarantine`` (registry revokes certs, drops ACL, kicks)."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        signer: ServiceTokenSigner,
        attempts: int = 4,
        base_s: float = 0.5,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client, self._base, self._signer = client, base_url.rstrip("/"), signer
        self._attempts, self._base_s, self._sleep = attempts, base_s, sleep

    async def quarantine(self, device_id: str, reason: str, alert_id: str) -> QuarantineResult:
        url = f"{self._base}/internal/v1/devices/{ids.validate_device_id(device_id)}/quarantine"

        async def call() -> httpx.Response:
            resp = await self._client.post(
                url,
                json={"reason": reason, "alert_id": alert_id},
                headers={
                    **self._signer.headers("registry"),
                    "Idempotency-Key": f"anomaly-quarantine-{alert_id}",
                },
            )
            if resp.status_code >= 500 or resp.status_code == 429:
                resp.raise_for_status()
            return resp

        try:
            resp = await with_retries(
                call,
                attempts=self._attempts,
                base_s=self._base_s,
                retry_if=_retryable_http,
                sleep=self._sleep,
            )
        except httpx.HTTPError as exc:
            return QuarantineResult(False, None, f"registry unavailable: {exc}")
        if resp.status_code < 300:
            return QuarantineResult(True, resp.status_code, "quarantined")
        if resp.status_code == 409:
            return QuarantineResult(False, 409, "conflict: device decommissioned")
        return QuarantineResult(False, resp.status_code, f"registry returned {resp.status_code}")
