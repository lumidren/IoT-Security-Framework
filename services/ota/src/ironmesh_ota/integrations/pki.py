"""PKI tenant policy: the OTA service owns the firmware-key field (API_CONTRACT §5).

``PUT /v1/tenants/{tenant}/firmware-keys`` with ``{public_keys_b64: [...]}`` (Ed25519 32-byte and
ML-DSA-65 1952-byte public keys) so EST bundles carry the keys devices verify manifests with.
Calls authenticate with the service's ES256 JWT (``aud=pki``) over mTLS.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

import httpx


class PkiPolicyError(Exception):
    pass


class PkiPolicyClient(Protocol):
    async def put_firmware_keys(self, tenant_id: UUID, public_keys: Sequence[bytes]) -> None: ...


def firmware_keys_body(public_keys: Sequence[bytes]) -> dict[str, list[str]]:
    return {"public_keys_b64": [base64.b64encode(k).decode() for k in public_keys]}


class HttpPkiPolicyClient:
    def __init__(self, client: httpx.AsyncClient, token: Callable[[str], str]) -> None:
        self._http = client
        self._token = token

    async def put_firmware_keys(self, tenant_id: UUID, public_keys: Sequence[bytes]) -> None:
        path = f"/v1/tenants/{tenant_id}/firmware-keys"
        try:
            resp = await self._http.put(
                path,
                json=firmware_keys_body(public_keys),
                headers={"Authorization": f"Bearer {self._token('pki')}"},
            )
        except httpx.HTTPError as exc:
            raise PkiPolicyError(f"PUT {path}: {type(exc).__name__}") from exc
        if not 200 <= resp.status_code < 300:
            raise PkiPolicyError(f"PUT {path}: HTTP {resp.status_code}")


@dataclass
class FakePkiPolicy:
    """Records pushes (tests and ``memory`` dev runs); ``fail`` upcoming calls raise."""

    firmware_keys: dict[UUID, list[bytes]] = field(default_factory=dict)
    calls: list[UUID] = field(default_factory=list)
    fail: int = 0

    async def put_firmware_keys(self, tenant_id: UUID, public_keys: Sequence[bytes]) -> None:
        if self.fail > 0:
            self.fail -= 1
            raise PkiPolicyError("pki unavailable")
        self.calls.append(tenant_id)
        self.firmware_keys[tenant_id] = list(public_keys)
