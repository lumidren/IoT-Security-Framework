"""Target resolution through the Registry (API_CONTRACT §1.2 ``GET /v1/devices``).

A device is targeted when it is a member of **any** listed group, **or** listed by id, **or**
carries **all** listed tags. Only ``active`` devices of the firmware's product are eligible;
everything else is reported back as skipped so the campaign audit explains the population.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID

import httpx

from ..domain import Target, TargetDevice

PAGE_LIMIT = 200
MAX_PAGES = 10_000


@dataclass
class Resolution:
    devices: list[TargetDevice] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)


class RegistryClient(Protocol):
    async def resolve(self, tenant_id: UUID, target: Target) -> list[TargetDevice]: ...


def select_eligible(candidates: Iterable[TargetDevice], product: str) -> Resolution:
    out = Resolution()
    seen: set[str] = set()
    for dev in candidates:
        if dev.id in seen:
            continue
        seen.add(dev.id)
        if dev.state != "active":
            out.skipped[dev.id] = f"state {dev.state}"
        elif dev.product != product:
            out.skipped[dev.id] = f"product {dev.product}"
        else:
            out.devices.append(dev)
    return out


def device_from_json(data: dict[str, Any]) -> TargetDevice:
    fw_hex = data.get("fw_hash_hex")
    fw_hash: bytes | None = None
    if isinstance(fw_hex, str) and len(fw_hex) == 64:
        try:
            fw_hash = bytes.fromhex(fw_hex)
        except ValueError:
            fw_hash = None
    tags = data.get("tags") or {}
    return TargetDevice(
        id=str(data["id"]),
        product=str(data.get("product", "")),
        state=str(data.get("state", "")),
        fw_hash=fw_hash,
        fw_version=data.get("fw_version"),
        groups=tuple(data.get("groups") or ()),
        tags={str(k): str(v) for k, v in tags.items()},
    )


class HttpRegistryClient:
    """Calls the registry as service ``ota`` with ``X-IronMesh-Tenant`` set to the tenant."""

    def __init__(self, client: httpx.AsyncClient, token: Callable[[str], str]) -> None:
        self._http = client
        self._token = token

    def _headers(self, tenant_id: UUID) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token('registry')}",
            "X-IronMesh-Tenant": str(tenant_id),
        }

    async def _pages(self, tenant_id: UUID, params: dict[str, str]) -> list[TargetDevice]:
        devices: list[TargetDevice] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            query = dict(params, limit=str(PAGE_LIMIT))
            if cursor:
                query["cursor"] = cursor
            resp = await self._http.get(
                "/v1/devices", params=query, headers=self._headers(tenant_id)
            )
            resp.raise_for_status()
            body = resp.json()
            devices.extend(device_from_json(item) for item in body.get("items", []))
            cursor = body.get("next_cursor")
            if not cursor:
                break
        return devices

    async def resolve(self, tenant_id: UUID, target: Target) -> list[TargetDevice]:
        found: list[TargetDevice] = []
        for group in target.groups:
            found.extend(await self._pages(tenant_id, {"group": group}))
        if target.tags:
            first_key = sorted(target.tags)[0]
            candidates = await self._pages(
                tenant_id, {"tag": f"{first_key}:{target.tags[first_key]}"}
            )
            found.extend(
                d for d in candidates if all(d.tags.get(k) == v for k, v in target.tags.items())
            )
        for device_id in target.device_ids:
            resp = await self._http.get(
                f"/v1/devices/{device_id}", headers=self._headers(tenant_id)
            )
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            found.append(device_from_json(resp.json()))
        return found


class FakeRegistry:
    """In-memory registry for tests and ``memory`` dev runs: ``{tenant: [TargetDevice]}``."""

    def __init__(self) -> None:
        self.devices: dict[UUID, dict[str, TargetDevice]] = {}

    def add(self, tenant_id: UUID, *devices: TargetDevice) -> None:
        bucket = self.devices.setdefault(tenant_id, {})
        for dev in devices:
            bucket[dev.id] = dev

    async def resolve(self, tenant_id: UUID, target: Target) -> list[TargetDevice]:
        out: list[TargetDevice] = []
        for dev in self.devices.get(tenant_id, {}).values():
            in_group = any(g in dev.groups for g in target.groups)
            by_id = dev.id in target.device_ids
            by_tags = bool(target.tags) and all(
                dev.tags.get(k) == v for k, v in target.tags.items()
            )
            if in_group or by_id or by_tags:
                out.append(dev)
        return out
