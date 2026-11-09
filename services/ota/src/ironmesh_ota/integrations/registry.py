"""The registry's internal OTA endpoints (API_CONTRACT §1.12).

* **Targeting**: ``POST /internal/v1/tenants/{tenant}/devices/resolve`` returns the union of the
  campaign's selectors: a device is targeted when it is a member of **any** listed group, **or**
  listed by id, **or** carries **all** listed tags. Only ``active`` devices of the firmware's
  product are eligible; everything else is reported back as skipped so the campaign audit
  explains the population.
* **Downlinks**: the registry is the only holder of the tenant command key. This service hands
  it the OtaNotify body (``bstr`` fields hex-encoded) via
  ``POST /internal/v1/tenants/{tenant}/devices/{id}/downlink``; the registry signs it on the
  device's type-7 replay stream and publishes it to ``.../ota/notify``.

Calls authenticate as service ``ota``: ``OTA_REGISTRY_TOKEN`` (the ``ota`` entry of the
registry's ``REGISTRY_INTERNAL_TOKENS``) or an ES256 service JWT with ``aud=registry``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

import httpx
from opentelemetry import propagate

from ironmesh_wire import envelope

from ..domain import Target, TargetDevice


@dataclass
class Resolution:
    devices: list[TargetDevice] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Downlink:
    """One OtaNotify for the registry to sign and publish (queued until the commit)."""

    tenant_id: UUID
    campaign_id: UUID
    device_id: str
    body: envelope.OtaNotify
    retain: bool = True


@dataclass(frozen=True)
class DownlinkReceipt:
    seq: int
    published_at: datetime


class RegistryError(Exception):
    """The registry refused or could not serve a call (``status`` 0 = transport error)."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"registry HTTP {status}: {detail}" if status else detail)
        self.status = status
        self.detail = detail


class RegistryClient(Protocol):
    async def resolve(self, tenant_id: UUID, target: Target) -> list[TargetDevice]: ...

    async def ota_notify(self, downlink: Downlink) -> DownlinkReceipt: ...


def notify_json(body: envelope.OtaNotify) -> dict[str, Any]:
    """DESIGN_CONTRACT §5 OtaNotify body as JSON, ``bstr`` fields hex-encoded."""
    return {
        "campaign_id": body.campaign_id,
        "manifest": body.manifest.hex(),
        "url": body.url,
        "delta_from": body.delta_from.hex() if body.delta_from is not None else None,
    }


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
    """A ``resolve`` item ``{device_id, product, state, fw_version, fw_hash_hex, connected}``."""
    fw_hex = data.get("fw_hash_hex")
    fw_hash: bytes | None = None
    if isinstance(fw_hex, str) and len(fw_hex) == 64:
        try:
            fw_hash = bytes.fromhex(fw_hex)
        except ValueError:
            fw_hash = None
    return TargetDevice(
        id=str(data["device_id"]),
        product=str(data.get("product", "")),
        state=str(data.get("state", "")),
        fw_hash=fw_hash,
        fw_version=data.get("fw_version"),
    )


def _detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.reason_phrase
    if isinstance(body, dict) and body.get("detail"):
        return str(body["detail"])
    return resp.reason_phrase


class HttpRegistryClient:
    def __init__(self, client: httpx.AsyncClient, token: Callable[[str], str]) -> None:
        self._http = client
        self._token = token

    def _headers(self) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self._token('registry')}"}
        carrier: dict[str, str] = {}
        propagate.inject(carrier)
        if "traceparent" in carrier:
            headers["traceparent"] = carrier["traceparent"]
        return headers

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._http.post(path, json=body, headers=self._headers())
        except httpx.HTTPError as exc:
            raise RegistryError(0, f"POST {path}: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise RegistryError(resp.status_code, _detail(resp))
        out: dict[str, Any] = resp.json()
        return out

    async def resolve(self, tenant_id: UUID, target: Target) -> list[TargetDevice]:
        body = await self._post(
            f"/internal/v1/tenants/{tenant_id}/devices/resolve",
            {
                "groups": list(target.groups),
                "tags": dict(target.tags),
                "device_ids": list(target.device_ids),
            },
        )
        return [device_from_json(item) for item in body.get("items", [])]

    async def ota_notify(self, downlink: Downlink) -> DownlinkReceipt:
        body = await self._post(
            f"/internal/v1/tenants/{downlink.tenant_id}/devices/{downlink.device_id}/downlink",
            {"type": "ota_notify", "body": notify_json(downlink.body), "retain": downlink.retain},
        )
        published = datetime.fromisoformat(str(body["published_at"]).replace("Z", "+00:00"))
        return DownlinkReceipt(seq=int(body["seq"]), published_at=published)


class FakeRegistry:
    """In-memory registry for tests and ``memory`` dev runs.

    Targeting reads ``{tenant: {id: TargetDevice}}``; downlinks are recorded (they are not
    signed: only the real registry holds tenant command keys). ``fail`` upcoming downlinks
    raise :class:`RegistryError`.
    """

    def __init__(self) -> None:
        self.devices: dict[UUID, dict[str, TargetDevice]] = {}
        self.downlinks: list[Downlink] = []
        self.fail = 0
        self._seq = 0

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

    async def ota_notify(self, downlink: Downlink) -> DownlinkReceipt:
        if self.fail > 0:
            self.fail -= 1
            raise RegistryError(503, "registry unavailable")
        self.downlinks.append(downlink)
        self._seq += 1
        return DownlinkReceipt(seq=self._seq, published_at=datetime.now(UTC))
