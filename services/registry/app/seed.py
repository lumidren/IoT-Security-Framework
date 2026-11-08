"""Demo data: ``python -m app.seed --tenant demo --devices 500 [--owner-sub S --owner-email E]``.

Writes through the normal repository (as ``registry_app`` under RLS) using the configured
``REGISTRY_*`` database settings. Idempotent per tenant: existing devices are left alone.
Random values here are demo data only, never security material.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import random
import uuid
from datetime import timedelta

from ironmesh_wire import ids

from .auth import SYSTEM
from .domain import (
    DEFAULT_TENANT_SETTINGS,
    AlertRecord,
    AuditDraft,
    CertificateRecord,
    DeviceRecord,
    GroupRecord,
    TelemetryRecord,
    TenantRecord,
    TwinRecord,
    UserRecord,
)
from .jsonutil import utcnow
from .main import _repo
from .repo.base import DuplicateError, Repository
from .settings import get_settings

PRODUCTS = [
    ("gateway-rpi", "rev-c", "tpm2"),
    ("sensor-esp32", "v3", "atecc608"),
    ("sensor-esp32", "v3", "software"),
    ("edge-imx8", "b1", "optee"),
]
GROUPS = [
    ("gateways", "Gateways", False),
    ("sensors", "Sensors", False),
    ("eu-west", "EU West", False),
    ("secure-core", "Secure core (hardware keys only)", True),
]
CITIES = [
    (52.52, 13.405),
    (48.8566, 2.3522),
    (51.5072, -0.1276),
    (40.4168, -3.7038),
    (59.33, 18.07),
]
FIRMWARE = ["2.4.1", "2.4.0", "2.3.7"]


def tenant_uuid(name: str) -> str:
    """A stable UUIDv4-shaped id for a tenant name (or the name itself if it is a UUIDv4)."""
    if ids.is_tenant_id(name):
        return name
    raw = bytearray(hashlib.sha256(f"ironmesh-tenant:{name}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


async def seed(
    repo: Repository,
    tenant_name: str,
    devices: int,
    *,
    owner_sub: str | None = None,
    owner_email: str | None = None,
    rng: random.Random | None = None,
) -> dict[str, int | str]:
    rng = rng or random.Random(tenant_name)  # nosec B311 - deterministic demo data, not secrets
    tenant_id = tenant_uuid(tenant_name)
    now = utcnow()
    created = 0
    async with repo.tenant(tenant_id) as tx:
        if await tx.get_tenant() is None:
            await tx.insert_tenant(
                TenantRecord(
                    id=tenant_id,
                    name=tenant_name,
                    settings=dict(DEFAULT_TENANT_SETTINGS) | {"allow_software_keys": True},
                    created_at=now,
                )
            )
        for slug, name, hw_only in GROUPS:
            if await tx.get_group(slug) is None:
                await tx.insert_group(
                    GroupRecord(
                        tenant_id=tenant_id,
                        slug=slug,
                        name=name,
                        created_at=now,
                        hardware_only=hw_only,
                    )
                )
        if owner_sub:
            await tx.save_user(
                UserRecord(
                    tenant_id=tenant_id,
                    id=owner_sub,
                    email=owner_email or owner_sub,
                    role="owner",
                    created_at=now,
                )
            )
        for i in range(devices):
            device_id = "dev-" + hashlib.sha256(f"{tenant_id}:{i}".encode()).hexdigest()[:16]
            if await tx.get_device(device_id) is not None:
                continue
            product, rev, se_type = rng.choice(PRODUCTS)
            state = rng.choices(
                ["active", "provisioned", "manufactured", "quarantined", "decommissioned"],
                weights=[80, 5, 8, 5, 2],
            )[0]
            lat, lon = rng.choice(CITIES)
            fw = rng.choice(FIRMWARE)
            serial = f"{rng.getrandbits(127) | (1 << 126):x}"
            not_after = now + timedelta(hours=rng.randint(-24, 14 * 24))
            dev = DeviceRecord(
                tenant_id=tenant_id,
                id=device_id,
                product=product,
                hw_revision=rev,
                state=state,
                created_at=now - timedelta(days=rng.randint(1, 90)),
                se_type=se_type,
                assurance_level=None
                if state == "manufactured"
                else ("software" if se_type == "software" else "hardware"),
                bootstrap_serial_hex=f"{rng.getrandbits(120) | (1 << 119):x}",
                tags={
                    "site": rng.choice(["berlin", "paris", "london", "madrid", "stockholm"]),
                    "tier": rng.choice(["prod", "pilot"]),
                },
                connected=state == "active" and rng.random() < 0.9,
                last_seen_at=now - timedelta(seconds=rng.randint(0, 3600)),
                fw_version=fw if state != "manufactured" else None,
                fw_hash_hex=hashlib.sha256(f"{product}/{fw}".encode()).hexdigest()
                if state != "manufactured"
                else None,
                cert_serial_hex=serial if state != "manufactured" else None,
                cert_not_after=not_after if state != "manufactured" else None,
                cert_revoked=state in ("quarantined", "decommissioned"),
                lat=lat + rng.uniform(-0.2, 0.2),
                lon=lon + rng.uniform(-0.2, 0.2),
                provisioned_at=now - timedelta(days=1) if state != "manufactured" else None,
                activated_at=now - timedelta(days=1)
                if state in ("active", "quarantined")
                else None,
                quarantined_at=now - timedelta(hours=2) if state == "quarantined" else None,
                quarantine_reason="anomaly: beaconing" if state == "quarantined" else None,
                decommissioned_at=now - timedelta(hours=5) if state == "decommissioned" else None,
                provisioning_status="done"
                if state not in ("manufactured", "provisioned")
                else "pending",
            )
            try:
                await tx.insert_device(dev)
            except DuplicateError:  # pragma: no cover - device id taken by another tenant
                continue
            created += 1
            await tx.save_twin(
                TwinRecord(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    version=1,
                    desired={"telemetry_interval_s": 30},
                    reported={"telemetry_interval_s": 30},
                    reported_version=1,
                    desired_updated_at=now,
                    reported_updated_at=now,
                )
            )
            await tx.add_member("gateways" if product == "gateway-rpi" else "sensors", device_id)
            if lat > 45:
                await tx.add_member("eu-west", device_id)
            if dev.cert_serial_hex and dev.cert_not_after:
                await tx.upsert_certificate(
                    CertificateRecord(
                        tenant_id=tenant_id,
                        serial_hex=dev.cert_serial_hex,
                        device_id=device_id,
                        not_before=dev.cert_not_after - timedelta(days=14),
                        not_after=dev.cert_not_after,
                        issuer="IronMesh Device CA",
                        created_at=now,
                        assurance_level=dev.assurance_level,
                        revoked_at=now if dev.cert_revoked else None,
                        revocation_reason="seed" if dev.cert_revoked else None,
                    )
                )
            if state == "active":
                for k in range(12):
                    at = now - timedelta(minutes=5 * k)
                    await tx.insert_telemetry(
                        TelemetryRecord(
                            tenant_id=tenant_id,
                            device_id=device_id,
                            at=at,
                            values={
                                "cpu_pct": round(rng.uniform(2, 85), 2),
                                "mem_pct": round(rng.uniform(20, 80), 2),
                                "temp_c": round(rng.uniform(30, 70), 1),
                                "net_rx_bytes": rng.randint(1_000, 5_000_000),
                                "net_tx_bytes": rng.randint(1_000, 2_000_000),
                                "rssi": rng.randint(-90, -40) if "esp32" in product else None,
                                "free_heap": rng.randint(40_000, 200_000)
                                if "esp32" in product
                                else None,
                            },
                        )
                    )
            if state == "quarantined" or rng.random() < 0.03:
                await tx.upsert_alert(
                    AlertRecord(
                        tenant_id=tenant_id,
                        id=str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                        device_id=device_id,
                        rule=rng.choice(["beaconing", "auth_burst"]),
                        severity=rng.choice(["critical", "high", "medium", "low"]),
                        state="open",
                        created_at=now,
                        updated_at=now,
                    )
                )
        await tx.append_audit(
            AuditDraft(
                tenant_id=tenant_id,
                at=now,
                actor_type="system",
                actor_id=SYSTEM.actor_id,
                actor_name="seed",
                action="tenant.seeded",
                target_type="tenant",
                target_id=tenant_id,
                details={"devices_created": created},
            )
        )
    return {"tenant_id": tenant_id, "devices_created": created}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Seed demo data into the registry")
    parser.add_argument("--tenant", default="demo")
    parser.add_argument("--devices", type=int, default=500)
    parser.add_argument("--owner-sub")
    parser.add_argument("--owner-email")
    args = parser.parse_args(argv)

    async def run() -> dict[str, int | str]:
        repo = _repo(get_settings())
        try:
            return await seed(
                repo,
                args.tenant,
                args.devices,
                owner_sub=args.owner_sub,
                owner_email=args.owner_email,
            )
        finally:
            await repo.close()

    result = asyncio.run(run())
    print(
        f"seeded tenant {args.tenant} ({result['tenant_id']}): "
        f"{result['devices_created']} devices created"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
