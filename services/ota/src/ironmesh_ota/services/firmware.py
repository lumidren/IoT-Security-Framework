"""Firmware artifacts: upload, signing, the pre-notify verification and delta generation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from ironmesh_wire import delta as wire_delta
from ironmesh_wire import errors as wire_errors
from ironmesh_wire.errors import WireError
from ironmesh_wire.manifest import DeltaInfo, Manifest

from ..auth import Principal
from ..container import Container, Effects, flush
from ..domain import Actor, DeltaArtifact, Firmware, Page, Severity
from ..models import FirmwareMetadataIn
from ..observability import get_logger
from ..problems import Problem, conflict, not_found, validation
from ..repository.base import RepositoryConflict, TenantRepository
from ..signing import ED25519, ML_DSA_65, SignedManifest, verify_signed
from ..storage import ArtifactConflict
from ..upload import ParsedUpload
from .audit import record

log = get_logger("ironmesh.ota.firmware")

CBOR = "application/cbor"
COSE = "application/cose"
OCTETS = "application/octet-stream"


async def require_firmware(repo: TenantRepository, firmware_id: uuid.UUID) -> Firmware:
    """Firmware referenced by a campaign (a foreign key guarantees it exists)."""
    fw = await repo.get_firmware(firmware_id)
    if fw is None:  # pragma: no cover - FK violation
        raise RuntimeError(f"firmware {firmware_id} referenced but missing")
    return fw


class ArtifactVerificationError(Exception):
    """The stored artifact does not match its signed manifest (or the manifest is not signed by a
    trusted key). ``code`` is the wire-format error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class NotifyArtifact:
    """What a device is told to fetch: full image or a delta for its base."""

    signed_manifest: bytes
    key: str
    delta_from: bytes | None


def _metadata_errors(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {"field": ".".join(str(p) for p in err["loc"]) or "metadata", "message": err["msg"]}
        for err in exc.errors()
    ]


class FirmwareService:
    def __init__(self, container: Container) -> None:
        self.c = container

    # --- signing --------------------------------------------------------------------------
    async def sign(self, manifest: Manifest, effects: Effects, purpose: str) -> SignedManifest:
        signed = await asyncio.to_thread(self.c.signer.sign, manifest)
        try:
            verify_signed(signed.signed, self.c.signer, require_pq=self.c.settings.require_pq)
        except WireError as exc:  # pragma: no cover - would indicate a broken key ring
            raise Problem(
                500, f"self-verification of the signed manifest failed: {exc.code}"
            ) from exc
        effects.signing.append((purpose, ED25519))
        if signed.pq_signed:
            effects.signing.append((purpose, ML_DSA_65))
        return signed

    async def _audit_signing(
        self,
        repo: TenantRepository,
        effects: Effects,
        actor: Actor,
        fw_id: uuid.UUID,
        signed: SignedManifest,
        purpose: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        await record(
            self.c,
            repo,
            effects,
            actor=actor,
            action="firmware.sign",
            target_type="firmware",
            target_id=str(fw_id),
            details={
                "purpose": purpose,
                "key_ids": list(signed.key_ids),
                "pq_signed": signed.pq_signed,
                "manifest_sha256": hashlib.sha256(signed.payload).hexdigest(),
                **(extra or {}),
            },
        )

    # --- upload ---------------------------------------------------------------------------
    async def upload(self, principal: Principal, parsed: ParsedUpload) -> Firmware:
        try:
            meta = FirmwareMetadataIn.model_validate(json.loads(parsed.metadata or b"null"))
        except json.JSONDecodeError as exc:
            raise validation([{"field": "metadata", "message": "metadata must be JSON"}]) from exc
        except ValidationError as exc:
            raise validation(_metadata_errors(exc)) from exc
        if meta.min_version_code > meta.version_code:
            raise validation(
                [{"field": "min_version_code", "message": "must not exceed version_code"}]
            )
        tenant = principal.tenant_id
        async with self.c.db.tenant(tenant) as repo:
            await self._check_version(repo, meta.product, meta.version, meta.version_code)

        now = self.c.clock()
        fw_id = uuid.uuid4()
        manifest = Manifest(
            product=meta.product,
            version=meta.version,
            version_code=meta.version_code,
            image_sha256=parsed.image_sha256,
            image_size=parsed.image_size,
            created_at=int(now.timestamp()),
            min_version_code=meta.min_version_code,
            delta=None,
            signing_key_id=self.c.signer.key_name,
        )
        effects = Effects()
        signed = await self.sign(manifest, effects, "upload")
        base = f"firmware/{tenant}/{meta.product}/{meta.version_code}"
        try:
            await self.c.store.put(f"{base}/image.bin", parsed.image_path, OCTETS)
            await self.c.store.put(f"{base}/manifest.cbor", signed.payload, CBOR)
            await self.c.store.put(f"{base}/manifest.sig", signed.signed, COSE)
        except ArtifactConflict as exc:
            raise conflict(str(exc)) from exc
        firmware = Firmware(
            id=fw_id,
            tenant_id=tenant,
            product=meta.product,
            version=meta.version,
            version_code=meta.version_code,
            sha256=parsed.image_sha256,
            size=parsed.image_size,
            min_version_code=meta.min_version_code,
            created_at=now,
            created_by=principal.actor.ref,
            manifest=signed.payload,
            signed_manifest=signed.signed,
            signing_key_id=self.c.signer.active_key_id,
            pq_signed=signed.pq_signed,
            notes=meta.notes,
            severity=meta.severity,
            image_key=f"{base}/image.bin",
            manifest_key=f"{base}/manifest.cbor",
            signature_key=f"{base}/manifest.sig",
        )
        async with self.c.db.tenant(tenant) as repo:
            await repo.lock_product(meta.product)
            await self._check_version(repo, meta.product, meta.version, meta.version_code)
            try:
                await repo.add_firmware(firmware)
            except RepositoryConflict as exc:
                raise conflict(str(exc)) from exc
            await record(
                self.c,
                repo,
                effects,
                actor=principal.actor,
                action="firmware.upload",
                target_type="firmware",
                target_id=str(fw_id),
                ip=principal.ip,
                request_id=principal.request_id,
                details={
                    "product": meta.product,
                    "version": meta.version,
                    "version_code": meta.version_code,
                    "sha256_hex": firmware.sha256_hex,
                    "size": firmware.size,
                    "severity": meta.severity.value,
                    "cross_tenant": principal.cross_tenant,
                },
            )
            await self._audit_signing(repo, effects, principal.actor, fw_id, signed, "upload")
        await flush(self.c, effects)
        log.info(
            "firmware stored",
            tenant_id=str(tenant),
            firmware_id=str(fw_id),
            product=meta.product,
            version=meta.version,
            version_code=meta.version_code,
        )
        return firmware

    async def _check_version(
        self, repo: TenantRepository, product: str, version: str, version_code: int
    ) -> None:
        latest = await repo.max_version_code(product)
        if latest is not None and version_code <= latest:
            raise validation(
                [
                    {
                        "field": "version_code",
                        "message": f"version_code must exceed {latest} (anti-rollback)",
                    }
                ]
            )
        if await repo.version_exists(product, version):
            raise conflict(f"{product}/{version} already exists")

    # --- reads ----------------------------------------------------------------------------
    async def get(self, tenant: uuid.UUID, firmware_id: str) -> Firmware:
        try:
            fid = uuid.UUID(firmware_id)
        except ValueError as exc:
            raise not_found("Firmware") from exc
        async with self.c.db.tenant(tenant) as repo:
            fw = await repo.get_firmware(fid)
        if fw is None:
            raise not_found("Firmware")
        return fw

    async def by_hash(self, tenant: uuid.UUID, sha256_hex: str) -> Firmware:
        try:
            digest = bytes.fromhex(sha256_hex)
        except ValueError as exc:
            raise not_found("Firmware") from exc
        if len(digest) != 32 or sha256_hex != sha256_hex.lower():
            raise not_found("Firmware")
        async with self.c.db.tenant(tenant) as repo:
            fw = await repo.get_firmware_by_hash(digest)
        if fw is None:
            raise not_found("Firmware")
        return fw

    async def list_page(
        self, tenant: uuid.UUID, product: str | None, cursor: str | None, limit: int
    ) -> Page[Firmware]:
        async with self.c.db.tenant(tenant) as repo:
            return await repo.list_firmware(product, cursor, limit)

    async def image_url(self, fw: Firmware) -> str:
        return await self.c.store.download_url(fw.image_key, self.c.settings.download_url_ttl_s)

    # --- verification before notify -------------------------------------------------------
    async def verify_firmware(self, fw: Firmware) -> None:
        """Re-verify the signed manifest with the trusted keys and the stored image against it."""
        try:
            verified = verify_signed(
                fw.signed_manifest, self.c.signer, require_pq=self.c.settings.require_pq
            )
        except WireError as exc:
            raise ArtifactVerificationError(exc.code, "manifest signature invalid") from exc
        m = verified.manifest
        if (
            verified.payload != fw.manifest
            or m.product != fw.product
            or m.version != fw.version
            or m.version_code != fw.version_code
            or m.image_sha256 != fw.sha256
            or m.image_size != fw.size
            or m.delta is not None
        ):
            raise ArtifactVerificationError(wire_errors.MF_FIELD, "manifest does not match record")
        image = await self.c.store.get(fw.image_key)
        if len(image) != m.image_size:
            raise ArtifactVerificationError(wire_errors.MF_SIZE_MISMATCH, "stored image size")
        digest = await asyncio.to_thread(lambda: hashlib.sha256(image).digest())
        if digest != m.image_sha256:
            raise ArtifactVerificationError(wire_errors.MF_HASH_MISMATCH, "stored image hash")

    async def verify_delta(self, fw: Firmware, delta: DeltaArtifact) -> None:
        try:
            verified = verify_signed(
                delta.signed_manifest, self.c.signer, require_pq=self.c.settings.require_pq
            )
        except WireError as exc:
            raise ArtifactVerificationError(exc.code, "delta manifest signature invalid") from exc
        m = verified.manifest
        if (
            m.delta is None
            or m.delta.base_sha256 != delta.base_sha256
            or m.delta.patch_sha256 != delta.patch_sha256
            or m.delta.patch_size != delta.patch_size
            or m.image_sha256 != fw.sha256
            or m.version_code != fw.version_code
        ):
            raise ArtifactVerificationError(wire_errors.MF_FIELD, "delta manifest mismatch")
        patch = await self.c.store.get(delta.patch_key)
        if len(patch) != delta.patch_size or hashlib.sha256(patch).digest() != delta.patch_sha256:
            raise ArtifactVerificationError(wire_errors.MF_HASH_MISMATCH, "stored patch hash")
        header = wire_delta.DeltaHeader.parse(patch)
        if header.base_sha256 != delta.base_sha256 or header.target_sha256 != fw.sha256:
            raise ArtifactVerificationError(wire_errors.DELTA_BASE_HASH, "patch header mismatch")

    # --- deltas ---------------------------------------------------------------------------
    async def ensure_deltas(
        self, tenant: uuid.UUID, fw: Firmware, base_hashes: Collection[bytes], actor: Actor
    ) -> dict[bytes, DeltaArtifact]:
        """IMDELTA1 patches from every known base image to ``fw`` (reused when present).

        Bases whose image is not in this tenant's store, or where the patch would not be smaller
        than the full image, get no delta; those devices receive the full image.
        """
        wanted = {h for h in base_hashes if h != fw.sha256}
        if not wanted:
            return {}
        async with self.c.db.tenant(tenant) as repo:
            bases = await repo.firmware_by_hashes(fw.product, wanted)
            existing = {h: await repo.get_delta(fw.id, h) for h in bases}
        result = {h: d for h, d in existing.items() if d is not None}
        missing = [bases[h] for h, d in existing.items() if d is None]
        if not missing:
            return result
        target = await self.c.store.get(fw.image_key)
        for base_fw in missing:
            created = await self._make_delta(tenant, fw, target, base_fw, actor)
            if created is not None:
                result[base_fw.sha256] = created
        return result

    async def _make_delta(
        self, tenant: uuid.UUID, fw: Firmware, target: bytes, base_fw: Firmware, actor: Actor
    ) -> DeltaArtifact | None:
        base = await self.c.store.get(base_fw.image_key)

        def build() -> bytes | None:
            patch = wire_delta.make_delta(base, target)
            # prove the device-side applier reproduces the exact image before shipping it
            if wire_delta.apply_delta(base, patch) != target:  # pragma: no cover - defensive
                raise ArtifactVerificationError(wire_errors.DELTA_TARGET_HASH, "delta round trip")
            return patch if len(patch) < len(target) else None

        patch = await asyncio.to_thread(build)
        if patch is None:
            log.info(
                "delta not smaller than image; full image only",
                firmware_id=str(fw.id),
                base=base_fw.sha256_hex,
            )
            return None
        patch_sha = hashlib.sha256(patch).digest()
        manifest = Manifest(
            product=fw.product,
            version=fw.version,
            version_code=fw.version_code,
            image_sha256=fw.sha256,
            image_size=fw.size,
            created_at=int(self.c.clock().timestamp()),
            min_version_code=fw.min_version_code,
            delta=DeltaInfo(base_fw.sha256, patch_sha, len(patch)),
            signing_key_id=self.c.signer.key_name,
        )
        effects = Effects()
        signed = await self.sign(manifest, effects, "delta")
        key_base = f"delta/{tenant}/{fw.product}/{fw.version_code}/{base_fw.sha256.hex()[:32]}"
        await self.c.store.put(f"{key_base}/patch.imdelta", patch, OCTETS)
        await self.c.store.put(f"{key_base}/manifest.sig", signed.signed, COSE)
        artifact = DeltaArtifact(
            id=uuid.uuid4(),
            tenant_id=tenant,
            firmware_id=fw.id,
            base_sha256=base_fw.sha256,
            patch_sha256=patch_sha,
            patch_size=len(patch),
            patch_key=f"{key_base}/patch.imdelta",
            signed_manifest=signed.signed,
            created_at=self.c.clock(),
        )
        async with self.c.db.tenant(tenant) as repo:
            try:
                await repo.add_delta(artifact)
            except RepositoryConflict:  # pragma: no cover - concurrent generation
                stored = await repo.get_delta(fw.id, base_fw.sha256)
                if stored is None:
                    raise
                return stored
            await record(
                self.c,
                repo,
                effects,
                actor=actor,
                action="firmware.delta.create",
                target_type="firmware",
                target_id=str(fw.id),
                details={
                    "base_sha256_hex": base_fw.sha256_hex,
                    "patch_size": len(patch),
                    "patch_sha256_hex": patch_sha.hex(),
                    "image_size": fw.size,
                },
            )
            await self._audit_signing(
                repo,
                effects,
                actor,
                fw.id,
                signed,
                "delta",
                {"base_sha256_hex": base_fw.sha256_hex},
            )
        await flush(self.c, effects)
        return artifact

    # --- rollback re-sign -----------------------------------------------------------------
    async def resign_previous(
        self,
        repo: TenantRepository,
        effects: Effects,
        previous: Firmware,
        *,
        actor: Actor,
        notes: str,
    ) -> Firmware:
        """Re-release ``previous``'s image under a **higher** ``version_code`` so devices accept
        it despite anti-rollback (DESIGN_CONTRACT §6)."""
        await repo.lock_product(previous.product)
        latest = await repo.max_version_code(previous.product) or 0
        code = latest + 1
        core = previous.version.split("+", 1)[0]
        version = f"{core}+rollback.{code}"
        now = self.c.clock()
        manifest = Manifest(
            product=previous.product,
            version=version,
            version_code=code,
            image_sha256=previous.sha256,
            image_size=previous.size,
            created_at=int(now.timestamp()),
            min_version_code=previous.min_version_code,
            delta=None,
            signing_key_id=self.c.signer.key_name,
        )
        signed = await self.sign(manifest, effects, "rollback")
        base = f"firmware/{repo.tenant_id}/{previous.product}/{code}"
        await self.c.store.put(f"{base}/manifest.cbor", signed.payload, CBOR)
        await self.c.store.put(f"{base}/manifest.sig", signed.signed, COSE)
        firmware = Firmware(
            id=uuid.uuid4(),
            tenant_id=repo.tenant_id,
            product=previous.product,
            version=version,
            version_code=code,
            sha256=previous.sha256,
            size=previous.size,
            min_version_code=previous.min_version_code,
            created_at=now,
            created_by=actor.ref,
            manifest=signed.payload,
            signed_manifest=signed.signed,
            signing_key_id=self.c.signer.active_key_id,
            pq_signed=signed.pq_signed,
            notes=notes,
            severity=Severity.SECURITY,
            image_key=previous.image_key,
            manifest_key=f"{base}/manifest.cbor",
            signature_key=f"{base}/manifest.sig",
            rollback_of=previous.id,
        )
        await repo.add_firmware(firmware)
        await record(
            self.c,
            repo,
            effects,
            actor=actor,
            action="firmware.resign",
            target_type="firmware",
            target_id=str(firmware.id),
            details={
                "rollback_of": str(previous.id),
                "version": version,
                "version_code": code,
                "sha256_hex": previous.sha256_hex,
            },
        )
        await self._audit_signing(
            repo,
            effects,
            actor,
            firmware.id,
            signed,
            "rollback",
            {"rollback_of": str(previous.id)},
        )
        return firmware
