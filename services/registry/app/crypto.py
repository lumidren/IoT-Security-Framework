"""Per-tenant key material: the AES-256 data key (config at rest) and the Ed25519 command key.

Both are generated on first use, wrapped by the KMS :class:`KeyWrapper` with an encryption
context bound to the tenant and purpose, and stored in ``tenant_keys``. Unwrapped keys are cached
in process memory for a short time so that KMS is not called on every request.

The registry is the **only** holder of the command key (API_CONTRACT §1.12). Creating one also
queues, in the same transaction, a ``pki_tenant_policy`` outbox action that publishes the public
key to the PKI (``PUT /v1/tenants/{t}/command-key``) so EST bundles carry it.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ironmesh_wire import envelope

from .domain import ActionRecord, TenantKeysRecord
from .integrations.kms import KeyWrapper
from .jsonutil import utcnow
from .repo.base import DuplicateError, TenantTx


@dataclass(slots=True)
class TenantKeys:
    data_key: bytes
    cmd_key: ed25519.Ed25519PrivateKey
    loaded_at: float

    def identity(self, tenant_id: str) -> envelope.SigningIdentity:
        return envelope.SigningIdentity.tenant(self.cmd_key, tenant_id)


PKI_TENANT_POLICY = "pki_tenant_policy"
"""Outbox kind: push the tenant's command key and enrollment policy to the PKI."""


class ConfigDecryptError(Exception):
    pass


def _ctx(tenant_id: str, purpose: str) -> dict[str, str]:
    return {"tenant_id": tenant_id, "purpose": purpose, "service": "registry"}


class TenantKeyring:
    def __init__(
        self,
        wrapper: KeyWrapper,
        cache_seconds: float = 300.0,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.wrapper = wrapper
        self.cache_seconds = cache_seconds
        self.clock = clock
        self._cache: dict[str, TenantKeys] = {}

    async def keys(self, tx: TenantTx) -> TenantKeys:
        tenant_id = tx.tenant_id
        hit = self._cache.get(tenant_id)
        if hit is not None and time.monotonic() - hit.loaded_at < self.cache_seconds:
            return hit
        rec = await tx.get_tenant_keys()
        if rec is None:
            rec = await self._create(tx)
        data_key = await self.wrapper.unwrap(rec.wrapped_data_key, _ctx(tenant_id, "data-key"))
        seed = await self.wrapper.unwrap(rec.wrapped_cmd_key, _ctx(tenant_id, "command-key"))
        keys = TenantKeys(
            data_key=data_key,
            cmd_key=ed25519.Ed25519PrivateKey.from_private_bytes(seed),
            loaded_at=time.monotonic(),
        )
        self._cache[tenant_id] = keys
        return keys

    async def _create(self, tx: TenantTx) -> TenantKeysRecord:
        tenant_id = tx.tenant_id
        cmd = ed25519.Ed25519PrivateKey.generate()
        seed = cmd.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        rec = TenantKeysRecord(
            tenant_id=tenant_id,
            kek_id=self.wrapper.key_id,
            wrapped_data_key=await self.wrapper.wrap(os.urandom(32), _ctx(tenant_id, "data-key")),
            wrapped_cmd_key=await self.wrapper.wrap(seed, _ctx(tenant_id, "command-key")),
            cmd_public_key=cmd.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            created_at=self.clock(),
        )
        try:
            await tx.insert_tenant_keys(rec)
        except DuplicateError:  # pragma: no cover - concurrent first use; the winner's keys stand
            existing = await tx.get_tenant_keys()
            assert existing is not None
            return existing
        await tx.insert_action(
            ActionRecord(
                tenant_id=tenant_id,
                id=str(uuid.uuid4()),
                kind=PKI_TENANT_POLICY,
                device_id="",
                payload={"cause": "command_key_created"},
                created_at=rec.created_at,
                next_attempt_at=rec.created_at,
            )
        )
        return rec

    @staticmethod
    def config_aad(tenant_id: str, device_id: str, version: int) -> bytes:
        return f"ironmesh-config-at-rest|{tenant_id}|{device_id}|{version}".encode()

    async def encrypt_config(
        self, tx: TenantTx, device_id: str, version: int, plaintext: bytes
    ) -> tuple[bytes, bytes]:
        keys = await self.keys(tx)
        iv = os.urandom(12)
        aad = self.config_aad(tx.tenant_id, device_id, version)
        return iv, AESGCM(keys.data_key).encrypt(iv, plaintext, aad)

    async def decrypt_config(
        self, tx: TenantTx, device_id: str, version: int, iv: bytes, ciphertext: bytes
    ) -> bytes:
        keys = await self.keys(tx)
        aad = self.config_aad(tx.tenant_id, device_id, version)
        try:
            return AESGCM(keys.data_key).decrypt(iv, ciphertext, aad)
        except InvalidTag as exc:
            raise ConfigDecryptError("stored config failed authentication") from exc
