"""Tenant command keys (Ed25519, ``kid = tenant-cmd-<tenant>``) that sign ``OtaNotify``.

Keys are loaded lazily per tenant and cached in memory. Production keys are KMS-wrapped seeds in
Secrets Manager (``<prefix><tenant>``, encryption context ``{"purpose": "ironmesh-tenant-cmd",
"tenant_id": <tenant>}``) so a blob for one tenant can never be decrypted as another's; dev keys
are passphrase-encrypted PKCS#8 PEM files ``<dir>/<tenant>.pem``.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ironmesh_wire.envelope import SigningIdentity

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient
    from mypy_boto3_secretsmanager import SecretsManagerClient


class TenantKeyError(Exception):
    pass


class TenantKeyProvider(Protocol):
    async def identity(self, tenant_id: UUID) -> SigningIdentity: ...


class StaticTenantKeyProvider:
    """Keys held in memory; ``generate_missing`` creates ephemeral dev keys on demand (devices
    will not trust them, which is the point: dev notifies are only for local inspection)."""

    def __init__(
        self,
        keys: dict[UUID, ed25519.Ed25519PrivateKey] | None = None,
        *,
        generate_missing: bool = False,
    ) -> None:
        self.keys = dict(keys or {})
        self._generate = generate_missing

    async def identity(self, tenant_id: UUID) -> SigningIdentity:
        key = self.keys.get(tenant_id)
        if key is None and self._generate:
            key = self.keys[tenant_id] = ed25519.Ed25519PrivateKey.generate()
        if key is None:
            raise TenantKeyError(f"no command key for tenant {tenant_id}")
        return SigningIdentity.tenant(key, str(tenant_id))


class _CachingProvider:
    def __init__(self) -> None:
        self._cache: dict[UUID, SigningIdentity] = {}
        self._lock = asyncio.Lock()

    def _load(self, tenant_id: UUID) -> ed25519.Ed25519PrivateKey:
        raise NotImplementedError

    async def identity(self, tenant_id: UUID) -> SigningIdentity:
        async with self._lock:
            cached = self._cache.get(tenant_id)
            if cached is None:
                key = await asyncio.to_thread(self._load, tenant_id)
                cached = SigningIdentity.tenant(key, str(tenant_id))
                self._cache[tenant_id] = cached
            return cached


class FileTenantKeyProvider(_CachingProvider):
    def __init__(self, directory: Path, passphrase: bytes | None) -> None:
        super().__init__()
        self._dir = directory
        self._passphrase = passphrase

    def _load(self, tenant_id: UUID) -> ed25519.Ed25519PrivateKey:
        path = self._dir / f"{tenant_id}.pem"
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), password=self._passphrase)
        except (OSError, ValueError, TypeError) as exc:
            raise TenantKeyError(f"cannot load command key for tenant {tenant_id}") from exc
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TenantKeyError("tenant command keys must be Ed25519")
        return key


def kms_context(tenant_id: UUID) -> dict[str, str]:
    return {"purpose": "ironmesh-tenant-cmd", "tenant_id": str(tenant_id)}


class KmsTenantKeyProvider(_CachingProvider):
    def __init__(
        self, secrets: SecretsManagerClient, kms: KMSClient, *, prefix: str, key_id: str
    ) -> None:
        super().__init__()
        self._secrets = secrets
        self._kms = kms
        self._prefix = prefix
        self._key_id = key_id

    def _load(self, tenant_id: UUID) -> ed25519.Ed25519PrivateKey:
        try:
            secret = self._secrets.get_secret_value(SecretId=f"{self._prefix}{tenant_id}")
            binary = secret.get("SecretBinary")
            blob = bytes(binary) if binary else base64.b64decode(secret.get("SecretString", ""))
            seed = self._kms.decrypt(
                CiphertextBlob=blob, KeyId=self._key_id, EncryptionContext=kms_context(tenant_id)
            )["Plaintext"]
            return ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        except Exception as exc:
            raise TenantKeyError(f"cannot unwrap command key for tenant {tenant_id}") from exc
