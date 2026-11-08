"""Key-encryption-key abstraction: a local file KEK for development, AWS KMS for production."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOCAL_VERSION = b"\x01"


class KeyWrapper(Protocol):
    key_id: str

    async def wrap(self, plaintext: bytes, context: dict[str, str]) -> bytes: ...
    async def unwrap(self, blob: bytes, context: dict[str, str]) -> bytes: ...


class KmsError(Exception):
    pass


def _aad(context: dict[str, str]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


class LocalKeyWrapper:
    """AES-256-GCM key wrap with a 32-byte KEK read from a file (created 0600 in dev only)."""

    def __init__(self, kek: bytes, key_id: str = "local") -> None:
        if len(kek) != 32:
            raise KmsError("local KEK must be 32 bytes")
        self._aead = AESGCM(kek)
        self.key_id = key_id

    @classmethod
    def from_file(cls, path: str, *, create: bool) -> LocalKeyWrapper:
        p = Path(path)
        if not p.exists():
            if not create:
                raise KmsError(f"KEK file {path} does not exist")
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(os.urandom(32))
        return cls(p.read_bytes(), key_id=f"local:{p.name}")

    async def wrap(self, plaintext: bytes, context: dict[str, str]) -> bytes:
        nonce = os.urandom(12)
        return LOCAL_VERSION + nonce + self._aead.encrypt(nonce, plaintext, _aad(context))

    async def unwrap(self, blob: bytes, context: dict[str, str]) -> bytes:
        if len(blob) < 29 or blob[:1] != LOCAL_VERSION:
            raise KmsError("malformed wrapped key")
        try:
            return self._aead.decrypt(blob[1:13], blob[13:], _aad(context))
        except InvalidTag as exc:
            raise KmsError("wrapped key failed authentication") from exc


class KmsClient(Protocol):
    """The subset of ``boto3.client("kms")`` used here."""

    def encrypt(self, **kwargs: Any) -> dict[str, Any]: ...
    def decrypt(self, **kwargs: Any) -> dict[str, Any]: ...


class AwsKmsKeyWrapper:
    """Wraps tenant keys with ``kms:Encrypt`` under an encryption context bound to the tenant."""

    def __init__(self, client: KmsClient, key_id: str) -> None:
        self.client = client
        self.key_id = key_id

    @classmethod
    def create(cls, key_id: str, region: str | None) -> AwsKmsKeyWrapper:  # pragma: no cover
        import boto3

        client: Any = boto3.client("kms", region_name=region)
        return cls(client, key_id)

    async def wrap(self, plaintext: bytes, context: dict[str, str]) -> bytes:
        resp = await asyncio.to_thread(
            self.client.encrypt, KeyId=self.key_id, Plaintext=plaintext, EncryptionContext=context
        )
        return bytes(resp["CiphertextBlob"])

    async def unwrap(self, blob: bytes, context: dict[str, str]) -> bytes:
        try:
            resp = await asyncio.to_thread(
                self.client.decrypt,
                KeyId=self.key_id,
                CiphertextBlob=blob,
                EncryptionContext=context,
            )
        except Exception as exc:
            raise KmsError(f"kms decrypt failed: {exc}") from exc
        return bytes(resp["Plaintext"])
