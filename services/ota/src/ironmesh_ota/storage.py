"""Artifact storage behind the :class:`ArtifactStore` protocol.

Every object is **write-once**: ``put`` refuses to replace an existing key with different
content (``ArtifactConflict``) and is idempotent for identical content, so a retried upload never
corrupts an artifact that devices may already be downloading.

* :class:`S3ArtifactStore` uses conditional writes (``If-None-Match: *``) and, when configured,
  S3 Object Lock (``GOVERNANCE``/``COMPLIANCE`` retention) on a bucket created with Object Lock
  enabled, so not even the service role can overwrite or delete a released image. Downloads are
  pre-signed ``GetObject`` URLs.
* :class:`LocalArtifactStore` (development and tests) writes files atomically with ``O_EXCL``
  semantics, marks them read-only and serves downloads through ``/v1/artifacts/...`` links
  authenticated by a short-lived HMAC token.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import quote, urlencode

from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

KEY_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
CHUNK: Final = 1024 * 1024


class ArtifactError(Exception):
    pass


class ArtifactConflict(ArtifactError):
    """An object already exists under this key with different content."""


class ArtifactNotFound(ArtifactError):
    pass


def validate_key(key: str) -> str:
    if len(key) > 512 or KEY_RE.fullmatch(key) is None or ".." in key.split("/"):
        raise ArtifactError(f"invalid artifact key {key!r}")
    return key


def _sha256_of(source: Path | bytes) -> str:
    if isinstance(source, bytes):
        return hashlib.sha256(source).hexdigest()
    digest = hashlib.sha256()
    with source.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


class ArtifactStore(Protocol):
    async def put(self, key: str, source: Path | bytes, content_type: str) -> None: ...

    async def get(self, key: str) -> bytes: ...

    async def exists(self, key: str) -> bool: ...

    async def download_url(self, key: str, ttl_s: int) -> str: ...

    async def ping(self) -> bool: ...


# --------------------------------------------------------------------------------------------
# Local filesystem
# --------------------------------------------------------------------------------------------


class DownloadSigner:
    """HMAC-SHA256 tokens for ``/v1/artifacts/<key>?exp=<unix>&sig=<b64url>`` links."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("download HMAC secret must be at least 32 bytes")
        self._secret = secret

    def _mac(self, key: str, exp: int) -> str:
        mac = hmac.new(self._secret, f"{key}\n{exp}".encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()

    def sign(self, key: str, exp: int) -> str:
        return self._mac(key, exp)

    def verify(self, key: str, exp: int, sig: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        if exp < current:
            return False
        return hmac.compare_digest(self._mac(key, exp), sig)


class LocalArtifactStore:
    def __init__(self, root: Path, base_url: str, signer: DownloadSigner) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.base_url = base_url.rstrip("/")
        self.signer = signer

    def path_for(self, key: str) -> Path:
        path = (self.root / validate_key(key)).resolve()
        if not path.is_relative_to(self.root):
            raise ArtifactError("artifact key escapes the store root")
        return path

    def _put_sync(self, key: str, source: Path | bytes) -> None:
        target = self.path_for(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if _sha256_of(target) != _sha256_of(source):
                raise ArtifactConflict(f"{key} already exists with different content")
            return
        tmp = target.with_name(f".{uuid.uuid4().hex[:12]}.tmp")
        try:
            if isinstance(source, bytes):
                tmp.write_bytes(source)
            else:
                with source.open("rb") as src, tmp.open("xb") as dst:
                    while chunk := src.read(CHUNK):
                        dst.write(chunk)
            tmp.chmod(0o444)
            try:
                os.link(tmp, target)  # atomic create-if-absent
            except FileExistsError:
                if _sha256_of(target) != _sha256_of(tmp):
                    raise ArtifactConflict(f"{key} already exists with different content") from None
        finally:
            if tmp.exists():
                tmp.chmod(0o644)
                tmp.unlink()

    async def put(self, key: str, source: Path | bytes, content_type: str) -> None:
        await asyncio.to_thread(self._put_sync, key, source)

    async def get(self, key: str) -> bytes:
        path = self.path_for(key)
        try:
            return await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError as exc:
            raise ArtifactNotFound(key) from exc

    async def exists(self, key: str) -> bool:
        return self.path_for(key).is_file()

    async def download_url(self, key: str, ttl_s: int) -> str:
        validate_key(key)
        exp = int(time.time()) + ttl_s
        query = urlencode({"exp": exp, "sig": self.signer.sign(key, exp)})
        return f"{self.base_url}/v1/artifacts/{quote(key)}?{query}"

    async def ping(self) -> bool:
        return self.root.is_dir()


# --------------------------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------------------------


class S3ArtifactStore:
    def __init__(
        self,
        client: S3Client,
        bucket: str,
        *,
        object_lock_mode: str | None = None,
        object_lock_days: int = 3650,
        kms_key_id: str | None = None,
    ) -> None:
        self._s3 = client
        self._bucket = bucket
        self._lock_mode = object_lock_mode
        self._lock_days = object_lock_days
        self._kms_key_id = kms_key_id

    def _put_sync(self, key: str, source: Path | bytes, content_type: str) -> None:
        validate_key(key)
        digest = _sha256_of(source)
        extra: dict[str, Any] = {}
        if self._kms_key_id is not None:
            extra["ServerSideEncryption"] = "aws:kms"
            extra["SSEKMSKeyId"] = self._kms_key_id
        if self._lock_mode is not None:
            extra["ObjectLockMode"] = self._lock_mode
            extra["ObjectLockRetainUntilDate"] = datetime.now(UTC) + timedelta(days=self._lock_days)
        try:
            if isinstance(source, bytes):
                self._s3.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=source,
                    ContentType=content_type,
                    IfNoneMatch="*",
                    Metadata={"sha256": digest},
                    **extra,
                )
            else:
                with source.open("rb") as fh:
                    self._s3.put_object(
                        Bucket=self._bucket,
                        Key=key,
                        Body=fh,
                        ContentType=content_type,
                        IfNoneMatch="*",
                        Metadata={"sha256": digest},
                        **extra,
                    )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("PreconditionFailed", "412", "ConditionalRequestConflict"):
                raise
            head = self._s3.head_object(Bucket=self._bucket, Key=key)
            if head.get("Metadata", {}).get("sha256") != digest:
                raise ArtifactConflict(f"{key} already exists with different content") from exc

    async def put(self, key: str, source: Path | bytes, content_type: str) -> None:
        await asyncio.to_thread(self._put_sync, key, source, content_type)

    def _get_sync(self, key: str) -> bytes:
        try:
            obj = self._s3.get_object(Bucket=self._bucket, Key=validate_key(key))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                raise ArtifactNotFound(key) from exc
            raise
        return obj["Body"].read()

    async def get(self, key: str) -> bytes:
        return await asyncio.to_thread(self._get_sync, key)

    def _exists_sync(self, key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self._bucket, Key=validate_key(key))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404", "NotFound"):
                return False
            raise
        return True

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._exists_sync, key)

    async def download_url(self, key: str, ttl_s: int) -> str:
        validate_key(key)
        return await asyncio.to_thread(
            self._s3.generate_presigned_url,
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=ttl_s,
        )

    def _ping_sync(self) -> bool:
        try:
            self._s3.head_bucket(Bucket=self._bucket)
        except ClientError:
            return False
        return True

    async def ping(self) -> bool:
        return await asyncio.to_thread(self._ping_sync)
