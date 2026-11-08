"""Firmware signing: the :class:`Signer` protocol, the key ring and its two key sources.

Key material never touches disk in clear text:

* **production** (``OTA_SIGNING_BACKEND=kms``): Secrets Manager holds a KMS ciphertext blob
  produced with the symmetric CMK ``ironmesh-firmware-kek`` (encryption context
  ``{"purpose": "ironmesh-firmware-signing"}``). At startup the service calls ``kms:Decrypt``
  and keeps the resulting key ring only in memory.
* **development** (``OTA_SIGNING_BACKEND=file``): a JSON file encrypted with AES-256-GCM under a
  scrypt-derived key from a passphrase (see :mod:`ironmesh_ota.keytool`).

The decrypted key ring is a JSON document ``{"version": 1, "keys": [{"algorithm": "Ed25519" |
"ML-DSA-65", "seed_b64", "created_at", "active"}]}``. Several Ed25519 keys may be present (key
rotation: all are trusted for verification, exactly one is active for signing); at most one
ML-DSA-65 key may be active, which turns on the hybrid second signature.

Key ids are ``SHA-256(raw public key)[0:8]`` in hex (``WIRE_FORMAT.md`` §2.3).
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ironmesh_wire import cose, mldsa
from ironmesh_wire.manifest import Manifest, VerifiedManifest, encode_manifest, verify_manifest

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient
    from mypy_boto3_secretsmanager import SecretsManagerClient

ED25519: Final = "Ed25519"
ML_DSA_65: Final = "ML-DSA-65"
KEYRING_FORMAT: Final = "ironmesh-keyring-v1"
KEYRING_AAD: Final = b"ironmesh-ota-keyring-v1"
KMS_ENCRYPTION_CONTEXT: Final = {"purpose": "ironmesh-firmware-signing"}
SCRYPT_N: Final = 2**15
SCRYPT_R: Final = 8
SCRYPT_P: Final = 1


class SigningError(Exception):
    """Key ring cannot be loaded or is inconsistent."""


@dataclass(frozen=True)
class SigningKeyInfo:
    key_id: str
    algorithm: str
    public_key: bytes
    active: bool
    created_at: datetime


@dataclass(frozen=True)
class SignedManifest:
    payload: bytes
    signed: bytes
    key_ids: tuple[str, ...]
    pq_signed: bool


class Signer(Protocol):
    """Signs firmware manifests and exposes the trusted verification keys."""

    @property
    def active_key_id(self) -> str: ...

    @property
    def key_name(self) -> str:
        """Informational name for manifest field 9 (``OTA_SIGNING_KEY_ID``)."""

    @property
    def pq_enabled(self) -> bool: ...

    def list_keys(self) -> list[SigningKeyInfo]: ...

    def trusted_public_keys(self) -> list[bytes]: ...

    def sign(self, manifest: Manifest | bytes) -> SignedManifest: ...


def key_id_hex(public_key: bytes) -> str:
    return cose.key_id(public_key).hex()


@dataclass(frozen=True)
class _KeyEntry:
    algorithm: str
    seed: bytes
    created_at: datetime
    active: bool


def _parse_keyring(plaintext: bytes) -> list[_KeyEntry]:
    try:
        doc = json.loads(plaintext)
        if doc.get("version") != 1 or not isinstance(doc.get("keys"), list):
            raise SigningError("unsupported key ring document")
        entries = [
            _KeyEntry(
                algorithm=str(k["algorithm"]),
                seed=base64.b64decode(k["seed_b64"], validate=True),
                created_at=datetime.fromisoformat(str(k["created_at"])),
                active=bool(k.get("active", False)),
            )
            for k in doc["keys"]
        ]
    except (ValueError, KeyError, TypeError) as exc:
        raise SigningError(f"malformed key ring: {type(exc).__name__}") from exc
    return entries


def keyring_document(entries: Sequence[dict[str, Any]]) -> bytes:
    """Serialize ``[{"algorithm", "seed": bytes, "created_at": datetime, "active"}]``."""
    keys = [
        {
            "algorithm": e["algorithm"],
            "seed_b64": base64.b64encode(e["seed"]).decode(),
            "created_at": e["created_at"].isoformat(),
            "active": bool(e["active"]),
        }
        for e in entries
    ]
    return json.dumps({"version": 1, "keys": keys}, sort_keys=True).encode()


class KeyringSigner:
    """In-memory key ring implementing :class:`Signer`."""

    def __init__(
        self,
        ed_keys: Sequence[tuple[ed25519.Ed25519PrivateKey, datetime, bool]],
        mldsa_key: tuple[mldsa.MlDsaSigner, datetime] | None = None,
        extra_trusted_mldsa: Sequence[tuple[bytes, datetime]] = (),
        *,
        pq_enabled: bool = True,
        key_name: str | None = None,
    ) -> None:
        active = [k for k, _, is_active in ed_keys if is_active]
        if len(active) != 1:
            raise SigningError("exactly one active Ed25519 signing key is required")
        self._active = cose.Ed25519Signer(active[0])
        self._infos: list[SigningKeyInfo] = []
        for key, created, is_active in ed_keys:
            raw = cose.raw_public_key(key.public_key())
            self._infos.append(SigningKeyInfo(key_id_hex(raw), ED25519, raw, is_active, created))
        self._mldsa = mldsa_key[0] if mldsa_key is not None and pq_enabled else None
        if mldsa_key is not None:
            raw = mldsa_key[0].public_key
            self._infos.append(
                SigningKeyInfo(key_id_hex(raw), ML_DSA_65, raw, pq_enabled, mldsa_key[1])
            )
        for raw, created in extra_trusted_mldsa:
            self._infos.append(SigningKeyInfo(key_id_hex(raw), ML_DSA_65, raw, False, created))
        self._key_name = key_name or self._active.kid.hex()
        if not 1 <= len(self._key_name) <= 64:
            raise SigningError("signing key name must be 1..64 characters")
        ids = [i.key_id for i in self._infos]
        if len(ids) != len(set(ids)):
            raise SigningError("duplicate signing key in key ring")

    @classmethod
    def from_plaintext(
        cls, plaintext: bytes, *, pq_enabled: bool = True, key_name: str | None = None
    ) -> KeyringSigner:
        """Accepts a key ring document or a bare 32-byte Ed25519 seed."""
        if len(plaintext) == 32 and not plaintext.lstrip().startswith(b"{"):
            key = ed25519.Ed25519PrivateKey.from_private_bytes(plaintext)
            return cls([(key, datetime.now(UTC), True)], key_name=key_name)
        ed_keys: list[tuple[ed25519.Ed25519PrivateKey, datetime, bool]] = []
        pq_active: tuple[mldsa.MlDsaSigner, datetime] | None = None
        pq_trusted: list[tuple[bytes, datetime]] = []
        for entry in _parse_keyring(plaintext):
            if entry.algorithm == ED25519:
                if len(entry.seed) != 32:
                    raise SigningError("Ed25519 seed must be 32 bytes")
                key = ed25519.Ed25519PrivateKey.from_private_bytes(entry.seed)
                ed_keys.append((key, entry.created_at, entry.active))
            elif entry.algorithm == ML_DSA_65:
                signer = mldsa.CryptographyMlDsa65Signer.from_seed(entry.seed)
                if entry.active:
                    if pq_active is not None:
                        raise SigningError("at most one active ML-DSA-65 key is allowed")
                    pq_active = (signer, entry.created_at)
                else:
                    pq_trusted.append((signer.public_key, entry.created_at))
            else:
                raise SigningError(f"unsupported signing algorithm {entry.algorithm!r}")
        return cls(ed_keys, pq_active, pq_trusted, pq_enabled=pq_enabled, key_name=key_name)

    @property
    def active_key_id(self) -> str:
        return self._active.kid.hex()

    @property
    def key_name(self) -> str:
        return self._key_name

    @property
    def pq_enabled(self) -> bool:
        return self._mldsa is not None

    def list_keys(self) -> list[SigningKeyInfo]:
        return list(self._infos)

    def trusted_public_keys(self) -> list[bytes]:
        return [i.public_key for i in self._infos]

    def sign(self, manifest: Manifest | bytes) -> SignedManifest:
        payload = manifest if isinstance(manifest, bytes) else encode_manifest(manifest)
        signers: list[cose.Signer] = [self._active]
        key_ids = [self._active.kid.hex()]
        if self._mldsa is not None:
            pq = cose.MlDsa65Signer(self._mldsa)
            signers.append(pq)
            key_ids.append(pq.kid.hex())
        signed = cose.sign_encode(payload, signers)
        return SignedManifest(payload, signed, tuple(key_ids), self._mldsa is not None)


def verify_signed(signed: bytes, signer: Signer, *, require_pq: bool) -> VerifiedManifest:
    """The service's own pre-notify check, using the wire library's ``verify_manifest``."""
    return verify_manifest(signed, signer.trusted_public_keys(), require_pq=require_pq)


# --------------------------------------------------------------------------------------------
# Development key source: passphrase-encrypted file
# --------------------------------------------------------------------------------------------


def _derive(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)


def encrypt_keyring(plaintext: bytes, passphrase: bytes, *, n: int = SCRYPT_N) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt, n, SCRYPT_R, SCRYPT_P)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, KEYRING_AAD)
    doc = {
        "format": KEYRING_FORMAT,
        "kdf": {
            "name": "scrypt",
            "salt_b64": base64.b64encode(salt).decode(),
            "n": n,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(doc, indent=2, sort_keys=True).encode()


def decrypt_keyring(data: bytes, passphrase: bytes) -> bytes:
    try:
        doc = json.loads(data)
        if doc.get("format") != KEYRING_FORMAT or doc["kdf"]["name"] != "scrypt":
            raise SigningError("unsupported key ring file format")
        kdf = doc["kdf"]
        key = _derive(
            passphrase,
            base64.b64decode(kdf["salt_b64"]),
            int(kdf["n"]),
            int(kdf["r"]),
            int(kdf["p"]),
        )
        return AESGCM(key).decrypt(
            base64.b64decode(doc["nonce_b64"]), base64.b64decode(doc["ciphertext_b64"]), KEYRING_AAD
        )
    except SigningError:
        raise
    except Exception as exc:  # InvalidTag, KeyError, ValueError ...
        raise SigningError("key ring file cannot be decrypted (wrong passphrase?)") from exc


def load_file_signer(
    path: Path, passphrase: bytes, *, pq_enabled: bool = True, key_name: str | None = None
) -> KeyringSigner:
    plaintext = decrypt_keyring(path.read_bytes(), passphrase)
    return KeyringSigner.from_plaintext(plaintext, pq_enabled=pq_enabled, key_name=key_name)


def load_pem_signer(
    pem: bytes, passphrase: bytes | None, *, key_name: str | None = None
) -> KeyringSigner:
    """Single Ed25519 key from PKCS#8 PEM (encrypted with ``passphrase`` when given)."""
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase)
    except (ValueError, TypeError) as exc:
        raise SigningError("signing key PEM cannot be loaded (wrong passphrase?)") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SigningError("firmware signing key must be Ed25519")
    return KeyringSigner([(key, datetime.now(UTC), True)], key_name=key_name)


def generate_pem_key(path: Path, passphrase: bytes | None) -> None:
    """Create a new Ed25519 key file (0600), encrypted when a passphrase is configured."""
    key = ed25519.Ed25519PrivateKey.generate()
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


# --------------------------------------------------------------------------------------------
# Production key source: Secrets Manager + KMS
# --------------------------------------------------------------------------------------------


def kms_wrap_keyring(kms: KMSClient, key_id: str, plaintext: bytes) -> str:
    """Encrypt a key ring under the KEK; the returned base64 string is the secret value."""
    blob = kms.encrypt(KeyId=key_id, Plaintext=plaintext, EncryptionContext=KMS_ENCRYPTION_CONTEXT)
    return base64.b64encode(blob["CiphertextBlob"]).decode()


def load_kms_signer(
    secrets: SecretsManagerClient,
    kms: KMSClient,
    *,
    secret_id: str,
    key_id: str,
    pq_enabled: bool = True,
    key_name: str | None = None,
) -> KeyringSigner:
    """Fetch the wrapped key ring from Secrets Manager and unwrap it with ``kms:Decrypt``.

    ``KeyId`` pins the CMK so a blob encrypted under any other key is refused by KMS.
    """
    secret = secrets.get_secret_value(SecretId=secret_id)
    binary = secret.get("SecretBinary")
    blob = bytes(binary) if binary else base64.b64decode(secret.get("SecretString", ""))
    plaintext = kms.decrypt(
        CiphertextBlob=blob, KeyId=key_id, EncryptionContext=KMS_ENCRYPTION_CONTEXT
    )["Plaintext"]
    return KeyringSigner.from_plaintext(plaintext, pq_enabled=pq_enabled, key_name=key_name)


def new_keyring_entries(*, with_mldsa: bool, now: datetime | None = None) -> list[dict[str, Any]]:
    created = now or datetime.now(UTC)
    entries: list[dict[str, Any]] = [
        {"algorithm": ED25519, "seed": os.urandom(32), "created_at": created, "active": True}
    ]
    if with_mldsa:
        entries.append(
            {"algorithm": ML_DSA_65, "seed": os.urandom(32), "created_at": created, "active": True}
        )
    return entries


def rotate_entries(
    entries: list[dict[str, Any]], algorithm: str, *, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Add a new active key of ``algorithm``; previous keys stay trusted but inactive."""
    created = now or datetime.now(UTC)
    rotated = [{**e, "active": False} if e["algorithm"] == algorithm else dict(e) for e in entries]
    rotated.append(
        {"algorithm": algorithm, "seed": os.urandom(32), "created_at": created, "active": True}
    )
    return rotated


def entries_from_plaintext(plaintext: bytes) -> list[dict[str, Any]]:
    return [
        {"algorithm": e.algorithm, "seed": e.seed, "created_at": e.created_at, "active": e.active}
        for e in _parse_keyring(plaintext)
    ]
