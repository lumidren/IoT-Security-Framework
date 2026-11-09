"""Signer key ring (file + KMS), rotation, keytool, and both artifact stores (moto for S3)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from moto import mock_aws

from ironmesh_ota import keytool, signing
from ironmesh_ota.storage import (
    ArtifactConflict,
    ArtifactError,
    ArtifactNotFound,
    DownloadSigner,
    LocalArtifactStore,
    S3ArtifactStore,
    validate_key,
)
from ironmesh_wire import cose
from ironmesh_wire.errors import CoseError
from ironmesh_wire.manifest import Manifest, verify_manifest

PASS = b"correct horse battery staple"


def _manifest(code: int = 7, key_name: str = "fw-ed25519-1") -> Manifest:
    return Manifest("gw", "1.2.3", code, b"\x11" * 32, 1024, 1_700_000_000, 0, None, key_name)


def test_keyring_round_trip_with_hybrid_signature(tmp_path: Path) -> None:
    entries = signing.new_keyring_entries(with_mldsa=True)
    path = tmp_path / "ring.json"
    path.write_bytes(signing.encrypt_keyring(signing.keyring_document(entries), PASS, n=2**12))
    signer = signing.load_file_signer(path, PASS, key_name="fw-ed25519-1")
    assert signer.pq_enabled and signer.key_name == "fw-ed25519-1"
    signed = signer.sign(_manifest())
    assert signed.pq_signed and len(signed.key_ids) == 2
    verified = verify_manifest(signed.signed, signer.trusted_public_keys(), require_pq=True)
    assert verified.pq_verified and verified.manifest.signing_key_id == "fw-ed25519-1"
    assert signing.verify_signed(signed.signed, signer, require_pq=True).payload == signed.payload
    infos = {i.algorithm: i for i in signer.list_keys()}
    assert infos["Ed25519"].key_id == signer.active_key_id
    assert infos["ML-DSA-65"].key_id == cose.key_id(infos["ML-DSA-65"].public_key).hex()
    # PQ can be switched off: Ed25519 only, ML-DSA key listed as inactive
    no_pq = signing.load_file_signer(path, PASS, pq_enabled=False)
    assert not no_pq.pq_enabled and not no_pq.sign(_manifest()).pq_signed
    assert [i.active for i in no_pq.list_keys() if i.algorithm == "ML-DSA-65"] == [False]
    with pytest.raises(signing.SigningError):
        signing.load_file_signer(path, b"wrong")


def test_rotation_keeps_old_keys_trusted(tmp_path: Path) -> None:
    entries = signing.new_keyring_entries(with_mldsa=True)
    old = signing.KeyringSigner.from_plaintext(signing.keyring_document(entries))
    old_signed = old.sign(_manifest()).signed
    rotated = signing.rotate_entries(entries, signing.ED25519)
    rotated = signing.rotate_entries(rotated, signing.ML_DSA_65)
    new = signing.KeyringSigner.from_plaintext(signing.keyring_document(rotated))
    assert new.active_key_id != old.active_key_id
    assert len(new.list_keys()) == 4
    assert sum(i.active for i in new.list_keys()) == 2
    # images signed before the rotation still verify; new signatures use the new key
    verify_manifest(old_signed, new.trusted_public_keys())
    fresh = new.sign(_manifest(8))
    assert verify_manifest(fresh.signed, new.trusted_public_keys()).ed25519_kid.hex() == (
        new.active_key_id
    )
    with pytest.raises(CoseError):
        verify_manifest(fresh.signed, old.trusted_public_keys())
    assert signing.entries_from_plaintext(signing.keyring_document(rotated))[0]["active"] is False


@pytest.mark.parametrize(
    "doc",
    [
        b"not json",
        json.dumps({"version": 2, "keys": []}).encode(),
        json.dumps({"version": 1, "keys": []}).encode(),
        json.dumps(
            {
                "version": 1,
                "keys": [
                    {
                        "algorithm": "RSA",
                        "seed_b64": "AA==",
                        "created_at": "2026-01-01T00:00:00+00:00",
                    }
                ],
            }
        ).encode(),
        json.dumps(
            {
                "version": 1,
                "keys": [
                    {
                        "algorithm": "Ed25519",
                        "seed_b64": "AA==",
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "active": True,
                    }
                ],
            }
        ).encode(),
    ],
)
def test_bad_keyrings_are_refused(doc: bytes) -> None:
    with pytest.raises(signing.SigningError):
        signing.KeyringSigner.from_plaintext(doc)


def test_keyring_consistency_rules() -> None:
    now = datetime.now(UTC)
    key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(signing.SigningError):
        signing.KeyringSigner([(key, now, False)])
    with pytest.raises(signing.SigningError):
        signing.KeyringSigner([(key, now, True), (key, now, False)])
    with pytest.raises(signing.SigningError):
        signing.KeyringSigner([(key, now, True)], key_name="x" * 65)
    two_pq = signing.new_keyring_entries(with_mldsa=True)
    two_pq.append({**two_pq[1], "seed": b"\x01" * 32})
    with pytest.raises(signing.SigningError):
        signing.KeyringSigner.from_plaintext(signing.keyring_document(two_pq))
    seed_only = signing.KeyringSigner.from_plaintext(b"\x07" * 32)
    assert len(seed_only.list_keys()) == 1
    with pytest.raises(signing.SigningError):
        signing.decrypt_keyring(
            json.dumps({"format": "other", "kdf": {"name": "x"}}).encode(), PASS
        )
    with pytest.raises(signing.SigningError):
        signing.decrypt_keyring(b"{}", PASS)


def test_pem_signers_and_generation(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "fw.pem"
    signing.generate_pem_key(path, PASS)
    signer = signing.load_pem_signer(path.read_bytes(), PASS, key_name="dev")
    assert signer.key_name == "dev"
    with pytest.raises(signing.SigningError):
        signing.load_pem_signer(path.read_bytes(), b"nope")
    with pytest.raises(FileExistsError):
        signing.generate_pem_key(path, PASS)
    plain = tmp_path / "plain.pem"
    signing.generate_pem_key(plain, None)
    assert signing.load_pem_signer(plain.read_bytes(), None).active_key_id
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(signing.SigningError):
        signing.load_pem_signer(ec_pem, None)


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    with mock_aws():
        yield


def test_kms_wrapped_keyring_from_secrets_manager(aws: None) -> None:
    kms = boto3.client("kms", region_name="eu-west-1")
    sm = boto3.client("secretsmanager", region_name="eu-west-1")
    key_id = kms.create_key(KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName="alias/ironmesh-firmware-kek", TargetKeyId=key_id)
    entries = signing.new_keyring_entries(with_mldsa=True)
    wrapped = signing.kms_wrap_keyring(
        kms, "alias/ironmesh-firmware-kek", signing.keyring_document(entries)
    )
    sm.create_secret(Name="ironmesh/ota/firmware-signing-keyring", SecretString=wrapped)
    signer = signing.load_kms_signer(
        sm,
        kms,
        secret_id="ironmesh/ota/firmware-signing-keyring",
        key_id="alias/ironmesh-firmware-kek",
        key_name="fw-ed25519-1",
    )
    assert signer.pq_enabled
    verify_manifest(signer.sign(_manifest()).signed, signer.trusted_public_keys(), True)
    # binary secrets holding a bare seed work too
    blob = kms.encrypt(
        KeyId=key_id, Plaintext=b"\x05" * 32, EncryptionContext=signing.KMS_ENCRYPTION_CONTEXT
    )["CiphertextBlob"]
    sm.create_secret(Name="seed", SecretBinary=blob)
    seed_signer = signing.load_kms_signer(sm, kms, secret_id="seed", key_id=key_id)
    assert not seed_signer.pq_enabled
    # a blob wrapped with a different encryption context is refused by KMS
    other = kms.encrypt(KeyId=key_id, Plaintext=b"\x05" * 32)["CiphertextBlob"]
    sm.create_secret(Name="other", SecretBinary=other)
    with pytest.raises(ClientError):
        signing.load_kms_signer(sm, kms, secret_id="other", key_id=key_id)


def test_keytool_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ring = tmp_path / "ring.json"
    with pytest.raises(SystemExit):
        keytool.main(["init", "--out", str(ring)])
    monkeypatch.setenv("OTA_SIGNING_PASSPHRASE", PASS.decode())
    monkeypatch.setattr(signing, "SCRYPT_N", 2**12)
    assert keytool.main(["init", "--out", str(ring), "--mldsa"]) == 0
    assert keytool.main(["rotate", "--file", str(ring)]) == 0
    assert keytool.main(["list", "--file", str(ring)]) == 0
    out = capsys.readouterr().out
    assert out.count("active") >= 2 and "trusted" in out
    signer = signing.load_file_signer(ring, PASS)
    assert len(signer.list_keys()) == 3
    # tenant command keys are the registry's alone: the tool no longer creates them
    with pytest.raises(SystemExit):
        keytool.main(["tenant-key", "--tenant", "x", "--dir", str(tmp_path / "t")])


# --- storage -----------------------------------------------------------------------------------


async def test_local_store_is_write_once(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "s", "http://x/", DownloadSigner(b"k" * 32))
    await store.put("a/b.bin", b"one", "application/octet-stream")
    await store.put("a/b.bin", b"one", "application/octet-stream")  # idempotent
    with pytest.raises(ArtifactConflict):
        await store.put("a/b.bin", b"two", "application/octet-stream")
    src = tmp_path / "src.bin"
    src.write_bytes(b"from file")
    await store.put("a/c.bin", src, "application/octet-stream")
    with pytest.raises(ArtifactConflict):
        await store.put("a/b.bin", src, "application/octet-stream")
    assert await store.get("a/c.bin") == b"from file"
    assert await store.exists("a/c.bin") and not await store.exists("a/zzz")
    with pytest.raises(ArtifactNotFound):
        await store.get("a/missing")
    for bad in ("../etc/passwd", "/abs", "a//b", "a/../b", "", "x" * 600):
        with pytest.raises(ArtifactError):
            validate_key(bad)
    assert await store.ping()
    url = await store.download_url("a/c.bin", 60)
    assert url.startswith("http://x/v1/artifacts/a/c.bin?exp=")
    assert list((tmp_path / "s" / "a").glob(".*.tmp")) == []


def test_download_signer() -> None:
    signer = DownloadSigner(b"s" * 32)
    sig = signer.sign("k", 2_000_000_000)
    assert signer.verify("k", 2_000_000_000, sig, now=1_900_000_000)
    assert not signer.verify("k", 2_000_000_000, sig, now=2_100_000_000)
    assert not signer.verify("other", 2_000_000_000, sig, now=1_900_000_000)
    with pytest.raises(ValueError, match="32 bytes"):
        DownloadSigner(b"short")


async def test_s3_store_with_moto(aws: None, tmp_path: Path) -> None:
    s3 = boto3.client("s3", region_name="eu-west-1", config=Config(signature_version="s3v4"))
    s3.create_bucket(
        Bucket="ota-artifacts",
        ObjectLockEnabledForBucket=True,
        CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
    )
    kms = boto3.client("kms", region_name="eu-west-1")
    key_arn = kms.create_key()["KeyMetadata"]["Arn"]
    store = S3ArtifactStore(
        s3, "ota-artifacts", object_lock_mode="COMPLIANCE", object_lock_days=30, kms_key_id=key_arn
    )
    await store.put("fw/image.bin", b"image", "application/octet-stream")
    await store.put("fw/image.bin", b"image", "application/octet-stream")  # same bytes: ok
    with pytest.raises(ArtifactConflict):
        await store.put("fw/image.bin", b"other", "application/octet-stream")
    src = tmp_path / "big.bin"
    src.write_bytes(b"\x00" * 10_000)
    await store.put("fw/big.bin", src, "application/octet-stream")
    head = s3.head_object(Bucket="ota-artifacts", Key="fw/big.bin")
    assert head["Metadata"]["sha256"] == hashlib.sha256(b"\x00" * 10_000).hexdigest()
    assert head["ObjectLockMode"] == "COMPLIANCE"
    assert head["ServerSideEncryption"] == "aws:kms"
    assert await store.get("fw/image.bin") == b"image"
    with pytest.raises(ArtifactNotFound):
        await store.get("fw/missing")
    assert await store.exists("fw/big.bin") and not await store.exists("fw/none")
    url = await store.download_url("fw/image.bin", 300)
    assert "X-Amz-Expires=300" in url and "ota-artifacts" in url
    assert await store.ping()
    assert not await S3ArtifactStore(s3, "no-such-bucket").ping()


async def test_s3_unexpected_errors_propagate(aws: None) -> None:
    from botocore.exceptions import ClientError

    class Broken:
        def put_object(self, **_: Any) -> None:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")

        def get_object(self, **_: Any) -> None:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")

        def head_object(self, **_: Any) -> None:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "HeadObject")

    store = S3ArtifactStore(Broken(), "b")  # type: ignore[arg-type]
    with pytest.raises(ClientError):
        await store.put("k", b"x", "t")
    with pytest.raises(ClientError):
        await store.get("k")
    with pytest.raises(ClientError):
        await store.exists("k")
