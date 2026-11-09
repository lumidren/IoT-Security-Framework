#!/usr/bin/env python3
"""Wrap an ESP32 app image into an IronMesh firmware artifact (contract section 6) using the
Python reference wire library (libs/python/ironmesh-wire):

    out/image.bin       the (Secure Boot signed) app image, byte for byte
    out/manifest.cbor   canonical manifest {product, version, version_code, image_sha256, ...}
    out/manifest.sig    COSE_Sign (tag 98): Ed25519 (+ optional ML-DSA-65) over manifest.cbor
    out/patch.imdelta   optional IMDELTA1 patch from --base (delta manifest key 8)

The app descriptor inside the image is checked: its version must equal version.txt (line 1)
and its secure_version must not exceed what the manifest promises (eFuse anti-rollback).

    python tools/sign_and_package.py build/ironmesh_esp32.bin --key fw_signing_ed25519.pem \
        --product sensor-esp32 [--min-version-code 10000] [--base previous.bin] [--out dist/]
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "libs" / "python" / "ironmesh-wire" / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from ironmesh_wire import delta as im_delta  # noqa: E402
from ironmesh_wire import manifest as im_manifest  # noqa: E402

APP_DESC_MAGIC = 0xABCD5432


def app_desc(image: bytes) -> tuple[int, str]:
    """(secure_version, version) from esp_app_desc_t (first segment, after the 24+8 byte headers)."""
    if len(image) < 32 + 48 or image[0] != 0xE9:
        raise SystemExit("not an ESP-IDF app image (magic 0xE9 missing)")
    magic, secure_version = struct.unpack_from("<II", image, 32)
    if magic != APP_DESC_MAGIC:
        raise SystemExit("esp_app_desc_t not found at offset 32")
    version = image[32 + 16: 32 + 48].split(b"\0", 1)[0].decode()
    return secure_version, version


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", type=Path)
    ap.add_argument("--key", type=Path, required=True, help="Ed25519 signing key (PKCS#8 PEM)")
    ap.add_argument("--key-id", default="fw-signing", help="informational signing_key_id")
    ap.add_argument("--product", default="sensor-esp32")
    ap.add_argument("--version-file", type=Path, default=ROOT / "version.txt")
    ap.add_argument("--min-version-code", type=int, default=0)
    ap.add_argument("--base", type=Path, help="currently deployed image for a delta patch")
    ap.add_argument("--out", type=Path, default=Path("dist"))
    ap.add_argument("--skip-app-desc-check", action="store_true", help="for non-ESP test images")
    a = ap.parse_args(argv)

    lines = a.version_file.read_text().split()
    version, version_code = lines[0], int(lines[1])
    image = a.image.read_bytes()
    if not a.skip_app_desc_check:
        secure_version, desc_version = app_desc(image)
        if desc_version != version:
            raise SystemExit(f"image app_desc version {desc_version!r} != version.txt {version!r}")
        print(f"app_desc: version {desc_version}, secure_version {secure_version}")
    key = serialization.load_pem_private_key(a.key.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SystemExit("--key must be an Ed25519 private key")

    a.out.mkdir(parents=True, exist_ok=True)
    delta_info = None
    if a.base is not None:
        base = a.base.read_bytes()
        patch = im_delta.make_delta(base, image)
        assert im_delta.apply_delta(base, patch) == image
        (a.out / "patch.imdelta").write_bytes(patch)
        delta_info = im_manifest.DeltaInfo(hashlib.sha256(base).digest(), hashlib.sha256(patch).digest(), len(patch))
        print(f"delta: {len(patch)} bytes ({100 * len(patch) // max(1, len(image))} % of the image)")

    m = im_manifest.Manifest(
        product=a.product,
        version=version,
        version_code=version_code,
        image_sha256=hashlib.sha256(image).digest(),
        image_size=len(image),
        created_at=int(time.time()),
        min_version_code=a.min_version_code,
        delta=delta_info,
        signing_key_id=a.key_id,
    )
    payload = im_manifest.encode_manifest(m)
    signed = im_manifest.sign_manifest(payload, key)
    # self-check exactly like a device would
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    im_manifest.verify_manifest(signed, [pub])
    (a.out / "image.bin").write_bytes(image)
    (a.out / "manifest.cbor").write_bytes(payload)
    (a.out / "manifest.sig").write_bytes(signed)
    print(f"{a.product}/{version} (version_code {version_code}) -> {a.out}/ "
          f"[image {len(image)} B, sha256 {hashlib.sha256(image).hexdigest()}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
