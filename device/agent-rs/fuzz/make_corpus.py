"""Derive the seed corpora under fuzz/corpus/<target>/ from device/common/vectors/.

Run from device/agent-rs:  python fuzz/make_corpus.py
Uses the Python reference implementation (libs/python/ironmesh-wire) for the few seeds the
vectors do not contain (signed trust bundles, certs-only PKCS#7, MQTT packets).
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
VECTORS = ROOT / "device" / "common" / "vectors"
sys.path.insert(0, str(ROOT / "libs" / "python" / "ironmesh-wire" / "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
import datetime  # noqa: E402

from ironmesh_wire import cbor, cose  # noqa: E402

CORPUS = HERE / "corpus"


def put(target: str, data: bytes) -> None:
    d = CORPUS / target
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha256(data).hexdigest()[:16]).write_bytes(data)


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def walk_hex(obj, out: list[bytes]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (k.endswith("_hex") or k == "hex") and len(v) % 2 == 0:
                try:
                    out.append(bytes.fromhex(v))
                except ValueError:
                    pass
            else:
                walk_hex(v, out)
    elif isinstance(obj, list):
        for v in obj:
            walk_hex(v, out)


def main() -> None:
    every: list[bytes] = []
    for f in sorted(VECTORS.glob("*.json")):
        if f.name.startswith("delta_") or f.name == "cbor_canonical.json":
            continue
        walk_hex(load(f.name), every)
    cb = load("cbor_canonical.json")
    for case in cb["valid"] + cb["invalid"]:
        data = bytes.fromhex(case["hex"])
        if len(data) <= 4096:
            put("cbor_decode", data)
    cose_like = [b for b in every if b[:1] in (b"\xd2", b"\xd8", b"\xd0", b"\xa4", b"\xa5", b"\xa9")]
    for b in cose_like:
        put("cbor_decode", b)
        if b[:1] == b"\xd2":
            put("cose_sign1_decode", b)
            put("envelope_decode", b)
        if b[:1] == b"\xd8":
            put("cose_sign_decode", b)
            put("manifest_decode", b)
        if b[:1] == b"\xd0":
            put("cose_encrypt0_decode", b)
        if b[:1] in (b"\xa4", b"\xa5"):
            put("envelope_decode", b)
        if b[:1] == b"\xa9":
            put("manifest_decode", b)
    for f in sorted(VECTORS.glob("delta_*.json")):
        doc = load(f.name)
        patches = [doc.get("patch_hex"), doc.get("valid_patch_hex")] + [c["patch_hex"] for c in doc.get("cases", [])]
        for p in patches:
            if p and len(p) <= 40_000:
                put("delta_apply", bytes([64, 0, 0]) + bytes.fromhex(p))
                put("delta_apply", bytes([1, 0, 0]) + bytes.fromhex(p))

    # Trust bundles signed with the fuzz key (seed 0x0b * 32).
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([11]) * 32)
    for port in (8883, 1):
        payload = cbor.encode({1: bytes(32), 2: [bytes(32)], 3: "broker.example", 4: port, 5: [bytes(32)]})
        put("bundle_decode", cose.sign1_encode(payload, key, b"pki-bundle"))
        put("bundle_decode", payload)

    # Certs-only PKCS#7.
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev-0123456789abcdef")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(0x3FA1B2C3D4E5F60718293A4B5C6D7E8F)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=14))
        .sign(ca_key, hashes.SHA256())
    )
    der = pkcs7.serialize_certificates([cert], serialization.Encoding.DER)
    put("pkcs7_decode", der)
    put("pkcs7_decode", pkcs7.serialize_certificates([cert, cert], serialization.Encoding.DER))
    put("pkcs7_decode", __import__("base64").b64encode(der))

    # MQTT 5 packets.
    def varint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n % 128
            n //= 128
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    def s(x: str) -> bytes:
        return struct.pack(">H", len(x)) + x.encode()

    def pkt(first: int, body: bytes) -> bytes:
        return bytes([first]) + varint(len(body)) + body

    props = b"\x11" + struct.pack(">I", 604800) + b"\x21" + struct.pack(">H", 32)
    connect = pkt(0x10, s("MQTT") + b"\x05\x00\x00\x3c" + varint(len(props)) + props + s("dev-0123456789abcdef"))
    connack = pkt(0x20, b"\x01\x00" + b"\x03" + b"\x21\x00\x20")
    up = b"\x26" + s("traceparent") + s("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
    topic = "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/telemetry"
    publish = pkt(0x32, s(topic) + b"\x00\x07" + varint(len(up)) + up + b"\xd2\x84")
    puback = pkt(0x40, b"\x00\x07\x87")
    subscribe = pkt(0x82, b"\x00\x01\x00" + s(topic.replace("telemetry", "cmd/req")) + b"\x01")
    suback = pkt(0x90, b"\x00\x01\x00\x01")
    for p in (connect, connack, publish, puback, subscribe, suback, b"\xc0\x00", b"\xd0\x00", b"\xe0\x00", connack + publish + b"\xd0\x00"):
        put("mqtt_decode", p)
    for target in ("cbor_decode", "cose_sign1_decode", "cose_sign_decode", "cose_encrypt0_decode", "envelope_decode", "manifest_decode", "delta_apply", "mqtt_decode", "pkcs7_decode", "bundle_decode"):
        print(target, len(list((CORPUS / target).iterdir())))


if __name__ == "__main__":
    main()
