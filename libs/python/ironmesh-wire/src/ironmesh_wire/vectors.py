"""Deterministic test-vector generator (``python -m ironmesh_wire vectors --out DIR``).

Every file written under the output directory is a JSON document with ``schema_version: 1`` and a
``description``; byte strings are lower-case hex. The generator is self-checking: every expected
error code is obtained by actually running the decoder and asserting the intended code, so a
vector file can never disagree with the reference implementation that produced it.

Determinism: all inputs are fixed (keys from ``tests/keys``, fixed timestamps, seeded PRNG for
bulk data). Ed25519 signatures are deterministic, so EdDSA/manifest vectors must be reproduced
byte-for-byte. ECDSA (ES256) in ``cryptography`` uses a random nonce, and ML-DSA is hedged, so
those signatures are stored as produced and are *verification* vectors: implementations must
accept them (and reject the tampered variants) but are not expected to regenerate them.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from . import (
    __version__,
    attestation,
    cbor,
    cose,
    delta,
    envelope,
    errors,
    hpke,
    ids,
    manifest,
    mldsa,
)
from .cbor import CborValue, Tag
from .constants import AckStatus, Direction, EventSeverity, MessageType, OtaState, SeType
from .errors import WireError

SCHEMA_VERSION: Final = 1

# Fixed scenario constants ----------------------------------------------------------------------
TENANT_ID: Final = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
OTHER_TENANT_ID: Final = "0f0d2d7a-6a11-4a4f-9c1b-7e4b1a9c3c2e"
DEVICE_ID: Final = "dev-8f3a1c2b9d4e5f60"
DEVICE_SERIAL: Final = 0x3FA1B2C3D4E5F60718293A4B5C6D7E8F
UNKNOWN_SERIAL: Final = 0x0123456789ABCDEF0123456789ABCDEF
NOW: Final = 1767225600  # 2026-01-01T00:00:00Z
CAMPAIGN_ID: Final = "0b1e2d3c-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
CMD_ID: Final = "123e4567-e89b-12d3-a456-426614174000"
NONCE: Final = bytes(range(16))
ATT_NONCE: Final = sha256(b"ironmesh-test-vectors/attestation-nonce").digest()
CSR_DER: Final = b"\x30\x82\x01\x00" + sha256(b"ironmesh-test-vectors/csr").digest() * 8
FW_VERSION: Final = "2.4.1"
PRODUCT: Final = "gateway-rpi"


def _rand(seed: str, length: int) -> bytes:
    return random.Random(f"ironmesh-test-vectors/{seed}").randbytes(length)


FIRMWARE_IMAGE: Final = _rand("firmware-image", 1000)
FW_HASH: Final = sha256(FIRMWARE_IMAGE).digest()


# Keys -------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TestKeys:
    """The fixed test keys from ``tests/keys`` (public test material)."""

    device: ec.EllipticCurvePrivateKey
    attacker: ec.EllipticCurvePrivateKey
    tenant: ed25519.Ed25519PrivateKey
    fw: ed25519.Ed25519PrivateKey
    fw_untrusted: ed25519.Ed25519PrivateKey
    fw_mldsa_seed: bytes | None

    @classmethod
    def load(cls, directory: Path) -> TestKeys:
        def pem(name: str) -> Any:
            return serialization.load_pem_private_key((directory / name).read_bytes(), None)

        seed_file = directory / "fw_mldsa65.seed.hex"
        seed = bytes.fromhex(seed_file.read_text().strip()) if seed_file.exists() else None
        return cls(
            device=pem("device_p256.pem"),
            attacker=pem("attacker_p256.pem"),
            tenant=pem("tenant_ed25519.pem"),
            fw=pem("fw_ed25519.pem"),
            fw_untrusted=pem("fw_ed25519_untrusted.pem"),
            fw_mldsa_seed=seed,
        )

    @property
    def device_identity(self) -> envelope.SigningIdentity:
        return envelope.SigningIdentity.device(self.device, DEVICE_SERIAL)

    @property
    def tenant_identity(self) -> envelope.SigningIdentity:
        return envelope.SigningIdentity.tenant(self.tenant, TENANT_ID)

    def resolver(self) -> envelope.StaticKeyResolver:
        return envelope.StaticKeyResolver(
            {
                self.device_identity.kid: self.device.public_key(),
                self.tenant_identity.kid: self.tenant.public_key(),
            }
        )

    def mldsa_signer(self) -> mldsa.CryptographyMlDsa65Signer | None:
        if self.fw_mldsa_seed is None or not mldsa.is_available():  # pragma: no cover
            return None
        return mldsa.CryptographyMlDsa65Signer.from_seed(self.fw_mldsa_seed)


def default_keys_dir() -> Path:
    """``<repo>/libs/python/ironmesh-wire/tests/keys`` when running from a source checkout."""
    return Path(__file__).resolve().parents[2] / "tests" / "keys"


# JSON helpers -----------------------------------------------------------------------------------


def _pem_private(key: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _pem_public(key: cose.PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _key_json(key: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    public = key.public_key()
    out: dict[str, Any] = {
        "algorithm": "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) else "EdDSA",
        "private_pem": _pem_private(key),
        "public_pem": _pem_public(public),
        "public_raw_hex": cose.raw_public_key(public).hex(),
    }
    if isinstance(key, ed25519.Ed25519PrivateKey):
        out["private_seed_hex"] = key.private_bytes_raw().hex()
    else:
        out["private_scalar_hex"] = key.private_numbers().private_value.to_bytes(32, "big").hex()
    return out


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, SeType):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            (f.name + "_hex" if isinstance(getattr(value, f.name), bytes) else f.name): _jsonable(
                getattr(value, f.name)
            )
            for f in dataclasses.fields(value)
        }
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    return value


def _message_json(message: envelope.Message, wire: bytes | None = None) -> dict[str, Any]:
    payload = envelope.encode_payload(message)
    out: dict[str, Any] = {
        "seq": message.seq,
        "ts": message.ts,
        "type": int(message.type),
        "type_name": message.type.name,
        "body": _jsonable(message.body),
        "payload_diag": cbor.diagnostic(cbor.decode(payload)),
        "payload_hex": payload.hex(),
    }
    if message.nonce is not None:
        out["nonce_hex"] = message.nonce.hex()
    if wire is not None:
        signed = cose.sign1_decode(wire)
        out["protected_hex"] = signed.protected.hex()
        out["sig_structure_hex"] = signed.to_be_signed().hex()
        out["signature_hex"] = signed.signature.hex()
        out["wire_hex"] = wire.hex()
    return out


def _doc(description: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "description": description,
        "generator": f"ironmesh_wire {__version__}",
        **fields,
    }


def _expect_error(fn: Callable[[], object], code: str) -> str:
    """Run ``fn``, assert it raises a WireError with ``code`` and return the code."""
    try:
        fn()
    except WireError as exc:
        if exc.code != code:
            raise AssertionError(f"expected {code}, got {exc.code}: {exc}") from exc
        return code
    raise AssertionError(f"expected error {code} but the call succeeded")


def _flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


# Individual files -------------------------------------------------------------------------------


def cbor_canonical_vectors() -> dict[str, Any]:
    valid: list[tuple[str, CborValue]] = [
        ("uint 0", 0),
        ("uint 23", 23),
        ("uint 24", 24),
        ("uint 255", 255),
        ("uint 256", 256),
        ("uint 65535", 65535),
        ("uint 65536", 65536),
        ("uint 2^32-1", 4294967295),
        ("uint 2^32", 4294967296),
        ("uint 2^64-1", 18446744073709551615),
        ("nint -1", -1),
        ("nint -24", -24),
        ("nint -25", -25),
        ("nint -256", -256),
        ("nint -257", -257),
        ("nint -2^64", -18446744073709551616),
        ("bstr empty", b""),
        ("bstr 4", b"\x01\x02\x03\x04"),
        ("bstr 24", bytes(range(24))),
        ("tstr empty", ""),
        ("tstr a", "a"),
        ("tstr IETF", "IETF"),
        ("tstr u-umlaut", "ü"),
        ("tstr CJK", "水"),
        ("tstr 24 chars", "x" * 24),
        ("array empty", []),
        ("array 1 2 3", [1, 2, 3]),
        ("array nested", [1, [2, 3], [4, 5]]),
        ("array 25 items", list(range(25))),
        ("map empty", {}),
        ("map int keys", {1: 2, 3: 4}),
        ("map int keys unsorted input", {3: 4, 1: 2}),
        ("map tstr keys", {"a": 1, "b": [2, 3]}),
        ("map key order by length-prefix", {"aa": 1, "b": 2}),
        ("map mixed key types", {1: "x", "a": 2, -1: 3, b"k": 4, 100: 5}),
        ("map key order 1 24 256", {256: "z", 1: "x", 24: "y"}),
        ("false", False),
        ("true", True),
        ("null", None),
        ("float 0.0", 0.0),
        ("float -0.0", -0.0),
        ("float 1.0", 1.0),
        ("float 1.5", 1.5),
        ("float 65504.0", 65504.0),
        ("float 100000.0", 100000.0),
        ("float 3.4028234663852886e38", 3.4028234663852886e38),
        ("float 1.1", 1.1),
        ("float 1.0e300", 1.0e300),
        ("float 5.960464477539063e-8", 5.960464477539063e-8),
        ("float 0.00006103515625", 0.00006103515625),
        ("float -4.0", -4.0),
        ("float 12.5 (telemetry cpu_pct)", 12.5),
        ("float 36.6 (needs double)", 36.6),
        ("float Infinity", float("inf")),
        ("float -Infinity", float("-inf")),
        ("float NaN", float("nan")),
        ("tag 18 skeleton", Tag(18, [b"", {}, b"", b""])),
        ("tag 98 skeleton", Tag(98, [b"", {}, b"", []])),
        ("tag 16 skeleton", Tag(16, [b"", {}, b""])),
        ("envelope-like map", {1: 42, 2: NOW, 3: 1, 4: {1: 12.5, 8: bytes(32), 9: "2.4.1"}}),
    ]
    valid_out = []
    for name, value in valid:
        encoded = cbor.encode(value)
        decoded = cbor.decode(encoded)
        if not (isinstance(value, float) and value != value):
            assert decoded == value, name
        valid_out.append({"name": name, "diag": cbor.diagnostic(value), "hex": encoded.hex()})

    invalid: list[tuple[str, str, str]] = [
        ("non-minimal uint 1 byte", "1801", errors.CBOR_NON_MINIMAL_INT),
        ("non-minimal uint 2 bytes", "190001", errors.CBOR_NON_MINIMAL_INT),
        ("non-minimal uint 4 bytes", "1a00000100", errors.CBOR_NON_MINIMAL_INT),
        ("non-minimal uint 8 bytes", "1b0000000000010000", errors.CBOR_NON_MINIMAL_INT),
        ("non-minimal nint", "3801", errors.CBOR_NON_MINIMAL_INT),
        ("non-minimal bstr length", "580401020304", errors.CBOR_NON_MINIMAL_INT),
        ("non-minimal array length", "9803010203", errors.CBOR_NON_MINIMAL_INT),
        ("indefinite bstr", "5f4101ff", errors.CBOR_INDEFINITE),
        ("indefinite tstr", "7f6161ff", errors.CBOR_INDEFINITE),
        ("indefinite array", "9f0102ff", errors.CBOR_INDEFINITE),
        ("indefinite map", "bf0102ff", errors.CBOR_INDEFINITE),
        ("duplicate keys", "a201000100", errors.CBOR_DUPLICATE_KEY),
        ("keys not sorted", "a202000100", errors.CBOR_KEY_ORDER),
        (
            "keys sorted length-first (RFC 7049) instead of bytewise",
            "a22000186400",
            errors.CBOR_KEY_ORDER,
        ),
        ("float key", "a1f93c0000", errors.CBOR_KEY_TYPE),
        ("array key", "a1800100", errors.CBOR_KEY_TYPE),
        ("bool key", "a1f500", errors.CBOR_KEY_TYPE),
        ("float 1.0 as single", "fa3f800000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("float 1.0 as double", "fb3ff0000000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("float 100000.0 as double", "fb40f86a0000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("NaN as double", "fb7ff8000000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("NaN half with payload", "f97e01", errors.CBOR_NON_MINIMAL_FLOAT),
        ("Infinity as single", "fa7f800000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("simple undefined", "f7", errors.CBOR_SIMPLE),
        ("simple value 16", "f0", errors.CBOR_SIMPLE),
        ("simple value 32 (two-byte form)", "f820", errors.CBOR_SIMPLE),
        ("reserved additional info 28", "1c", errors.CBOR_RESERVED),
        ("lone break", "ff", errors.CBOR_BREAK),
        ("tag 0 not allowed", "c000", errors.CBOR_TAG),
        ("tag 2 bignum not allowed", "c249010000000000000000", errors.CBOR_TAG),
        ("tag 24 not allowed", "d81841a0", errors.CBOR_TAG),
        ("truncated uint", "18", errors.CBOR_TRUNCATED),
        ("truncated bstr", "440102", errors.CBOR_TRUNCATED),
        ("truncated array", "830102", errors.CBOR_TRUNCATED),
        ("truncated map", "a20101", errors.CBOR_TRUNCATED),
        ("empty input", "", errors.CBOR_TRUNCATED),
        ("trailing bytes", "0100", errors.CBOR_TRAILING),
        ("invalid utf-8", "62c328", errors.CBOR_UTF8),
        ("depth 17 (16 nested arrays around a value)", "81" * 16 + "00", errors.CBOR_DEPTH),
        ("size over 64 KiB", "59ffff" + "00" * 65535, errors.CBOR_SIZE),
    ]
    invalid_out = []
    for name, hex_data, code in invalid:
        data = bytes.fromhex(hex_data)
        _expect_error(functools.partial(cbor.decode, data), code)
        invalid_out.append({"name": name, "hex": hex_data, "error": code})
    # depth exactly 16 is accepted
    assert cbor.decode(bytes.fromhex("81" * 15 + "00")) is not None
    return _doc(
        "Canonical CBOR (RFC 8949 section 4.2.1) encoding vectors: 'valid' entries map a diagnostic-"
        "notation value to its unique canonical encoding (encoders MUST produce exactly 'hex'; "
        "decoders MUST accept it); 'invalid' entries MUST be rejected by the strict decoder with "
        "the given error code (see WIRE_FORMAT.md section 2).",
        limits={
            "max_size": cbor.DEFAULT_MAX_SIZE,
            "max_depth": cbor.DEFAULT_MAX_DEPTH,
            "allowed_tags": [16, 18, 98],
        },
        valid=valid_out,
        invalid=invalid_out,
    )


def _sign1_cases(key: cose.PrivateKey, kid: cose.Kid) -> list[dict[str, Any]]:
    payloads = [
        ("empty payload", b""),
        ("short payload", b"IronMesh"),
        ("cbor map payload", cbor.encode({1: 1, 2: NOW, 3: 1, 4: {}})),
    ]
    out = []
    for name, payload in payloads:
        wire = cose.sign1_encode(payload, key, kid)
        signed = cose.sign1_decode(wire)
        cose.sign1_verify(signed, key.public_key())
        out.append(
            {
                "name": name,
                "payload_hex": payload.hex(),
                "protected_hex": signed.protected.hex(),
                "sig_structure_hex": signed.to_be_signed().hex(),
                "signature_hex": signed.signature.hex(),
                "message_hex": wire.hex(),
            }
        )
    return out


def _sign1_negative(
    wire: bytes, public_key: cose.PublicKey, wrong_key: cose.PublicKey
) -> list[dict[str, Any]]:
    signed = cose.sign1_decode(wire)
    protected_offset = wire.index(signed.protected)
    payload_offset = wire.index(signed.payload, protected_offset + len(signed.protected))
    signature_offset = wire.index(signed.signature, payload_offset + len(signed.payload))

    def verify(data: bytes, key: cose.PublicKey = public_key) -> None:
        cose.sign1_verify(cose.sign1_decode(data), key)

    alg_name = "-7 -> -8" if signed.alg == cose.ALG_ES256 else "-8 -> -7"
    cases: list[tuple[str, bytes, str, str]] = [
        ("flip payload byte", _flip(wire, payload_offset), "key", errors.COSE_SIGNATURE),
        ("flip signature byte", _flip(wire, signature_offset), "key", errors.COSE_SIGNATURE),
        (
            f"flip alg byte ({alg_name}): algorithm no longer matches the key",
            _flip(wire, protected_offset + 2),
            "key",
            errors.COSE_ALG,
        ),
        (
            "flip last kid byte (header still valid, signature breaks)",
            _flip(wire, protected_offset + len(signed.protected) - 1),
            "key",
            errors.COSE_SIGNATURE,
        ),
        ("wrong public key", wire, "wrong_key", errors.COSE_SIGNATURE),
        ("tag 18 removed", wire[1:], "key", errors.COSE_TAG),
        ("unprotected header not empty", _with_unprotected(wire), "key", errors.COSE_HEADER),
        ("signature truncated", _truncate_signature(wire), "key", errors.COSE_SIGNATURE),
    ]
    out = []
    for name, data, which, code in cases:
        key = public_key if which == "key" else wrong_key
        _expect_error(functools.partial(verify, data, key), code)
        out.append({"name": name, "message_hex": data.hex(), "verify_with": which, "error": code})
    return out


def _with_unprotected(wire: bytes) -> bytes:
    value = cbor.decode(wire)
    assert isinstance(value, Tag)
    assert isinstance(value.value, list)
    protected, _unprotected, payload, signature = value.value
    return cbor.encode(Tag(18, [protected, {1: -7}, payload, signature]))


def _truncate_signature(wire: bytes) -> bytes:
    value = cbor.decode(wire)
    assert isinstance(value, Tag)
    assert isinstance(value.value, list)
    protected, unprotected, payload, signature = value.value
    assert isinstance(signature, bytes)
    return cbor.encode(Tag(18, [protected, unprotected, payload, signature[:-1]]))


def cose_sign1_es256_vectors(keys: TestKeys) -> dict[str, Any]:
    kid = ids.kid_from_serial(DEVICE_SERIAL)
    cases = _sign1_cases(keys.device, kid)
    negative = _sign1_negative(
        bytes.fromhex(cases[1]["message_hex"]), keys.device.public_key(), keys.attacker.public_key()
    )
    return _doc(
        "COSE_Sign1 with ES256 (ECDSA P-256 / SHA-256, raw r||s signature) over the IronMesh "
        "protected header {1: -7, 4: kid}. ECDSA signatures are randomized, so these are "
        "VERIFICATION vectors: implementations must accept every case with the given public key "
        "and reject every 'negative' case with the given error code; they are not expected to "
        "reproduce signature_hex.",
        deterministic=False,
        key=_key_json(keys.device),
        wrong_key=_key_json(keys.attacker),
        kid_hex=kid.hex(),
        cases=cases,
        negative=negative,
    )


def cose_sign1_eddsa_vectors(keys: TestKeys) -> dict[str, Any]:
    kid = ids.tenant_kid(TENANT_ID)
    cases = _sign1_cases(keys.tenant, kid)
    other = ed25519.Ed25519PrivateKey.from_private_bytes(
        sha256(b"ironmesh-test-vectors/other-ed25519/v1").digest()
    )
    negative = _sign1_negative(
        bytes.fromhex(cases[1]["message_hex"]), keys.tenant.public_key(), other.public_key()
    )
    return _doc(
        "COSE_Sign1 with EdDSA (Ed25519) over the IronMesh protected header {1: -8, 4: kid}. "
        "Ed25519 is deterministic: implementations MUST reproduce message_hex byte-for-byte from "
        "the private seed, and must reject every 'negative' case with the given error code.",
        deterministic=True,
        key=_key_json(keys.tenant),
        wrong_key=_key_json(other),
        kid=kid,
        cases=cases,
        negative=negative,
    )


def _telemetry() -> envelope.Telemetry:
    return envelope.Telemetry(
        cpu_pct=12.5,
        mem_pct=40.25,
        net_rx_bytes=1048576,
        net_tx_bytes=65536,
        temp_c=36.6,
        uptime_s=86400,
        auth_failures=0,
        fw_hash=FW_HASH,
        fw_version=FW_VERSION,
        proc_count=142,
        top_procs=("ironmesh-agent", "sshd", "mosquitto"),
        lat=52.52,
        lon=13.405,
    )


def envelope_telemetry_vectors(keys: TestKeys) -> dict[str, Any]:
    message = envelope.Message(seq=1001, ts=NOW - 2, body=_telemetry())
    wire = envelope.encode(message, keys.device_identity)
    decoded = envelope.decode(wire, keys.resolver(), envelope.InMemoryReplayStore(), NOW)
    assert decoded == message
    return _doc(
        "A Telemetry envelope (type 1) signed by the device key (ES256, kid = certificate serial). "
        "Implementations MUST produce payload_hex from the body fields and MUST accept wire_hex "
        "with now = 'now' (verification vector: the ES256 signature is randomized).",
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        device_key=_key_json(keys.device),
        cert_serial_hex=f"{DEVICE_SERIAL:032x}",
        kid_hex=ids.kid_from_serial(DEVICE_SERIAL).hex(),
        topic=ids.build_topic(TENANT_ID, DEVICE_ID, ids.TopicClass.TELEMETRY),
        now=NOW,
        message=_message_json(message, wire),
        expect="accept",
    )


def _command() -> envelope.Message:
    return envelope.Message(
        seq=7,
        ts=NOW,
        body=envelope.Command(
            cmd_id=CMD_ID,
            name="reboot",
            args={"delay_s": 5, "reason": "maintenance"},
            idempotency_key="idem-2026-01-01-0001",
            expires_at=NOW + 600,
        ),
        nonce=NONCE,
    )


def _ack(nonce: bytes = NONCE, status: int = AckStatus.OK) -> envelope.Message:
    return envelope.Message(
        seq=1002,
        ts=NOW + 1,
        body=envelope.CommandAck(cmd_id=CMD_ID, status=status, result={"rebooted": True}),
        nonce=nonce,
    )


def envelope_command_ack_vectors(keys: TestKeys) -> dict[str, Any]:
    command = _command()
    command_wire = envelope.encode(command, keys.tenant_identity)
    ack = _ack()
    ack_wire = envelope.encode(ack, keys.device_identity)
    resolver = keys.resolver()
    store = envelope.InMemoryReplayStore()
    decoded_cmd = envelope.decode(command_wire, resolver, store, NOW, expected_tenant=TENANT_ID)
    decoded_ack = envelope.decode(ack_wire, resolver, store, NOW, expected_nonce=decoded_cmd.nonce)
    envelope.check_ack(decoded_cmd, decoded_ack)
    bad_nonce_wire = envelope.encode(_ack(nonce=bytes(16)), keys.device_identity)
    code = _expect_error(
        lambda: envelope.decode(
            bad_nonce_wire, resolver, envelope.InMemoryReplayStore(), NOW, expected_nonce=NONCE
        ),
        errors.ENV_NONCE,
    )
    return _doc(
        "A Command (type 5, downlink, EdDSA by the tenant key - deterministic, MUST be reproduced) "
        "and the matching CommandAck (type 6, uplink, ES256 by the device key - verification "
        "vector). The ack MUST echo the command nonce; 'ack_bad_nonce' MUST be rejected with the "
        "given error when verified with expected_nonce = command nonce.",
        tenant_id=TENANT_ID,
        tenant_key=_key_json(keys.tenant),
        tenant_kid=ids.tenant_kid(TENANT_ID),
        device_key=_key_json(keys.device),
        device_kid_hex=ids.kid_from_serial(DEVICE_SERIAL).hex(),
        now=NOW,
        command=_message_json(command, command_wire),
        ack=_message_json(ack, ack_wire),
        ack_bad_nonce={
            "wire_hex": bad_nonce_wire.hex(),
            "expected_nonce_hex": NONCE.hex(),
            "error": code,
        },
    )


def _manifest() -> manifest.Manifest:
    return manifest.Manifest(
        product=PRODUCT,
        version=FW_VERSION,
        version_code=20401,
        image_sha256=FW_HASH,
        image_size=len(FIRMWARE_IMAGE),
        created_at=NOW - 86400,
        min_version_code=20000,
        delta=None,
        signing_key_id="fw-signing-2026",
    )


def manifest_vectors(keys: TestKeys) -> dict[str, Any]:
    m = _manifest()
    payload = manifest.encode_manifest(m)
    ed_pub = cose.raw_public_key(keys.fw.public_key())
    untrusted_pub = cose.raw_public_key(keys.fw_untrusted.public_key())
    signed_ed = manifest.sign_manifest(m, keys.fw)
    trusted = [ed_pub]
    pq = keys.mldsa_signer()
    pq_json: dict[str, Any] | None = None
    signed_hybrid: bytes | None = None
    if pq is not None:
        signed_hybrid = manifest.sign_manifest(m, keys.fw, pq)
        trusted.append(pq.public_key)
        pq_json = {
            "seed_hex": pq.seed.hex(),
            "public_raw_hex": pq.public_key.hex(),
            "kid_hex": cose.key_id(pq.public_key).hex(),
        }
        verified = manifest.verify_manifest(signed_hybrid, trusted, require_pq=True)
        assert verified.pq_verified
        assert verified.manifest == m

    verified_ed = manifest.verify_manifest(signed_ed, trusted)
    assert verified_ed.manifest == m
    assert not verified_ed.pq_verified

    sign_message = cose.sign_decode(signed_ed)
    ed_sig = sign_message.signatures[0]

    verify_cases: list[dict[str, Any]] = [
        {
            "name": "ed25519 only, pq not required",
            "signed_hex": signed_ed.hex(),
            "require_pq": False,
            "expect": "accept",
        },
        {
            "name": "ed25519 only, pq required",
            "signed_hex": signed_ed.hex(),
            "require_pq": True,
            "expect": "reject",
            "error": _expect_error(
                lambda: manifest.verify_manifest(signed_ed, trusted, require_pq=True),
                errors.COSE_PQ_REQUIRED,
            ),
        },
    ]
    untrusted_signed = manifest.sign_manifest(m, keys.fw_untrusted)
    verify_cases.append(
        {
            "name": "signed by an untrusted ed25519 key",
            "signed_hex": untrusted_signed.hex(),
            "require_pq": False,
            "expect": "reject",
            "error": _expect_error(
                lambda: manifest.verify_manifest(untrusted_signed, trusted), errors.COSE_UNKNOWN_KEY
            ),
        }
    )
    tampered = bytearray(signed_ed)
    tampered[signed_ed.index(payload) + 5] ^= 0x01  # inside the embedded manifest payload
    verify_cases.append(
        {
            "name": "manifest payload tampered",
            "signed_hex": bytes(tampered).hex(),
            "require_pq": False,
            "expect": "reject",
            "error": _expect_error(
                lambda: manifest.verify_manifest(bytes(tampered), trusted), errors.COSE_SIGNATURE
            ),
        }
    )
    if signed_hybrid is not None:
        verify_cases.append(
            {
                "name": "hybrid, pq required",
                "signed_hex": signed_hybrid.hex(),
                "require_pq": True,
                "expect": "accept",
            }
        )
        pq_sig = cose.sign_decode(signed_hybrid).signature_for(cose.ALG_ML_DSA_65)
        assert pq_sig is not None
        bad_pq = bytearray(signed_hybrid)
        bad_pq[signed_hybrid.index(pq_sig.signature) + 10] ^= 0x01
        verify_cases.append(
            {
                "name": "hybrid with corrupted ML-DSA signature, pq required",
                "signed_hex": bytes(bad_pq).hex(),
                "require_pq": True,
                "expect": "reject",
                "error": _expect_error(
                    lambda: manifest.verify_manifest(bytes(bad_pq), trusted, require_pq=True),
                    errors.COSE_SIGNATURE,
                ),
            }
        )

    acceptance_inputs: list[tuple[str, bytes, int, str]] = [
        ("accept", FIRMWARE_IMAGE, 20400, PRODUCT),
        ("downgrade (equal version_code)", FIRMWARE_IMAGE, 20401, PRODUCT),
        ("downgrade (higher current)", FIRMWARE_IMAGE, 20402, PRODUCT),
        ("current below min_version_code", FIRMWARE_IMAGE, 19999, PRODUCT),
        ("product mismatch", FIRMWARE_IMAGE, 20400, "sensor-esp32"),
        ("image tampered", _flip(FIRMWARE_IMAGE, 100), 20400, PRODUCT),
        ("image truncated", FIRMWARE_IMAGE[:-1], 20400, PRODUCT),
    ]
    acceptance_cases = []
    for name, image, current, product in acceptance_inputs:
        result = manifest.accept_image(m, image, current, product)
        acceptance_cases.append(
            {
                "name": name,
                "image_hex": image.hex(),
                "current_version_code": current,
                "product": product,
                "accepted": result.accepted,
                "reason": result.reason,
            }
        )

    return _doc(
        "Firmware manifest (contract section 6): canonical manifest bytes, the COSE_Sign (tag 98) "
        "signed manifest with Ed25519 only (deterministic, MUST be reproduced) and with the hybrid "
        "Ed25519 + ML-DSA-65 pair (verification only - ML-DSA signing is hedged), verification "
        "cases and the pure accept_image() acceptance cases.",
        manifest=_jsonable(m),
        manifest_diag=cbor.diagnostic(cbor.decode(payload)),
        manifest_hex=payload.hex(),
        image_hex=FIRMWARE_IMAGE.hex(),
        ed25519_key={**_key_json(keys.fw), "kid_hex": ed_sig.kid.hex()},
        ed25519_signature={
            "protected_hex": ed_sig.protected.hex(),
            "sig_structure_hex": sign_message.to_be_signed(ed_sig).hex(),
            "signature_hex": ed_sig.signature.hex(),
        },
        untrusted_ed25519_public_raw_hex=untrusted_pub.hex(),
        mldsa65_key=pq_json,
        trusted_pubkeys_hex=[k.hex() for k in trusted],
        signed_ed25519_only_hex=signed_ed.hex(),
        signed_hybrid_hex=None if signed_hybrid is None else signed_hybrid.hex(),
        verify_cases=verify_cases,
        acceptance_cases=acceptance_cases,
    )


def _delta_doc(name: str, description: str, old: bytes, new: bytes) -> dict[str, Any]:
    patch = delta.make_delta(old, new)
    assert delta.apply_delta(old, patch) == new
    header, copies, literal_bytes = delta.inspect_delta(patch)
    return _doc(
        description,
        name=name,
        block_size=delta.BLOCK_SIZE,
        old_hex=old.hex(),
        new_hex=new.hex(),
        patch_hex=patch.hex(),
        header={
            "base_size": header.base_size,
            "base_sha256_hex": header.base_sha256.hex(),
            "target_sha256_hex": header.target_sha256.hex(),
            "target_size": header.target_size,
        },
        copy_ops=copies,
        literal_bytes=literal_bytes,
    )


def delta_vectors() -> dict[str, dict[str, Any]]:
    b = delta.BLOCK_SIZE
    blocks = [_rand(f"delta-block-{i}", b) for i in range(4)]
    old = b"".join(blocks[:3]) + _rand("delta-tail-old", 100)
    files = {
        "delta_identical": _delta_doc(
            "identical",
            "Target equals base: every full block is a COPY, the 100-byte tail is a LITERAL.",
            old,
            old,
        ),
        "delta_small_change": _delta_doc(
            "small_change",
            "One byte changed in block 1: COPY 0, LITERAL(block 1'), COPY 2, LITERAL(tail).",
            old,
            blocks[0] + _flip(blocks[1], 17) + blocks[2] + old[3 * b :],
        ),
        "delta_insert_shift": _delta_doc(
            "insert_shift",
            "A new block inserted at the front and blocks reordered: COPY ops reference base "
            "blocks by index (first occurrence wins), the new block is a LITERAL.",
            old,
            blocks[3] + blocks[2] + blocks[0] + blocks[0] + old[3 * b :],
        ),
        "delta_partial_tail": _delta_doc(
            "partial_tail",
            "Base and target sizes are not multiples of 4096; the base tail is never a COPY "
            "source because only full 4 KiB base blocks are indexed.",
            blocks[0] + b"tail-old",
            blocks[0] + b"tail-new-longer",
        ),
        "delta_empty_base": _delta_doc(
            "empty_base",
            "Empty base image: the whole target is LITERAL ops (<= 4096 bytes each).",
            b"",
            blocks[1] + b"xyz",
        ),
        "delta_empty_target": _delta_doc(
            "empty_target",
            "Empty target: header with target_size 0 followed directly by END.",
            old,
            b"",
        ),
        "delta_both_empty": _delta_doc(
            "both_empty",
            "Both images empty: 92-byte header plus END (SHA-256 of empty input).",
            b"",
            b"",
        ),
    }
    files["delta_invalid"] = _delta_invalid_doc(
        old, blocks[0] + _flip(blocks[1], 17) + blocks[2] + old[3 * b :]
    )
    return files


def _delta_invalid_doc(old: bytes, new: bytes) -> dict[str, Any]:
    patch = delta.make_delta(old, new)
    header_end = delta.HEADER_SIZE
    cases: list[tuple[str, bytes, bytes, str]] = []

    def add(name: str, base: bytes, bad: bytes, code: str) -> None:
        _expect_error(lambda: delta.apply_delta(base, bad), code)
        cases.append((name, base, bad, code))

    add("bad magic", old, b"IMDELTA2" + patch[8:], errors.DELTA_MAGIC)
    add(
        "block size 2048",
        old,
        patch[:8] + (2048).to_bytes(4, "big") + patch[12:],
        errors.DELTA_BLOCK_SIZE,
    )
    add("header truncated", old, patch[:50], errors.DELTA_TRUNCATED)
    add(
        "base_size mismatch",
        old,
        patch[:12] + (len(old) + 1).to_bytes(8, "big") + patch[20:],
        errors.DELTA_BASE_SIZE,
    )
    add("wrong base image (base hash mismatch)", _flip(old, 0), patch, errors.DELTA_BASE_HASH)
    add("corrupted base_sha256 field", old, _flip(patch, 20), errors.DELTA_BASE_HASH)
    add("corrupted target_sha256 field", old, _flip(patch, 52), errors.DELTA_TARGET_HASH)
    add(
        "corrupted literal byte",
        old,
        _flip(patch, header_end + 5 + 3 + 10),
        errors.DELTA_TARGET_HASH,
    )
    add(
        "unknown op 0x09",
        old,
        patch[:header_end] + b"\x09" + patch[header_end + 1 :],
        errors.DELTA_OP,
    )
    add(
        "COPY index out of bounds",
        old,
        patch[:header_end] + b"\x01\xff\xff\xff\xff" + patch[header_end + 5 :],
        errors.DELTA_BOUNDS,
    )
    add(
        "LITERAL length 0",
        old,
        patch[:header_end] + b"\x02\x00\x00" + patch[header_end:],
        errors.DELTA_LITERAL_LEN,
    )
    add(
        "extra COPY makes output too long",
        old,
        patch[:-1] + b"\x01\x00\x00\x00\x00\x03",
        errors.DELTA_OVERFLOW,
    )
    add("END too early (output short)", old, patch[:header_end] + b"\x03", errors.DELTA_SHORT)
    add("missing END", old, patch[:-1], errors.DELTA_MISSING_END)
    add("truncated inside an op", old, patch[: header_end + 3], errors.DELTA_TRUNCATED)
    add("trailing bytes after END", old, patch + b"\x00", errors.DELTA_TRAILING)
    return _doc(
        "Invalid patches that apply_delta MUST reject with the given error code. Each case gives "
        "the base image and the patch; 'old_hex' is the shared base unless overridden per case.",
        valid_patch_hex=patch.hex(),
        old_hex=old.hex(),
        new_hex=new.hex(),
        cases=[
            {
                "name": name,
                "old_hex": None if base == old else base.hex(),
                "patch_hex": bad.hex(),
                "error": code,
            }
            for name, base, bad, code in cases
        ],
    )


RFC9180_A3_1: Final[dict[str, Any]] = {
    "mode": 0,
    "kem_id": 16,
    "kdf_id": 1,
    "aead_id": 1,
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "ikmE": "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
    "pkEm": "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
    "skEm": "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
    "ikmR": "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550",
    "pkRm": "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
    "skRm": "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
    "enc": "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
    "shared_secret": "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
    "key_schedule_context": "00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85",
    "secret": "2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1",
    "key": "868c066ef58aae6dc589b6cfdd18f97e",
    "base_nonce": "4e0bc5018beba4bf004cca59",
    "exporter_secret": "14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f",
    "encryptions": [
        {
            "sequence_number": 0,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d30",
            "nonce": "4e0bc5018beba4bf004cca59",
            "ct": "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
        },
        {
            "sequence_number": 1,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d31",
            "nonce": "4e0bc5018beba4bf004cca58",
            "ct": "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82",
        },
        {
            "sequence_number": 2,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d32",
            "nonce": "4e0bc5018beba4bf004cca5b",
            "ct": "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec",
        },
        {
            "sequence_number": 4,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d34",
            "nonce": "4e0bc5018beba4bf004cca5d",
            "ct": "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f",
        },
        {
            "sequence_number": 255,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d323535",
            "nonce": "4e0bc5018beba4bf004ccaa6",
            "ct": "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd",
        },
        {
            "sequence_number": 256,
            "pt": "4265617574792069732074727574682c20747275746820626561757479",
            "aad": "436f756e742d323536",
            "nonce": "4e0bc5018beba4bf004ccb59",
            "ct": "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2",
        },
    ],
    "exports": [
        {
            "exporter_context": "",
            "L": 32,
            "exported_value": "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d",
        },
        {
            "exporter_context": "00",
            "L": 32,
            "exported_value": "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796",
        },
        {
            "exporter_context": "54657374436f6e74657874",
            "L": 32,
            "exported_value": "d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a",
        },
    ],
}


def check_rfc9180_a3_1() -> None:
    """Reproduce RFC 9180 Appendix A.3.1 with :mod:`ironmesh_wire.hpke` (raises on mismatch)."""
    v = RFC9180_A3_1
    sk_r = hpke.derive_key_pair(bytes.fromhex(v["ikmR"]))
    assert hpke.serialize_public_key(sk_r.public_key()).hex() == v["pkRm"]
    assert sk_r.private_numbers().private_value.to_bytes(32, "big").hex() == v["skRm"]
    sk_e = hpke.derive_key_pair(bytes.fromhex(v["ikmE"]))
    assert sk_e.private_numbers().private_value.to_bytes(32, "big").hex() == v["skEm"]
    enc, ctx_s = hpke.setup_base_s(
        sk_r.public_key(), bytes.fromhex(v["info"]), bytes.fromhex(v["ikmE"])
    )
    assert enc.hex() == v["enc"]
    assert ctx_s.key.hex() == v["key"]
    assert ctx_s.base_nonce.hex() == v["base_nonce"]
    assert ctx_s.exporter_secret.hex() == v["exporter_secret"]
    ctx_r = hpke.setup_base_r(enc, sk_r, bytes.fromhex(v["info"]))
    assert ctx_r.key == ctx_s.key
    for encryption in v["encryptions"]:
        # The RFC lists selected sequence numbers only; position both contexts explicitly.
        ctx_s.seq = encryption["sequence_number"]
        ctx_r.seq = encryption["sequence_number"]
        assert ctx_s._next_nonce().hex() == encryption["nonce"]
        ct = ctx_s.seal(bytes.fromhex(encryption["aad"]), bytes.fromhex(encryption["pt"]))
        assert ct.hex() == encryption["ct"], encryption["sequence_number"]
        assert ctx_r.open(bytes.fromhex(encryption["aad"]), ct).hex() == encryption["pt"]
    for export in v["exports"]:
        assert (
            ctx_s.export(bytes.fromhex(export["exporter_context"]), export["L"]).hex()
            == export["exported_value"]
        )


def hpke_vectors(keys: TestKeys) -> dict[str, Any]:
    check_rfc9180_a3_1()
    config_message = envelope.Message(
        seq=3,
        ts=NOW,
        body=envelope.Config(
            version=12, settings={"telemetry_interval_s": 60, "log_level": "info"}
        ),
    )
    plaintext = envelope.encode(config_message, keys.tenant_identity)
    cek = _rand("config-cek", 32)
    iv = _rand("config-iv", 12)
    ikm_e = _rand("config-ikm-e", 32)
    encrypt0 = hpke.wrap_config(plaintext, keys.device.public_key(), cek=cek, iv=iv, ikm_e=ikm_e)
    assert hpke.unwrap_config(encrypt0, keys.device) == plaintext
    parsed = cose.encrypt0_decode(encrypt0)
    tampered = _flip(encrypt0, len(encrypt0) - 1)
    bad = _expect_error(lambda: hpke.unwrap_config(tampered, keys.device), errors.COSE_DECRYPT)
    wrong = _expect_error(lambda: hpke.unwrap_config(encrypt0, keys.attacker), errors.HPKE_OPEN)
    return _doc(
        "HPKE (RFC 9180) DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM base-mode vectors "
        "copied from RFC 9180 Appendix A.3.1 (which this library reproduces), plus an IronMesh "
        "Config key-wrap example: the plaintext (a signed Config envelope, deterministic) is "
        "encrypted as COSE_Encrypt0 with fixed CEK, IV and ephemeral ikm so that encrypt0_hex is "
        "reproducible by an implementation exposing the same test hooks; every implementation MUST "
        "at least decrypt encrypt0_hex with the device private key.",
        rfc9180_a3_1=RFC9180_A3_1,
        config_encrypt0={
            "device_key": _key_json(keys.device),
            "wrong_device_key": _key_json(keys.attacker),
            "hpke_info_hex": hpke.CONFIG_HPKE_INFO.hex(),
            "hpke_info_ascii": hpke.CONFIG_HPKE_INFO.decode(),
            "cek_hex": cek.hex(),
            "iv_hex": iv.hex(),
            "ephemeral_ikm_hex": ikm_e.hex(),
            "protected_hex": parsed.protected.hex(),
            "enc_structure_hex": parsed.enc_structure().hex(),
            "enc_hex": parsed.enc.hex(),
            "wrapped_key_hex": parsed.wrapped_key.hex(),
            "ciphertext_hex": parsed.ciphertext.hex(),
            "plaintext_message": _message_json(config_message, plaintext),
            "plaintext_hex": plaintext.hex(),
            "encrypt0_hex": encrypt0.hex(),
            "negative": [
                {
                    "name": "ciphertext tag byte flipped",
                    "encrypt0_hex": tampered.hex(),
                    "error": bad,
                },
                {"name": "wrong recipient key", "encrypt0_hex": encrypt0.hex(), "error": wrong},
            ],
        },
    )


def attestation_vectors(keys: TestKeys) -> dict[str, Any]:
    wire = attestation.build_attestation(
        keys.device_identity,
        seq=1,
        ts=NOW,
        nonce=ATT_NONCE,
        csr_der=CSR_DER,
        fw_hash=FW_HASH,
        fw_version=FW_VERSION,
        se_type=SeType.SOFTWARE,
    )
    message = attestation.verify_attestation(
        wire, keys.device.public_key(), expected_nonce=ATT_NONCE, csr_der=CSR_DER, now=NOW
    )
    wrong_nonce = _expect_error(
        lambda: attestation.verify_attestation(
            wire, keys.device.public_key(), expected_nonce=bytes(32), csr_der=CSR_DER, now=NOW
        ),
        errors.ATT_NONCE,
    )
    wrong_csr = _expect_error(
        lambda: attestation.verify_attestation(
            wire,
            keys.device.public_key(),
            expected_nonce=ATT_NONCE,
            csr_der=CSR_DER + b"x",
            now=NOW,
        ),
        errors.ATT_CSR_HASH,
    )
    policy = _expect_error(
        lambda: attestation.verify_attestation(
            wire,
            keys.device.public_key(),
            expected_nonce=ATT_NONCE,
            csr_der=CSR_DER,
            now=NOW,
            allowed_se_types=[SeType.ATECC608, SeType.TPM2],
        ),
        errors.ATT_SE_TYPE,
    )
    return _doc(
        "Attestation envelope (type 10, contract section 3) for a software-keyed device: signed "
        "with the current identity key (ES256, kid = cert serial), body {1: nonce, 2: sha256(csr), "
        "3: fw_hash, 4: fw_version, 5: 'software', 6: null}. Verification vector (ES256).",
        device_key=_key_json(keys.device),
        kid_hex=ids.kid_from_serial(DEVICE_SERIAL).hex(),
        now=NOW,
        nonce_hex=ATT_NONCE.hex(),
        csr_der_hex=CSR_DER.hex(),
        csr_hash_hex=sha256(CSR_DER).hexdigest(),
        message=_message_json(message, wire),
        negative=[
            {"name": "nonce mismatch", "expected_nonce_hex": bytes(32).hex(), "error": wrong_nonce},
            {"name": "csr mismatch", "csr_der_hex": (CSR_DER + b"x").hex(), "error": wrong_csr},
            {
                "name": "se_type not allowed by policy",
                "allowed_se_types": ["atecc608", "tpm2"],
                "error": policy,
            },
        ],
    )


def replay_vectors(keys: TestKeys) -> dict[str, Any]:
    resolver = keys.resolver()
    store = envelope.InMemoryReplayStore()
    steps: list[dict[str, Any]] = []

    def telemetry(seq: int, ts: int) -> bytes:
        return envelope.encode(
            envelope.Message(seq=seq, ts=ts, body=_telemetry()), keys.device_identity
        )

    def run(
        name: str,
        wire: bytes,
        *,
        now: int = NOW,
        expected_nonce: bytes | None = None,
        error: str | None = None,
    ) -> None:
        def call() -> envelope.Message:
            return envelope.decode(
                wire, resolver, store, now, expected_nonce=expected_nonce, expected_tenant=TENANT_ID
            )

        step: dict[str, Any] = {"name": name, "wire_hex": wire.hex(), "now": now}
        if expected_nonce is not None:
            step["expected_nonce_hex"] = expected_nonce.hex()
        if error is None:
            call()
            step["expect"] = "accept"
        else:
            step["expect"] = "reject"
            step["error"] = _expect_error(call, error)
        step["store_after"] = {
            "uplink_last_seq": store.last_seq(keys.device_identity.kid, Direction.UPLINK),
            "downlink_last_seq": store.last_seq(keys.tenant_identity.kid, Direction.DOWNLINK),
        }
        steps.append(step)

    run("uplink seq 10 accepted", telemetry(10, NOW))
    run("uplink seq 10 again rejected (equal)", telemetry(10, NOW), error=errors.ENV_REPLAY)
    run("uplink seq 9 rejected (lower)", telemetry(9, NOW), error=errors.ENV_REPLAY)
    run("uplink seq 11 accepted (higher)", telemetry(11, NOW))
    run(
        "uplink seq 12 ts 301 s in the past rejected",
        telemetry(12, NOW - 301),
        error=errors.ENV_TS_SKEW,
    )
    run(
        "uplink seq 12 ts 301 s in the future rejected",
        telemetry(12, NOW + 301),
        error=errors.ENV_TS_SKEW,
    )
    run("uplink seq 12 ts exactly 300 s old accepted", telemetry(12, NOW - 300))
    run("uplink seq 13 ts exactly 300 s ahead accepted", telemetry(13, NOW + 300))
    good = telemetry(14, NOW)
    signed = cose.sign1_decode(good)
    run(
        "uplink seq 14 with flipped signature byte rejected",
        _flip(good, good.index(signed.signature)),
        error=errors.COSE_SIGNATURE,
    )
    run(
        "uplink seq 14 with flipped payload byte rejected",
        _flip(good, good.index(signed.payload) + 3),
        error=errors.COSE_SIGNATURE,
    )
    forged = envelope.encode(
        envelope.Message(seq=14, ts=NOW, body=_telemetry()),
        envelope.SigningIdentity(keys.attacker, keys.device_identity.kid),
    )
    run(
        "uplink seq 14 signed by another key under the device kid rejected",
        forged,
        error=errors.COSE_SIGNATURE,
    )
    unknown = envelope.encode(
        envelope.Message(seq=14, ts=NOW, body=_telemetry()),
        envelope.SigningIdentity.device(keys.attacker, UNKNOWN_SERIAL),
    )
    run("uplink seq 14 from an unknown kid rejected", unknown, error=errors.ENV_UNKNOWN_KEY)
    wrong_direction = cose.sign1_encode(
        envelope.encode_payload(envelope.Message(seq=14, ts=NOW, body=_telemetry())),
        keys.tenant,
        keys.tenant_identity.kid,
    )
    run(
        "telemetry signed by the tenant key (downlink header) rejected",
        wrong_direction,
        error=errors.ENV_DIRECTION,
    )
    wrong_alg = cose.sign1_encode(
        envelope.encode_payload(envelope.Message(seq=14, ts=NOW, body=_telemetry())),
        keys.tenant,
        keys.device_identity.kid,
    )
    run("device kid with EdDSA algorithm rejected", wrong_alg, error=errors.ENV_DIRECTION)
    run("uplink seq 14 accepted (store unchanged by rejected messages)", telemetry(14, NOW))

    command = envelope.encode(_command(), keys.tenant_identity)
    run("downlink command seq 7 accepted", command)
    run("downlink command seq 7 replayed rejected", command, error=errors.ENV_REPLAY)
    other_tenant = envelope.encode(
        dataclasses.replace(_command(), seq=8),
        envelope.SigningIdentity.tenant(keys.tenant, OTHER_TENANT_ID),
    )
    run(
        "downlink command signed under another tenant kid rejected (expected_tenant)",
        other_tenant,
        error=errors.ENV_TENANT,
    )
    ack = envelope.encode(dataclasses.replace(_ack(), seq=15), keys.device_identity)
    run("uplink ack seq 15 with matching nonce accepted", ack, expected_nonce=NONCE)
    bad_ack = envelope.encode(
        dataclasses.replace(_ack(nonce=bytes(16)), seq=16), keys.device_identity
    )
    run(
        "uplink ack seq 16 with wrong nonce rejected",
        bad_ack,
        expected_nonce=NONCE,
        error=errors.ENV_NONCE,
    )
    no_nonce_payload = cbor.encode(
        {1: 17, 2: NOW, 3: 6, 4: envelope.CommandAck(CMD_ID, 0).to_map()}
    )
    run(
        "uplink ack seq 17 without nonce rejected",
        cose.sign1_encode(no_nonce_payload, keys.device, keys.device_identity.kid),
        error=errors.ENV_NONCE,
    )
    telemetry_with_nonce = cbor.encode({1: 17, 2: NOW, 3: 1, 4: _telemetry().to_map(), 5: NONCE})
    run(
        "telemetry seq 17 carrying a nonce rejected",
        cose.sign1_encode(telemetry_with_nonce, keys.device, keys.device_identity.kid),
        error=errors.ENV_NONCE,
    )
    unknown_type = cbor.encode({1: 17, 2: NOW, 3: 11, 4: {}})
    run(
        "unknown message type 11 rejected",
        cose.sign1_encode(unknown_type, keys.device, keys.device_identity.kid),
        error=errors.ENV_TYPE,
    )
    run("uplink seq 17 accepted", telemetry(17, NOW))

    return _doc(
        "Ordered sequence of envelopes verified against one replay store (initially empty) with "
        "the given key resolver (device kid -> device key, tenant kid -> tenant key) and "
        "expected_tenant = tenant_id. Each step gives 'now', the expected outcome and, for "
        "rejections, the error code; 'store_after' is the store state after the step. All "
        "device-signed messages are ES256 verification vectors.",
        tenant_id=TENANT_ID,
        tenant_key=_key_json(keys.tenant),
        tenant_kid=ids.tenant_kid(TENANT_ID),
        device_key=_key_json(keys.device),
        device_kid_hex=ids.kid_from_serial(DEVICE_SERIAL).hex(),
        attacker_key=_key_json(keys.attacker),
        max_skew=envelope.MAX_SKEW_DEFAULT,
        steps=steps,
    )


def ids_vectors() -> dict[str, Any]:
    topics = [
        {
            "class": cls.name,
            "suffix": cls.value,
            "topic": ids.build_topic(TENANT_ID, DEVICE_ID, cls),
            "direction": cls.direction.value,
            "device_publishes": cls.device_publishes,
            "message_type": int(cls.message_type),
            "retained_allowed": cls.retained_allowed,
            "qos": cls.qos,
        }
        for cls in ids.TopicClass
    ]
    bad_topics = [
        "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/#",
        "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/+/telemetry",
        "im/v2/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/telemetry",
        "im/v1/not-a-tenant/dev-8f3a1c2b9d4e5f60/telemetry",
        "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8F3A1C2B9D4E5F60/telemetry",
        "im/v1/7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11/dev-8f3a1c2b9d4e5f60/shadow",
    ]
    for topic in bad_topics:
        _expect_error(functools.partial(ids.parse_topic, topic), errors.TOPIC_FORMAT)
    return _doc(
        "Identifier formats (contract section 1), key identifiers (section 5) and the MQTT topic "
        "scheme (section 4).",
        identifiers={
            "tenant_valid": [TENANT_ID, OTHER_TENANT_ID],
            "tenant_invalid": [
                "7E4B1A9C-3C2E-4A4F-9C1B-0F0D2D7A6A11",
                "7e4b1a9c-3c2e-1a4f-9c1b-0f0d2d7a6a11",
                "7e4b1a9c3c2e4a4f9c1b0f0d2d7a6a11",
            ],
            "device_valid": [DEVICE_ID, "dev-0000000000000000"],
            "device_invalid": [
                "dev-8f3a1c2b9d4e5f6",
                "dev-8F3A1C2B9D4E5F60",
                "device-8f3a1c2b9d4e5f60",
            ],
            "group_valid": ["eu-west-gateways", "a", "x" * 48],
            "group_invalid": ["", "EU-west", "x" * 49, "eu_west"],
            "firmware_id_valid": ["gateway-rpi/2.4.1", "sensor-esp32/1.0.0-rc.1+build.5"],
            "firmware_id_invalid": ["gateway-rpi", "gateway-rpi/2.4", "Gateway/1.0.0"],
        },
        key_ids={
            "device_kid_hex": ids.kid_from_serial(DEVICE_SERIAL).hex(),
            "device_serial_hex": f"{DEVICE_SERIAL:032x}",
            "device_kid_leading_zero_stripped_hex": ids.kid_from_serial(0x00FF).hex(),
            "tenant_kid": ids.tenant_kid(TENANT_ID),
            "fw_ed25519_kid_rule": "SHA-256(raw 32-byte public key)[0:8]",
            "fw_mldsa65_kid_rule": "SHA-256(raw 1952-byte public key)[0:8]",
        },
        topics=topics,
        invalid_topics=bad_topics,
        bridge_shared_subscription=ids.BRIDGE_SHARED_SUBSCRIPTION,
    )


# Driver -----------------------------------------------------------------------------------------


def generate_all(out_dir: Path, keys: TestKeys) -> list[Path]:
    """Write every vector file into ``out_dir`` and return the written paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    documents: dict[str, dict[str, Any]] = {
        "cbor_canonical": cbor_canonical_vectors(),
        "cose_sign1_es256": cose_sign1_es256_vectors(keys),
        "cose_sign1_eddsa": cose_sign1_eddsa_vectors(keys),
        "envelope_telemetry": envelope_telemetry_vectors(keys),
        "envelope_command_ack": envelope_command_ack_vectors(keys),
        "manifest_signed": manifest_vectors(keys),
        "hpke_rfc9180_a3": hpke_vectors(keys),
        "attestation_software": attestation_vectors(keys),
        "replay_cases": replay_vectors(keys),
        "ids_topics": ids_vectors(),
        **delta_vectors(),
    }
    written: list[Path] = []
    for name, document in documents.items():
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written


def _unused_hint() -> Sequence[type[object]]:  # pragma: no cover - keeps enum imports documented
    return (EventSeverity, OtaState, MessageType)
