"""Message envelope (design contract §5): typed bodies, signing and verification.

A message on the wire is ``COSE_Sign1(payload)`` where ``payload`` is the canonical CBOR map
``{1: seq, 2: ts, 3: type, 4: body, ?5: nonce}``. :func:`encode` produces it; :func:`decode`
verifies the signature, the header profile for the message direction, the timestamp window,
the nonce rules and the strictly increasing sequence number (via a :class:`ReplayStore`).

See ``device/common/WIRE_FORMAT.md`` §4 for the normative description of every rule here.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import ClassVar, Final, Protocol, Self

from . import cbor, cose, errors, fields, ids
from .cbor import DEFAULT_LIMITS, CborValue, DecodeLimits
from .constants import (
    DIRECTION_OF,
    NONCE_TYPES,
    AckStatus,
    Direction,
    EventSeverity,
    MessageType,
    OtaState,
    SeType,
)
from .cose import Kid, PrivateKey, PublicKey
from .errors import EnvelopeError, ReplayError, WireError

KEY_SEQ: Final = 1
KEY_TS: Final = 2
KEY_TYPE: Final = 3
KEY_BODY: Final = 4
KEY_NONCE: Final = 5

NONCE_SIZE: Final = 16
SHA256_SIZE: Final = 32
MAX_SKEW_DEFAULT: Final = 300
MAX_TOP_PROCS: Final = 10
MAX_NAME_LEN: Final = 64
MAX_URL_LEN: Final = 2048
MAX_ERROR_LEN: Final = 1024

type IntMap = fields.IntMap


def _field_error(message: str) -> WireError:
    return EnvelopeError(errors.ENV_FIELD, message)


def _uuid(value: str, what: str) -> str:
    if not ids.is_uuid(value):
        raise _field_error(f"{what}: must be a lower-case hyphenated UUID")
    return value


def _uuid4(value: str, what: str) -> str:
    if not ids.is_uuid4(value):
        raise _field_error(f"{what}: must be a lower-case hyphenated UUIDv4")
    return value


def _semver(value: str) -> str:
    if not ids.is_semver(value):
        raise _field_error(f"fw_version: {value!r} is not a semantic version")
    return value


def _app_map(value: Mapping[str, CborValue], what: str) -> dict[str, CborValue]:
    return fields.check_tstr_map(value, what, _field_error)


# --------------------------------------------------------------------------------------------
# Bodies
# --------------------------------------------------------------------------------------------


class Body(ABC):
    """Base class of the ten message bodies."""

    TYPE: ClassVar[MessageType]

    @abstractmethod
    def to_map(self) -> dict[int, CborValue]:
        """Serialize to the integer-keyed body map (not yet validated)."""

    @classmethod
    @abstractmethod
    def from_map(cls, m: IntMap) -> Self:
        """Parse and validate a decoded body map."""


@dataclass(frozen=True)
class Telemetry(Body):
    """``type = 1``. Keys 1-9 are mandatory; 10-15 are platform specific / optional."""

    TYPE = MessageType.TELEMETRY

    cpu_pct: float
    mem_pct: float
    net_rx_bytes: int
    net_tx_bytes: int
    temp_c: float
    uptime_s: int
    auth_failures: int
    fw_hash: bytes
    fw_version: str
    proc_count: int | None = None
    top_procs: tuple[str, ...] | None = None
    rssi: int | None = None
    free_heap: int | None = None
    lat: float | None = None
    lon: float | None = None

    def to_map(self) -> dict[int, CborValue]:
        m: dict[int, CborValue] = {
            1: float(self.cpu_pct),
            2: float(self.mem_pct),
            3: self.net_rx_bytes,
            4: self.net_tx_bytes,
            5: float(self.temp_c),
            6: self.uptime_s,
            7: self.auth_failures,
            8: self.fw_hash,
            9: self.fw_version,
        }
        if self.proc_count is not None:
            m[10] = self.proc_count
        if self.top_procs is not None:
            m[11] = list(self.top_procs)
        if self.rssi is not None:
            m[12] = self.rssi
        if self.free_heap is not None:
            m[13] = self.free_heap
        if self.lat is not None:
            m[14] = float(self.lat)
        if self.lon is not None:
            m[15] = float(self.lon)
        return m

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, set(range(1, 10)), set(range(10, 16)), "Telemetry", e)
        return cls(
            cpu_pct=fields.get_float(m, 1, "cpu_pct", e),
            mem_pct=fields.get_float(m, 2, "mem_pct", e),
            net_rx_bytes=fields.get_uint(m, 3, "net_rx_bytes", e),
            net_tx_bytes=fields.get_uint(m, 4, "net_tx_bytes", e),
            temp_c=fields.get_float(m, 5, "temp_c", e),
            uptime_s=fields.get_uint(m, 6, "uptime_s", e),
            auth_failures=fields.get_uint(m, 7, "auth_failures", e),
            fw_hash=fields.get_bstr(m, 8, "fw_hash", e, SHA256_SIZE),
            fw_version=_semver(fields.get_tstr(m, 9, "fw_version", e, 1, MAX_NAME_LEN)),
            proc_count=fields.get_uint_opt(m, 10, "proc_count", e),
            top_procs=fields.get_tstr_list_opt(m, 11, "top_procs", e, MAX_TOP_PROCS),
            rssi=fields.get_int_opt(m, 12, "rssi", e),
            free_heap=fields.get_uint_opt(m, 13, "free_heap", e),
            lat=fields.get_float_opt(m, 14, "lat", e),
            lon=fields.get_float_opt(m, 15, "lon", e),
        )


@dataclass(frozen=True)
class Event(Body):
    """``type = 2``: ``{1: name, 2: severity, 3: data}``."""

    TYPE = MessageType.EVENT

    name: str
    severity: int
    data: Mapping[str, CborValue] = field(default_factory=dict)

    def to_map(self) -> dict[int, CborValue]:
        return {1: self.name, 2: self.severity, 3: _app_map(self.data, "Event.data")}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3}, set(), "Event", e)
        return cls(
            name=fields.get_tstr(m, 1, "name", e, 1, MAX_NAME_LEN),
            severity=fields.get_uint(m, 2, "severity", e, max(EventSeverity)),
            data=fields.get_map(m, 3, "data", e),
        )


@dataclass(frozen=True)
class ShadowReported(Body):
    """``type = 3``: ``{1: state, 2: version}``."""

    TYPE = MessageType.SHADOW_REPORTED

    state: Mapping[str, CborValue]
    version: int

    def to_map(self) -> dict[int, CborValue]:
        return {1: _app_map(self.state, "ShadowReported.state"), 2: self.version}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2}, set(), "ShadowReported", e)
        return cls(
            state=fields.get_map(m, 1, "state", e), version=fields.get_uint(m, 2, "version", e)
        )


@dataclass(frozen=True)
class ShadowDesired(Body):
    """``type = 4``: ``{1: state, 2: version}``."""

    TYPE = MessageType.SHADOW_DESIRED

    state: Mapping[str, CborValue]
    version: int

    def to_map(self) -> dict[int, CborValue]:
        return {1: _app_map(self.state, "ShadowDesired.state"), 2: self.version}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2}, set(), "ShadowDesired", e)
        return cls(
            state=fields.get_map(m, 1, "state", e), version=fields.get_uint(m, 2, "version", e)
        )


@dataclass(frozen=True)
class Command(Body):
    """``type = 5``: ``{1: cmd_id, 2: name, 3: args, 4: idempotency_key, 5: expires_at}``."""

    TYPE = MessageType.COMMAND

    cmd_id: str
    name: str
    args: Mapping[str, CborValue]
    idempotency_key: str
    expires_at: int

    def to_map(self) -> dict[int, CborValue]:
        return {
            1: self.cmd_id,
            2: self.name,
            3: _app_map(self.args, "Command.args"),
            4: self.idempotency_key,
            5: self.expires_at,
        }

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3, 4, 5}, set(), "Command", e)
        return cls(
            cmd_id=_uuid(fields.get_tstr(m, 1, "cmd_id", e, 36, 36), "cmd_id"),
            name=fields.get_tstr(m, 2, "name", e, 1, MAX_NAME_LEN),
            args=fields.get_map(m, 3, "args", e),
            idempotency_key=fields.get_tstr(m, 4, "idempotency_key", e, 1, 128),
            expires_at=fields.get_uint(m, 5, "expires_at", e),
        )


@dataclass(frozen=True)
class CommandAck(Body):
    """``type = 6``: ``{1: cmd_id, 2: status, ?3: result, ?4: error}``."""

    TYPE = MessageType.COMMAND_ACK

    cmd_id: str
    status: int
    result: Mapping[str, CborValue] | None = None
    error: str | None = None

    def to_map(self) -> dict[int, CborValue]:
        m: dict[int, CborValue] = {1: self.cmd_id, 2: self.status}
        if self.result is not None:
            m[3] = _app_map(self.result, "CommandAck.result")
        if self.error is not None:
            m[4] = self.error
        return m

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2}, {3, 4}, "CommandAck", e)
        return cls(
            cmd_id=_uuid(fields.get_tstr(m, 1, "cmd_id", e, 36, 36), "cmd_id"),
            status=fields.get_uint(m, 2, "status", e, max(AckStatus)),
            result=fields.get_map_opt(m, 3, "result", e),
            error=fields.get_tstr_opt(m, 4, "error", e, 1, MAX_ERROR_LEN),
        )


@dataclass(frozen=True)
class OtaNotify(Body):
    """``type = 7``: ``{1: campaign_id, 2: manifest, 3: url, 4: delta_from}``."""

    TYPE = MessageType.OTA_NOTIFY

    campaign_id: str
    manifest: bytes
    url: str
    delta_from: bytes | None = None

    def to_map(self) -> dict[int, CborValue]:
        return {1: self.campaign_id, 2: self.manifest, 3: self.url, 4: self.delta_from}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3, 4}, set(), "OtaNotify", e)
        manifest = fields.get_bstr(m, 2, "manifest", e)
        if not manifest:
            raise e("manifest: must not be empty")
        return cls(
            campaign_id=_uuid4(fields.get_tstr(m, 1, "campaign_id", e, 36, 36), "campaign_id"),
            manifest=manifest,
            url=fields.get_tstr(m, 3, "url", e, 1, MAX_URL_LEN),
            delta_from=fields.get_bstr_or_null(m, 4, "delta_from", e, SHA256_SIZE),
        )


@dataclass(frozen=True)
class OtaStatus(Body):
    """``type = 8``: ``{1: campaign_id, 2: state, 3: progress_pct, ?4: error, ?5: fw_hash}``."""

    TYPE = MessageType.OTA_STATUS

    campaign_id: str
    state: int
    progress_pct: int
    error: str | None = None
    fw_hash: bytes | None = None

    def to_map(self) -> dict[int, CborValue]:
        m: dict[int, CborValue] = {1: self.campaign_id, 2: self.state, 3: self.progress_pct}
        if self.error is not None:
            m[4] = self.error
        if self.fw_hash is not None:
            m[5] = self.fw_hash
        return m

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3}, {4, 5}, "OtaStatus", e)
        return cls(
            campaign_id=_uuid4(fields.get_tstr(m, 1, "campaign_id", e, 36, 36), "campaign_id"),
            state=fields.get_uint(m, 2, "state", e, max(OtaState)),
            progress_pct=fields.get_uint(m, 3, "progress_pct", e, 100),
            error=fields.get_tstr_opt(m, 4, "error", e, 1, MAX_ERROR_LEN),
            fw_hash=fields.get_bstr_opt(m, 5, "fw_hash", e, SHA256_SIZE),
        )


@dataclass(frozen=True)
class Config(Body):
    """``type = 9`` (carried inside COSE_Encrypt0): ``{1: version, 2: settings}``."""

    TYPE = MessageType.CONFIG

    version: int
    settings: Mapping[str, CborValue]

    def to_map(self) -> dict[int, CborValue]:
        return {1: self.version, 2: _app_map(self.settings, "Config.settings")}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2}, set(), "Config", e)
        return cls(
            version=fields.get_uint(m, 1, "version", e),
            settings=fields.get_map(m, 2, "settings", e),
        )


@dataclass(frozen=True)
class Tpm2Evidence:
    """``{1: quote (TPMS_ATTEST), 2: signature, 3: ak_cert_der}`` (contract §3)."""

    quote: bytes
    signature: bytes
    ak_cert_der: bytes

    def to_map(self) -> dict[int, CborValue]:
        return {1: self.quote, 2: self.signature, 3: self.ak_cert_der}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3}, set(), "Tpm2Evidence", e)
        quote = fields.get_bstr(m, 1, "quote", e)
        signature = fields.get_bstr(m, 2, "signature", e)
        ak_cert_der = fields.get_bstr(m, 3, "ak_cert_der", e)
        if not quote or not signature or not ak_cert_der:
            raise e("Tpm2Evidence: quote, signature and ak_cert_der must not be empty")
        return cls(quote, signature, ak_cert_der)


@dataclass(frozen=True)
class Attestation(Body):
    """``type = 10``.

    ``{1: nonce, 2: csr_hash, 3: fw_hash, 4: fw_version, 5: se_type, 6: evidence}``
    """

    TYPE = MessageType.ATTESTATION

    nonce: bytes
    csr_hash: bytes
    fw_hash: bytes
    fw_version: str
    se_type: SeType
    evidence: Tpm2Evidence | None = None

    def to_map(self) -> dict[int, CborValue]:
        return {
            1: self.nonce,
            2: self.csr_hash,
            3: self.fw_hash,
            4: self.fw_version,
            5: self.se_type.value,
            6: None if self.evidence is None else self.evidence.to_map(),
        }

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3, 4, 5, 6}, set(), "Attestation", e)
        se_type_text = fields.get_tstr(m, 5, "se_type", e, 1, 16)
        try:
            se_type = SeType(se_type_text)
        except ValueError as exc:
            raise e(f"se_type: unknown value {se_type_text!r}") from exc
        raw_evidence = m.get(6)
        evidence: Tpm2Evidence | None
        if raw_evidence is None:
            evidence = None
        elif isinstance(raw_evidence, dict):
            evidence = Tpm2Evidence.from_map(raw_evidence)
        else:
            raise e("evidence: expected null or map")
        if se_type is SeType.TPM2 and evidence is None:
            raise e("evidence: required for se_type tpm2")
        if se_type is not SeType.TPM2 and evidence is not None:
            raise e(f"evidence: must be null for se_type {se_type.value}")
        return cls(
            nonce=fields.get_bstr(m, 1, "nonce", e, SHA256_SIZE),
            csr_hash=fields.get_bstr(m, 2, "csr_hash", e, SHA256_SIZE),
            fw_hash=fields.get_bstr(m, 3, "fw_hash", e, SHA256_SIZE),
            fw_version=_semver(fields.get_tstr(m, 4, "fw_version", e, 1, MAX_NAME_LEN)),
            se_type=se_type,
            evidence=evidence,
        )


BODY_TYPES: Final[dict[MessageType, type[Body]]] = {
    MessageType.TELEMETRY: Telemetry,
    MessageType.EVENT: Event,
    MessageType.SHADOW_REPORTED: ShadowReported,
    MessageType.SHADOW_DESIRED: ShadowDesired,
    MessageType.COMMAND: Command,
    MessageType.COMMAND_ACK: CommandAck,
    MessageType.OTA_NOTIFY: OtaNotify,
    MessageType.OTA_STATUS: OtaStatus,
    MessageType.CONFIG: Config,
    MessageType.ATTESTATION: Attestation,
}


# --------------------------------------------------------------------------------------------
# Message and payload
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Message:
    """The envelope ``{1: seq, 2: ts, 3: type, 4: body, ?5: nonce}``."""

    seq: int
    ts: int
    body: Body
    nonce: bytes | None = None
    sender_kid: Kid | None = field(default=None, compare=False)
    """Set by :func:`decode` to the verified sender's ``kid``; ignored by :func:`encode`."""

    @property
    def type(self) -> MessageType:
        return self.body.TYPE

    @property
    def direction(self) -> Direction:
        return DIRECTION_OF[self.type]


def _check_nonce(message_type: MessageType, nonce: bytes | None) -> None:
    if message_type in NONCE_TYPES:
        if nonce is None or len(nonce) != NONCE_SIZE:
            raise EnvelopeError(errors.ENV_NONCE, f"{message_type.name}: nonce must be bstr(16)")
    elif nonce is not None:
        raise EnvelopeError(errors.ENV_NONCE, f"{message_type.name}: nonce must be absent")


def encode_payload(message: Message) -> bytes:
    """Canonical CBOR of the envelope map (validated, unsigned)."""
    for name, value in (("seq", message.seq), ("ts", message.ts)):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= cbor.UINT64_MAX
        ):
            raise EnvelopeError(errors.ENV_FIELD, f"{name}: expected uint64")
    body_map = message.body.to_map()
    type(message.body).from_map(body_map)  # validate exactly like a receiver would
    _check_nonce(message.type, message.nonce)
    payload: dict[int, CborValue] = {
        KEY_SEQ: message.seq,
        KEY_TS: message.ts,
        KEY_TYPE: int(message.type),
        KEY_BODY: body_map,
    }
    if message.nonce is not None:
        payload[KEY_NONCE] = message.nonce
    return cbor.encode(payload)


def decode_payload(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> Message:
    """Parse and validate an envelope map; performs no cryptography or replay checks."""
    m = cbor.decode_map(data, limits)
    try:
        fields.expect_keys(
            m, {KEY_SEQ, KEY_TS, KEY_TYPE, KEY_BODY}, {KEY_NONCE}, "envelope", _field_error
        )
    except EnvelopeError as exc:
        raise EnvelopeError(errors.ENV_STRUCTURE, exc.message) from exc
    e = _field_error
    seq = fields.get_uint(m, KEY_SEQ, "seq", e)
    ts = fields.get_uint(m, KEY_TS, "ts", e)
    raw_type = m[KEY_TYPE]
    if (
        not isinstance(raw_type, int)
        or isinstance(raw_type, bool)
        or raw_type not in MessageType._value2member_map_
    ):
        raise EnvelopeError(errors.ENV_TYPE, f"unknown message type {raw_type!r}")
    message_type = MessageType(raw_type)
    raw_body = m[KEY_BODY]
    if not isinstance(raw_body, dict):
        raise EnvelopeError(errors.ENV_STRUCTURE, "body must be a map")
    for key in raw_body:
        if not isinstance(key, int):
            raise EnvelopeError(errors.ENV_FIELD, "body keys must be integers")
    body = BODY_TYPES[message_type].from_map(raw_body)
    raw_nonce = m.get(KEY_NONCE)
    if raw_nonce is not None and not isinstance(raw_nonce, bytes):
        raise EnvelopeError(errors.ENV_NONCE, "nonce must be a bstr")
    _check_nonce(message_type, raw_nonce)
    return Message(seq=seq, ts=ts, body=body, nonce=raw_nonce)


# --------------------------------------------------------------------------------------------
# Signing identities, key resolution and replay store
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SigningIdentity:
    """A private key plus the ``kid`` placed in the protected header."""

    key: PrivateKey
    kid: Kid

    @classmethod
    def device(cls, key: PrivateKey, cert_serial: int) -> SigningIdentity:
        """Device identity: P-256 certificate key, ``kid`` = certificate serial."""
        return cls(key, ids.kid_from_serial(cert_serial))

    @classmethod
    def tenant(cls, key: PrivateKey, tenant_id: str) -> SigningIdentity:
        """Cloud identity: Ed25519 tenant command key, ``kid`` = ``tenant-cmd-<tenant>``."""
        return cls(key, ids.tenant_kid(tenant_id))


type KeyResolver = Callable[[Kid], PublicKey | None]
"""Maps a ``kid`` to the sender's public key (``None`` -> unknown sender)."""


class StaticKeyResolver:
    """A :data:`KeyResolver` backed by a dictionary."""

    def __init__(self, keys: Mapping[Kid, PublicKey]) -> None:
        self._keys = dict(keys)

    def __call__(self, kid: Kid) -> PublicKey | None:
        return self._keys.get(kid)


class ReplayStore(Protocol):
    """Persists the last accepted ``seq`` per ``(sender_kid, direction)``.

    ``check_and_record`` must atomically accept ``seq`` iff it is strictly greater than the last
    accepted value for that sender (or no value exists yet), record it, and return ``True``;
    otherwise it returns ``False`` and leaves the store unchanged.
    """

    def check_and_record(self, sender_kid: Kid, direction: Direction, seq: int) -> bool: ...


class InMemoryReplayStore:
    """Dictionary-backed :class:`ReplayStore` (single process, not durable)."""

    def __init__(self) -> None:
        self._last: dict[tuple[Kid, Direction], int] = {}

    def last_seq(self, sender_kid: Kid, direction: Direction) -> int | None:
        return self._last.get((sender_kid, direction))

    def check_and_record(self, sender_kid: Kid, direction: Direction, seq: int) -> bool:
        key = (sender_kid, direction)
        last = self._last.get(key)
        if last is not None and seq <= last:
            return False
        self._last[key] = seq
        return True


# --------------------------------------------------------------------------------------------
# Header profile per direction
# --------------------------------------------------------------------------------------------


def header_direction(kid: Kid) -> Direction:
    """A bstr ``kid`` means a device sender (uplink); a tstr ``kid`` means the cloud (downlink)."""
    return Direction.UPLINK if isinstance(kid, bytes) else Direction.DOWNLINK


def check_header_profile(alg: int, kid: Kid, direction: Direction) -> None:
    """Enforce contract §5: uplink = ES256 + serial kid; downlink = EdDSA + tenant-cmd kid."""
    if direction is Direction.UPLINK:
        if not ids.is_device_kid(kid):
            raise EnvelopeError(
                errors.ENV_KID, "uplink kid must be the certificate serial (bstr 1..20)"
            )
        if alg != cose.ALG_ES256:
            raise EnvelopeError(errors.ENV_DIRECTION, "uplink messages must be signed with ES256")
    else:
        if not ids.is_tenant_kid(kid):
            raise EnvelopeError(errors.ENV_KID, "downlink kid must be tenant-cmd-<tenant uuid>")
        if alg != cose.ALG_EDDSA:
            raise EnvelopeError(errors.ENV_DIRECTION, "downlink messages must be signed with EdDSA")


# --------------------------------------------------------------------------------------------
# encode / decode
# --------------------------------------------------------------------------------------------


def encode(message: Message, identity: SigningIdentity) -> bytes:
    """Sign ``message`` as a COSE_Sign1 envelope."""
    payload = encode_payload(message)
    alg = cose.alg_for_private_key(identity.key)
    check_header_profile(alg, identity.kid, message.direction)
    return cose.sign1_encode(payload, identity.key, identity.kid)


def decode(
    data: bytes,
    key_resolver: KeyResolver,
    replay_store: ReplayStore,
    now: int | None = None,
    max_skew: int = MAX_SKEW_DEFAULT,
    *,
    expected_direction: Direction | None = None,
    expected_nonce: bytes | None = None,
    expected_tenant: str | None = None,
    limits: DecodeLimits = DEFAULT_LIMITS,
) -> Message:
    """Verify and decode an envelope; raises a :class:`WireError` subclass on any violation.

    Check order (the first failure wins, which fixes the error code for a given input):
    CBOR/COSE structure -> header profile for the kid's direction -> ``expected_direction`` ->
    ``expected_tenant`` -> key resolution -> signature -> payload fields -> type/direction match
    -> timestamp window -> ``expected_nonce`` -> replay (``seq`` strictly increasing).
    The replay store is updated only when every other check has passed.
    """
    if now is None:
        now = int(time.time())
    signed = cose.sign1_decode(data, limits)
    direction = header_direction(signed.kid)
    check_header_profile(signed.alg, signed.kid, direction)
    if expected_direction is not None and direction is not expected_direction:
        raise EnvelopeError(errors.ENV_DIRECTION, f"expected a {expected_direction.value} message")
    if expected_tenant is not None and direction is Direction.DOWNLINK:
        assert isinstance(signed.kid, str)
        if ids.tenant_from_kid(signed.kid) != expected_tenant:
            raise EnvelopeError(errors.ENV_TENANT, "message signed by another tenant's key")
    public_key = key_resolver(signed.kid)
    if public_key is None:
        raise EnvelopeError(errors.ENV_UNKNOWN_KEY, "unknown sender kid")
    cose.sign1_verify(signed, public_key)
    message = decode_payload(signed.payload, limits)
    if message.direction is not direction:
        raise EnvelopeError(
            errors.ENV_DIRECTION,
            f"{message.type.name} cannot be sent in the {direction.value} direction",
        )
    if abs(now - message.ts) > max_skew:
        raise EnvelopeError(
            errors.ENV_TS_SKEW, f"timestamp {message.ts} outside now +/- {max_skew}"
        )
    if expected_nonce is not None and (
        message.type is not MessageType.COMMAND_ACK or message.nonce != expected_nonce
    ):
        raise EnvelopeError(errors.ENV_NONCE, "CommandAck nonce does not echo the command nonce")
    if not replay_store.check_and_record(signed.kid, direction, message.seq):
        raise ReplayError(errors.ENV_REPLAY, f"seq {message.seq} not greater than last accepted")
    return replace(message, sender_kid=signed.kid)


def check_ack(command: Message, ack: Message) -> None:
    """Verify that ``ack`` answers ``command``: same ``cmd_id`` and echoed nonce."""
    if command.type is not MessageType.COMMAND or ack.type is not MessageType.COMMAND_ACK:
        raise EnvelopeError(errors.ENV_TYPE, "check_ack expects a Command and a CommandAck")
    assert isinstance(command.body, Command)
    assert isinstance(ack.body, CommandAck)
    if ack.nonce != command.nonce:
        raise EnvelopeError(errors.ENV_NONCE, "CommandAck nonce does not echo the command nonce")
    if ack.body.cmd_id != command.body.cmd_id:
        raise EnvelopeError(errors.ENV_FIELD, "CommandAck cmd_id does not match the command")
