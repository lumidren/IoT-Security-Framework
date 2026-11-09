"""Identifier validators, key identifiers and MQTT topic builder/parser (contract §1, §4, §5)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final

from . import errors
from .constants import DIRECTION_OF, Direction, MessageType
from .errors import IdError

UUID4_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
UUID_RE: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DEVICE_ID_RE: Final = re.compile(r"^dev-[0-9a-f]{16}$")
GROUP_SLUG_RE: Final = re.compile(r"^[a-z0-9-]{1,48}$")
PRODUCT_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# Semantic Versioning 2.0.0 (https://semver.org/#is-there-a-suggested-regular-expression-regex)
SEMVER_RE: Final = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
    re.ASCII,  # \d must not match non-ASCII digits (C and Rust implementations are ASCII-only)
)

TENANT_KID_PREFIX: Final = "tenant-cmd-"
TENANT_KID_RE: Final = re.compile(
    r"^tenant-cmd-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
MAX_SERIAL_BYTES: Final = 20  # RFC 5280 §4.1.2.2

TOPIC_PREFIX: Final = "im/v1"
BRIDGE_SHARED_SUBSCRIPTION: Final = "$share/bridge/im/v1/#"
BRIDGE_CN: Final = "svc-bridge"


# --------------------------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------------------------


def is_tenant_id(value: str) -> bool:
    return UUID4_RE.fullmatch(value) is not None


def validate_tenant_id(value: str) -> str:
    if not is_tenant_id(value):
        raise IdError(errors.ID_FORMAT, "tenant id must be a lower-case hyphenated UUIDv4")
    return value


def is_device_id(value: str) -> bool:
    return DEVICE_ID_RE.fullmatch(value) is not None


def validate_device_id(value: str) -> str:
    if not is_device_id(value):
        raise IdError(errors.ID_FORMAT, "device id must match ^dev-[0-9a-f]{16}$")
    return value


def is_group_slug(value: str) -> bool:
    return GROUP_SLUG_RE.fullmatch(value) is not None


def validate_group_slug(value: str) -> str:
    if not is_group_slug(value):
        raise IdError(errors.ID_FORMAT, "group slug must match ^[a-z0-9-]{1,48}$")
    return value


def is_uuid(value: str) -> bool:
    """Any lower-case hyphenated UUID (used for ``cmd_id``)."""
    return UUID_RE.fullmatch(value) is not None


def validate_uuid(value: str, what: str = "uuid") -> str:
    if not is_uuid(value):
        raise IdError(errors.ID_FORMAT, f"{what} must be a lower-case hyphenated UUID")
    return value


def is_uuid4(value: str) -> bool:
    return UUID4_RE.fullmatch(value) is not None


def validate_uuid4(value: str, what: str = "uuid") -> str:
    if not is_uuid4(value):
        raise IdError(errors.ID_FORMAT, f"{what} must be a lower-case hyphenated UUIDv4")
    return value


def is_semver(value: str) -> bool:
    return SEMVER_RE.fullmatch(value) is not None


def validate_semver(value: str) -> str:
    if not is_semver(value):
        raise IdError(errors.ID_FORMAT, f"{value!r} is not a semantic version")
    return value


def is_product(value: str) -> bool:
    return PRODUCT_RE.fullmatch(value) is not None


def validate_product(value: str) -> str:
    if not is_product(value):
        raise IdError(errors.ID_FORMAT, "product must match ^[a-z0-9][a-z0-9-]{0,63}$")
    return value


def firmware_id(product: str, version: str) -> str:
    """``<product>/<semver>`` (contract §1)."""
    return f"{validate_product(product)}/{validate_semver(version)}"


def parse_firmware_id(value: str) -> tuple[str, str]:
    product, sep, version = value.partition("/")
    if not sep:
        raise IdError(errors.ID_FORMAT, "firmware id must be <product>/<semver>")
    return validate_product(product), validate_semver(version)


# --------------------------------------------------------------------------------------------
# Key identifiers (contract §5)
# --------------------------------------------------------------------------------------------


def kid_from_serial(serial: int) -> bytes:
    """Device ``kid``: the certificate serial as a minimal big-endian unsigned integer."""
    if serial < 0:
        raise IdError(errors.ID_FORMAT, "certificate serial must be non-negative")
    length = max(1, (serial.bit_length() + 7) // 8)
    if length > MAX_SERIAL_BYTES:
        raise IdError(errors.ID_FORMAT, "certificate serial longer than 20 bytes")
    return serial.to_bytes(length, "big")


def serial_from_kid(kid: bytes) -> int:
    if not 1 <= len(kid) <= MAX_SERIAL_BYTES or (len(kid) > 1 and kid[0] == 0):
        raise IdError(
            errors.ID_FORMAT, "device kid must be a minimal big-endian serial (1..20 bytes)"
        )
    return int.from_bytes(kid, "big")


def is_device_kid(kid: object) -> bool:
    return (
        isinstance(kid, bytes)
        and 1 <= len(kid) <= MAX_SERIAL_BYTES
        and (len(kid) == 1 or kid[0] != 0)
    )


def tenant_kid(tenant_id: str) -> str:
    """Cloud ``kid``: ``tenant-cmd-<tenant>``."""
    return TENANT_KID_PREFIX + validate_tenant_id(tenant_id)


def tenant_from_kid(kid: str) -> str:
    match = TENANT_KID_RE.fullmatch(kid)
    if match is None:
        raise IdError(errors.ID_FORMAT, "tenant kid must be tenant-cmd-<uuid4>")
    return match.group(1)


def is_tenant_kid(kid: object) -> bool:
    return isinstance(kid, str) and TENANT_KID_RE.fullmatch(kid) is not None


# --------------------------------------------------------------------------------------------
# Topics (contract §4)
# --------------------------------------------------------------------------------------------


class TopicClass(Enum):
    """The nine device topics; the value is the suffix after ``im/v1/<t>/<d>/``."""

    TELEMETRY = "telemetry"
    EVENTS = "events"
    SHADOW_REPORTED = "shadow/reported"
    CMD_ACK = "cmd/ack"
    OTA_STATUS = "ota/status"
    SHADOW_DESIRED = "shadow/desired"
    CMD_REQ = "cmd/req"
    OTA_NOTIFY = "ota/notify"
    CONFIG = "config"

    @property
    def message_type(self) -> MessageType:
        return _TOPIC_MESSAGE_TYPE[self]

    @property
    def direction(self) -> Direction:
        return DIRECTION_OF[self.message_type]

    @property
    def device_publishes(self) -> bool:
        return self.direction is Direction.UPLINK

    @property
    def retained_allowed(self) -> bool:
        return self in _RETAINED_ALLOWED

    @property
    def encrypted(self) -> bool:
        """``config`` carries COSE_Encrypt0; everything else is a bare COSE_Sign1."""
        return self is TopicClass.CONFIG

    @property
    def qos(self) -> int:
        return 1


_TOPIC_MESSAGE_TYPE: Final[dict[TopicClass, MessageType]] = {
    TopicClass.TELEMETRY: MessageType.TELEMETRY,
    TopicClass.EVENTS: MessageType.EVENT,
    TopicClass.SHADOW_REPORTED: MessageType.SHADOW_REPORTED,
    TopicClass.CMD_ACK: MessageType.COMMAND_ACK,
    TopicClass.OTA_STATUS: MessageType.OTA_STATUS,
    TopicClass.SHADOW_DESIRED: MessageType.SHADOW_DESIRED,
    TopicClass.CMD_REQ: MessageType.COMMAND,
    TopicClass.OTA_NOTIFY: MessageType.OTA_NOTIFY,
    TopicClass.CONFIG: MessageType.CONFIG,
}
_RETAINED_ALLOWED: Final = frozenset(
    {TopicClass.SHADOW_DESIRED, TopicClass.OTA_NOTIFY, TopicClass.CONFIG}
)
_SUFFIX_TO_CLASS: Final[dict[str, TopicClass]] = {cls.value: cls for cls in TopicClass}


def topic_class_for_type(message_type: MessageType) -> TopicClass:
    for cls, mtype in _TOPIC_MESSAGE_TYPE.items():
        if mtype is message_type:
            return cls
    raise IdError(errors.TOPIC_FORMAT, f"message type {message_type} has no MQTT topic")


@dataclass(frozen=True)
class Topic:
    tenant_id: str
    device_id: str
    topic_class: TopicClass

    def __str__(self) -> str:
        return build_topic(self.tenant_id, self.device_id, self.topic_class)

    @property
    def direction(self) -> Direction:
        return self.topic_class.direction

    @property
    def message_type(self) -> MessageType:
        return self.topic_class.message_type


def build_topic(tenant_id: str, device_id: str, topic_class: TopicClass) -> str:
    """``im/v1/<tenant>/<device>/<suffix>``."""
    tenant = validate_tenant_id(tenant_id)
    device = validate_device_id(device_id)
    return f"{TOPIC_PREFIX}/{tenant}/{device}/{topic_class.value}"


def parse_topic(topic: str) -> Topic:
    """Parse and validate a device topic; rejects wildcards and unknown suffixes."""
    parts = topic.split("/")
    if len(parts) < 5 or parts[0] != "im" or parts[1] != "v1":
        raise IdError(errors.TOPIC_FORMAT, "topic must start with im/v1/<tenant>/<device>/")
    tenant, device = parts[2], parts[3]
    suffix = "/".join(parts[4:])
    if not is_tenant_id(tenant):
        raise IdError(errors.TOPIC_FORMAT, "invalid tenant id in topic")
    if not is_device_id(device):
        raise IdError(errors.TOPIC_FORMAT, "invalid device id in topic")
    topic_class = _SUFFIX_TO_CLASS.get(suffix)
    if topic_class is None:
        raise IdError(errors.TOPIC_FORMAT, f"unknown topic suffix {suffix!r}")
    return Topic(tenant, device, topic_class)


def device_may_publish(topic: str, device_id: str) -> bool:
    """Authorization helper: a device may publish only to its own uplink topics."""
    try:
        parsed = parse_topic(topic)
    except IdError:
        return False
    return parsed.device_id == device_id and parsed.topic_class.device_publishes


def device_may_subscribe(topic: str, device_id: str) -> bool:
    """Authorization helper: a device may subscribe only to its own downlink topics."""
    try:
        parsed = parse_topic(topic)
    except IdError:
        return False
    return parsed.device_id == device_id and not parsed.topic_class.device_publishes
