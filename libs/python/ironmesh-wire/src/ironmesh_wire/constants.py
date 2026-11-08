"""Enumerations shared by the envelope, identifier and topic modules (design contract §4/§5)."""

from __future__ import annotations

from enum import Enum, IntEnum, StrEnum
from typing import Final


class MessageType(IntEnum):
    """``type`` field of the envelope (contract §5)."""

    TELEMETRY = 1
    EVENT = 2
    SHADOW_REPORTED = 3
    SHADOW_DESIRED = 4
    COMMAND = 5
    COMMAND_ACK = 6
    OTA_NOTIFY = 7
    OTA_STATUS = 8
    CONFIG = 9
    ATTESTATION = 10


class Direction(Enum):
    """Who signs a message: the device (uplink) or the tenant command key (downlink)."""

    UPLINK = "uplink"  # device -> cloud, ES256 by the device certificate key, kid = cert serial
    DOWNLINK = "downlink"  # cloud -> device, EdDSA by the tenant key, kid = "tenant-cmd-<tenant>"


DIRECTION_OF: Final[dict[MessageType, Direction]] = {
    MessageType.TELEMETRY: Direction.UPLINK,
    MessageType.EVENT: Direction.UPLINK,
    MessageType.SHADOW_REPORTED: Direction.UPLINK,
    MessageType.SHADOW_DESIRED: Direction.DOWNLINK,
    MessageType.COMMAND: Direction.DOWNLINK,
    MessageType.COMMAND_ACK: Direction.UPLINK,
    MessageType.OTA_NOTIFY: Direction.DOWNLINK,
    MessageType.OTA_STATUS: Direction.UPLINK,
    MessageType.CONFIG: Direction.DOWNLINK,
    MessageType.ATTESTATION: Direction.UPLINK,
}

NONCE_TYPES: Final = frozenset({MessageType.COMMAND, MessageType.COMMAND_ACK})


class AckStatus(IntEnum):
    """``CommandAck.status``."""

    OK = 0
    REJECTED = 1
    FAILED = 2
    EXPIRED = 3


class OtaState(IntEnum):
    """``OtaStatus.state``."""

    RECEIVED = 0
    DOWNLOADING = 1
    VERIFYING = 2
    APPLYING = 3
    REBOOTING = 4
    SUCCESS = 5
    ROLLED_BACK = 6
    REJECTED = 7


class EventSeverity(IntEnum):
    """``Event.severity`` (defined by WIRE_FORMAT.md §4.3; the contract leaves the body open)."""

    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4


class SeType(StrEnum):
    """Secure-element type reported in an attestation (contract §3)."""

    ATECC608 = "atecc608"
    TPM2 = "tpm2"
    OPTEE = "optee"
    SOFTWARE = "software"

    @property
    def assurance_level(self) -> str:
        return "software" if self is SeType.SOFTWARE else "hardware"
