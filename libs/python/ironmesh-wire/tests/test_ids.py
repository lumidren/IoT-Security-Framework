"""Identifier validators, key ids and MQTT topics."""

from __future__ import annotations

import pytest

from ironmesh_wire import errors, ids
from ironmesh_wire.constants import Direction, MessageType
from tests.helpers import raises_code

TENANT = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
DEVICE = "dev-8f3a1c2b9d4e5f60"


def test_tenant_ids() -> None:
    assert ids.validate_tenant_id(TENANT) == TENANT
    for bad in (
        "7E4B1A9C-3C2E-4A4F-9C1B-0F0D2D7A6A11",
        "7e4b1a9c-3c2e-1a4f-9c1b-0f0d2d7a6a11",
        "x",
        "",
    ):
        assert not ids.is_tenant_id(bad)
        with raises_code(errors.ID_FORMAT):
            ids.validate_tenant_id(bad)


def test_device_ids() -> None:
    assert ids.validate_device_id(DEVICE) == DEVICE
    for bad in (
        "dev-8f3a1c2b9d4e5f6",
        "dev-8F3A1C2B9D4E5F60",
        "device-8f3a1c2b9d4e5f60",
        "dev-8f3a1c2b9d4e5f600",
    ):
        with raises_code(errors.ID_FORMAT):
            ids.validate_device_id(bad)


def test_group_slugs() -> None:
    assert ids.validate_group_slug("eu-west-gateways") == "eu-west-gateways"
    assert ids.is_group_slug("x" * 48)
    for bad in ("", "x" * 49, "EU", "eu_west", "eu west"):
        with raises_code(errors.ID_FORMAT):
            ids.validate_group_slug(bad)


def test_uuids_and_semver() -> None:
    assert (
        ids.validate_uuid("123e4567-e89b-12d3-a456-426614174000")
        == "123e4567-e89b-12d3-a456-426614174000"
    )
    assert not ids.is_uuid4("123e4567-e89b-12d3-a456-426614174000")
    assert ids.validate_uuid4(TENANT, "campaign") == TENANT
    with raises_code(errors.ID_FORMAT):
        ids.validate_uuid("nope")
    with raises_code(errors.ID_FORMAT):
        ids.validate_uuid4("123e4567-e89b-12d3-a456-426614174000")
    for good in ("0.0.0", "2.4.1", "1.0.0-rc.1", "1.0.0-rc.1+build.5", "10.20.30+meta"):
        assert ids.validate_semver(good) == good
    for bad in ("1", "1.0", "01.0.0", "1.0.0-", "v1.0.0", "1.0.0+", ""):
        with raises_code(errors.ID_FORMAT):
            ids.validate_semver(bad)


def test_firmware_ids() -> None:
    assert ids.firmware_id("gateway-rpi", "2.4.1") == "gateway-rpi/2.4.1"
    assert ids.parse_firmware_id("sensor-esp32/1.0.0-rc.1") == ("sensor-esp32", "1.0.0-rc.1")
    for bad in ("gateway-rpi", "gateway-rpi/2.4", "Gateway/1.0.0", "-x/1.0.0", "/1.0.0"):
        with raises_code(errors.ID_FORMAT):
            ids.parse_firmware_id(bad)
    with raises_code(errors.ID_FORMAT):
        ids.validate_product("x" * 65)
    assert ids.is_product("a")


def test_key_ids() -> None:
    assert ids.kid_from_serial(0) == b"\x00"
    assert ids.kid_from_serial(0xFF) == b"\xff"
    assert ids.kid_from_serial(0x0100) == b"\x01\x00"
    serial = 0x3FA1B2C3D4E5F60718293A4B5C6D7E8F
    kid = ids.kid_from_serial(serial)
    assert len(kid) == 16
    assert ids.serial_from_kid(kid) == serial
    assert ids.is_device_kid(kid)
    assert ids.is_device_kid(b"\x00")
    assert not ids.is_device_kid(b"\x00\x01")
    assert not ids.is_device_kid(b"")
    assert not ids.is_device_kid(bytes(21))
    assert not ids.is_device_kid("text")
    with raises_code(errors.ID_FORMAT):
        ids.kid_from_serial(-1)
    with raises_code(errors.ID_FORMAT):
        ids.kid_from_serial(1 << 160)
    with raises_code(errors.ID_FORMAT):
        ids.serial_from_kid(b"\x00\x01")
    with raises_code(errors.ID_FORMAT):
        ids.serial_from_kid(b"")
    assert ids.tenant_kid(TENANT) == f"tenant-cmd-{TENANT}"
    assert ids.tenant_from_kid(f"tenant-cmd-{TENANT}") == TENANT
    assert ids.is_tenant_kid(f"tenant-cmd-{TENANT}")
    assert not ids.is_tenant_kid(b"x")
    assert not ids.is_tenant_kid("tenant-cmd-x")
    with raises_code(errors.ID_FORMAT):
        ids.tenant_from_kid("tenant-cmd-nope")
    with raises_code(errors.ID_FORMAT):
        ids.tenant_kid("nope")


@pytest.mark.parametrize(
    ("cls", "suffix", "direction", "mtype", "retained"),
    [
        (ids.TopicClass.TELEMETRY, "telemetry", Direction.UPLINK, MessageType.TELEMETRY, False),
        (ids.TopicClass.EVENTS, "events", Direction.UPLINK, MessageType.EVENT, False),
        (
            ids.TopicClass.SHADOW_REPORTED,
            "shadow/reported",
            Direction.UPLINK,
            MessageType.SHADOW_REPORTED,
            False,
        ),
        (ids.TopicClass.CMD_ACK, "cmd/ack", Direction.UPLINK, MessageType.COMMAND_ACK, False),
        (ids.TopicClass.OTA_STATUS, "ota/status", Direction.UPLINK, MessageType.OTA_STATUS, False),
        (
            ids.TopicClass.SHADOW_DESIRED,
            "shadow/desired",
            Direction.DOWNLINK,
            MessageType.SHADOW_DESIRED,
            True,
        ),
        (ids.TopicClass.CMD_REQ, "cmd/req", Direction.DOWNLINK, MessageType.COMMAND, False),
        (ids.TopicClass.OTA_NOTIFY, "ota/notify", Direction.DOWNLINK, MessageType.OTA_NOTIFY, True),
        (ids.TopicClass.CONFIG, "config", Direction.DOWNLINK, MessageType.CONFIG, True),
    ],
)
def test_topics(
    cls: ids.TopicClass, suffix: str, direction: Direction, mtype: MessageType, retained: bool
) -> None:
    topic = ids.build_topic(TENANT, DEVICE, cls)
    assert topic == f"im/v1/{TENANT}/{DEVICE}/{suffix}"
    parsed = ids.parse_topic(topic)
    assert parsed == ids.Topic(TENANT, DEVICE, cls)
    assert str(parsed) == topic
    assert parsed.direction is direction
    assert parsed.message_type is mtype
    assert cls.retained_allowed is retained
    assert cls.qos == 1
    assert cls.device_publishes is (direction is Direction.UPLINK)
    assert cls.encrypted is (cls is ids.TopicClass.CONFIG)
    assert ids.topic_class_for_type(mtype) is cls
    assert ids.device_may_publish(topic, DEVICE) is (direction is Direction.UPLINK)
    assert ids.device_may_subscribe(topic, DEVICE) is (direction is Direction.DOWNLINK)
    assert not ids.device_may_publish(topic, "dev-0000000000000000")
    assert not ids.device_may_subscribe(topic, "dev-0000000000000000")


def test_topic_errors() -> None:
    for bad in (
        f"im/v1/{TENANT}/{DEVICE}/#",
        f"im/v1/{TENANT}/+/telemetry",
        f"im/v2/{TENANT}/{DEVICE}/telemetry",
        f"im/v1/not-a-tenant/{DEVICE}/telemetry",
        f"im/v1/{TENANT}/dev-8F3A1C2B9D4E5F60/telemetry",
        f"im/v1/{TENANT}/{DEVICE}/shadow",
        f"im/v1/{TENANT}/{DEVICE}",
        "",
        f"$share/bridge/im/v1/{TENANT}/{DEVICE}/telemetry",
    ):
        with raises_code(errors.TOPIC_FORMAT):
            ids.parse_topic(bad)
        assert not ids.device_may_publish(bad, DEVICE)
        assert not ids.device_may_subscribe(bad, DEVICE)
    with raises_code(errors.ID_FORMAT):
        ids.build_topic("x", DEVICE, ids.TopicClass.TELEMETRY)
    with raises_code(errors.TOPIC_FORMAT):
        ids.topic_class_for_type(MessageType.ATTESTATION)
    assert ids.BRIDGE_SHARED_SUBSCRIPTION == "$share/bridge/im/v1/#"
