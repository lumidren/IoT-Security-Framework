"""Ingest consumer: verification order, replay persistence, skew, signatures, side effects."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ironmesh_wire import envelope
from ironmesh_wire.ids import TopicClass

from app.domain import CommandRecord, DeviceRecord, TenantRecord
from app.integrations.bus import BusMessage
from app.integrations.services import PkiCertificate

from .conftest import VECTORS, Env, telemetry_body


def counter(env: Env, name: str, **labels: str) -> float:
    value = env.ctx.metrics.registry.get_sample_value(name, labels or None)
    return value or 0.0


async def test_telemetry_accepted_stored_and_queryable(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    for i in range(3):
        assert (
            await env.send(dk, TopicClass.TELEMETRY, telemetry_body(cpu_pct=10.0 + i)) == "accepted"
        )
        env.clock.advance(seconds=20)
    r = await env.client.get(f"/v1/devices/{dev['id']}", headers=env.auth(t))
    d = r.json()
    assert d["last_telemetry"]["cpu_pct"] == 12.0 and d["location"] == {"lat": 52.52, "lon": 13.405}
    assert d["last_seen_at"] is not None and d["fw_hash_hex"] == "00" * 32
    r = await env.client.get(
        f"/v1/devices/{dev['id']}/telemetry",
        headers=env.auth(t),
        params={
            "metrics": "cpu_pct,temp_c",
            "step": "1h",
            "from": (env.clock() - timedelta(hours=2)).isoformat(),
            "to": (env.clock() + timedelta(hours=1)).isoformat(),
        },
    )
    series = {s["metric"]: s["points"] for s in r.json()["series"]}
    values = [p[1] for p in series["cpu_pct"]]
    assert sum(values) / len(values) == pytest.approx(11.0, abs=1.0)
    assert series["temp_c"][0][1] == pytest.approx(36.6)
    # summary aggregates telemetry
    r = await env.client.get("/v1/fleet/summary", headers=env.auth(t, "viewer"))
    s = r.json()
    assert s["devices_total"] == 1 and s["by_state"]["active"] == 1
    assert s["firmware"] == [{"version": "2.4.1", "count": 1}]
    assert s["map"][0]["device_id"] == dev["id"] and s["assurance"]["hardware"] == 1
    # health aggregation
    from app.auth import SYSTEM
    from app.services import admin

    await admin.flush_health(env.ctx, SYSTEM)
    r = await env.client.get("/v1/fleet/health", headers=env.auth(t), params={"window": "1h"})
    h = r.json()
    assert h["msgs_per_s"] > 0 and h["p99_ingest_ms"] >= 0
    for bad in ("1x", "10s", "30d"):
        assert (
            await env.client.get("/v1/fleet/health", headers=env.auth(t), params={"window": bad})
        ).status_code == 422


async def test_replay_skew_signature_and_identity(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    body = telemetry_body()
    before = counter(env, "ironmesh_replay_rejected_total")
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=100) == "accepted"
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=100) == "ENV_REPLAY"
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=99) == "ENV_REPLAY"
    assert counter(env, "ironmesh_replay_rejected_total") == before + 2
    now = int(env.clock().timestamp())
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=101, ts=now - 301) == "ENV_TS_SKEW"
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=101, ts=now + 301) == "ENV_TS_SKEW"
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=101, ts=now - 300) == "accepted"
    # rejected messages did not advance the stored seq: 102 still works after rejected 102s
    wire = bytearray(env.wire(dk, body, seq=102))
    wire[-1] ^= 1
    assert await env.deliver(t, dev["id"], TopicClass.TELEMETRY, bytes(wire)) == "COSE_SIGNATURE"
    attacker = ec.generate_private_key(ec.SECP256R1())
    forged = envelope.encode(
        envelope.Message(seq=102, ts=now, body=body),
        envelope.SigningIdentity.device(attacker, dk.serial),
    )
    assert await env.deliver(t, dev["id"], TopicClass.TELEMETRY, forged) == "COSE_SIGNATURE"
    assert await env.send(dk, TopicClass.TELEMETRY, body, seq=102) == "accepted"
    # wrong topic for the message type, downlink topic, mismatching headers, unknown kid
    assert await env.send(dk, TopicClass.EVENTS, body) == "ENV_TYPE"
    assert await env.send(dk, TopicClass.CMD_REQ, body) == "ENV_DIRECTION"
    other = await env.device(t)
    assert await env.deliver(t, other["id"], TopicClass.TELEMETRY, env.wire(dk, body)) == "ENV_KID"
    stranger = envelope.encode(
        envelope.Message(seq=1, ts=now, body=body),
        envelope.SigningIdentity.device(attacker, 0x1234),
    )
    assert await env.deliver(t, dev["id"], TopicClass.TELEMETRY, stranger) == "ENV_UNKNOWN_KEY"
    assert await env.deliver(t, dev["id"], TopicClass.TELEMETRY, b"\x00garbage") != "accepted"
    msg = BusMessage(
        "im.ingest",
        None,
        env.wire(dk, body),
        {"mqtt_topic": "im/v1/x/y/telemetry", "tenant_id": t, "device_id": dev["id"]},
    )
    assert await env.ingest.on_ingest(msg) == "TOPIC_FORMAT"
    other_tenant = await env.tenant()
    msg = BusMessage(
        "im.ingest",
        None,
        env.wire(dk, body),
        {
            "mqtt_topic": f"im/v1/{other_tenant}/{dev['id']}/telemetry",
            "tenant_id": t,
            "device_id": dev["id"],
        },
    )
    assert await env.ingest.on_ingest(msg) == "TOPIC_FORMAT"
    assert counter(env, "ironmesh_ingest_rejected_total", code="ENV_TS_SKEW") == 2


async def test_cert_state_and_device_state_rejections(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    body = telemetry_body()
    cert = env.pki.certs[dk.serial_hex]
    env.pki.certs[dk.serial_hex] = PkiCertificate(
        **{**{s: getattr(cert, s) for s in cert.__slots__}, "status": "revoked"}
    )
    assert await env.send(dk, TopicClass.TELEMETRY, body) == "CERT_REVOKED"
    env.pki.certs[dk.serial_hex] = PkiCertificate(
        **{**{s: getattr(cert, s) for s in cert.__slots__}, "not_after": env.clock() - timedelta(1)}
    )
    assert await env.send(dk, TopicClass.TELEMETRY, body) == "CERT_EXPIRED"
    env.pki.certs[dk.serial_hex] = cert
    env.pki.fail_lookup = True
    assert await env.send(dk, TopicClass.TELEMETRY, body) == "PKI_UNAVAILABLE"
    env.pki.fail_lookup = False
    await env.client.post(
        f"/v1/devices/{dev['id']}/quarantine", headers=env.auth(t, "operator"), json={"reason": "x"}
    )
    env.pki.certs[dk.serial_hex] = cert  # even if the PKI were stale, the registry state wins
    assert await env.send(dk, TopicClass.TELEMETRY, body) == "DEVICE_STATE"


async def test_events_ota_status_and_forwarding(env: Env) -> None:
    t = await env.tenant()
    dev, dk = await env.active_device(t)
    campaign = str(uuid.uuid4())
    status = envelope.OtaStatus(
        campaign_id=campaign, state=5, progress_pct=100, fw_hash=b"\x11" * 32
    )
    assert await env.send(dk, TopicClass.OTA_STATUS, status) == "accepted"
    assert env.ota.statuses[-1]["campaign_id"] == campaign
    assert env.ota.statuses[-1]["fw_hash_hex"] == "11" * 32
    env.ota.fail = True
    assert await env.send(dk, TopicClass.OTA_STATUS, status) == "accepted"  # forwarding is async
    assert (
        await env.send(
            dk, TopicClass.EVENTS, envelope.Event(name="tamper", severity=4, data={"pin": 3})
        )
        == "accepted"
    )
    assert (
        await env.send(dk, TopicClass.EVENTS, envelope.Event(name="boot", severity=1, data={}))
        == "accepted"
    )
    r = await env.client.get(
        f"/v1/devices/{dev['id']}/timeline", headers=env.auth(t), params={"kinds": "ota,alert"}
    )
    kinds = [e["kind"] for e in r.json()["items"]]
    assert kinds.count("ota") == 2 and kinds.count("alert") == 1
    r = await env.client.get(f"/v1/devices/{dev['id']}", headers=env.auth(t))
    assert r.json()["fw_hash_hex"] == "11" * 32


async def test_auth_and_alert_events(env: Env) -> None:
    t = await env.tenant()
    dev, _ = await env.active_device(t)
    did = dev["id"]
    at = env.clock().isoformat()

    async def auth(event: str, **extra: str) -> None:
        payload = {"event": event, "clientid": did, "peerhost": "10.0.0.5", "at": at, **extra}
        await env.bus.deliver(BusMessage("im.auth", did, json.dumps(payload).encode()))

    await auth("connected")
    r = await env.client.get(f"/v1/devices/{did}", headers=env.auth(t))
    assert r.json()["connected"] is True
    r = await env.client.get("/v1/devices", headers=env.auth(t), params={"connected": "true"})
    assert [d["id"] for d in r.json()["items"]] == [did]
    await auth("authz_denied", topic="im/v1/x", action="publish")
    await auth("authn_failed", reason="bad cert")
    await auth("disconnected")
    r = await env.client.get(
        f"/v1/devices/{did}/timeline",
        headers=env.auth(t),
        params={"kinds": "connect,disconnect,authz_denied"},
    )
    assert [e["kind"] for e in r.json()["items"]].count("authz_denied") == 2
    assert counter(env, "ironmesh_auth_failures_total") >= 1
    await env.bus.deliver(BusMessage("im.auth", None, b"not json"))
    await env.bus.deliver(BusMessage("im.auth", None, b"[1]"))
    await env.bus.deliver(
        BusMessage("im.auth", None, json.dumps({"event": "connected", "clientid": "x"}).encode())
    )

    alert = {
        "id": "alert-1",
        "tenant_id": t,
        "device_id": did,
        "rule": "beaconing",
        "severity": "high",
        "state": "open",
        "created_at": at,
    }
    await env.bus.deliver(BusMessage("im.alerts", None, json.dumps(alert).encode()))
    r = await env.client.get(f"/v1/devices/{did}", headers=env.auth(t))
    assert r.json()["open_alerts"] == 1
    r = await env.client.get("/v1/fleet/summary", headers=env.auth(t))
    assert r.json()["alerts_open"]["high"] == 1
    await env.bus.deliver(
        BusMessage("im.alerts", None, json.dumps({**alert, "state": "resolved"}).encode())
    )
    r = await env.client.get(f"/v1/devices/{did}", headers=env.auth(t))
    assert r.json()["open_alerts"] == 0
    # spoofed tenant / malformed alerts are dropped
    other = await env.tenant()
    await env.bus.deliver(
        BusMessage(
            "im.alerts", None, json.dumps({**alert, "id": "a2", "tenant_id": other}).encode()
        )
    )
    await env.bus.deliver(BusMessage("im.alerts", None, b"{}"))
    async with env.repo.tenant(other) as tx:
        assert (await tx.fleet_aggregate(env.clock())).alerts_open == {}


async def test_audit_events_from_other_services(env: Env) -> None:
    t = await env.tenant()
    ev = {
        "id": str(uuid.uuid4()),
        "at": env.clock().isoformat(),
        "tenant_id": t,
        "actor": {"type": "user", "id": "u1", "name": "Ops"},
        "action": "campaign.started",
        "target": {"type": "campaign", "id": "c1"},
        "outcome": "success",
        "details": {"n": 1},
    }
    await env.bus.deliver(BusMessage("im.audit", t, json.dumps(ev).encode(), {"source": "ota"}))
    await env.bus.deliver(
        BusMessage("im.audit", t, json.dumps(ev).encode(), {"source": "registry"})
    )
    await env.bus.deliver(BusMessage("im.audit", t, b"{", {"source": "ota"}))
    await env.bus.deliver(
        BusMessage(
            "im.audit", t, json.dumps({**ev, "tenant_id": "nope"}).encode(), {"source": "ota"}
        )
    )
    await env.bus.deliver(
        BusMessage(
            "im.audit",
            t,
            json.dumps({**ev, "tenant_id": str(uuid.uuid4()), "actor": {"type": "robot"}}).encode(),
            {"source": "ota"},
        )
    )
    r = await env.client.get(
        "/v1/audit", headers=env.auth(t), params={"action": "campaign.started"}
    )
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["details"]["source"] == "ota"
    r = await env.client.get("/v1/audit/verify", headers=env.auth(t, "admin"))
    assert r.json()["ok"] is True


# ------------------------------------------------------------------------------------------------
# Conformance vectors from the wire library (fixed tenant/device ids: memory repository only)
# ------------------------------------------------------------------------------------------------


async def _vector_env(mem: Env, data: dict[str, object]) -> tuple[str, str]:
    tenant_id = str(data["tenant_id"])
    device_id = "dev-8f3a1c2b9d4e5f60"
    now = datetime.fromtimestamp(int(data.get("now", 1767225600)), UTC)  # type: ignore[call-overload]
    mem.clock.now = now
    async with mem.repo.tenant(tenant_id) as tx:
        await tx.insert_tenant(
            TenantRecord(id=tenant_id, name="vectors", settings={}, created_at=now)
        )
        await tx.insert_device(
            DeviceRecord(
                tenant_id=tenant_id,
                id=device_id,
                product="p",
                hw_revision="1",
                state="active",
                created_at=now,
            )
        )
    key_pem = data["device_key"]["public_pem"]  # type: ignore[index]
    public = serialization.load_pem_public_key(str(key_pem).encode())
    assert isinstance(public, ec.EllipticCurvePublicKey)
    mem.pki.add(
        PkiCertificate(
            serial_hex="3fa1b2c3d4e5f60718293a4b5c6d7e8f",
            device_id=device_id,
            tenant_id=tenant_id,
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=13),
            status="valid",
            issuer="vectors",
            public_key=public,
        )
    )
    return tenant_id, device_id


async def test_vector_telemetry_envelope(mem: Env) -> None:
    data = json.loads((VECTORS / "envelope_telemetry.json").read_text())
    tenant_id, device_id = await _vector_env(mem, data)
    wire = bytes.fromhex(data["message"]["wire_hex"])
    assert await mem.deliver(tenant_id, device_id, TopicClass.TELEMETRY, wire) == "accepted"
    assert await mem.deliver(tenant_id, device_id, TopicClass.TELEMETRY, wire) == "ENV_REPLAY"


async def test_vector_replay_cases(mem: Env) -> None:
    data = json.loads((VECTORS / "replay_cases.json").read_text())
    tenant_id, device_id = await _vector_env(mem, data)
    async with mem.repo.tenant(tenant_id) as tx:
        await tx.insert_command(
            CommandRecord(
                tenant_id=tenant_id,
                cmd_id="123e4567-e89b-12d3-a456-426614174000",
                device_id=device_id,
                name="reboot",
                args={},
                idempotency_key="k",
                request_hash="h",
                status="sent",
                created_at=mem.clock(),
                expires_at=mem.clock() + timedelta(hours=1),
                nonce=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            )
        )
    for step in data["steps"]:
        mem.clock.now = datetime.fromtimestamp(step["now"], UTC)
        downlink = step["name"].startswith("downlink")
        cls = TopicClass.CMD_ACK if " ack " in step["name"] else TopicClass.TELEMETRY
        result = await mem.deliver(tenant_id, device_id, cls, bytes.fromhex(step["wire_hex"]))
        if downlink:
            assert result == "ENV_DIRECTION", step["name"]  # the registry never ingests downlink
        elif step["expect"] == "accept":
            assert result == "accepted", (step["name"], result)
        else:
            assert result == step["error"], (step["name"], result)


async def test_vector_command_ack(mem: Env) -> None:
    data = json.loads((VECTORS / "envelope_command_ack.json").read_text())
    tenant_id, device_id = await _vector_env(mem, data)
    async with mem.repo.tenant(tenant_id) as tx:
        await tx.insert_command(
            CommandRecord(
                tenant_id=tenant_id,
                cmd_id=data["command"]["body"]["cmd_id"],
                device_id=device_id,
                name="reboot",
                args={},
                idempotency_key="k",
                request_hash="h",
                status="sent",
                created_at=mem.clock(),
                expires_at=mem.clock() + timedelta(hours=1),
                nonce=bytes.fromhex(data["command"]["nonce_hex"]),
            )
        )
    bad = bytes.fromhex(data["ack_bad_nonce"]["wire_hex"])
    assert await mem.deliver(tenant_id, device_id, TopicClass.CMD_ACK, bad) == "ENV_NONCE"
    ack = bytes.fromhex(data["ack"]["wire_hex"])
    assert await mem.deliver(tenant_id, device_id, TopicClass.CMD_ACK, ack) == "accepted"
    async with mem.repo.tenant(tenant_id) as tx:
        cmd = await tx.get_command(data["command"]["body"]["cmd_id"])
    assert cmd is not None and cmd.status == "acked"
