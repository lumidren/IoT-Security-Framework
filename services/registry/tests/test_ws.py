"""WebSocket ``/v1/ws``: tickets, default and explicit subscriptions, frames, sampling, ping."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from httpx_ws import WebSocketDisconnect, WebSocketUpgradeError, aconnect_ws
from httpx_ws.transport import ASGIWebSocketTransport
from ironmesh_wire.ids import TopicClass

from app.ws import Connection, Hub, TicketStore, frame

from .conftest import Env, telemetry_body


def ws_client(env: Env) -> httpx.AsyncClient:
    """Created inside each test: the ASGI transport's task group must stay in one task."""
    return httpx.AsyncClient(transport=ASGIWebSocketTransport(env.app), base_url="http://registry")


async def ticket(env: Env, tenant: str, role: str = "viewer") -> str:
    r = await env.client.post("/v1/ws/ticket", headers=env.auth(tenant, role))
    assert r.status_code == 200 and r.json()["expires_in"] == 60
    return str(r.json()["ticket"])


async def next_frame(ws: Any, types: set[str], timeout: float = 2.0) -> dict[str, Any]:
    async def loop() -> dict[str, Any]:
        while True:
            data = json.loads(await ws.receive_text())
            if data["type"] in types:
                return dict(data)

    return await asyncio.wait_for(loop(), timeout)


async def test_ticket_required_and_single_use(mem: Env) -> None:
    async with ws_client(mem) as client:
        await _ticket_required(mem, client)


async def _ticket_required(mem: Env, ws_client: httpx.AsyncClient) -> None:
    t = await mem.tenant()
    with pytest.raises((WebSocketUpgradeError, WebSocketDisconnect)):
        async with aconnect_ws("http://registry/v1/ws", ws_client):
            pass
    with pytest.raises((WebSocketUpgradeError, WebSocketDisconnect)):
        async with aconnect_ws("http://registry/v1/ws?ticket=forged", ws_client):
            pass
    tk = await ticket(mem, t)
    async with aconnect_ws(f"http://registry/v1/ws?ticket={tk}", ws_client) as ws:  # type: ignore[var-annotated]
        await ws.send_json({"type": "ping"})
        assert (await next_frame(ws, {"pong"}))["data"] == {}
    with pytest.raises((WebSocketUpgradeError, WebSocketDisconnect)):
        async with aconnect_ws(f"http://registry/v1/ws?ticket={tk}", ws_client):
            pass
    assert (await mem.client.post("/v1/ws/ticket")).status_code == 401


async def test_frames_routing_and_isolation(mem: Env) -> None:
    async with ws_client(mem) as client:
        await _frames(mem, client)


async def _frames(mem: Env, ws_client: httpx.AsyncClient) -> None:
    a = await mem.tenant("a")
    b = await mem.tenant("b")
    dev, dk = await mem.active_device(a)
    did = dev["id"]
    async with (
        aconnect_ws(f"http://registry/v1/ws?ticket={await ticket(mem, a)}", ws_client) as wa,  # type: ignore[var-annotated]
        aconnect_ws(f"http://registry/v1/ws?ticket={await ticket(mem, b)}", ws_client) as wb,  # type: ignore[var-annotated]
    ):
        # default subscription (fleet + alerts) receives state changes
        await mem.client.post(
            f"/v1/devices/{did}/quarantine",
            headers=mem.auth(a, "operator"),
            json={"reason": "test"},
        )
        changed = await next_frame(wa, {"device.state_changed"})
        assert changed["data"] == {
            "device_id": did,
            "state": "quarantined",
            "previous_state": "active",
        }
        assert changed["at"].endswith("Z")
        audit = await next_frame(wa, {"audit.created"})
        assert audit["data"]["tenant_id"] == a
        await mem.client.post(
            f"/v1/devices/{did}/release", headers=mem.auth(a, "admin"), json={"note": "ok"}
        )
        dk = await mem.enroll(a, did)  # release requires re-enrollment (old certs were revoked)
        # device-scoped frames need an explicit subscription
        await wa.send_json({"type": "subscribe", "topics": [f"device:{did}"]})
        sub = await next_frame(wa, {"subscribed"})
        assert f"device:{did}" in sub["data"]["topics"]
        assert await mem.send(dk, TopicClass.TELEMETRY, telemetry_body(cpu_pct=1.0)) == "accepted"
        tele = await next_frame(wa, {"device.telemetry"})
        assert tele["data"]["device_id"] == did and tele["data"]["sample"]["cpu_pct"] == 1.0
        # sampled to 1 frame / s / device
        assert await mem.send(dk, TopicClass.TELEMETRY, telemetry_body(cpu_pct=2.0)) == "accepted"
        await mem.client.patch(
            f"/v1/devices/{did}/twin/desired",
            headers=mem.auth(a, "operator"),
            json={"patch": {"led": "on"}},
        )
        nxt = await next_frame(wa, {"device.telemetry", "twin.updated"})
        assert nxt["type"] == "twin.updated" and nxt["data"]["desired"] == {"led": "on"}
        r = await mem.client.post(
            f"/v1/devices/{did}/commands",
            headers=mem.auth(a, "operator"),
            json={"name": "reboot", "args": {}, "ttl_s": 60},
        )
        cmd = await next_frame(wa, {"command.updated"})
        assert cmd["data"]["cmd_id"] == r.json()["cmd_id"]
        alert = {
            "id": "al-1",
            "tenant_id": a,
            "device_id": did,
            "rule": "auth_burst",
            "severity": "critical",
            "state": "open",
        }
        from app.integrations.bus import BusMessage

        await mem.bus.deliver(BusMessage("im.alerts", None, json.dumps(alert).encode()))
        assert (await next_frame(wa, {"alert.created"}))["data"]["id"] == "al-1"
        # unsubscribe + invalid frames
        await wa.send_json({"type": "unsubscribe", "topics": [f"device:{did}"]})
        assert f"device:{did}" not in (await next_frame(wa, {"subscribed"}))["data"]["topics"]
        for bad in (
            {"type": "subscribe", "topics": ["device:../../x"]},
            {"type": "subscribe", "topics": "fleet"},
            {"type": "dance"},
            [1],
        ):
            await wa.send_json(bad)
            assert (await next_frame(wa, {"error"}))["type"] == "error"
        await wa.send_text("{not json")
        assert (await next_frame(wa, {"error"}))["type"] == "error"
        await wa.send_text("x" * 20_000)
        assert "too large" in (await next_frame(wa, {"error"}))["data"]["detail"]
        # server keep-alive
        assert (await next_frame(wa, {"pong"}))["data"] == {"keepalive": True}
        # tenant B saw nothing of tenant A
        await wb.send_json({"type": "subscribe", "topics": [f"device:{did}"]})
        await next_frame(wb, {"subscribed"})
        await mem.send(dk, TopicClass.TELEMETRY, telemetry_body())
        with pytest.raises(TimeoutError):
            await next_frame(
                wb,
                {
                    "device.telemetry",
                    "device.state_changed",
                    "audit.created",
                    "alert.created",
                    "twin.updated",
                },
                timeout=0.3,
            )


async def test_hub_unit_behaviour() -> None:
    from app.auth import Principal
    from app.observability import Metrics

    clock = [100.0]
    store = TicketStore(ttl_seconds=60, clock=lambda: clock[0])
    p = Principal(tenant_id="t", actor_type="user", actor_id="u", role="viewer")
    tk = store.issue(p)
    clock[0] += 61
    assert store.redeem(tk) is None and store.redeem(None) is None
    store.issue(p)
    clock[0] += 61
    store.issue(p)
    assert len(store._tickets) == 1

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    hub = Hub(Metrics(), clock=lambda: clock[0])
    conn = Connection(principal=p, send=send)
    hub.register(conn)
    for _ in range(1000):
        conn.queue.put_nowait(frame("x", {}))
    assert hub.publish("t", "device.state_changed", {}, {"fleet"}) == 0 and conn.dropped == 1
    hub.unregister(conn)
    hub.unregister(conn)
    reply = Hub.handle_client_message(
        conn, {"type": "subscribe", "topics": [f"device:dev-{i:016x}" for i in range(300)]}
    )
    assert reply is not None and "at most" in reply["data"]["detail"]
