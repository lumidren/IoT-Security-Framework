"""SIEM formatters (ECS, RFC 5424, HMAC) and delivery (retry/backoff, DLQ, SSRF guard)."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import re
import ssl
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ironmesh_anomaly.models import Alert, RuleName, Severity, SiemSettings, TenantSettings, from_ts
from ironmesh_anomaly.siem import (
    SIGNATURE_HEADER,
    Delivery,
    SiemDispatcher,
    SyslogSink,
    UnsafeTarget,
    WebhookSink,
    check_address,
    octet_frame,
    resolve_public,
    sign_webhook,
    to_ecs,
    to_syslog,
    validate_host,
    validate_webhook_url,
    verify_webhook,
)
from tests.support import TENANT

DEV = "dev-00000000000000aa"


def alert(
    rule: RuleName = RuleName.AUTH_BURST,
    sev: Severity = Severity.HIGH,
    explanation: str = "25 failures",
) -> Alert:
    a = Alert(
        "4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        TENANT,
        DEV,
        rule,
        sev,
        0.6,
        {"source_ip": "203.0.113.50", "failures": 25},
        explanation,
        from_ts(1_760_000_000.123456),
    )
    a.last_seen_at = from_ts(1_760_000_060.5)
    return a


def settings(**siem: Any) -> TenantSettings:
    return TenantSettings(siem=SiemSettings(enabled=True, **siem))


# ------------------------------------------------------------------------------- formatters


def test_ecs_required_fields() -> None:
    doc = to_ecs(alert())
    assert doc["@timestamp"] == "2025-10-09T08:54:20.500000Z"
    assert doc["ecs"]["version"].startswith("8.")
    assert doc["event"]["kind"] == "alert"
    assert doc["event"]["category"] == ["intrusion_detection"]
    assert doc["event"]["type"] == ["info"]
    assert doc["event"]["severity"] == 73 and 0 < doc["event"]["risk_score"] <= 100
    assert doc["rule"]["name"] == "auth_burst"
    assert doc["host"]["id"] == DEV
    assert doc["observer"]["vendor"] == "IronMesh" and doc["observer"]["type"] == "ids"
    assert doc["organization"]["id"] == TENANT
    assert doc["source"]["ip"] == "203.0.113.50"
    assert doc["threat"]["framework"] == "MITRE ATT&CK"
    assert doc["threat"]["technique"]["id"] == ["T1110"]
    assert doc["threat"]["tactic"]["id"] == ["TA0006"]
    json.dumps(doc)  # serialisable
    iso = to_ecs(alert(RuleName.ISOLATION_FOREST))
    assert "threat" not in iso
    bad_ip = alert()
    bad_ip.features["source_ip"] = "not-an-ip"
    assert "source" not in to_ecs(bad_ip)


RFC5424 = re.compile(
    rb"^<(?P<pri>\d{1,3})>1 (?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z) (?P<host>[!-~]{1,255}) "
    rb"(?P<app>[!-~]{1,48}) (?P<proc>[!-~]{1,128}) (?P<msgid>[!-~]{1,32}) "
    rb"(?P<sd>\[[^ \]=\"]+(?: [^ \]=\"]+=\"(?:[^\"\\\]]|\\.)*\")*\]) \xef\xbb\xbf(?P<msg>.*)$",
    re.DOTALL,
)


def test_rfc5424_structure() -> None:
    msg = to_syslog(
        alert(explanation='quote " and ] and \\ and\nnewline ü'),
        facility=10,
        hostname="anomaly-0",
        procid="42",
    )
    m = RFC5424.match(msg)
    assert m is not None, msg
    assert int(m["pri"]) == 10 * 8 + 3  # authpriv.err for high
    assert m["ts"] == b"2025-10-09T08:54:20.500000Z"
    assert m["host"] == b"anomaly-0" and m["app"] == b"ironmesh-anomaly" and m["proc"] == b"42"
    assert m["msgid"] == b"AUTH_BURST"
    assert b'deviceId="dev-00000000000000aa"' in m["sd"]
    assert b"\n" not in m["msg"] and "ü".encode() in m["msg"]
    crit = RFC5424.match(to_syslog(alert(sev=Severity.CRITICAL), hostname="h o s t"))
    assert crit is not None and int(crit["pri"]) == 82 and crit["host"] == b"host"
    escaped = to_syslog(alert(RuleName.TOPIC_VIOLATION))
    sd_with_quote = alert()
    sd_with_quote.device_id = 'dev"x]'
    assert b'deviceId="dev\\"x\\]"' in to_syslog(sd_with_quote)
    assert escaped.startswith(b"<83>1 ")
    with pytest.raises(ValueError):
        to_syslog(alert(), facility=24)
    assert octet_frame(b"abc") == b"3 abc"


def test_hmac_signature_verifies() -> None:
    body = json.dumps(to_ecs(alert())).encode()
    header = sign_webhook(b"s3cret", body, timestamp=1000)
    assert header.startswith("t=1000,v1=")
    assert verify_webhook(b"s3cret", body, header, now=1100)
    assert not verify_webhook(b"other", body, header, now=1100)
    assert not verify_webhook(b"s3cret", body + b" ", header, now=1100)
    assert not verify_webhook(b"s3cret", body, header, now=2000)  # replay window
    assert not verify_webhook(b"s3cret", body, "v1=abc", now=1000)
    assert verify_webhook(b"k", b"x", sign_webhook(b"k", b"x"))


# ------------------------------------------------------------------------------- SSRF guard


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "224.0.0.1",
        "192.168.1.1",
    ],
)
def test_private_addresses_refused(addr: str) -> None:
    with pytest.raises(UnsafeTarget):
        check_address(addr)


def test_url_and_host_validation() -> None:
    assert validate_webhook_url("https://siem.example.com/hook", allow_private=False)
    for bad in (
        "http://siem.example.com",
        "https://user:pw@siem.example.com",
        "https://localhost/x",
        "https://10.0.0.1/x",
        "https://metadata.internal/",
        "file:///etc/passwd",
    ):
        with pytest.raises(UnsafeTarget):
            validate_webhook_url(bad, allow_private=False)
    assert validate_webhook_url("http://127.0.0.1:9/x", allow_private=True)
    assert validate_host("siem.example.com", allow_private=False)
    for bad in ("", "a/b", "127.0.0.1", "x.localhost"):
        with pytest.raises(UnsafeTarget):
            validate_host(bad, allow_private=False)


async def test_resolve_public_rebinding_guard() -> None:
    async def evil(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "127.0.0.1"]

    async def none(host: str, port: int) -> list[str]:
        return []

    with pytest.raises(UnsafeTarget):
        await resolve_public("evil.example", 443, evil, allow_private=False)
    with pytest.raises(UnsafeTarget):
        await resolve_public("void.example", 443, none, allow_private=False)
    await resolve_public("evil.example", 443, evil, allow_private=True)


# ---------------------------------------------------------------------------------- delivery


async def public_resolver(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


async def test_webhook_sink_signs_and_posts() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(202)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        sink = WebhookSink(client, b"k", resolver=public_resolver)
        s = settings(ecs_webhook_url="https://siem.example.com/hook")
        assert sink.wants(s) and not sink.wants(TenantSettings())
        await sink.send(Delivery(alert(), s))
        platform = WebhookSink(
            client, b"k", fixed_url="http://10.0.0.5/ingest", name="webhook_platform"
        )
        assert platform.wants(TenantSettings())
        await platform.send(Delivery(alert(), TenantSettings()))
    req = seen[0]
    assert verify_webhook(b"k", req.content, req.headers[SIGNATURE_HEADER])
    assert json.loads(req.content)["event"]["kind"] == "alert"
    assert str(seen[1].url) == "http://10.0.0.5/ingest"


async def test_dispatcher_retries_then_dead_letters_and_redrives() -> None:
    attempts: list[int] = []
    fail = [True]

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503 if fail[0] else 200)

    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        sink = WebhookSink(client, b"k", resolver=public_resolver)
        disp = SiemDispatcher(
            [sink], max_attempts=3, backoff_base_s=1, backoff_max_s=4, dlq_max=2, sleep=fake_sleep
        )
        s = settings(ecs_webhook_url="https://siem.example.com/hook")
        ok = await disp.deliver(sink, Delivery(alert(), s))
        assert not ok and len(attempts) == 3 and len(sleeps) == 2
        assert all(0 <= x <= 4 for x in sleeps)
        assert len(disp.dlq["webhook"]) == 1 and "503" in disp.dlq["webhook"][0].last_error
        for _ in range(3):
            await disp.deliver(sink, Delivery(alert(), s))
        assert len(disp.dlq["webhook"]) == 2  # bounded
        fail[0] = False
        assert await disp.redrive("webhook") == 2
        assert len(disp.dlq["webhook"]) == 0
        # unsafe target: no retries
        bad = settings(ecs_webhook_url="https://127.0.0.1/x")
        before = len(attempts)
        assert not await disp.deliver(sink, Delivery(alert(), bad))
        assert len(attempts) == before and "unsafe" in disp.dlq["webhook"][-1].last_error


async def test_dispatcher_queue_workers() -> None:
    delivered: list[str] = []

    class Sink:
        name = "mem"

        def wants(self, s: TenantSettings) -> bool:
            return s.siem.enabled

        async def send(self, d: Delivery) -> None:
            delivered.append(d.alert.id)

    disp = SiemDispatcher([Sink()], queue_max=1, dlq_max=5)
    assert disp.targets(settings()) == ["mem"]
    assert disp.submit(alert(), TenantSettings()) == []
    assert disp.submit(alert(), settings()) == ["mem"]
    assert disp.submit(alert(), settings()) == []  # queue full -> dead letter
    assert len(disp.dlq["mem"]) == 1
    disp.start()
    await asyncio.wait_for(disp.drain(), 5)
    await disp.stop()
    assert delivered == [alert().id]


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


async def _tcp_server(
    ssl_ctx: ssl.SSLContext | None,
) -> tuple[asyncio.Server, int, asyncio.Queue[bytes]]:
    got: asyncio.Queue[bytes] = asyncio.Queue()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        got.put_nowait(await reader.read(65536))
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port, got


async def test_syslog_tls_tcp_and_udp(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert, key)
    server, port, got = await _tcp_server(server_ctx)
    async with server:
        sink = SyslogSink(transport="tls", ca_file=str(cert), allow_private=True)
        assert sink.default_port() == 6514
        await sink.send(Delivery(alert(), settings(syslog_host="localhost", syslog_port=port)))
        framed = await asyncio.wait_for(got.get(), 5)
    length, _, message = framed.partition(b" ")
    assert int(length) == len(message) and RFC5424.match(message)

    server, port, got = await _tcp_server(None)
    async with server:
        sink = SyslogSink(transport="tcp", allow_private=True)
        assert sink.wants(settings(syslog_host="h")) and not sink.wants(TenantSettings())
        await sink.send(Delivery(alert(), settings(syslog_host="127.0.0.1", syslog_port=port)))
        assert RFC5424.match((await asyncio.wait_for(got.get(), 5)).partition(b" ")[2])

    loop = asyncio.get_running_loop()
    received: asyncio.Queue[bytes] = asyncio.Queue()

    class Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: Any) -> None:
            received.put_nowait(data)

    transport, _ = await loop.create_datagram_endpoint(Proto, local_addr=("127.0.0.1", 0))
    try:
        uport = transport.get_extra_info("sockname")[1]
        sink = SyslogSink(transport="udp", allow_private=True)
        assert sink.default_port() == 514
        await sink.send(Delivery(alert(), settings(syslog_host="127.0.0.1", syslog_port=uport)))
        datagram = await asyncio.wait_for(received.get(), 5)
        assert RFC5424.match(datagram)  # UDP: one message per datagram, no framing
    finally:
        transport.close()
    with pytest.raises(ValueError):
        SyslogSink(transport="carrier-pigeon")
    with pytest.raises(UnsafeTarget):
        await SyslogSink(transport="tcp").send(Delivery(alert(), settings(syslog_host="127.0.0.1")))
