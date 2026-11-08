"""Bus implementations, config, state snapshots, stats/geo helpers, logging, app lifecycle, OIDC."""

from __future__ import annotations

import json
import math
import ssl
from pathlib import Path
from typing import Any

import httpx
import jwt
import maxminddb
import pytest
import structlog
from aiokafka import TopicPartition
from cryptography.hazmat.primitives.asymmetric import ec

from ironmesh_anomaly import bus as bus_mod
from ironmesh_anomaly import geo as geo_mod
from ironmesh_anomaly.app import Components, create_app
from ironmesh_anomaly.auth import AuthError, TokenVerifier
from ironmesh_anomaly.bus import (
    BusRecord,
    InMemoryEventBus,
    KafkaEventBus,
    kafka_client_options,
    next_offsets,
)
from ironmesh_anomaly.config import Settings
from ironmesh_anomaly.geo import (
    GeoLocation,
    MaxMindGeoIPProvider,
    NullGeoIPProvider,
    build_geoip_provider,
    haversine_km,
    is_public_ip,
    valid_coordinates,
)
from ironmesh_anomaly.models import (
    AuthEvent,
    AuthKind,
    OtaStatusEvent,
    RuleOverride,
    Severity,
    TenantSettings,
    event_from_dict,
    event_to_dict,
)
from ironmesh_anomaly.observability import configure_logging, configure_tracing
from ironmesh_anomaly.state import DeviceState, StateStore
from ironmesh_anomaly.stats import acf_peak, autocorrelation, mad, median, psi, robust_cv, robust_z
from tests.support import T0, TENANT, make_harness, telemetry_event

# ------------------------------------------------------------------------------------- bus


async def test_in_memory_bus() -> None:
    b = InMemoryEventBus(["a", "b"])
    await b.start()
    for i in range(3):
        b.produce("a", f"{i}".encode())
    b.produce("b", b"x")
    first = await b.poll(2, 0)
    assert [r.value for r in first] == [b"0", b"1"]
    rest = await b.poll(10, 0)
    assert [(r.topic, r.value) for r in rest] == [("a", b"2"), ("b", b"x")]
    await b.commit(next_offsets(first))
    assert b.committed == {"a": 2}
    b.rewind_to_committed()
    assert [r.value for r in await b.poll(10, 0)][:1] == [b"2"]
    b.seek("a", 0, 0)
    assert len(await b.poll(10, 0)) == 3
    assert await b.lag() == {"a": 1, "b": 1}
    b.fail_publish.add("a")
    with pytest.raises(ConnectionError):
        await b.publish("a", None, b"")
    await b.stop()
    assert not b.started


class _FakeRecord:
    def __init__(self, offset: int) -> None:
        self.offset, self.key, self.value, self.headers, self.timestamp = (
            offset,
            b"k",
            b"v",
            [("h", b"1")],
            5,
        )


class _FakeConsumer:
    instances: list[_FakeConsumer] = []

    def __init__(self, *topics: str, **kwargs: Any) -> None:
        self.topics, self.kwargs = topics, kwargs
        self.committed: Any = None
        self.seeks: list[Any] = []
        _FakeConsumer.instances.append(self)

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    async def getmany(self, *_: Any, timeout_ms: int = 0, max_records: int | None = None) -> Any:
        return {TopicPartition("im.ingest", 0): [_FakeRecord(7), _FakeRecord(8)]}

    async def commit(self, offsets: Any = None) -> None:
        self.committed = offsets

    def seek(self, tp: Any, offset: int) -> None:
        self.seeks.append((tp, offset))

    def assignment(self) -> set[Any]:
        return {TopicPartition("im.ingest", 0), TopicPartition("im.auth", 0)}

    def highwater(self, tp: Any) -> int | None:
        return 10 if tp.topic == "im.ingest" else None

    async def position(self, tp: Any) -> int:
        return 4


class _FakeProducer:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.sent: list[Any] = []

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    async def send_and_wait(self, topic: str, **kw: Any) -> None:
        self.sent.append((topic, kw))


async def test_kafka_bus_with_fake_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bus_mod, "AIOKafkaConsumer", _FakeConsumer)
    monkeypatch.setattr(bus_mod, "AIOKafkaProducer", _FakeProducer)
    kb = KafkaEventBus("broker:9092", "grp", ["im.ingest"], security_protocol="PLAINTEXT")
    await kb.start()
    recs = await kb.poll(10, 100)
    assert [r.offset for r in recs] == [7, 8] and recs[0].headers == {"h": b"1"}
    await kb.publish("im.alerts", b"k", b"v", {"x": b"y"})
    await kb.commit({("im.ingest", 0): 9})
    await kb.commit({})
    kb.seek("im.ingest", 0, 3)
    assert await kb.lag() == {"im.ingest": 6}
    await kb.stop()
    consumer = _FakeConsumer.instances[-1]
    assert (
        consumer.kwargs["enable_auto_commit"] is False
        and consumer.kwargs["isolation_level"] == "read_committed"
    )
    assert consumer.committed == {TopicPartition("im.ingest", 0): 9}
    producer: Any = kb._producer
    assert producer.kwargs["enable_idempotence"] is True and producer.kwargs["acks"] == "all"
    assert producer.sent[0][1]["headers"] == [("x", b"y")]


def test_kafka_client_options() -> None:
    none = kafka_client_options(tls_enabled=False, sasl_mechanism="none")
    assert none == {"security_protocol": "PLAINTEXT"}
    assert kafka_client_options(tls_enabled=False, sasl_mechanism="") == {
        "security_protocol": "PLAINTEXT"
    }
    tls = kafka_client_options(tls_enabled=True, sasl_mechanism=None)
    assert tls["security_protocol"] == "SSL" and isinstance(tls["ssl_context"], ssl.SSLContext)
    scram = kafka_client_options(
        tls_enabled=True, sasl_mechanism="scram-sha-512", sasl_username="u", sasl_password="p"
    )
    assert scram["security_protocol"] == "SASL_SSL" and scram["sasl_mechanism"] == "SCRAM-SHA-512"
    assert (
        kafka_client_options(tls_enabled=False, sasl_mechanism="PLAIN")["security_protocol"]
        == "SASL_PLAINTEXT"
    )
    msk = kafka_client_options(tls_enabled=False, sasl_mechanism="AWS_MSK_IAM")
    assert msk["sasl_mechanism"] == "OAUTHBEARER" and msk["security_protocol"] == "SASL_SSL"
    with pytest.raises(ValueError):
        kafka_client_options(tls_enabled=False, sasl_mechanism="GSSAPI")


# ---------------------------------------------------------------------------------- config


def test_settings_use_chart_env_names(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "ANOMALY_LISTEN_PORT": "9000",
        "ANOMALY_DB_HOST": "db.internal",
        "ANOMALY_DB_PORT": "5433",
        "ANOMALY_DB_PASSWORD": "p@ss word",
        "ANOMALY_DB_SSLMODE": "verify-full",
        "ANOMALY_DB_IAM_AUTH": "",
        "ANOMALY_KAFKA_BROKERS": "k1:9092,k2:9092",
        "ANOMALY_KAFKA_TLS_ENABLED": "true",
        "ANOMALY_AUTO_QUARANTINE": "true",
        "ANOMALY_QUARANTINE_MIN_SEVERITY": "critical",
        "ANOMALY_MODEL_DIR": "/models",
        "ANOMALY_OIDC_ISSUER": "",
        "ANOMALY_LOG_LEVEL": "debug",
        "ANOMALY_INTERNAL_TOKEN": "tok",
        "ANOMALY_SIEM_WEBHOOK_URL": "https://siem/x",
        "ANOMALY_TLS_KEY_FILE": "/etc/tls.key",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    s = Settings()
    assert s.listen_port == 9000 and s.kafka_tls_enabled and s.auto_quarantine
    assert s.quarantine_min_severity is Severity.CRITICAL and s.model_dir == "/models"
    assert s.oidc_issuer is None and s.log_level == "DEBUG" and not s.db_iam_auth
    assert (
        s.database_dsn()
        == "postgresql://anomaly_app:p%40ss%20word@db.internal:5433/anomaly?sslmode=verify-full"
    )
    assert s.internal_token is not None and s.internal_token.get_secret_value() == "tok"
    assert s.jwt_key_file() == "/etc/tls.key"
    monkeypatch.setenv("ANOMALY_DATABASE_URL", "postgresql://x/y")
    assert Settings().database_dsn() == "postgresql://x/y"
    monkeypatch.delenv("ANOMALY_DATABASE_URL")
    monkeypatch.setenv("ANOMALY_TLS_CA_FILE", "/etc/ironmesh/tls/ca.crt")
    assert Settings().database_dsn() == (
        "postgresql://anomaly_app:p%40ss%20word@db.internal:5433/anomaly"
        "?sslmode=verify-full&sslrootcert=%2Fetc%2Fironmesh%2Ftls%2Fca.crt"
    )
    monkeypatch.delenv("ANOMALY_TLS_CA_FILE")
    monkeypatch.setenv("ANOMALY_DB_IAM_AUTH", "true")
    monkeypatch.setenv("ANOMALY_DB_PORT", "")
    monkeypatch.setenv("ANOMALY_DB_SSLMODE", "")
    assert Settings().database_dsn() == "postgresql://anomaly_app@db.internal/anomaly"
    monkeypatch.setenv("ANOMALY_DB_HOST", "")
    assert Settings().database_dsn() is None


# ----------------------------------------------------------------------------------- state


def test_state_snapshot_roundtrip_and_counter_reset() -> None:
    store = StateStore(geo_mod.StaticGeoIPProvider({"203.0.113.1": GeoLocation(1.0, 2.0, 5.0)}))
    dev = "dev-00000000000000aa"
    store.apply(telemetry_event(dev, T0, tx=1000, rx=1000, lat=1.0, lon=2.0, uptime=100))
    obs = store.apply(
        telemetry_event(dev, T0 + 60, seq=2, tx=61000, rx=1000, auth_failures=3, uptime=160)
    )
    assert obs.tx_rate == pytest.approx(1000.0)
    reboot = store.apply(telemetry_event(dev, T0 + 120, seq=3, tx=500, rx=500, uptime=10))
    assert reboot.tx_rate == pytest.approx(500 / 60)
    store.apply(AuthEvent(TENANT, dev, T0 + 130, AuthKind.CONNECTED, peerhost="203.0.113.1"))
    store.apply(AuthEvent(TENANT, dev, T0 + 131, AuthKind.AUTHN_FAILED, peerhost="203.0.113.1"))
    store.apply(AuthEvent(TENANT, dev, T0 + 132, AuthKind.AUTHZ_DENIED))
    store.apply(OtaStatusEvent(TENANT, dev, T0 + 140, state=5, fw_hash_hex="ab" * 32))
    store.apply(telemetry_event(dev, T0 + 140, seq=4, tx=600, uptime=30))  # dt=20, rates fine
    store.apply(telemetry_event(dev, T0 + 140, seq=5, tx=700, uptime=30))  # dt=0 -> no features
    st = store.get(TENANT, dev)
    assert st is not None
    st.last_seq = 5
    clone = DeviceState.from_dict(json.loads(json.dumps(st.to_dict())))
    assert clone.to_dict() == st.to_dict() and not clone.dirty
    assert clone.sample_count == 3 and clone.fw_last_installed == "ab" * 32
    assert clone.ip_fix is not None and clone.ip_fix.source == "ip:203.0.113.1"
    assert math.isnan(clone.features[0][1][7])
    assert store.ip_failures_in(TENANT, "203.0.113.1", 60, T0 + 140) == 1
    assert store.ip_failures_in(TENANT, "198.51.100.1", 60, T0) == 0
    assert store.tenants() == {TENANT} and len(store) == 1 and len(list(store)) == 1
    assert store.dirty_states() == [st]
    # device class updates
    store.get_or_create(TENANT, dev, "gateway-rpi")
    assert st.device_class == "gateway-rpi"
    # old auth failures pruned
    store.apply(AuthEvent(TENANT, dev, T0 + 10_000, AuthKind.DISCONNECTED))
    assert st.auth_failures_in(3600, T0 + 10_000) == 0 and st.denies_in(10**6, T0 + 10_000) == 1


def test_event_dict_roundtrip() -> None:
    for ev in (
        telemetry_event(),
        AuthEvent(TENANT, "dev-00000000000000aa", 1.0, AuthKind.CONNECTED, "1.1.1.1"),
        OtaStatusEvent(TENANT, "dev-00000000000000aa", 2.0, 5, "aa"),
    ):
        assert event_from_dict(event_to_dict(ev)) == ev
    with pytest.raises(ValueError):
        event_from_dict({"kind": "nope"})


def test_models_settings_roundtrip() -> None:
    s = TenantSettings.from_api(
        {
            "auto_quarantine": True,
            "quarantine_min_severity": "low",
            "siem": {"enabled": True, "syslog_port": 514},
        }
    )
    assert TenantSettings.from_api(s.to_api()) == s
    o = RuleOverride.from_dict(
        RuleOverride(enabled=True, severity=Severity.LOW, params={"a": 1}).to_dict()
    )
    assert o.severity is Severity.LOW and o.params == {"a": 1}
    assert (
        Severity.CRITICAL.escalate() is Severity.CRITICAL
        and Severity.LOW.escalate(2) is Severity.HIGH
    )


# ----------------------------------------------------------------------------- stats / geo


def test_stats() -> None:
    assert median([3, 1, 2]) == 2 and mad([1, 2, 3, 4, 100]) == 1
    assert robust_cv([10, 10, 10]) == 0 and robust_cv([0, 0]) == math.inf
    assert robust_z(10, 0, 0, 2) == 5
    with pytest.raises(ValueError):
        median([])
    with pytest.raises(ValueError):
        mad([])
    assert autocorrelation([], 3) == []
    assert autocorrelation([1, 1, 1, 1], 2) == [1.0, 0.0, 0.0]
    series = [10.0 if i % 4 == 0 else 1.0 for i in range(40)]
    lag, peak = acf_peak(series, 2, 10)
    assert lag == 4 and peak > 0.8
    assert psi([], [1.0], [0, 1]) == 0.0
    assert psi([0.1] * 50 + [0.9] * 50, [0.1] * 50 + [0.9] * 50, [0, 0.5, 1]) == pytest.approx(0)
    assert psi([0.1] * 100, [0.9] * 100, [0, 0.5, 1]) > 1


def test_geo_helpers() -> None:
    assert haversine_km(0, 0, 0, 0) == 0
    assert 340 < haversine_km(51.5074, -0.1278, 48.8566, 2.3522) < 345  # London-Paris
    assert (
        valid_coordinates(10, 10)
        and not valid_coordinates(91, 0)
        and not valid_coordinates(math.nan, 0)
    )
    assert is_public_ip("8.8.8.8") and not is_public_ip("10.0.0.1") and not is_public_ip("nope")
    assert NullGeoIPProvider().lookup("8.8.8.8") is None
    assert isinstance(build_geoip_provider(None), NullGeoIPProvider)


def test_maxmind_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    class Reader:
        def get(self, ip: str) -> Any:
            return {
                "8.8.8.8": {
                    "location": {"latitude": 37.4, "longitude": -122.1, "accuracy_radius": 1000},
                    "country": {"iso_code": "US"},
                },
                "1.1.1.1": {"location": {"latitude": "x"}},
                "9.9.9.9": {"city": {}},
                "4.4.4.4": [],
            }.get(ip)

        def close(self) -> None: ...

    monkeypatch.setattr(maxminddb, "open_database", lambda path: Reader())
    p = build_geoip_provider("/fake.mmdb")
    assert isinstance(p, MaxMindGeoIPProvider)
    loc = p.lookup("8.8.8.8")
    assert loc == GeoLocation(37.4, -122.1, 1000.0, "US")
    assert p.lookup("10.0.0.1") is None and p.lookup("1.1.1.1") is None
    assert (
        p.lookup("9.9.9.9") is None and p.lookup("4.4.4.4") is None and p.lookup("5.5.5.5") is None
    )
    p.close()


# ----------------------------------------------------------------------- logging / tracing


def test_logging_contract_fields(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("anomaly", "INFO", "json")
    structlog.get_logger("t").info("hello", tenant_id=TENANT)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert {
        "ts",
        "level",
        "service",
        "trace_id",
        "span_id",
        "tenant_id",
        "device_id",
        "msg",
    } <= set(line)
    assert line["msg"] == "hello" and line["service"] == "anomaly"
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    tracer = TracerProvider().get_tracer("t")
    with tracer.start_as_current_span("s"):
        structlog.get_logger("t2").info("in span")
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["trace_id"] and len(line["trace_id"]) == 32
    configure_logging("anomaly", "WARNING", "console")
    structlog.reset_defaults()
    assert configure_tracing("anomaly", None) is None
    assert trace.get_tracer_provider() is not None


# ---------------------------------------------------------------------------- app lifespan


async def test_app_lifespan_runs_pipeline(tmp_path: Path) -> None:
    settings = Settings(
        run_pipeline=True,
        model_dir=str(tmp_path / "m"),
        snapshot_interval_s=0.01,
        training_interval_s=0.01,
        poll_timeout_ms=0,
    )
    h = make_harness(tmp_path, settings=settings)
    closed: list[int] = []

    async def closer() -> None:
        closed.append(1)

    app = create_app(Components(settings, h.engine, None, closers=[closer]))
    async with app.router.lifespan_context(app):
        assert app.state.ready
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://x") as c:
            assert (await c.get("/readyz")).json()["status"] == "ready"
    assert not app.state.ready and closed == [1] and not h.bus.started


# ---------------------------------------------------------------------------------- OIDC


async def test_oidc_discovery_and_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    import time

    tok = jwt.encode(
        {
            "sub": "u",
            "aud": "ironmesh-api",
            "iss": "https://idp",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        key,
        algorithm="ES256",
        headers={"kid": "k1"},
    )

    def fake_get(url: str, **_: Any) -> httpx.Response:
        assert url == "https://idp/.well-known/openid-configuration"
        return httpx.Response(
            200, json={"jwks_uri": "https://idp/jwks"}, request=httpx.Request("GET", url)
        )

    class FakeJwk:
        def __init__(self, *_: Any, **__: Any) -> None: ...

        def get_signing_key_from_jwt(self, token: str) -> Any:
            return type("K", (), {"key": key.public_key()})()

    import ironmesh_anomaly.auth as auth_mod

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(auth_mod, "PyJWKClient", FakeJwk)
    v = TokenVerifier.from_issuer(
        audience="ironmesh-api", issuer="https://idp", algorithms=["ES256"]
    )
    assert (await v.verify(tok))["sub"] == "u"
    assert (await v.verify(tok))["sub"] == "u"  # discovery cached
    jw = TokenVerifier.from_jwks(
        "https://idp/jwks", audience="ironmesh-api", issuer="https://idp", algorithms=["ES256"]
    )
    assert (await jw.verify(tok))["sub"] == "u"

    def no_jwks(url: str, **_: Any) -> httpx.Response:
        return httpx.Response(200, json={}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", no_jwks)
    v2 = TokenVerifier.from_issuer(
        audience="ironmesh-api", issuer="https://idp", algorithms=["ES256"]
    )
    with pytest.raises(AuthError):
        await v2.verify(tok)

    def down(url: str, **_: Any) -> httpx.Response:
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", down)
    v3 = TokenVerifier.from_issuer(
        audience="ironmesh-api", issuer="https://idp", algorithms=["ES256"]
    )
    with pytest.raises(AuthError) as info:
        await v3.verify(tok)
    assert info.value.status == 503
    hs = jwt.encode({"sub": "x"}, "k" * 64, algorithm="HS256")
    with pytest.raises(AuthError):
        await v.verify(hs)


def test_bus_record_defaults() -> None:
    r = BusRecord("t", 0, 1, None, b"")
    assert r.headers == {} and next_offsets([r, BusRecord("t", 0, 0, None, b"")]) == {("t", 0): 2}
