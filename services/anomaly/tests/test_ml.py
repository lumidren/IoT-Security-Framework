"""Isolation Forest + device baseline: precision on synthetic outliers, persistence, poisoning."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ironmesh_anomaly.features import FEATURE_NAMES, counter_delta, log_rate, msg_rate_per_min
from ironmesh_anomaly.ml import (
    AlertPeriod,
    LocalModelStore,
    ModelIntegrityError,
    ModelManager,
    S3ModelStore,
    TrainingParams,
    combine,
    deserialize,
    device_robust_z,
    serialize,
)
from ironmesh_anomaly.models import from_ts
from ironmesh_anomaly.state import DeviceState
from tests.support import T0, TENANT

CLASS = "gateway-rpi"
PARAMS = TrainingParams(
    contamination=0.01, n_estimators=150, min_train_samples=200, max_samples_per_device=200
)


def normal_vector(rng: np.random.Generator, base: dict[str, float]) -> list[float]:
    return [
        float(np.clip(rng.normal(base["cpu"], 3.0), 0, 100)),
        float(rng.normal(base["mem"], 1.5)),
        float(rng.normal(base["temp"], 0.7)),
        math.log1p(max(0.0, rng.normal(base["rx"], base["rx"] * 0.05))),
        math.log1p(max(0.0, rng.normal(base["tx"], base["tx"] * 0.05))),
        float(base["proc"] + rng.integers(-2, 3)),
        0.0,
        math.nan,
        math.nan,
        1.0,
    ]


def make_bases(rng: np.random.Generator, n: int) -> list[dict[str, float]]:
    return [
        {
            "cpu": rng.uniform(10, 40),
            "mem": rng.uniform(30, 60),
            "temp": rng.uniform(38, 52),
            "rx": rng.uniform(1500, 4000),
            "tx": rng.uniform(800, 2500),
            "proc": float(rng.integers(80, 160)),
        }
        for _ in range(n)
    ]


def make_states(
    n_devices: int, n_samples: int, seed: int
) -> tuple[list[DeviceState], list[dict[str, float]], np.random.Generator]:
    rng = np.random.default_rng(seed)
    bases = make_bases(rng, n_devices)
    states = []
    for d, base in enumerate(bases):
        st = DeviceState(TENANT, f"dev-{d:016x}", CLASS)
        for i in range(n_samples):
            st.features.append((T0 + i * 60, normal_vector(rng, base)))
        st.sample_count = n_samples
        st.last_ts = T0 + (n_samples - 1) * 60
        states.append(st)
    return states, bases, rng


def inject(rng: np.random.Generator, x: list[float]) -> list[float]:
    """Large multi-feature deviation (resource abuse / exfiltration / process injection)."""
    y = list(x)
    kind = int(rng.integers(0, 4))
    if kind == 0:  # cryptominer: cpu pegged + temperature
        y[0], y[2] = 99.0, y[2] + 15.0
    elif kind == 1:  # exfiltration: tx x30
        y[4] = math.log1p(math.expm1(y[4]) * 30)
    elif kind == 2:  # process injection + memory
        y[5], y[1] = y[5] + 60, y[1] + 25
    else:  # brute force on the device itself
        y[6] = 40.0
        y[0] = y[0] + 30
    return y


def test_isolation_forest_precision_on_synthetic_outliers(tmp_path: Path) -> None:
    states, bases, rng = make_states(100, 120, seed=42)
    mgr = ModelManager(LocalModelStore(tmp_path), seed=1337)
    result = mgr.train(states, TENANT, CLASS, [], set(), PARAMS, now=T0)
    assert result is not None
    tp = fp = fn = tn = 0
    for st, base in zip(states, bases, strict=True):
        for i in range(30):
            x = normal_vector(rng, base)
            outlier = rng.random() < 0.03
            if outlier:
                x = inject(rng, x)
            st.features.append((T0 + (120 + i) * 60, x))
            raw = mgr.score(st, x)
            assert raw is not None
            # the isolation_forest rule's decision (see rules/isolation_forest.py)
            flagged = raw.device_z >= 6.0 and (raw.combined > 0.5 or bool(raw.novel_features))
            tp += flagged and outlier
            fp += flagged and not outlier
            fn += (not flagged) and outlier
            tn += (not flagged) and not outlier
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    print(
        f"isolation_forest synthetic: tp={tp} fp={fp} fn={fn} tn={tn} precision={precision:.3f} recall={recall:.3f}"
    )
    assert tp + fn > 50  # enough injected outliers for the estimate to be meaningful
    assert precision >= 0.9
    assert recall >= 0.8
    assert fp <= 1


def test_cold_start_and_class_isolation(tmp_path: Path) -> None:
    states, _, _ = make_states(2, 50, seed=1)
    mgr = ModelManager(LocalModelStore(tmp_path))
    assert mgr.train(states, TENANT, CLASS, [], set(), PARAMS) is None  # < min devices/samples
    raw = mgr.score(states[0], states[0].features[-1][1])
    assert raw is not None and raw.trained_at is None and raw.combined == 0.0
    other = DeviceState(TENANT, "dev-00000000000000ff", "other-class")
    assert mgr.get(TENANT, "other-class") is None
    assert mgr.score(other, [0.0] * 10) is not None


def test_poisoning_resistance_exclusions_and_cap(tmp_path: Path) -> None:
    states, _, _ = make_states(5, 250, seed=3)
    mgr = ModelManager(LocalModelStore(tmp_path))
    states[0].quarantined = True
    periods = [AlertPeriod(states[1].device_id, T0, T0 + 99 * 60)]  # first 100 samples tainted
    x, devices, stats = mgr.build_training_set(
        states, TENANT, CLASS, periods, {states[2].device_id}, PARAMS
    )
    # device 0 quarantined (state), device 2 quarantined (registry record): excluded entirely;
    # device 1 loses its 100 samples inside the alert period; devices 3 and 4 are capped at 200
    assert devices == 3
    assert stats["devices_quarantined"] == 2
    assert stats["samples_excluded_alerts"] == 100
    assert x.shape == (150 + 200 + 200, len(FEATURE_NAMES))
    assert stats["samples_capped"] == 100


def test_model_persistence_integrity(tmp_path: Path) -> None:
    states, _, _ = make_states(10, 60, seed=5)
    mgr = ModelManager(LocalModelStore(tmp_path), seed=9)
    result = mgr.train(states, TENANT, CLASS, [], set(), PARAMS, now=T0)
    assert result is not None
    model, blob = result
    meta = mgr.meta_for(model)
    assert meta.sha256_hex == hashlib.sha256(blob).hexdigest()
    assert meta.trained_at == from_ts(T0)
    fresh = ModelManager(LocalModelStore(tmp_path))
    loaded = fresh.load(meta)
    x = states[0].features[-1][1]
    assert loaded.class_score(x) == pytest.approx(model.class_score(x))
    # tamper with the stored blob -> refused before unpickling
    path = tmp_path / ModelManager.key_for(meta)
    path.write_bytes(path.read_bytes()[:-1] + b"\x00")
    with pytest.raises(ModelIntegrityError):
        ModelManager(LocalModelStore(tmp_path)).load(meta)
    with pytest.raises(ModelIntegrityError):
        deserialize(blob, "")
    meta.tenant_id = "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
    good = serialize(model)
    LocalModelStore(tmp_path).put(ModelManager.key_for(meta), good)
    meta.sha256_hex = hashlib.sha256(good).hexdigest()
    with pytest.raises(ModelIntegrityError):
        ModelManager(LocalModelStore(tmp_path)).load(meta)


def test_payload_validation() -> None:
    import io

    import joblib

    buf = io.BytesIO()
    joblib.dump({"format": 2}, buf)
    blob = buf.getvalue()
    with pytest.raises(ModelIntegrityError):
        deserialize(blob, hashlib.sha256(blob).hexdigest())
    buf = io.BytesIO()
    joblib.dump(["not", "a", "dict"], buf)
    blob = buf.getvalue()
    with pytest.raises(ModelIntegrityError):
        deserialize(blob, hashlib.sha256(blob).hexdigest())
    buf = io.BytesIO()
    joblib.dump({"format": 1, "feature_names": list(FEATURE_NAMES), "forest": "nope"}, buf)
    blob = buf.getvalue()
    with pytest.raises(ModelIntegrityError):
        deserialize(blob, hashlib.sha256(blob).hexdigest())


def test_store_key_validation(tmp_path: Path) -> None:
    store = LocalModelStore(tmp_path)
    for bad in ("../x", "/abs", "a/../../b", "sp ace"):
        with pytest.raises(ValueError):
            store.put(bad, b"x")


def test_s3_store_with_fake_client() -> None:
    class Body:
        def __init__(self, data: bytes) -> None:
            self.data = data

        def read(self) -> bytes:
            return self.data

    class FakeS3:
        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}
            self.kwargs: list[dict[str, Any]] = []

        def put_object(self, **kwargs: Any) -> None:
            self.kwargs.append(kwargs)
            self.objects[kwargs["Key"]] = kwargs["Body"]

        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {"Body": Body(self.objects[kwargs["Key"]])}

    s3 = FakeS3()
    store = S3ModelStore(s3, "bucket", "p/")
    store.put("t/c/v1.joblib", b"abc")
    assert store.get("t/c/v1.joblib") == b"abc"
    assert (
        s3.kwargs[0]["ServerSideEncryption"] == "aws:kms"
        and s3.kwargs[0]["Key"] == "p/t/c/v1.joblib"
    )


def test_drift_and_metrics(tmp_path: Path) -> None:
    states, bases, rng = make_states(10, 60, seed=11)
    mgr = ModelManager(LocalModelStore(tmp_path))
    result = mgr.train(states, TENANT, CLASS, [], set(), PARAMS, now=T0)
    assert result is not None
    model, _ = result
    assert model.drift() == 0.0  # nothing scored yet
    for _ in range(200):
        model.class_score(normal_vector(rng, bases[0]))
    stable = model.drift()
    for _ in range(500):
        model.class_score(inject(rng, normal_vector(rng, bases[0])))
    assert model.drift() > stable
    mgr.refresh_metrics(now=T0 + 100)
    from prometheus_client import REGISTRY

    assert REGISTRY.get_sample_value(
        "ironmesh_anomaly_model_age_seconds", {"device_class": CLASS}
    ) == pytest.approx(100)
    assert REGISTRY.get_sample_value(
        "ironmesh_anomaly_model_score_threshold", {"device_class": CLASS}
    ) == pytest.approx(model.threshold)


def test_device_robust_z_and_combine() -> None:
    hist = [[10.0 + (i % 3)] + [math.nan] * 9 for i in range(30)]
    z = device_robust_z(hist, [40.0] + [math.nan] * 9)
    assert set(z) == {"cpu_pct"} and z["cpu_pct"] > 6
    assert device_robust_z([], [0.0] * 10) == {}
    assert device_robust_z([[math.nan] * 10], [0.0] * 10) == {}
    assert combine(0.0, 0.1, 6.0, 6.0) == pytest.approx(0.5)
    assert combine(0.2, 0.1, 12.0, 6.0) > 0.5 > combine(-0.2, 0.1, 3.0, 6.0)


def test_feature_helpers() -> None:
    assert counter_delta(10, None) == 0
    assert counter_delta(15, 10) == 5
    assert counter_delta(3, 10) == 3  # reset
    assert log_rate(100, 0) == 0.0
    assert log_rate(600, 60) == pytest.approx(math.log1p(10))
    assert msg_rate_per_min([1.0]) == 0.0
    assert msg_rate_per_min([5.0, 5.0]) == 0.0
    assert msg_rate_per_min([0.0, 60.0, 120.0]) == pytest.approx(1.0)
