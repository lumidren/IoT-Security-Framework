"""Unsupervised detection: per-(tenant, device class) Isolation Forest + device baselines.

Scoring (README "isolation_forest"):

* class score ``c = -decision_function(x)`` of the class model. scikit-learn sets the decision
  offset so that a fraction ``contamination`` of the training set has ``c > 0``.
* device score ``d = max_j |x_j - median_j| / max(1.4826 * MAD_j, floor_j)`` over the device's own
  feature history (robust z-score; NaN features are skipped).
* a sample is anomalous iff ``c > 0`` **and** ``d >= z_threshold`` (both the fleet-class model and
  the device's own history agree). The reported score is the geometric mean of the two squashed
  scores ``0.5 * (1 + tanh(c / tau))`` and ``0.5 * (1 + tanh((d - z) / z))``, which is > 0.5 exactly
  when both components are past their thresholds.

Training (poisoning resistance): samples of quarantined devices and samples inside the period of
any open/acked or true-positive alert of that device (``[created_at - margin, resolved_at|now]``)
are excluded; each device contributes at most ``max_samples_per_device`` samples (uniform random
subsample with a fixed seed) and at least ``min_train_devices`` distinct devices are required, so
a single compromised device can neither dominate nor define "normal" for its class.

Models are serialised with joblib and stored in a :class:`ModelStore`; the SHA-256 digest is kept
in the repository (a separate trust domain from the blob store) and verified **before**
deserialisation, because unpickling an attacker-controlled blob would be code execution.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import re
import tempfile
import time
import warnings
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

import joblib
import numpy as np
import structlog
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES, SCALE_FLOORS
from .metrics import (
    ANOMALY_SCORE,
    MODEL_AGE,
    MODEL_DRIFT,
    MODEL_SCORE,
    MODEL_SCORE_THRESHOLD,
    MODEL_TRAININGS,
)
from .models import ModelMeta, from_ts
from .rules.base import RawScore
from .state import DeviceState
from .stats import MAD_TO_SIGMA, psi

log = structlog.get_logger(__name__)

_FLOORS: Final = np.array([SCALE_FLOORS[n] for n in FEATURE_NAMES], dtype=float)
_KEY_RE: Final = re.compile(r"^[A-Za-z0-9._/-]+$")
DRIFT_WINDOW: Final = 1000


class ModelIntegrityError(RuntimeError):
    """The stored model blob does not match the digest recorded in the repository."""


# --------------------------------------------------------------------------------------------
# Model store
# --------------------------------------------------------------------------------------------


class ModelStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...


def _check_key(key: str) -> str:
    if not _KEY_RE.fullmatch(key) or ".." in key.split("/") or key.startswith("/"):
        raise ValueError(f"invalid model key {key!r}")
    return key


class LocalModelStore:
    """Directory-backed store; writes are atomic (temp file + rename) with mode 0600."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _path(self, key: str) -> Path:
        return self._root / _check_key(key)

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()


class S3Client(Protocol):
    def put_object(self, **kwargs: Any) -> Any: ...

    def get_object(self, **kwargs: Any) -> Any: ...


class S3ModelStore:
    """S3 store (``boto3`` client injected; server-side encryption requested on every put)."""

    def __init__(self, client: S3Client, bucket: str, prefix: str = "") -> None:
        self._client, self._bucket, self._prefix = client, bucket, prefix

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(
            Bucket=self._bucket,
            Key=self._prefix + _check_key(key),
            Body=data,
            ServerSideEncryption="aws:kms",
        )

    def get(self, key: str) -> bytes:
        response = self._client.get_object(Bucket=self._bucket, Key=self._prefix + _check_key(key))
        body: bytes = response["Body"].read()
        return body


# --------------------------------------------------------------------------------------------
# Class model
# --------------------------------------------------------------------------------------------


def average_path_length(n: float) -> float:
    """Expected path length of an unsuccessful BST search, ``c(n)`` (Liu et al., 2008)."""
    if n <= 1:
        return 0.0
    if n <= 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + float(np.euler_gamma)) - 2.0 * (n - 1.0) / n


@dataclass(slots=True)
class _FlatTree:
    left: list[int]
    right: list[int]
    feature: list[int]
    threshold: list[float]
    leaf_value: list[float]


class FastForest:
    """Single-sample Isolation Forest scorer over the fitted trees' flattened arrays.

    scikit-learn's ``decision_function`` has ~10 ms of per-call overhead (input validation and a
    Python loop over estimators calling ``tree.apply``); streaming scoring is one sample at a
    time, so this walks the trees directly (~50x faster). It reproduces
    ``score_samples(x) = -2 ** (-sum_t (depth_t(x) + c(n_leaf)) / (T * c(max_samples)))``
    (root depth 0)
    and is verified against scikit-learn at construction; on any mismatch it is disabled.
    """

    def __init__(self, forest: IsolationForest, check: np.ndarray | None = None) -> None:
        n_features = int(forest.n_features_in_)
        self.trees: list[_FlatTree] = []
        for est, feats in zip(forest.estimators_, forest.estimators_features_, strict=True):
            t = est.tree_
            left = [int(v) for v in t.children_left]
            right = [int(v) for v in t.children_right]
            fmap = [int(f) for f in feats]
            subsample = len(fmap) != n_features
            feature = [
                (fmap[int(f)] if subsample else int(f)) if int(f) >= 0 else -1 for f in t.feature
            ]
            depth = [0] * len(left)
            for node in range(len(left)):  # parents precede children in sklearn's layout
                if left[node] != -1:
                    depth[left[node]] = depth[node] + 1
                    depth[right[node]] = depth[node] + 1
            leaf_value = [
                depth[i] + average_path_length(float(t.n_node_samples[i])) if left[i] == -1 else 0.0
                for i in range(len(left))
            ]
            self.trees.append(
                _FlatTree(left, right, feature, [float(v) for v in t.threshold], leaf_value)
            )
        self.denominator = len(self.trees) * average_path_length(float(forest.max_samples_))
        self.offset = float(forest.offset_)
        self.enabled = True
        if check is not None and len(check):
            fast = np.array([self.decision(row) for row in check])
            slow = forest.decision_function(check)
            if not np.allclose(fast, slow, rtol=0, atol=1e-9):
                log.warning("fast isolation forest scorer disagrees with sklearn; disabled")
                self.enabled = False

    def decision(self, x: Sequence[float]) -> float:
        """``decision_function`` for one (imputed) sample."""
        xs = [float(np.float32(v)) for v in x]  # trees compare in float32
        total = 0.0
        for tree in self.trees:
            node = 0
            left, right, feature, threshold = tree.left, tree.right, tree.feature, tree.threshold
            while left[node] != -1:
                node = left[node] if xs[feature[node]] <= threshold[node] else right[node]
            total += tree.leaf_value[node]
        score = 2.0 ** (-total / self.denominator) if self.denominator else 1.0
        return -score - self.offset


@dataclass(frozen=True, slots=True)
class TrainingParams:
    contamination: float = 0.01
    n_estimators: int = 200
    min_train_samples: int = 200
    min_train_devices: int = 3
    max_samples_per_device: int = 200
    exclusion_margin_s: float = 3600.0


@dataclass(slots=True)
class ClassModel:
    tenant_id: str
    device_class: str
    version: str
    trained_at: float
    samples: int
    devices: int
    forest: IsolationForest
    impute: np.ndarray
    tau: float
    score_bins: list[float]
    train_scores: list[float]
    feature_means: dict[str, float]
    contamination: float
    lo: np.ndarray
    hi: np.ndarray
    sha256_hex: str = ""
    recent: deque[float] = field(default_factory=lambda: deque(maxlen=DRIFT_WINDOW))
    fast: FastForest | None = None

    def _filled(self, x: Sequence[float]) -> np.ndarray:
        arr = np.asarray(x, dtype=float)
        mask = np.isnan(arr)
        return np.where(mask, self.impute, arr) if mask.any() else arr

    def class_score(self, x: Sequence[float], *, record: bool = True) -> float:
        arr = self._filled(x)
        if self.fast is None:
            self.fast = FastForest(self.forest, None)
        if self.fast.enabled:
            value = -self.fast.decision(arr.tolist())
        else:
            value = float(-self.forest.decision_function(arr.reshape(1, -1))[0])
        if record:
            self.recent.append(value)
        return value

    def outside_envelope(self, x: Sequence[float]) -> list[str]:
        """Features outside the class's training envelope ``[q0.1%, q99.9%] +/- 10%``."""
        out: list[str] = []
        for i, name in enumerate(FEATURE_NAMES):
            v = x[i]
            if math.isnan(v):
                continue
            margin = 0.1 * max(float(self.hi[i] - self.lo[i]), float(_FLOORS[i]))
            if v < self.lo[i] - margin or v > self.hi[i] + margin:
                out.append(name)
        return out

    @property
    def threshold(self) -> float:
        """Decision threshold on ``-score_samples`` (= ``-offset_``)."""
        return float(-self.forest.offset_)

    def drift(self) -> float:
        return psi(self.train_scores, list(self.recent), self.score_bins)

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": 1,
            "tenant_id": self.tenant_id,
            "device_class": self.device_class,
            "version": self.version,
            "trained_at": self.trained_at,
            "samples": self.samples,
            "devices": self.devices,
            "forest": self.forest,
            "impute": self.impute,
            "tau": self.tau,
            "score_bins": self.score_bins,
            "train_scores": self.train_scores,
            "feature_means": self.feature_means,
            "contamination": self.contamination,
            "lo": self.lo,
            "hi": self.hi,
            "feature_names": list(FEATURE_NAMES),
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any], sha256_hex: str) -> ClassModel:
        if payload.get("format") != 1 or payload.get("feature_names") != list(FEATURE_NAMES):
            raise ModelIntegrityError("model payload format/feature set mismatch")
        forest = payload["forest"]
        if not isinstance(forest, IsolationForest):
            raise ModelIntegrityError("model payload does not contain an IsolationForest")
        return cls(
            tenant_id=payload["tenant_id"],
            device_class=payload["device_class"],
            version=payload["version"],
            trained_at=float(payload["trained_at"]),
            samples=int(payload["samples"]),
            devices=int(payload["devices"]),
            forest=forest,
            impute=np.asarray(payload["impute"], dtype=float),
            tau=float(payload["tau"]),
            score_bins=list(payload["score_bins"]),
            train_scores=list(payload["train_scores"]),
            feature_means=dict(payload["feature_means"]),
            contamination=float(payload["contamination"]),
            lo=np.asarray(payload["lo"], dtype=float),
            hi=np.asarray(payload["hi"], dtype=float),
            sha256_hex=sha256_hex,
        )


def serialize(model: ClassModel) -> bytes:
    buf = io.BytesIO()
    joblib.dump(model.to_payload(), buf, compress=3)
    return buf.getvalue()


def deserialize(blob: bytes, expected_sha256_hex: str) -> ClassModel:
    digest = hashlib.sha256(blob).hexdigest()
    if not expected_sha256_hex or digest != expected_sha256_hex.lower():
        raise ModelIntegrityError("model blob sha256 mismatch; refusing to deserialize")
    # digest verified above, before any unpickling
    payload = joblib.load(io.BytesIO(blob))  # nosec B301
    if not isinstance(payload, dict):
        raise ModelIntegrityError("model payload is not a mapping")
    return ClassModel.from_payload(payload, digest)


def fit_class_model(
    tenant_id: str,
    device_class: str,
    x: np.ndarray,
    devices: int,
    params: TrainingParams,
    seed: int,
    now: float | None = None,
) -> ClassModel:
    now = time.time() if now is None else now
    impute = np.nanmedian(np.where(np.isnan(x).all(axis=0), 0.0, x), axis=0)
    impute = np.where(np.isnan(impute), 0.0, impute)
    filled = np.where(np.isnan(x), impute, x)
    forest = IsolationForest(
        n_estimators=params.n_estimators,
        contamination=params.contamination,
        random_state=seed,
    )
    forest.fit(filled)
    scores = -forest.decision_function(filled)
    qs = np.quantile(scores, np.linspace(0.1, 0.9, 9))
    bins = [float(scores.min()) - 1.0, *[float(q) for q in qs], float(scores.max()) + 1.0]
    bins = sorted(set(bins))
    if len(scores) > 2000:
        kept = np.random.default_rng(seed).choice(scores, size=2000, replace=False)
    else:
        kept = scores
    means = {
        name: (float(np.nanmean(x[:, i])) if not np.isnan(x[:, i]).all() else 0.0)
        for i, name in enumerate(FEATURE_NAMES)
    }
    lo = np.quantile(filled, 0.001, axis=0)
    hi = np.quantile(filled, 0.999, axis=0)
    rng = np.random.default_rng(seed)
    check = filled[rng.choice(len(filled), size=min(64, len(filled)), replace=False)]
    return ClassModel(
        tenant_id=tenant_id,
        device_class=device_class,
        version=f"v{int(now * 1000)}",
        trained_at=now,
        samples=int(x.shape[0]),
        devices=devices,
        forest=forest,
        impute=impute,
        tau=max(1e-3, float(np.std(scores))),
        score_bins=bins,
        train_scores=[float(s) for s in kept],
        feature_means=means,
        contamination=params.contamination,
        lo=lo,
        hi=hi,
        fast=FastForest(forest, check),
    )


# --------------------------------------------------------------------------------------------
# Device baseline
# --------------------------------------------------------------------------------------------


def nanmedian_cols(arr: np.ndarray) -> np.ndarray:
    """Column medians ignoring NaN; all-NaN columns yield NaN (without a RuntimeWarning)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        return np.asarray(np.nanmedian(arr, axis=0), dtype=float)


def device_robust_z(history: Iterable[list[float]], x: Sequence[float]) -> dict[str, float]:
    """Robust z of each feature of ``x`` against the device's history (NaNs skipped)."""
    hist = np.asarray(list(history), dtype=float)
    out: dict[str, float] = {}
    if hist.size == 0:
        return out
    med = nanmedian_cols(hist) if not np.isnan(hist).all() else None
    if med is None:
        return out
    mad = nanmedian_cols(np.abs(hist - med))
    for i, name in enumerate(FEATURE_NAMES):
        v = x[i]
        if math.isnan(v) or math.isnan(med[i]):
            continue
        scale = max(MAD_TO_SIGMA * float(mad[i]) if not math.isnan(mad[i]) else 0.0, _FLOORS[i])
        out[name] = (v - float(med[i])) / scale
    return out


def combine(class_score: float, tau: float, device_z: float, z_threshold: float) -> float:
    c_n = 0.5 * (1.0 + math.tanh(class_score / tau))
    d_n = 0.5 * (1.0 + math.tanh((device_z - z_threshold) / z_threshold))
    return math.sqrt(c_n * d_n)


# --------------------------------------------------------------------------------------------
# Manager
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AlertPeriod:
    device_id: str
    start: float
    end: float


class ModelManager:
    def __init__(self, store: ModelStore, *, seed: int = 1337, z_threshold: float = 6.0) -> None:
        self._store = store
        self._seed = seed
        self.z_threshold = z_threshold
        self._models: dict[tuple[str, str], ClassModel] = {}

    def get(self, tenant_id: str, device_class: str) -> ClassModel | None:
        return self._models.get((tenant_id, device_class))

    def models(self) -> list[ClassModel]:
        return list(self._models.values())

    def install(self, model: ClassModel) -> None:
        self._models[(model.tenant_id, model.device_class)] = model

    # -- scoring ---------------------------------------------------------------------------
    def score(
        self,
        state: DeviceState,
        x: list[float],
        z_threshold: float | None = None,
        *,
        record: bool = True,
    ) -> RawScore | None:
        z_thr = self.z_threshold if z_threshold is None else z_threshold
        model = self.get(state.tenant_id, state.device_class)
        history = [f for _, f in list(state.features)[:-1]]
        zs = device_robust_z(history, x)
        device_z = max((abs(v) for v in zs.values()), default=0.0)
        top = dict(sorted(zs.items(), key=lambda kv: -abs(kv[1]))[:3])
        if model is None:
            return RawScore(
                class_score=-math.inf,
                device_z=device_z,
                top_features={k: round(v, 3) for k, v in top.items()},
                combined=0.0,
                trained_at=None,
            )
        deviating = {k for k, v in zs.items() if abs(v) >= z_thr}
        novel = [f for f in model.outside_envelope(x) if f in deviating]
        c = model.class_score(x, record=record)
        combined = combine(c, model.tau, device_z, z_thr)
        if record:
            MODEL_SCORE.observe(c + model.threshold)
            ANOMALY_SCORE.observe(combined)
        state.scores.append((state.last_ts or time.time(), round(combined, 6)))
        return RawScore(
            class_score=c,
            device_z=device_z,
            top_features={k: round(v, 3) for k, v in top.items()},
            combined=combined,
            trained_at=model.trained_at,
            novel_features=tuple(novel),
        )

    # -- training --------------------------------------------------------------------------
    def build_training_set(
        self,
        states: Iterable[DeviceState],
        tenant_id: str,
        device_class: str,
        periods: Sequence[AlertPeriod],
        quarantined: set[str],
        params: TrainingParams,
    ) -> tuple[np.ndarray, int, dict[str, int]]:
        rng = np.random.default_rng(self._seed)
        by_device: dict[str, list[AlertPeriod]] = {}
        for p in periods:
            by_device.setdefault(p.device_id, []).append(p)
        rows: list[list[float]] = []
        stats = {"devices_quarantined": 0, "samples_excluded_alerts": 0, "samples_capped": 0}
        devices = 0
        for st in states:
            if st.tenant_id != tenant_id or st.device_class != device_class:
                continue
            if st.quarantined or st.device_id in quarantined:
                stats["devices_quarantined"] += 1
                continue
            own = by_device.get(st.device_id, [])
            kept = [f for t, f in st.features if not any(p.start <= t <= p.end for p in own)]
            stats["samples_excluded_alerts"] += len(st.features) - len(kept)
            if not kept:
                continue
            if len(kept) > params.max_samples_per_device:
                idx = rng.choice(len(kept), size=params.max_samples_per_device, replace=False)
                stats["samples_capped"] += len(kept) - params.max_samples_per_device
                kept = [kept[i] for i in sorted(idx)]
            rows.extend(kept)
            devices += 1
        x = np.asarray(rows, dtype=float).reshape(-1, len(FEATURE_NAMES))
        return x, devices, stats

    def train(
        self,
        states: Iterable[DeviceState],
        tenant_id: str,
        device_class: str,
        periods: Sequence[AlertPeriod],
        quarantined: set[str],
        params: TrainingParams,
        now: float | None = None,
    ) -> tuple[ClassModel, bytes] | None:
        x, devices, stats = self.build_training_set(
            states, tenant_id, device_class, periods, quarantined, params
        )
        if x.shape[0] < params.min_train_samples or devices < params.min_train_devices:
            log.info(
                "training skipped (cold start)",
                tenant_id=tenant_id,
                device_class=device_class,
                samples=int(x.shape[0]),
                devices=devices,
            )
            MODEL_TRAININGS.labels(result="skipped").inc()
            return None
        model = fit_class_model(tenant_id, device_class, x, devices, params, self._seed, now)
        blob = serialize(model)
        model.sha256_hex = hashlib.sha256(blob).hexdigest()
        self._store.put(self.key_for(model), blob)
        self.install(model)
        MODEL_TRAININGS.labels(result="trained").inc()
        log.info(
            "model trained",
            tenant_id=tenant_id,
            device_class=device_class,
            samples=model.samples,
            devices=devices,
            version=model.version,
            **stats,
        )
        return model, blob

    @staticmethod
    def key_for(model: ClassModel | ModelMeta) -> str:
        cls = re.sub(r"[^a-z0-9-]", "_", model.device_class.lower()) or "unknown"
        return f"{model.tenant_id}/{cls}/{model.version}.joblib"

    def load(self, meta: ModelMeta) -> ClassModel:
        blob = self._store.get(self.key_for(meta))
        model = deserialize(blob, meta.sha256_hex)
        if model.tenant_id != meta.tenant_id or model.device_class != meta.device_class:
            raise ModelIntegrityError("model payload does not match its metadata")
        self.install(model)
        return model

    def meta_for(self, model: ClassModel) -> ModelMeta:
        return ModelMeta(
            tenant_id=model.tenant_id,
            device_class=model.device_class,
            version=model.version,
            sha256_hex=model.sha256_hex,
            trained_at=from_ts(model.trained_at),
            samples=model.samples,
            metadata={
                "devices": model.devices,
                "contamination": model.contamination,
                "feature_means": model.feature_means,
            },
        )

    def refresh_metrics(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        ages: dict[str, float] = {}
        drifts: dict[str, float] = {}
        thresholds: dict[str, float] = {}
        for m in self._models.values():
            ages[m.device_class] = max(ages.get(m.device_class, 0.0), now - m.trained_at)
            drifts[m.device_class] = max(drifts.get(m.device_class, 0.0), m.drift())
            thresholds[m.device_class] = max(thresholds.get(m.device_class, 0.0), m.threshold)
        for cls, age in ages.items():
            MODEL_AGE.labels(device_class=cls).set(age)
            MODEL_DRIFT.labels(device_class=cls).set(drifts[cls])
            MODEL_SCORE_THRESHOLD.labels(device_class=cls).set(thresholds[cls])
