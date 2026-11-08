"""Robust statistics used by the rules and the per-device baselines.

All functions are pure and documented in README "Detection math".
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Final

import numpy as np

MAD_TO_SIGMA: Final = 1.4826
"""Consistency constant: ``1.4826 * MAD`` estimates the standard deviation for Gaussian data."""


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median of empty sequence")
    return float(np.median(np.asarray(values, dtype=float)))


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation ``median(|x - median(x)|)`` (unscaled)."""
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        raise ValueError("MAD of empty sequence")
    return float(np.median(np.abs(arr - np.median(arr))))


def robust_cv(values: Sequence[float]) -> float:
    """Robust coefficient of variation ``1.4826 * MAD / median`` (``inf`` if median <= 0)."""
    med = median(values)
    if med <= 0:
        return math.inf
    return MAD_TO_SIGMA * mad(values) / med


def robust_z(value: float, center: float, scale_mad: float, floor: float) -> float:
    """``(value - center) / max(1.4826 * MAD, floor)``."""
    scale = max(MAD_TO_SIGMA * scale_mad, floor)
    return (value - center) / scale


def autocorrelation(series: Sequence[float], max_lag: int) -> list[float]:
    """Sample autocorrelation ``r(k)`` for ``k = 0..max_lag`` (``r(0) = 1``).

    The series is centred on its **median** (robust to the very bursts we are looking for) and
    normalised by the lag-0 autocovariance. A constant series yields zeros for k >= 1.
    """
    arr = np.asarray(series, dtype=float)
    n = arr.size
    if n == 0:
        return []
    centred = arr - np.median(arr)
    denom = float(np.dot(centred, centred))
    out = [1.0]
    for k in range(1, min(max_lag, n - 1) + 1):
        if denom == 0.0:
            out.append(0.0)
            continue
        out.append(float(np.dot(centred[:-k], centred[k:]) / denom))
    return out


def acf_peak(series: Sequence[float], min_lag: int, max_lag: int) -> tuple[int, float]:
    """Lag in ``[min_lag, max_lag]`` with the highest autocorrelation, and its value."""
    acf = autocorrelation(series, max_lag)
    best_lag, best = 0, 0.0
    for lag in range(min_lag, len(acf)):
        if acf[lag] > best:
            best_lag, best = lag, acf[lag]
    return best_lag, best


def psi(expected: Sequence[float], actual: Sequence[float], bins: Sequence[float]) -> float:
    """Population stability index between two samples over fixed bin edges.

    ``PSI = sum_i (a_i - e_i) * ln(a_i / e_i)`` with proportions floored at 1e-4. Rule of thumb:
    < 0.1 stable, 0.1-0.25 moderate drift, > 0.25 significant drift.
    """
    if not expected or not actual:
        return 0.0
    edges = np.asarray(bins, dtype=float)
    e_counts, _ = np.histogram(np.clip(expected, edges[0], edges[-1]), bins=edges)
    a_counts, _ = np.histogram(np.clip(actual, edges[0], edges[-1]), bins=edges)
    e = np.maximum(e_counts / max(1, e_counts.sum()), 1e-4)
    a = np.maximum(a_counts / max(1, a_counts.sum()), 1e-4)
    return float(np.sum((a - e) * np.log(a / e)))
