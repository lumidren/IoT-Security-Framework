"""Feature engineering for the Isolation Forest and the per-device robust baselines.

One feature vector is produced per accepted telemetry sample from the sample itself and a rolling
window of the device's recent history (rates are computed from counter deltas between consecutive
samples; ``msg_rate`` from the inter-arrival times inside a 5-minute window). Byte rates and free
heap are ``log1p``-compressed so that the scale of a device does not dominate the distance.
"""

from __future__ import annotations

import math
from typing import Final

FEATURE_NAMES: Final[tuple[str, ...]] = (
    "cpu_pct",
    "mem_pct",
    "temp_c",
    "net_rx_rate",
    "net_tx_rate",
    "proc_count",
    "auth_failures_delta",
    "rssi",
    "free_heap",
    "msg_rate",
)

# Minimum robust scale per feature (in the feature's own unit) so that a feature that has been
# perfectly constant in a device's history does not turn every tiny change into an infinite z.
SCALE_FLOORS: Final[dict[str, float]] = {
    "cpu_pct": 2.0,
    "mem_pct": 2.0,
    "temp_c": 1.0,
    "net_rx_rate": 0.25,
    "net_tx_rate": 0.25,
    "proc_count": 2.0,
    "auth_failures_delta": 1.0,
    "rssi": 3.0,
    "free_heap": 0.1,
    "msg_rate": 0.25,
}

MSG_RATE_WINDOW_S: Final = 300.0
NAN: Final = float("nan")


def counter_delta(current: int, previous: int | None) -> int:
    """Delta of a monotonically increasing counter; a decrease means the counter was reset."""
    if previous is None:
        return 0
    if current >= previous:
        return current - previous
    return current


def log_rate(delta: int, dt: float) -> float:
    if dt <= 0:
        return 0.0
    return math.log1p(max(0.0, delta / dt))


def msg_rate_per_min(times: list[float]) -> float:
    """Messages per minute from inter-arrival times (``(n-1) / (t_n - t_1)``)."""
    if len(times) < 2:
        return 0.0
    span = times[-1] - times[0]
    if span <= 0:
        return 0.0
    return 60.0 * (len(times) - 1) / span


def opt(value: float | int | None) -> float:
    return NAN if value is None else float(value)
