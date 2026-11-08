"""Downlink ``seq`` allocation for tenant-signed envelopes.

Devices keep one replay counter per tenant key (WIRE_FORMAT §3.7), and both the registry
(commands, shadow, config) and this service (OtaNotify) sign with that key. A per-service
counter would therefore collide, so the sequence is derived from wall-clock **microseconds**,
forced strictly monotonic within the process. Two services sharing a key stay strictly
increasing as long as their clocks are NTP-synchronised and they do not sign within the same
microsecond, which the registry's own allocator must also respect (same scheme).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class MicrosecondSequencer:
    def __init__(self, clock: Callable[[], int] = time.time_ns) -> None:
        self._clock = clock
        self._last = 0
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            value = max(self._clock() // 1000, self._last + 1)
            self._last = value
            return value
