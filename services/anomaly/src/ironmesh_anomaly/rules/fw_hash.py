"""``fw_hash_mismatch``: the running firmware hash is not one the fleet operator shipped.

Checks, in order (all reasons found are reported in one detection):

1. ``unknown_hash`` - telemetry ``fw_hash`` is not in the OTA service's known image hashes for the
   device's product (``GET /internal/v1/firmware/known-hashes?product=``). Skipped when the list is
   unavailable (fail-open on this check only; the other checks still run).
2. ``differs_from_installed`` - the hash differs from the one the device last reported after a
   successful OTA install (``OtaStatus`` state ``success``).
3. ``unexpected_change`` - the hash changed between two telemetry samples without an intervening
   successful install (catches re-flashing an *older, still-known* image).
"""

from __future__ import annotations

from typing import ClassVar

from ironmesh_anomaly.models import Detection, DeviceEvent, RuleName, Severity, TelemetryEvent
from ironmesh_anomaly.state import DeviceState, Observation

from .base import Rule, RuleContext, RuleParams


class FwHashParams(RuleParams):
    check_known_hashes: bool = True
    check_installed: bool = True
    alert_on_unexpected_change: bool = True


class FwHashMismatchRule(Rule[FwHashParams]):
    name: ClassVar[RuleName] = RuleName.FW_HASH_MISMATCH
    description: ClassVar[str] = (
        "Telemetry fw_hash not among the OTA service's known hashes for the product, different "
        "from the last successfully installed image, or changed without an OTA install."
    )
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    params_model: ClassVar[type[RuleParams]] = FwHashParams

    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        if not isinstance(event, TelemetryEvent):
            return None
        p = self.params
        current = event.fw_hash_hex
        reasons: list[str] = []
        if (
            p.check_known_hashes
            and ctx.known_hashes is not None
            and current not in ctx.known_hashes
        ):
            reasons.append("unknown_hash")
        if (
            p.check_installed
            and state.fw_last_installed is not None
            and current != state.fw_last_installed
        ):
            reasons.append("differs_from_installed")
        if (
            p.alert_on_unexpected_change
            and obs.prev_fw_seen is not None
            and obs.prev_fw_seen != current
            and current != state.fw_last_installed
        ):
            reasons.append("unexpected_change")
        if not reasons:
            return None
        return self.detection(
            event,
            score=min(1.0, len(reasons) / 2),
            explanation=(
                f"Firmware hash {current[:16]}... ({event.fw_version}) failed integrity checks: "
                + ", ".join(reasons)
            ),
            features={
                "reasons": reasons,
                "fw_hash_hex": current,
                "fw_version": event.fw_version,
                "previous_hash_hex": obs.prev_fw_seen,
                "installed_hash_hex": state.fw_last_installed,
                "product": ctx.device_class,
                "known_hashes_available": ctx.known_hashes is not None,
            },
        )
