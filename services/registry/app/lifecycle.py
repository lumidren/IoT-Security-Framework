"""Device lifecycle state machine (design contract §7).

``manufactured -> provisioned -> active -> quarantined -> active | decommissioned``.
``decommissioned`` is terminal. Quarantine is also allowed before activation (a device reported
stolen at the factory must not be able to enroll), and any non-terminal state may be
decommissioned. Every transition is audited by the caller.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from .problems import ProblemError


class DeviceState(StrEnum):
    MANUFACTURED = "manufactured"
    PROVISIONED = "provisioned"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DECOMMISSIONED = "decommissioned"


S = DeviceState

TRANSITIONS: Final[dict[DeviceState, frozenset[DeviceState]]] = {
    S.MANUFACTURED: frozenset({S.PROVISIONED, S.QUARANTINED, S.DECOMMISSIONED}),
    S.PROVISIONED: frozenset({S.ACTIVE, S.QUARANTINED, S.DECOMMISSIONED}),
    S.ACTIVE: frozenset({S.QUARANTINED, S.DECOMMISSIONED}),
    S.QUARANTINED: frozenset({S.ACTIVE, S.DECOMMISSIONED}),
    S.DECOMMISSIONED: frozenset(),
}

TERMINAL: Final = frozenset(s for s, targets in TRANSITIONS.items() if not targets)

# States in which a device may hold a broker session / send messages that the registry accepts.
OPERATIONAL: Final = frozenset({S.PROVISIONED, S.ACTIVE})
# States in which the PKI may (re-)enroll a device (contract §3 step 5).
ENROLLABLE: Final = frozenset({S.MANUFACTURED, S.PROVISIONED, S.ACTIVE})


class TransitionError(ProblemError):
    def __init__(self, current: DeviceState, target: DeviceState) -> None:
        super().__init__(
            409,
            f"cannot transition device from {current.value} to {target.value}",
            title="Conflict",
            type_="https://ironmesh.dev/problems/invalid-transition",
        )
        self.current = current
        self.target = target


def can_transition(current: DeviceState, target: DeviceState) -> bool:
    return target in TRANSITIONS[current]


def check_transition(current: DeviceState, target: DeviceState) -> None:
    if not can_transition(current, target):
        raise TransitionError(current, target)


def timestamp_field(target: DeviceState) -> str | None:
    """Name of the ``DeviceRecord`` attribute stamped when entering ``target``."""
    return {
        S.PROVISIONED: "provisioned_at",
        S.ACTIVE: "activated_at",
        S.QUARANTINED: "quarantined_at",
        S.DECOMMISSIONED: "decommissioned_at",
    }.get(target)
