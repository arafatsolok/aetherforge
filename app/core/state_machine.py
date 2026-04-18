"""Scan state machine.

Tracks the lifecycle of a single autonomous loop run. States are explicit
and transitions are enumerated so invalid states cannot be reached.

Phase 0 defines the state enum + valid transitions. Phase 3 wires it up
to Temporal workflow state + Postgres persistence.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ScanState(enum.StrEnum):
    """Every valid state a scan can be in."""

    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ESCALATING = "escalating"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Allowed transitions — any edge not listed here is illegal.
_ALLOWED: dict[ScanState, frozenset[ScanState]] = {
    ScanState.PENDING:     frozenset({ScanState.STARTING, ScanState.CANCELLED}),
    ScanState.STARTING:    frozenset({ScanState.RUNNING, ScanState.FAILED}),
    ScanState.RUNNING:     frozenset(
        {ScanState.PAUSED, ScanState.ESCALATING, ScanState.STOPPING,
         ScanState.COMPLETED, ScanState.FAILED}
    ),
    ScanState.PAUSED:      frozenset({ScanState.RUNNING, ScanState.STOPPING}),
    ScanState.ESCALATING:  frozenset({ScanState.RUNNING, ScanState.FAILED}),
    ScanState.STOPPING:    frozenset({ScanState.COMPLETED, ScanState.CANCELLED, ScanState.FAILED}),
    ScanState.COMPLETED:   frozenset(),
    ScanState.FAILED:      frozenset(),
    ScanState.CANCELLED:   frozenset(),
}


class InvalidTransition(RuntimeError):
    def __init__(self, from_: ScanState, to: ScanState) -> None:
        super().__init__(f"illegal transition {from_.value} -> {to.value}")
        self.from_ = from_
        self.to = to


@dataclass(slots=True)
class StateMachine:
    """Deterministic in-memory FSM. Persistence is callers' responsibility."""

    state: ScanState = ScanState.PENDING

    def transition(self, to: ScanState) -> None:
        if to not in _ALLOWED[self.state]:
            raise InvalidTransition(self.state, to)
        self.state = to

    def is_terminal(self) -> bool:
        return self.state in {ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED}

    def can_transition_to(self, to: ScanState) -> bool:
        return to in _ALLOWED[self.state]


__all__ = ["InvalidTransition", "ScanState", "StateMachine"]
