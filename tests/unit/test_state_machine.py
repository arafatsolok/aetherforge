"""Scan state machine transition rules."""

from __future__ import annotations

import pytest

from app.core.state_machine import InvalidTransition, ScanState, StateMachine


@pytest.mark.unit
def test_happy_path() -> None:
    fsm = StateMachine()
    fsm.transition(ScanState.STARTING)
    fsm.transition(ScanState.RUNNING)
    fsm.transition(ScanState.STOPPING)
    fsm.transition(ScanState.COMPLETED)
    assert fsm.is_terminal()


@pytest.mark.unit
def test_illegal_transition_raises() -> None:
    fsm = StateMachine()
    with pytest.raises(InvalidTransition):
        fsm.transition(ScanState.COMPLETED)


@pytest.mark.unit
def test_terminal_is_sink() -> None:
    fsm = StateMachine(state=ScanState.COMPLETED)
    with pytest.raises(InvalidTransition):
        fsm.transition(ScanState.RUNNING)
