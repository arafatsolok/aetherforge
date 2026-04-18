"""Unit tests for the black-persona replica_only safety gate."""

from __future__ import annotations

import pytest

from app.config import Persona
from app.models.target import Target


def _target(*, replica_only: bool, allowed: list[str]) -> Target:
    return Target(
        slug="x", description="", owner="",
        cidrs=["10.77.0.0/24"], domains=[],
        allowed_personas=allowed, tags=[], notes="", meta={},
        active=True, replica_only=replica_only,
    )


@pytest.mark.unit
class TestReplicaOnlyGate:
    def test_white_always_allowed_when_listed(self) -> None:
        t = _target(replica_only=False, allowed=["white"])
        assert t.accepts_persona(Persona.WHITE) is True

    def test_black_refused_without_replica_only(self) -> None:
        t = _target(replica_only=False, allowed=["black"])
        assert t.accepts_persona(Persona.BLACK) is False

    def test_black_allowed_only_with_replica_only(self) -> None:
        t = _target(replica_only=True, allowed=["black"])
        assert t.accepts_persona(Persona.BLACK) is True

    def test_replica_only_does_not_unlock_unlisted_personas(self) -> None:
        t = _target(replica_only=True, allowed=["white"])
        assert t.accepts_persona(Persona.GRAY) is False
        assert t.accepts_persona(Persona.BLACK) is False

    def test_gray_unaffected_by_replica_flag(self) -> None:
        for flag in (True, False):
            t = _target(replica_only=flag, allowed=["gray"])
            assert t.accepts_persona(Persona.GRAY) is True
