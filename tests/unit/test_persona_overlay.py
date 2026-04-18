"""Unit tests for the persona YAML overlay loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.config import Persona
from app.core.persona_engine import PersonaEngine, load_persona_overlay


@pytest.mark.unit
class TestOverlay:
    def test_missing_file_returns_baseline(self, tmp_path: Path) -> None:
        caps = load_persona_overlay(tmp_path / "does-not-exist.yaml")
        assert caps[Persona.WHITE].max_rps == 2
        assert "exfil_simulation" in caps[Persona.BLACK].allowed_phases

    def test_yaml_can_tighten_but_not_loosen(self, tmp_path: Path) -> None:
        """Overlay may only restrict — it must never grant beyond baseline."""
        path = tmp_path / "personas.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "personas": {
                        # White tries to enable exploit — must be ignored (AND with baseline).
                        "white": {
                            "capabilities": {"exploit": True},
                            "rate_limit_rps": 999,
                            "allowed_phases": ["recon.passive", "exploit.full"],
                        },
                    }
                }
            )
        )
        caps = load_persona_overlay(path)
        assert caps[Persona.WHITE].can_exploit is False
        assert caps[Persona.WHITE].max_rps == 2  # min(999, baseline=2)
        # exploit.full isn't in the white baseline -> intersection drops it.
        assert "exploit.full" not in caps[Persona.WHITE].allowed_phases

    def test_yaml_can_reduce_rate(self, tmp_path: Path) -> None:
        path = tmp_path / "personas.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "personas": {"gray": {"rate_limit_rps": 5}},
                }
            )
        )
        caps = load_persona_overlay(path)
        assert caps[Persona.GRAY].max_rps == 5


@pytest.mark.unit
class TestEngine:
    def test_require_forbidden_raises(self) -> None:
        eng = PersonaEngine()
        with pytest.raises(PermissionError):
            eng.require(Persona.WHITE, phase="exploit.full")

    def test_require_allowed_noop(self) -> None:
        eng = PersonaEngine()
        eng.require(Persona.GRAY, phase="vuln_scan")

    def test_allows_rule_personas_strict(self) -> None:
        eng = PersonaEngine()
        # Active=white, rule=[gray,black] -> no match.
        assert eng.allows_rule_personas(Persona.WHITE, [Persona.GRAY, Persona.BLACK]) is False
        # Active=black, rule=[black] -> match.
        assert eng.allows_rule_personas(Persona.BLACK, [Persona.BLACK]) is True
