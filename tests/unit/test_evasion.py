"""Unit tests for the per-persona evasion profiles."""

from __future__ import annotations

import pytest

from app.config import Persona
from app.core.evasion import evasion_for


@pytest.mark.unit
class TestEvasion:
    def test_white_has_no_evasion(self) -> None:
        p = evasion_for(Persona.WHITE, rule_id="r.x")
        assert p.nmap_extra == ()
        assert p.nuclei_extra == ()

    def test_gray_keeps_nmap_default_but_rotates_ua(self) -> None:
        p = evasion_for(Persona.GRAY, rule_id="r.x")
        assert p.nmap_extra == ()                   # operators want it fast
        assert any(s.startswith("User-Agent:") for s in p.nuclei_extra)
        assert any(s.startswith("User-Agent:") for s in p.httpx_extra)

    def test_black_uses_decoys_and_slow_timing(self) -> None:
        p = evasion_for(Persona.BLACK, rule_id="r.x")
        assert "-T1" in p.nmap_extra
        assert "-D" in p.nmap_extra
        # Decoy list always ends with "ME"
        decoy_idx = p.nmap_extra.index("-D")
        decoys = p.nmap_extra[decoy_idx + 1].split(",")
        assert decoys[-1] == "ME"

    def test_evasion_is_deterministic_per_rule_id(self) -> None:
        a1 = evasion_for(Persona.GRAY, rule_id="r.alpha")
        a2 = evasion_for(Persona.GRAY, rule_id="r.alpha")
        b1 = evasion_for(Persona.GRAY, rule_id="r.beta")
        assert a1 == a2
        assert a1 != b1   # different rules → likely different UAs (deterministic by hash)
