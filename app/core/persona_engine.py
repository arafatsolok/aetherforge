"""Persona engine — enforces capability boundaries at runtime.

Baseline capabilities live in code (safe fallback). Phase 1 adds a YAML
overlay loaded from ``configs/personas.yaml`` so operators can tighten
(never loosen above the baseline) without redeploying.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import yaml

from app.config import Persona


@dataclass(frozen=True, slots=True)
class PersonaCapabilities:
    persona: Persona
    can_passive_recon: bool
    can_active_recon: bool
    can_vuln_scan: bool
    can_exploit: bool
    can_post_exploit: bool
    can_persistence: bool
    can_exfil_simulation: bool
    max_rps: int
    allowed_phases: frozenset[str]
    description: str


_BASELINE: dict[Persona, PersonaCapabilities] = {
    Persona.WHITE: PersonaCapabilities(
        persona=Persona.WHITE,
        can_passive_recon=True,
        can_active_recon=False,
        can_vuln_scan=False,
        can_exploit=False,
        can_post_exploit=False,
        can_persistence=False,
        can_exfil_simulation=False,
        max_rps=2,
        allowed_phases=frozenset({"recon.passive"}),
        description="Passive recon + non-destructive observation only.",
    ),
    Persona.GRAY: PersonaCapabilities(
        persona=Persona.GRAY,
        can_passive_recon=True,
        can_active_recon=True,
        can_vuln_scan=True,
        can_exploit=True,
        can_post_exploit=False,
        can_persistence=False,
        can_exfil_simulation=False,
        max_rps=20,
        allowed_phases=frozenset(
            {"recon.passive", "recon.active", "enumeration", "vuln_scan", "exploit.safe"}
        ),
        description="Active scanning + safe limited exploitation.",
    ),
    Persona.BLACK: PersonaCapabilities(
        persona=Persona.BLACK,
        can_passive_recon=True,
        can_active_recon=True,
        can_vuln_scan=True,
        can_exploit=True,
        can_post_exploit=True,
        can_persistence=True,
        can_exfil_simulation=True,
        max_rps=100,
        allowed_phases=frozenset(
            {
                "recon.passive", "recon.active", "enumeration", "vuln_scan",
                "exploit.safe", "exploit.full", "post_exploit",
                "persistence", "pivoting", "exfil_simulation",
            }
        ),
        description="Full kill-chain (replica only).",
    ),
}


# ---------------------------------------------------------------------------
# YAML overlay
# ---------------------------------------------------------------------------
def load_persona_overlay(yaml_path: Path) -> dict[Persona, PersonaCapabilities]:
    """Merge ``configs/personas.yaml`` over the hardcoded baseline.

    The overlay can only RESTRICT — it cannot grant a capability the
    baseline forbids, and it cannot raise a rate limit above the
    baseline max. (This is intentional: defence-in-depth against a
    compromised configs file.)
    """
    if not yaml_path.exists():
        return dict(_BASELINE)

    with yaml_path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}

    overlay = doc.get("personas") or {}
    merged: dict[Persona, PersonaCapabilities] = {}

    for persona, baseline in _BASELINE.items():
        cfg: dict[str, Any] = overlay.get(persona.value, {}) or {}
        caps_cfg: dict[str, bool] = cfg.get("capabilities") or {}

        # Rate limit: take min(baseline, yaml). Never exceed baseline.
        rps = int(cfg.get("rate_limit_rps", baseline.max_rps))
        rps = min(rps, baseline.max_rps)

        # Allowed phases: intersect with baseline (yaml can't add phases).
        yaml_phases = set(cfg.get("allowed_phases") or baseline.allowed_phases)
        phases = frozenset(yaml_phases) & baseline.allowed_phases

        # Bind ``caps_cfg`` explicitly so the closure can't accidentally
        # capture a later iteration's value (caught by ruff B023).
        def _and(field_: str, default: bool, _caps: dict[str, bool] = caps_cfg) -> bool:
            return bool(_caps.get(field_, default)) and default

        merged[persona] = PersonaCapabilities(
            persona=persona,
            can_passive_recon=_and("passive_recon",    baseline.can_passive_recon),
            can_active_recon= _and("active_recon",     baseline.can_active_recon),
            can_vuln_scan=    _and("vuln_scan",        baseline.can_vuln_scan),
            can_exploit=      _and("exploit",          baseline.can_exploit),
            can_post_exploit= _and("post_exploit",     baseline.can_post_exploit),
            can_persistence=  _and("persistence",      baseline.can_persistence),
            can_exfil_simulation=_and("exfil_simulation", baseline.can_exfil_simulation),
            max_rps=rps,
            allowed_phases=phases,
            description=cfg.get("description", baseline.description) or baseline.description,
        )
    return merged


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class PersonaEngine:
    _capabilities: dict[Persona, PersonaCapabilities] = field(
        default_factory=lambda: dict(_BASELINE)
    )

    BLACK_ONLY_PHASES: ClassVar[frozenset[str]] = frozenset(
        {"post_exploit", "persistence", "pivoting", "exfil_simulation"}
    )

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> PersonaEngine:
        return cls(_capabilities=load_persona_overlay(yaml_path))

    def get(self, persona: Persona) -> PersonaCapabilities:
        return self._capabilities[persona]

    def allows_phase(self, persona: Persona, phase: str) -> bool:
        return phase in self._capabilities[persona].allowed_phases

    def allows_rule_personas(self, active: Persona, rule_personas: list[Persona]) -> bool:
        return any(active == p for p in rule_personas)

    def rate_limit(self, persona: Persona) -> int:
        return self._capabilities[persona].max_rps

    def require(self, persona: Persona, *, phase: str) -> None:
        if not self.allows_phase(persona, phase):
            raise PersonaForbidden(persona, phase)


class PersonaForbidden(PermissionError):
    def __init__(self, persona: Persona, phase: str) -> None:
        super().__init__(f"persona {persona.value!r} is not permitted to run phase {phase!r}")
        self.persona = persona
        self.phase = phase


__all__ = [
    "PersonaCapabilities",
    "PersonaEngine",
    "PersonaForbidden",
    "load_persona_overlay",
]
