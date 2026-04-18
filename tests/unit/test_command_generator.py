"""Unit tests for the DeterministicCommandGenerator."""

from __future__ import annotations

import pytest

from app.config import Persona, get_settings
from app.core.command_generator import (
    CommandRejected,
    DeterministicCommandGenerator,
)
from app.core.persona_engine import PersonaEngine
from app.core.rule_engine import Fact, RuleDefinition, RuleMatch
from app.tools.registry_loader import bootstrap_registry


@pytest.fixture(scope="module")
def gen() -> DeterministicCommandGenerator:
    settings = get_settings()
    registry = bootstrap_registry(configs_dir=settings.configs_dir)
    return DeterministicCommandGenerator(
        registry=registry,
        persona_engine=PersonaEngine(),
        settings=settings,
        forbidden_cidrs_extra=(),
    )


def _match(
    *, tool: str, params: dict[str, object], persona: Persona = Persona.GRAY,
    phase: str = "recon.active", priority: int = 50,
) -> RuleMatch:
    rule = RuleDefinition(
        id=f"r.test.{tool}",
        version=1,
        persona=(persona,),
        phase=phase,
        priority=priority,
        description="",
        when={"fact_type": "host_alive"},
        then={"action": "execute_tool", "tool": tool, "params": params},
        metadata={"enabled": True},
    )
    fact = Fact(
        fact_type="host_alive", body={"host": "10.77.10.5"},
        source_tool="t", scan_id="s1", iteration=0, fingerprint="fp",
    )
    return RuleMatch(rule=rule, triggering_fact=fact, bindings={"fact": fact.body})


@pytest.mark.unit
class TestGenerator:
    def test_rejects_persona_mismatch(self, gen: DeterministicCommandGenerator) -> None:
        m = _match(tool="nmap", params={"target": "10.77.10.5"}, persona=Persona.BLACK)
        with pytest.raises(CommandRejected, match="persona"):
            gen.generate(m, persona=Persona.WHITE,
                         target_scope_cidrs=["10.77.0.0/16"], scan_id="s1")

    def test_rejects_unknown_tool(self, gen: DeterministicCommandGenerator) -> None:
        m = _match(tool="ghosttool", params={"target": "10.77.10.5"})
        with pytest.raises(CommandRejected, match="unknown tool"):
            gen.generate(m, persona=Persona.GRAY,
                         target_scope_cidrs=["10.77.0.0/16"], scan_id="s1")

    def test_rejects_target_out_of_scope(self, gen: DeterministicCommandGenerator) -> None:
        m = _match(tool="nmap", params={"target": "203.0.113.5"})
        with pytest.raises(CommandRejected, match="out of scope"):
            gen.generate(m, persona=Persona.GRAY,
                         target_scope_cidrs=["10.77.0.0/16"], scan_id="s1")

    def test_rejects_forbidden_cidr(self) -> None:
        # Build a fresh gen with an extra forbidden CIDR; isolates this
        # test from the global FORBIDDEN_CIDRS env var.
        s = get_settings()
        gen2 = DeterministicCommandGenerator(
            registry=bootstrap_registry(configs_dir=s.configs_dir),
            persona_engine=PersonaEngine(),
            settings=s,
            forbidden_cidrs_extra=("8.0.0.0/8",),
        )
        m = _match(tool="nmap", params={"target": "8.8.8.8"})
        with pytest.raises(CommandRejected, match="forbidden CIDR"):
            gen2.generate(m, persona=Persona.GRAY,
                          target_scope_cidrs=["0.0.0.0/0"], scan_id="s1")

    def test_happy_path_argv(self, gen: DeterministicCommandGenerator) -> None:
        m = _match(
            tool="nmap",
            params={"target": "10.77.10.5", "ports": [22, 80, 443],
                    "flags": ["-sV", "-T3"]},
        )
        inv = gen.generate(m, persona=Persona.GRAY,
                           target_scope_cidrs=["10.77.0.0/16"], scan_id="s1")
        assert inv.tool_name == "nmap"
        assert inv.image == "aetherforge/nmap:latest"
        assert "10.77.10.5" in inv.argv
        assert "-p" in inv.argv
        assert "22,80,443" in inv.argv
        assert inv.persona == Persona.GRAY

    def test_unsafe_argv_token_rejected(
        self, gen: DeterministicCommandGenerator
    ) -> None:
        m = _match(
            tool="nmap",
            params={"target": "10.77.10.5", "flags": ["$(curl evil)"]},
        )
        with pytest.raises(CommandRejected, match="unsafe argv token"):
            gen.generate(m, persona=Persona.GRAY,
                         target_scope_cidrs=["10.77.0.0/16"], scan_id="s1")

    def test_resolves_fact_refs(self, gen: DeterministicCommandGenerator) -> None:
        rule = RuleDefinition(
            id="r.test.deepscan",
            version=1,
            persona=(Persona.GRAY,),
            phase="enumeration",
            priority=50,
            description="",
            when={"fact_type": "port_open"},
            then={"action": "execute_tool", "tool": "nmap",
                  "params": {"target": "$fact.host", "ports": ["$fact.port"]}},
            metadata={"enabled": True},
        )
        fact = Fact(
            fact_type="port_open",
            body={"host": "10.77.10.5", "port": 8443},
            source_tool="t", scan_id="s1", iteration=0, fingerprint="fp",
        )
        match = RuleMatch(rule=rule, triggering_fact=fact,
                          bindings={"fact": fact.body})

        inv = gen.generate(match, persona=Persona.GRAY,
                           target_scope_cidrs=["10.77.0.0/16"], scan_id="s1")
        assert "10.77.10.5" in inv.argv
        assert "8443" in inv.argv
