"""Unit tests for the DeterministicRuleEngine."""

from __future__ import annotations

import pytest

from app.config import Persona
from app.core.rule_engine import (
    DeterministicRuleEngine,
    Fact,
    RuleDefinition,
)


def _rule(
    rid: str,
    *,
    personas: list[Persona],
    priority: int = 50,
    when: dict[str, object] | None = None,
    enabled: bool = True,
    phase: str = "recon.passive",
) -> RuleDefinition:
    return RuleDefinition(
        id=rid,
        version=1,
        persona=tuple(personas),
        phase=phase,
        priority=priority,
        description="",
        when=when or {"fact_type": "host_alive"},
        then={"action": "noop"},
        metadata={"enabled": enabled},
    )


def _fact(t: str, body: dict[str, object], fp: str = "fp") -> Fact:
    return Fact(fact_type=t, body=body, source_tool="t", scan_id="s", iteration=0, fingerprint=fp)


@pytest.mark.unit
class TestEvaluate:
    def test_empty_ruleset_produces_nothing(self) -> None:
        engine = DeterministicRuleEngine()
        engine.load([])
        assert engine.evaluate([_fact("host_alive", {})], persona=Persona.GRAY, executed_rule_ids=set()) == []

    def test_persona_filter_rejects_too_low(self) -> None:
        engine = DeterministicRuleEngine()
        engine.load([_rule("r.black", personas=[Persona.BLACK])])
        assert engine.evaluate(
            [_fact("host_alive", {})], persona=Persona.WHITE, executed_rule_ids=set()
        ) == []

    def test_executed_rule_ids_skipped(self) -> None:
        engine = DeterministicRuleEngine()
        engine.load([_rule("r.one", personas=[Persona.WHITE])])
        assert engine.evaluate(
            [_fact("host_alive", {})],
            persona=Persona.WHITE,
            executed_rule_ids={"r.one"},
        ) == []

    def test_disabled_rule_skipped(self) -> None:
        engine = DeterministicRuleEngine()
        engine.load([_rule("r.off", personas=[Persona.WHITE], enabled=False)])
        assert engine.evaluate(
            [_fact("host_alive", {})], persona=Persona.WHITE, executed_rule_ids=set()
        ) == []

    def test_priority_sorted_descending(self) -> None:
        engine = DeterministicRuleEngine()
        engine.load([
            _rule("r.low",  personas=[Persona.WHITE], priority=10),
            _rule("r.high", personas=[Persona.WHITE], priority=90),
            _rule("r.mid",  personas=[Persona.WHITE], priority=50),
        ])
        matches = engine.evaluate(
            [_fact("host_alive", {})],
            persona=Persona.WHITE,
            executed_rule_ids=set(),
        )
        assert [m.rule.id for m in matches] == ["r.high", "r.mid", "r.low"]

    def test_deterministic_across_runs(self) -> None:
        """Same input → same output, exactly."""
        engine = DeterministicRuleEngine()
        engine.load([
            _rule("r.a", personas=[Persona.WHITE], priority=50),
            _rule("r.b", personas=[Persona.WHITE], priority=50),  # tied priority
        ])
        facts = [
            _fact("host_alive", {"host": "x"}, fp="fp-x"),
            _fact("host_alive", {"host": "y"}, fp="fp-y"),
        ]
        a = engine.evaluate(facts, persona=Persona.WHITE, executed_rule_ids=set())
        b = engine.evaluate(facts, persona=Persona.WHITE, executed_rule_ids=set())

        assert [(m.rule.id, m.triggering_fact.fingerprint) for m in a] == \
               [(m.rule.id, m.triggering_fact.fingerprint) for m in b]

    def test_all_helpers(self) -> None:
        engine = DeterministicRuleEngine()
        engine.load([_rule("r.a", personas=[Persona.WHITE]), _rule("r.b", personas=[Persona.WHITE])])
        assert engine.count() == 2
        assert engine.get("r.a") is not None
        assert engine.get("r.missing") is None
        all_rules = engine.all()
        assert [r.id for r in all_rules] == ["r.a", "r.b"]
