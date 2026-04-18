"""DeterministicRuleEngine — concrete implementation of the Phase 0 Protocol.

``evaluate(facts, persona, executed_rule_ids)`` is a pure function. Given
identical inputs, it returns an identical (and totally-ordered) output.
No logging, no I/O, no clock reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Persona
from app.core.rule_engine.contract import (
    Fact,
    RuleDefinition,
    RuleMatch,
)
from app.core.rule_engine.dsl import evaluate_when


@dataclass(slots=True)
class DeterministicRuleEngine:
    """In-memory rule engine.

    Load once at boot via ``load()`` (typically from the DB, populated by
    the YAML loader). ``evaluate`` is thread-safe w.r.t. concurrent
    readers — it never mutates loaded state.
    """

    _by_id: dict[str, RuleDefinition] = field(default_factory=dict)

    # -------------------------------------------------------------------
    # Population
    # -------------------------------------------------------------------
    def load(self, rules: list[RuleDefinition]) -> None:
        """Replace the in-memory rule set atomically."""
        self._by_id = {r.id: r for r in rules}

    def add(self, rule: RuleDefinition) -> None:
        """Incremental add — replaces on id collision."""
        self._by_id[rule.id] = rule

    # -------------------------------------------------------------------
    # Read accessors
    # -------------------------------------------------------------------
    def get(self, rule_id: str) -> RuleDefinition | None:
        return self._by_id.get(rule_id)

    def all(self) -> list[RuleDefinition]:
        return sorted(self._by_id.values(), key=lambda r: (r.priority * -1, r.id))

    def count(self) -> int:
        return len(self._by_id)

    # -------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------
    def evaluate(
        self,
        facts: list[Fact],
        *,
        persona: Persona,
        executed_rule_ids: set[str],
    ) -> list[RuleMatch]:
        """Return a priority-sorted, deterministic list of rule matches.

        Rules are filtered by:
          1. ``enabled`` (from metadata)
          2. persona — ``rule.persona`` must include the active one
          3. not already fired in this iteration (``executed_rule_ids``)

        Among the survivors, DSL evaluation produces zero-or-more
        ``RuleMatch`` per rule. Order:
          1. priority DESC
          2. rule.id ASC
          3. triggering_fact.fingerprint ASC (stable tiebreak)
        """
        out: list[RuleMatch] = []

        for rule in self._by_id.values():
            if not rule.metadata.get("enabled", True):
                continue
            if rule.id in executed_rule_ids:
                continue
            if persona not in rule.persona:
                continue

            for pred_match in evaluate_when(rule.when, facts):
                triggering = pred_match.triggering_fact
                if triggering is None:
                    # `not_fact`-only match — synthesize a sentinel fact so
                    # downstream consumers always have one.
                    triggering = _SENTINEL_FACT
                out.append(
                    RuleMatch(
                        rule=rule,
                        triggering_fact=triggering,
                        bindings=pred_match.bindings,
                    )
                )

        out.sort(
            key=lambda m: (
                -m.rule.priority,
                m.rule.id,
                m.triggering_fact.fingerprint,
            )
        )
        return out


# Shared sentinel — never mutated, never persisted. Flags `not_fact`-only matches.
_SENTINEL_FACT = Fact(
    fact_type="__none__",
    body={},
    source_tool="rule_engine",
    scan_id="",
    iteration=0,
    fingerprint="",
)


__all__ = ["DeterministicRuleEngine"]
