"""Rule engine contract — the Phase 0 Protocol + value objects.

Pure data. No I/O, no DB. Implementations live alongside in this package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.config import Persona


@dataclass(frozen=True, slots=True)
class Fact:
    """A single observation produced by a tool parser.

    ``body`` is free-form (tool-specific) but MUST be JSON-serialisable.
    ``fingerprint`` is stable and unique per (scan, fact_type, body) —
    used for deduplication and drift diffs.
    """

    fact_type: str
    body: dict[str, Any]
    source_tool: str
    scan_id: str
    iteration: int
    fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Parsed YAML rule, ready for evaluation."""

    id: str
    version: int
    persona: tuple[Persona, ...]
    phase: str
    priority: int
    description: str
    when: dict[str, Any]
    then: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A rule that fired against a specific fact set."""

    rule: RuleDefinition
    triggering_fact: Fact
    bindings: dict[str, Any]


@runtime_checkable
class RuleEngine(Protocol):
    def load(self, rules: list[RuleDefinition]) -> None: ...

    def evaluate(
        self,
        facts: list[Fact],
        *,
        persona: Persona,
        executed_rule_ids: set[str],
    ) -> list[RuleMatch]: ...

    def get(self, rule_id: str) -> RuleDefinition | None: ...

    def all(self) -> list[RuleDefinition]: ...


class RuleValidationError(ValueError):
    """Raised when a rule YAML fails schema validation."""


__all__ = [
    "Fact",
    "RuleDefinition",
    "RuleEngine",
    "RuleMatch",
    "RuleValidationError",
]
