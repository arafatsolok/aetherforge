"""Deterministic rule engine — the only decision-maker in the platform.

Public surface:
  * Contract types (Phase 0): ``Fact``, ``RuleDefinition``, ``RuleMatch``,
    ``RuleEngine`` Protocol, ``RuleValidationError``
  * Concrete engine:           ``DeterministicRuleEngine``
  * DSL value objects:         ``PredicateMatch``, ``EvalContext``, ``DslError``
  * Loader / validator:        ``load_rules_from_dir``, ``parse_rule_document``,
                               ``validate_rule_payload``, ``RULE_JSON_SCHEMA``
"""

from __future__ import annotations

from app.core.rule_engine.contract import (
    Fact,
    RuleDefinition,
    RuleEngine,
    RuleMatch,
    RuleValidationError,
)
from app.core.rule_engine.dsl import (
    DslError,
    EvalContext,
    PredicateMatch,
    evaluate_when,
)
from app.core.rule_engine.engine import DeterministicRuleEngine
from app.core.rule_engine.loader import (
    LoadedRule,
    load_rules_from_dir,
    parse_rule_document,
)
from app.core.rule_engine.schema import (
    RULE_JSON_SCHEMA,
    RuleValidationIssue,
    validate_rule_payload,
)

__all__ = [
    "RULE_JSON_SCHEMA",
    "DeterministicRuleEngine",
    "DslError",
    "EvalContext",
    "Fact",
    "LoadedRule",
    "PredicateMatch",
    "RuleDefinition",
    "RuleEngine",
    "RuleMatch",
    "RuleValidationError",
    "RuleValidationIssue",
    "evaluate_when",
    "load_rules_from_dir",
    "parse_rule_document",
    "validate_rule_payload",
]
