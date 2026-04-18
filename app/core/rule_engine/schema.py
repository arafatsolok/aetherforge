"""JSONSchema for rule YAML documents.

The schema is the single source of truth for rule structure. If you add a
new DSL clause (e.g. ``any:``, ``not_fact:``), update this schema first —
the loader and evaluator follow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from jsonschema import Draft202012Validator

RULE_JSON_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://aetherforge.local/schemas/rule.json",
    "title": "AetherForge rule",
    "type": "object",
    "additionalProperties": False,
    "required": ["id", "version", "persona", "phase", "priority", "description", "when", "then"],
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9._-]*$",
            "minLength": 1,
            "maxLength": 128,
        },
        "version": {"type": "integer", "minimum": 1},
        "description": {"type": "string", "maxLength": 1024},
        "phase": {
            "type": "string",
            "enum": [
                "recon.passive",
                "recon.active",
                "enumeration",
                "vuln_scan",
                "exploit.safe",
                "exploit.full",
                "post_exploit",
                "persistence",
                "pivoting",
                "exfil_simulation",
            ],
        },
        "priority": {"type": "integer", "minimum": 0, "maximum": 1000},
        "persona": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": {"type": "string", "enum": ["white", "gray", "black"]},
        },
        "enabled": {"type": "boolean"},
        "tags": {"type": "array", "items": {"type": "string", "maxLength": 64}},
        "metadata": {"type": "object"},
        "when": {"$ref": "#/$defs/predicate"},
        "then": {"$ref": "#/$defs/action"},
    },

    "$defs": {
        # -- Predicates ------------------------------------------------------
        "predicate": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "all":      {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/predicate"}},
                "any":      {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/predicate"}},
                "fact_type": {"type": "string", "minLength": 1, "maxLength": 32},
                "not_fact": {"$ref": "#/$defs/notFact"},
                "where":    {"$ref": "#/$defs/where"},
            },
            "oneOf": [
                {"required": ["all"]},
                {"required": ["any"]},
                {"required": ["fact_type"]},
                {"required": ["not_fact"]},
            ],
        },
        "notFact": {
            "type": "object",
            "additionalProperties": False,
            "required": ["fact_type"],
            "properties": {
                "fact_type": {"type": "string", "minLength": 1, "maxLength": 32},
                "where": {"$ref": "#/$defs/where"},
            },
        },
        "where": {
            "type": "object",
            "additionalProperties": {
                # Scalar OR $fact.X binding ref OR simple op object.
                "oneOf": [
                    {"type": ["string", "number", "boolean", "null"]},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "eq":       {},
                            "ne":       {},
                            "in":       {"type": "array"},
                            "contains": {"type": "string"},
                            "matches":  {"type": "string"},
                            "gt":       {"type": "number"},
                            "lt":       {"type": "number"},
                            "gte":      {"type": "number"},
                            "lte":      {"type": "number"},
                        },
                        "minProperties": 1,
                        "maxProperties": 1,
                    },
                ],
            },
        },

        # -- Actions ---------------------------------------------------------
        "action": {
            "type": "object",
            "additionalProperties": False,
            "required": ["action"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["execute_tool", "emit_fact", "emit_finding", "noop"],
                },
                "tool":   {"type": "string", "minLength": 1, "maxLength": 64},
                "params": {"type": "object"},
                "fact":   {"type": "object"},
                "finding": {"type": "object"},
                "on_success": {"type": "array", "items": {"type": "object"}},
                "on_failure": {"type": "array", "items": {"type": "object"}},
                "cooldown_seconds": {"type": "integer", "minimum": 0, "maximum": 86400},
            },
        },
    },
}


@dataclass(frozen=True, slots=True)
class RuleValidationIssue:
    """A single JSONSchema error — richer than the raw validator message."""

    rule_id: str | None
    path: str
    message: str


_validator = Draft202012Validator(RULE_JSON_SCHEMA)


def validate_rule_payload(doc: dict[str, Any]) -> list[RuleValidationIssue]:
    """Return a list of issues. Empty list means the rule is valid."""
    errors = sorted(_validator.iter_errors(doc), key=lambda e: list(e.path))
    if not errors:
        return []
    rid = str(doc.get("id") or "<unknown>")
    issues: list[RuleValidationIssue] = []
    for e in errors:
        path = "/".join(str(p) for p in e.path) or "<root>"
        issues.append(RuleValidationIssue(rule_id=rid, path=path, message=e.message))
    return issues


__all__ = ["RULE_JSON_SCHEMA", "RuleValidationIssue", "validate_rule_payload"]
