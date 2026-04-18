"""Focused JSONSchema tests beyond the loader's coverage."""

from __future__ import annotations

import pytest

from app.core.rule_engine import RULE_JSON_SCHEMA, validate_rule_payload


@pytest.mark.unit
def test_schema_has_expected_phases() -> None:
    enum_phases = RULE_JSON_SCHEMA["properties"]["phase"]["enum"]
    assert "recon.passive" in enum_phases
    assert "exfil_simulation" in enum_phases


@pytest.mark.unit
def test_where_supports_op_dicts() -> None:
    doc = {
        "id": "r.x", "version": 1, "description": "",
        "phase": "recon.active", "priority": 50,
        "persona": ["gray"],
        "when": {
            "fact_type": "port_open",
            "where": {"port": {"in": [80, 443]}},
        },
        "then": {"action": "noop"},
    }
    assert validate_rule_payload(doc) == []


@pytest.mark.unit
def test_multiple_op_dicts_rejected() -> None:
    doc = {
        "id": "r.x", "version": 1, "description": "",
        "phase": "recon.active", "priority": 50,
        "persona": ["gray"],
        "when": {
            "fact_type": "port_open",
            "where": {"port": {"eq": 80, "ne": 443}},  # >1 op → invalid
        },
        "then": {"action": "noop"},
    }
    assert validate_rule_payload(doc)  # non-empty issues


@pytest.mark.unit
def test_predicate_needs_one_shape() -> None:
    # `when` object with no shape at all must fail.
    doc = {
        "id": "r.x", "version": 1, "description": "",
        "phase": "recon.active", "priority": 50, "persona": ["gray"],
        "when": {}, "then": {"action": "noop"},
    }
    assert validate_rule_payload(doc)
