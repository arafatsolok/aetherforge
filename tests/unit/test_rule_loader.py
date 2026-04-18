"""Unit tests for the rule YAML loader + JSONSchema validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.rule_engine import (
    RuleValidationError,
    load_rules_from_dir,
    parse_rule_document,
    validate_rule_payload,
)

VALID_RULE = {
    "id": "r.recon.subfinder.seed",
    "version": 1,
    "description": "Passive subdomain seed.",
    "phase": "recon.passive",
    "priority": 95,
    "persona": ["white", "gray"],
    "when": {"fact_type": "host_alive"},
    "then": {"action": "execute_tool", "tool": "subfinder"},
}


@pytest.mark.unit
class TestValidator:
    def test_valid_rule_has_no_issues(self) -> None:
        assert validate_rule_payload(VALID_RULE) == []

    def test_missing_required_field_detected(self) -> None:
        doc = {k: v for k, v in VALID_RULE.items() if k != "phase"}
        issues = validate_rule_payload(doc)
        assert issues
        assert any("phase" in i.message for i in issues)

    def test_bad_priority_detected(self) -> None:
        doc = dict(VALID_RULE, priority=9999)
        assert validate_rule_payload(doc)

    def test_bad_persona_enum_detected(self) -> None:
        doc = dict(VALID_RULE, persona=["magenta"])
        assert validate_rule_payload(doc)

    def test_when_requires_one_of_the_predicates(self) -> None:
        doc = dict(VALID_RULE, when={"unknown": 1})
        assert validate_rule_payload(doc)


@pytest.mark.unit
class TestParseRuleDocument:
    def test_returns_definition(self) -> None:
        rd = parse_rule_document(VALID_RULE)
        assert rd.id == "r.recon.subfinder.seed"
        assert rd.priority == 95
        assert len(rd.persona) == 2
        assert rd.metadata.get("enabled") is True

    def test_invalid_raises_RuleValidationError(self) -> None:
        with pytest.raises(RuleValidationError):
            parse_rule_document({"id": "x"})


@pytest.mark.unit
class TestLoadRulesFromDir:
    def test_loads_builtin_rules_clean(self) -> None:
        """Live-fire against the baseline rules we ship in rules/*.yaml."""
        root = Path(__file__).resolve().parents[2] / "rules"
        loaded, errors = load_rules_from_dir(root)
        assert errors == [], f"expected clean baseline, got {errors}"
        assert len(loaded) >= 15

        # id uniqueness
        ids = [lr.definition.id for lr in loaded]
        assert len(set(ids)) == len(ids)

        # every baseline rule has a non-empty sha
        for lr in loaded:
            assert len(lr.source_sha256) == 64

    def test_bad_rule_reported_not_raised(self, tmp_path: Path) -> None:
        (tmp_path / "bad.yaml").write_text("id: broken\nphase: nope\n")
        loaded, errors = load_rules_from_dir(tmp_path)
        assert loaded == []
        assert errors
