"""Rule YAML loader + validator.

Pipeline:
    file on disk
       → yaml.safe_load (defusedxml analogue for YAML)
       → validate_rule_payload (jsonschema)
       → parse_rule_document  (dict -> RuleDefinition)
       → LoadedRule bundle    (+ sha256 + source path)

The loader is stateless — orchestration + upsert happens in the caller.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.config import Persona
from app.core.rule_engine.contract import RuleDefinition, RuleValidationError
from app.core.rule_engine.schema import RuleValidationIssue, validate_rule_payload

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LoadedRule:
    """A validated, parsed rule plus on-disk provenance."""

    definition: RuleDefinition
    source_path: Path
    source_sha256: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_rule_document(doc: dict[str, Any]) -> RuleDefinition:
    """Validate + convert a raw dict into a ``RuleDefinition``.

    Raises ``RuleValidationError`` with concatenated JSONSchema errors
    if the doc doesn't conform.
    """
    issues = validate_rule_payload(doc)
    if issues:
        raise RuleValidationError(_format_issues(issues))

    try:
        personas = tuple(Persona(p) for p in doc["persona"])
    except ValueError as err:
        raise RuleValidationError(f"bad persona in {doc.get('id')!r}: {err}") from err

    return RuleDefinition(
        id=doc["id"],
        version=int(doc["version"]),
        persona=personas,
        phase=doc["phase"],
        priority=int(doc["priority"]),
        description=doc.get("description", ""),
        when=doc["when"],
        then=doc["then"],
        metadata={
            "tags": tuple(doc.get("tags", [])),
            "enabled": bool(doc.get("enabled", True)),
            **(doc.get("metadata") or {}),
        },
    )


def load_rules_from_dir(root: Path) -> tuple[list[LoadedRule], list[RuleValidationIssue]]:
    """Walk ``root``, parse every ``*.yaml`` / ``*.yml``.

    Returns ``(loaded, errors)`` — partial loads are exposed so the
    caller (e.g. make rules-validate) can report the good ones AND the
    bad ones in the same pass.
    """
    loaded: list[LoadedRule] = []
    errors: list[RuleValidationIssue] = []
    seen_ids: dict[str, Path] = {}

    for path in sorted(root.rglob("*.y*ml")):
        if path.name.startswith("."):
            continue
        try:
            raw = path.read_bytes()
            doc = yaml.safe_load(raw.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as err:
            errors.append(
                RuleValidationIssue(rule_id=None, path=str(path), message=f"yaml parse error: {err}")
            )
            continue

        if not isinstance(doc, dict):
            errors.append(
                RuleValidationIssue(
                    rule_id=None, path=str(path),
                    message=f"top-level document must be a mapping (got {type(doc).__name__})",
                )
            )
            continue

        issues = validate_rule_payload(doc)
        if issues:
            for i in issues:
                errors.append(
                    RuleValidationIssue(
                        rule_id=i.rule_id,
                        path=f"{path}:{i.path}",
                        message=i.message,
                    )
                )
            continue

        rid = doc["id"]
        if rid in seen_ids:
            errors.append(
                RuleValidationIssue(
                    rule_id=rid, path=str(path),
                    message=f"duplicate rule id — first seen at {seen_ids[rid]}",
                )
            )
            continue
        seen_ids[rid] = path

        try:
            definition = parse_rule_document(doc)
        except RuleValidationError as err:
            errors.append(
                RuleValidationIssue(rule_id=rid, path=str(path), message=str(err))
            )
            continue

        loaded.append(
            LoadedRule(
                definition=definition,
                source_path=path,
                source_sha256=_sha256(raw),
            )
        )

    log.info(
        "rule-loader scan complete: loaded=%d errors=%d root=%s",
        len(loaded), len(errors), root,
    )
    return loaded, errors


def _format_issues(issues: list[RuleValidationIssue]) -> str:
    lines = [f"  {i.path}: {i.message}" for i in issues]
    return "rule validation failed:\n" + "\n".join(lines)


__all__ = ["LoadedRule", "load_rules_from_dir", "parse_rule_document"]
