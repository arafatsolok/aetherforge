"""Tool output parsers — each returns a list of ``Fact``s.

Every parser is a pure function. Its input is the raw stdout/stderr
bytes; its output is a list of ``Fact`` with a stable fingerprint.

The fingerprint is the sha1 of a canonical JSON of ``(scan_id,
fact_type, body)`` so that the same observation, seen twice, yields the
same id — required by the drift detector and by fact dedup in the DB.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.core.rule_engine import Fact


def fingerprint(fact_type: str, body: dict[str, Any]) -> str:
    """Stable, **scan-INDEPENDENT** hash of an observation.

    Drift detection diffs fingerprint sets across consecutive scans —
    identical observations MUST collide across scans. Within-scan
    dedup is enforced by the ``uq_facts_scan_fingerprint`` unique
    constraint, which works fine against the (scan_id, fingerprint)
    tuple even with cross-scan fingerprint collisions.
    """
    canonical = json.dumps(
        {"fact_type": fact_type, "body": body},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha1(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()


def make_fact(
    *, fact_type: str, body: dict[str, Any], source_tool: str,
    scan_id: str, iteration: int,
) -> Fact:
    """Build a ``Fact`` with a deterministic fingerprint."""
    return Fact(
        fact_type=fact_type,
        body=body,
        source_tool=source_tool,
        scan_id=scan_id,
        iteration=iteration,
        fingerprint=fingerprint(fact_type, body),
    )


__all__ = ["fingerprint", "make_fact"]
