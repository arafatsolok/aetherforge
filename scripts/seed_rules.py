"""Seed / re-seed rules from the YAML tree under ``rules/``.

Idempotent: upsert by (rule_id, version). Safe to re-run.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.core.rule_engine import load_rules_from_dir
from app.database import dispose_db, get_session_factory
from app.logging_config import configure_logging, get_logger
from app.repositories import RuleRepository


async def _run() -> int:
    settings = get_settings()
    configure_logging(settings)
    log = get_logger(__name__)

    rules_root: Path = settings.rules_dir
    log.info("seed_rules.start", root=str(rules_root))

    loaded, errors = load_rules_from_dir(rules_root)
    if errors:
        for e in errors:
            log.error("seed_rules.invalid", path=e.path, message=e.message, rule_id=e.rule_id)
        log.error("seed_rules.aborted", errors=len(errors))
        return 2

    rows: list[dict[str, Any]] = []
    for lr in loaded:
        d = lr.definition
        rows.append(
            {
                "rule_id":    d.id,
                "version":    d.version,
                "description": d.description,
                "phase":      d.phase,
                "priority":   d.priority,
                "personas":   [p.value for p in d.persona],
                "enabled":    bool(d.metadata.get("enabled", True)),
                "source_path": str(lr.source_path.relative_to(rules_root.parent)),
                "source_sha256": lr.source_sha256,
                "body":       {"when": d.when, "then": d.then, "metadata": d.metadata},
            }
        )

    async with get_session_factory()() as session:
        repo = RuleRepository(session)
        written = await repo.upsert_many(rows)
        await session.commit()

    log.info("seed_rules.done", upserted=written, total_loaded=len(loaded))
    await dispose_db()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_run()))
