"""Full rule-YAML validation — JSONSchema + DSL parse.

Exits non-zero if any rule under ``rules/`` is invalid.
"""

from __future__ import annotations

import sys

from app.config import get_settings
from app.core.rule_engine import load_rules_from_dir
from app.logging_config import configure_logging, get_logger


def main() -> int:
    settings = get_settings()
    configure_logging(settings)
    log = get_logger(__name__)

    loaded, errors = load_rules_from_dir(settings.rules_dir)

    for lr in loaded:
        log.info("rule.ok", id=lr.definition.id, path=str(lr.source_path))

    for e in errors:
        log.error("rule.invalid", path=e.path, message=e.message, rule_id=e.rule_id)

    if errors:
        log.error("rule.validate.failed", loaded=len(loaded), failures=len(errors))
        return 1

    log.info("rule.validate.ok", files=len(loaded))
    return 0


if __name__ == "__main__":
    sys.exit(main())
