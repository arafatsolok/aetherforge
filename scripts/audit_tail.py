"""Tail the audit log (Phase 3 provides the table + real tailer)."""

from __future__ import annotations

import sys

from app.config import get_settings
from app.logging_config import configure_logging, get_logger


def main() -> int:
    configure_logging(get_settings())
    log = get_logger(__name__)
    log.info("audit_tail.stub", phase=0, note="audit table materialised in Phase 3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
