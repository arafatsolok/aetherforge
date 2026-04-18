"""Seed the built-in CVE / CPE / Nuclei template catalogue.

Idempotent. Phase 1 ships a small curated set; production operators
swap in the full NVD + pd-nuclei-templates via env-selectable sources.
"""

from __future__ import annotations

import asyncio
import sys

from app.config import get_settings
from app.database import dispose_db, get_session_factory
from app.kb import seed_builtin_catalogue
from app.logging_config import configure_logging, get_logger


async def _run() -> int:
    settings = get_settings()
    configure_logging(settings)
    log = get_logger(__name__)

    log.info("seed_kb.start")
    async with get_session_factory()() as session:
        res = await seed_builtin_catalogue(session)
        await session.commit()

    log.info("seed_kb.done", cves=res.cves, cpes=res.cpes, nuclei=res.nuclei, total=res.total())
    await dispose_db()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_run()))
