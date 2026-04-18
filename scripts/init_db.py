"""One-shot DB init: ping, create extensions, print schema summary.

Used by ``make migrate`` as a sanity step before `alembic upgrade head`.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import text

from app.config import get_settings
from app.database import dispose_db, get_engine, init_db
from app.logging_config import configure_logging, get_logger


async def _run() -> int:
    settings = get_settings()
    configure_logging(settings)
    log = get_logger(__name__)

    log.info("init_db.start", env=settings.env)
    try:
        await init_db()
    except Exception as exc:
        log.error("init_db.failed", error=str(exc))
        return 1

    async with get_engine().begin() as conn:
        result = await conn.execute(
            text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
        )
        table_count = result.scalar_one()
        log.info("init_db.done", public_tables=int(table_count))

    await dispose_db()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_run()))
