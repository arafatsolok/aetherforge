"""Health / readiness probes.

* ``/health``                   — liveness. No side-effects.
* ``/ready``                    — readiness. DB + Redis reachable?
* ``/api/v1/metrics/overview``  — operator metrics (separate router).
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, status
from sqlalchemy import text

from app import __version__
from app.api.dependencies import SessionDep, SettingsDep
from app.logging_config import get_logger

log = get_logger(__name__)
router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict[str, Any]:
    """Liveness probe — returns 200 if the process is up."""
    return {"status": "ok", "version": __version__}


@router.get("/ready")
async def ready(session: SessionDep, settings: SettingsDep) -> dict[str, Any]:
    """Readiness probe — returns 200 only if all infra dependencies are live.

    Does not actively verify Temporal (expensive); Phase 3 will add a
    lightweight Temporal ``DescribeNamespace`` check.
    """
    checks: dict[str, dict[str, Any]] = {}
    overall_ok = True

    # --- DB -----------------------------------------------------------------
    try:
        result = await session.execute(text("SELECT 1"))
        checks["postgres"] = {"ok": result.scalar_one() == 1}
    except Exception as exc:
        overall_ok = False
        checks["postgres"] = {"ok": False, "error": str(exc)}

    # --- Redis --------------------------------------------------------------
    client: aioredis.Redis | None = None
    try:
        client = aioredis.from_url(settings.redis_url, decode_responses=True)
        pong = await client.ping()
        checks["redis"] = {"ok": bool(pong)}
    except Exception as exc:
        overall_ok = False
        checks["redis"] = {"ok": False, "error": str(exc)}
    finally:
        if client is not None:
            await client.aclose()

    return {
        "status": "ok" if overall_ok else "degraded",
        "version": __version__,
        "checks": checks,
    }


__all__ = ["router"]
