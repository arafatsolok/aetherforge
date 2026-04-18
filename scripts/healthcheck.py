"""Container healthcheck — used by Docker HEALTHCHECK directives.

Exits 0 when the declared role is reachable, non-zero otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import urllib.request


def _check_api(timeout: float) -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


async def _check_worker(timeout: float) -> bool:
    # Minimum readiness: can import settings + open a DB connection.
    try:
        from sqlalchemy import text

        from app.database import get_session_factory

        factory = get_session_factory()
        async with asyncio.timeout(timeout):
            async with factory() as s:
                result = await s.execute(text("SELECT 1"))
                return result.scalar_one() == 1
    except Exception:
        return False


def main() -> int:
    p = argparse.ArgumentParser(description="AetherForge container healthcheck")
    p.add_argument("--role", choices=["api", "worker"], required=True)
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args()

    if args.role == "api":
        ok = _check_api(args.timeout)
    else:
        ok = asyncio.run(_check_worker(args.timeout))

    if not ok:
        print(f"[healthcheck] {args.role}: UNHEALTHY", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
