"""Per-IP API rate limiting middleware.

In-process token bucket — one per client IP. Phase 8 ships this; if you
need cluster-wide enforcement migrate to Redis (the same shape applies).

Defaults: 60 req / 60 s per IP. Override via ``AETHERFORGE_API_RATE_LIMIT``.
Health/readiness probes are exempt so monitoring doesn't get throttled.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass(slots=True)
class _Bucket:
    capacity: float
    tokens: float
    refill_per_s: float
    last_refill: float


class APIRateLimit(BaseHTTPMiddleware):
    """Token-bucket rate limiter keyed by ``request.client.host``.

    Exempt paths: ``/health``, ``/ready``, ``/static/*``, ``/api/v1/audit/scans/*/sse``
    (long-lived stream — counting these would starve the bucket).
    """

    EXEMPT_PREFIXES = (
        "/health", "/ready", "/static/", "/openapi.json",
        "/docs", "/redoc",
    )
    EXEMPT_SUFFIXES = ("/sse", "/stream")

    def __init__(self, app, *, capacity: float = 60.0,    # type: ignore[no-untyped-def]
                 refill_per_s: float = 1.0) -> None:
        super().__init__(app)
        self._capacity = capacity
        self._refill = refill_per_s
        self._buckets: dict[str, _Bucket] = defaultdict(self._new_bucket)
        self._lock = asyncio.Lock()

    def _new_bucket(self) -> _Bucket:
        now = time.monotonic()
        return _Bucket(
            capacity=self._capacity, tokens=self._capacity,
            refill_per_s=self._refill, last_refill=now,
        )

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        path = request.url.path
        if any(path.startswith(p) for p in self.EXEMPT_PREFIXES):
            return await call_next(request)
        if any(path.endswith(s) for s in self.EXEMPT_SUFFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        async with self._lock:
            bucket = self._buckets[client_ip]
            now = time.monotonic()
            elapsed = max(0.0, now - bucket.last_refill)
            bucket.tokens = min(
                bucket.capacity,
                bucket.tokens + elapsed * bucket.refill_per_s,
            )
            bucket.last_refill = now
            if bucket.tokens < 1.0:
                # When refill_per_s is 0 (test mode) we can't compute a
                # useful retry estimate — fall back to 1s.
                if bucket.refill_per_s <= 0.0:
                    retry_after = 1
                else:
                    retry_after = int((1.0 - bucket.tokens) / bucket.refill_per_s) + 1
                return JSONResponse(
                    status_code=429,
                    content={"error": {"type": "rate_limited",
                                       "detail": f"too many requests; retry in {retry_after}s"}},
                    headers={"Retry-After": str(retry_after)},
                )
            bucket.tokens -= 1.0

        return await call_next(request)


__all__ = ["APIRateLimit"]
