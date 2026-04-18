"""Per-persona in-process token-bucket rate limiter.

Phase 2 provides a simple in-process bucket — good enough inside a
worker. Phase 8 (scale-out) migrates to Redis-backed cluster limiter.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Final

from app.config import Persona


@dataclass(slots=True)
class _Bucket:
    capacity: float
    tokens: float
    refill_rate: float   # tokens per second
    last_refill: float


class RateLimiter:
    """One bucket per persona. Thread-safe via a lock; async-friendly."""

    _DEFAULT_BURST: Final[float] = 5.0    # allow a 5× burst over steady RPS

    def __init__(self, *, rps_by_persona: dict[Persona, int]) -> None:
        now = time.monotonic()
        self._buckets: dict[Persona, _Bucket] = {
            p: _Bucket(
                capacity=rps * self._DEFAULT_BURST,
                tokens=rps * self._DEFAULT_BURST,
                refill_rate=float(rps),
                last_refill=now,
            )
            for p, rps in rps_by_persona.items()
        }
        self._lock = asyncio.Lock()

    async def acquire(self, persona: Persona, cost: float = 1.0) -> None:
        """Block until ``cost`` tokens are available for ``persona``."""
        while True:
            async with self._lock:
                bucket = self._buckets[persona]
                self._refill(bucket)
                if bucket.tokens >= cost:
                    bucket.tokens -= cost
                    return
                shortfall = cost - bucket.tokens
                wait = shortfall / bucket.refill_rate
            await asyncio.sleep(wait)

    def try_acquire(self, persona: Persona, cost: float = 1.0) -> bool:
        """Non-blocking variant — returns True iff tokens were available."""
        bucket = self._buckets[persona]
        self._refill(bucket)
        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return True
        return False

    # -- Internal ----------------------------------------------------------
    @staticmethod
    def _refill(bucket: _Bucket) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - bucket.last_refill)
        bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.refill_rate)
        bucket.last_refill = now


__all__ = ["RateLimiter"]
