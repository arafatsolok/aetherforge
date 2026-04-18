"""Unit tests for the per-persona rate limiter."""

from __future__ import annotations

import pytest

from app.config import Persona
from app.executor.rate_limiter import RateLimiter


@pytest.mark.unit
class TestRateLimiter:
    def test_try_acquire_consumes(self) -> None:
        rl = RateLimiter(rps_by_persona={Persona.WHITE: 2, Persona.GRAY: 20, Persona.BLACK: 100})
        # 2 RPS × default 5× burst = 10 tokens
        consumed = 0
        for _ in range(20):
            if rl.try_acquire(Persona.WHITE):
                consumed += 1
        assert 1 <= consumed <= 10

    def test_different_personas_have_different_buckets(self) -> None:
        rl = RateLimiter(rps_by_persona={Persona.WHITE: 1, Persona.BLACK: 50})
        # Drain white
        while rl.try_acquire(Persona.WHITE):
            pass
        # Black should still have capacity
        assert rl.try_acquire(Persona.BLACK) is True

    @pytest.mark.asyncio
    async def test_acquire_blocks_until_refill(self) -> None:
        rl = RateLimiter(rps_by_persona={Persona.WHITE: 10, Persona.GRAY: 10, Persona.BLACK: 10})
        # Drain
        while rl.try_acquire(Persona.WHITE):
            pass
        import asyncio
        # Acquire with timeout to prove it blocks but succeeds
        await asyncio.wait_for(rl.acquire(Persona.WHITE, cost=1.0), timeout=1.0)
