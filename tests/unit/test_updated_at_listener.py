"""L2 — regression test for the ``_touch_updated_at`` Session event.

The audit flagged that the listener is bound to sync ``Session`` while
the codebase uses ``AsyncSession``. SQLAlchemy 2.0's ``AsyncSession``
internally wraps a sync ``Session`` and forwards ORM events — so the
listener DOES fire under async use, but the audit was right that this
is non-obvious. We lock the behaviour in here so a future refactor
(e.g. switching to a different async ORM) can't silently break the
``updated_at`` bump.

Uses an in-memory SQLite DB so the test stays in the unit tier (no
postgres needed).
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

# Importing the database module installs the event listener as a
# side-effect — that's exactly the integration we're testing.
import app.database  # noqa: F401  pylint: disable=unused-import
from app.models.base import TimestampMixin, _utcnow

Base = declarative_base()


class _Widget(Base, TimestampMixin):
    """Minimal model that mixes in TimestampMixin so the listener applies.

    SQLite needs explicit DateTime — TimestampMixin's SQLModel-style
    Field declaration doesn't inherit cleanly into a plain SQLAlchemy
    Base, so we re-declare ``created_at`` / ``updated_at`` here.
    """

    __tablename__ = "widgets_test"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False, default="x")
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    updated_at = Column(DateTime, nullable=False, default=_utcnow)


@pytest.mark.unit
class TestUpdatedAtBumpsUnderAsyncSession:
    """The listener fires for every dirty ``TimestampMixin`` instance
    on every flush, regardless of whether the flush originated from a
    sync ``Session`` or an ``AsyncSession``."""

    @pytest.mark.asyncio
    async def test_async_session_bumps_updated_at(self) -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            factory = async_sessionmaker(engine, class_=AsyncSession,
                                         expire_on_commit=False)

            # Insert a row, capture its initial updated_at.
            async with factory() as s, s.begin():
                w = _Widget(name="a")
                s.add(w)
                await s.flush()
                first = w.updated_at

            # Wait long enough that any real bump is observable.
            await asyncio.sleep(0.01)

            # Mutate -> commit -> re-fetch and check the timestamp moved.
            async with factory() as s, s.begin():
                widget = (await s.get(_Widget, w.id))
                assert widget is not None
                widget.name = "b"
                await s.flush()
                bumped = widget.updated_at

            assert bumped > first, (
                f"updated_at did NOT advance under AsyncSession "
                f"(first={first!r}, bumped={bumped!r}) — the "
                f"_touch_updated_at listener is no longer firing."
            )
        finally:
            await engine.dispose()
