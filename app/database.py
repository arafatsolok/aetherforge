"""Async SQLAlchemy + SQLModel database layer.

Exposes:
  * ``engine``        — lazily-built ``AsyncEngine``
  * ``SessionLocal``  — ``async_sessionmaker`` factory
  * ``get_session``   — FastAPI dependency yielding ``AsyncSession``
  * ``Base``          — shared declarative base for ORM models
  * ``init_db``       — ensure extensions + ping at startup

The engine is NOT created at import time (so tests can override
``DATABASE_URL`` before any table is materialised).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel

from app.config import get_settings
from app.logging_config import get_logger

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

log = get_logger(__name__)


# SQLModel's own metadata is what Alembic targets.
metadata = SQLModel.metadata


class Base(DeclarativeBase):
    """Declarative base for non-SQLModel pure-SQLAlchemy models (rare)."""


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    settings = get_settings()
    log.info("db.engine.build", url=_mask_dsn(settings.database_url))

    kwargs: dict[str, Any] = {
        "echo": settings.database_echo,
        "future": True,
        "pool_pre_ping": True,
    }
    if settings.is_development:
        # Keeps psql -c ALTER from being blocked by stale pooled conns.
        kwargs["poolclass"] = NullPool
    else:
        kwargs["pool_size"] = settings.database_pool_size
        kwargs["max_overflow"] = settings.database_max_overflow

    return create_async_engine(settings.database_url, **kwargs)


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Ping DB + ensure critical extensions. Called from FastAPI startup."""
    engine = get_engine()

    async with engine.begin() as conn:
        await _ensure_extensions(conn)
        await conn.exec_driver_sql("SELECT 1")

    log.info("db.ready")


async def dispose_db() -> None:
    """Gracefully close the pool. Called from FastAPI shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


async def _ensure_extensions(conn: AsyncConnection) -> None:
    """Idempotently create extensions used across the schema."""
    for ext in ("pgcrypto", "pg_trgm", "uuid-ossp"):
        try:
            await conn.exec_driver_sql(f'CREATE EXTENSION IF NOT EXISTS "{ext}"')
        except Exception as exc:
            log.warning("db.extension.skip", extension=ext, error=str(exc))


def _mask_dsn(dsn: str) -> str:
    """Obfuscate the password inside a DSN for safe logging."""
    if "@" not in dsn or "://" not in dsn:
        return dsn
    scheme, rest = dsn.split("://", 1)
    if ":" not in rest.split("@", 1)[0]:
        return dsn
    creds, host = rest.split("@", 1)
    user = creds.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"


# ---------------------------------------------------------------------------
# Auto-bump ``updated_at`` on every ORM-mediated UPDATE.
# Done via a session event so we don't need a per-class mixin using
# SQLAlchemy's ``onupdate=``, which tripped the shared-Column mixin trap.
#
# NB — this listener is bound to the SYNC ``Session`` class on purpose.
# ``AsyncSession`` is a thin wrapper that delegates flush/commit work
# to an internal sync ``Session``, so this listener fires for both
# code paths. A regression test in tests/unit/test_updated_at_listener.py
# locks this behaviour in: a previous audit incorrectly assumed events
# bound to ``Session`` are silent under ``AsyncSession``.
# ---------------------------------------------------------------------------
@event.listens_for(Session, "before_flush")
def _touch_updated_at(session: Session, _ctx: object, _instances: object) -> None:
    from app.models.base import TimestampMixin, _utcnow  # avoid import cycle

    now = _utcnow()
    for obj in session.dirty:
        if isinstance(obj, TimestampMixin):
            obj.updated_at = now


__all__ = [
    "Base",
    "SQLModel",
    "dispose_db",
    "get_engine",
    "get_session",
    "get_session_factory",
    "init_db",
    "metadata",
]
