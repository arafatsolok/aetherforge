"""Reusable model mixins.

Mixins intentionally use plain ``Field(default_factory=...)`` (not
``sa_column=Column(...)``) because a bare ``Column`` instance attached at
class level is shared across every subclass and SQLAlchemy rejects that.
Server-side defaults / onupdate are applied per-model where needed.
"""


from datetime import UTC, datetime

import ulid
from sqlmodel import Field


def _utcnow() -> datetime:
    # Naive UTC — matches the ``TIMESTAMP WITHOUT TIME ZONE`` columns
    # that SQLModel generates for plain Field(datetime) declarations.
    # Every write goes through ``datetime.now(utc)`` so there is no
    # ambiguity about the reference clock.
    return datetime.now(UTC).replace(tzinfo=None)


def _new_ulid() -> str:
    return str(ulid.new())


class TimestampMixin:
    """``created_at`` / ``updated_at`` as ORM-managed tz-aware timestamps.

    Defaults are set by ``default_factory`` at INSERT time; ``updated_at``
    is bumped by a SQLAlchemy ``before_update`` event listener installed
    in ``app.database`` to avoid the shared-Column mixin trap.
    """

    created_at: datetime = Field(
        default_factory=_utcnow,
        nullable=False,
        index=True,
    )
    updated_at: datetime = Field(
        default_factory=_utcnow,
        nullable=False,
    )


class ULIDMixin:
    """26-char time-sortable ULID — unique identifier for API exposure.

    ``id`` stays the BIGSERIAL primary key (fast joins); ``ulid`` is the
    stable public identifier external systems should reference.
    """

    ulid: str = Field(
        default_factory=_new_ulid,
        max_length=26,
        nullable=False,
        unique=True,
        index=True,
    )


__all__ = ["TimestampMixin", "ULIDMixin"]
