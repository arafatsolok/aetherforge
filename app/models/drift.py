"""DriftSnapshot + DriftDelta — continuous-monitoring inputs."""


from typing import Any

from sqlalchemy import Column, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

from app.models.base import TimestampMixin, ULIDMixin


class DriftSnapshot(SQLModel, TimestampMixin, ULIDMixin, table=True):
    """Summary of a completed scan used by Phase 7 drift comparison."""

    __tablename__ = "drift_snapshots"
    __table_args__ = (Index("ix_drift_target_time", "target_id", "created_at"),)

    id: int | None = Field(default=None, primary_key=True)

    target_id: int = Field(foreign_key="targets.id", nullable=False, index=True)
    scan_id: int = Field(foreign_key="scans.id", nullable=False, unique=True)

    host_count: int = Field(default=0, nullable=False)
    open_port_count: int = Field(default=0, nullable=False)
    finding_counts: dict[str, int] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    # Set of fact fingerprints — used for add/remove set-diff.
    fact_fingerprints: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSONB, nullable=False, server_default="[]"),
    )

    summary: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )


class DriftDelta(SQLModel, TimestampMixin, ULIDMixin, table=True):
    """Computed delta between two snapshots."""

    __tablename__ = "drift_deltas"
    __table_args__ = (Index("ix_drift_deltas_target", "target_id", "created_at"),)

    id: int | None = Field(default=None, primary_key=True)

    target_id: int = Field(foreign_key="targets.id", nullable=False, index=True)
    from_snapshot_id: int = Field(foreign_key="drift_snapshots.id", nullable=False)
    to_snapshot_id: int = Field(foreign_key="drift_snapshots.id", nullable=False)

    added_fingerprints: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSONB, nullable=False, server_default="[]"),
    )
    removed_fingerprints: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSONB, nullable=False, server_default="[]"),
    )
    severity_shift: dict[str, int] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )


__all__ = ["DriftDelta", "DriftSnapshot"]
