"""Execution — one row per tool-container invocation."""


from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import ARRAY, Column, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import TimestampMixin, ULIDMixin
from app.models.enums import ExecutionState

if TYPE_CHECKING:
    from app.models.fact import Fact
    from app.models.scan import Scan


class Execution(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "executions"
    __table_args__ = (
        Index("ix_executions_scan_state", "scan_id", "state"),
        Index("ix_executions_tool", "tool"),
        Index("ix_executions_container_id", "container_id"),
    )

    id: int | None = Field(default=None, primary_key=True)

    scan_id: int = Field(foreign_key="scans.id", nullable=False, index=True)
    scan: "Scan" = Relationship(back_populates="executions")

    rule_id: str = Field(max_length=128, nullable=False, index=True)
    iteration: int = Field(default=0, nullable=False)

    tool: str = Field(max_length=64, nullable=False)
    image: str = Field(max_length=256, nullable=False)

    argv: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(2048)), nullable=False, server_default="{}"),
    )
    env_redacted: dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    container_id: str | None = Field(default=None, max_length=64, nullable=True)
    network: str | None = Field(default=None, max_length=64, nullable=True)

    state: str = Field(
        default=ExecutionState.PENDING.value,
        sa_column=Column(String(16), nullable=False, index=True),
    )
    exit_code: int | None = Field(default=None, nullable=True)
    rejected_reason: str | None = Field(default=None, max_length=512, nullable=True)

    started_at: datetime | None = Field(default=None, nullable=True)
    finished_at: datetime | None = Field(default=None, nullable=True)

    duration_ms: int | None = Field(default=None, nullable=True)
    stdout_bytes: int = Field(default=0, nullable=False)
    stderr_bytes: int = Field(default=0, nullable=False)

    # Pointers to on-disk artefacts (sha256 + path).
    artifact_meta: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    # First 4 KiB of stdout/stderr so operators can glance without pulling artefacts.
    stdout_head: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    stderr_head: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )

    facts: list["Fact"] = Relationship(
        back_populates="execution",
        sa_relationship_kwargs={"lazy": "noload"},
    )


__all__ = ["Execution"]
