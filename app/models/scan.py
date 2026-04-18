"""Scan — a single invocation of the autonomous loop against a target."""


from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Column, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from app.config import Persona
from app.models.base import TimestampMixin, ULIDMixin
from app.models.enums import ScanState

if TYPE_CHECKING:
    from app.models.audit import AuditLog
    from app.models.execution import Execution
    from app.models.fact import Fact
    from app.models.finding import Finding
    from app.models.target import Target


class Scan(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_target_state", "target_id", "state"),
        Index("ix_scans_workflow_id", "workflow_id"),
    )

    id: int | None = Field(default=None, primary_key=True)

    target_id: int = Field(foreign_key="targets.id", nullable=False, index=True)
    target: "Target" = Relationship(back_populates="scans")

    persona: str = Field(
        sa_column=Column(String(16), nullable=False, index=True),
    )
    state: str = Field(
        default=ScanState.PENDING.value,
        sa_column=Column(String(16), nullable=False, index=True),
    )

    # Temporal handles
    workflow_id: str | None = Field(default=None, max_length=128, nullable=True)
    run_id: str | None = Field(default=None, max_length=64, nullable=True)
    task_queue: str | None = Field(default=None, max_length=64, nullable=True)

    started_by: str = Field(default="system", max_length=128)
    started_at: datetime | None = Field(default=None, nullable=True)
    finished_at: datetime | None = Field(default=None, nullable=True)

    # Loop progress
    iterations: int = Field(default=0, nullable=False)
    executions_total: int = Field(default=0, nullable=False)
    facts_total: int = Field(default=0, nullable=False)
    findings_total: int = Field(default=0, nullable=False)

    # Terminal reason when state ∈ {completed, failed, cancelled}.
    terminal_reason: str | None = Field(default=None, max_length=512, nullable=True)

    # Per-scan config overrides (rate-limit bump, rule allowlist, …).
    overrides: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    executions: list["Execution"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "noload"},
    )
    facts: list["Fact"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "noload"},
    )
    findings: list["Finding"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "noload"},
    )
    audit_entries: list["AuditLog"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "noload"},
    )

    @property
    def persona_enum(self) -> Persona:
        return Persona(self.persona)


__all__ = ["Scan"]
