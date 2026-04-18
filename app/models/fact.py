"""Fact — a single observation produced by a tool parser.

Facts feed the rule engine. Phase 1 gives them a stable schema + index;
Phase 2 adds the parsers that actually emit them.
"""


from typing import TYPE_CHECKING, Any

from sqlalchemy import Column, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import TimestampMixin, ULIDMixin

if TYPE_CHECKING:
    from app.models.execution import Execution
    from app.models.scan import Scan


class Fact(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "facts"
    __table_args__ = (
        # Dedup via (scan_id, fingerprint) — persist activity uses
        # ON CONFLICT DO NOTHING on this constraint.
        UniqueConstraint("scan_id", "fingerprint", name="uq_facts_scan_fingerprint"),
        Index("ix_facts_scan_type", "scan_id", "fact_type"),
        Index("ix_facts_body", "body", postgresql_using="gin"),
    )

    id: int | None = Field(default=None, primary_key=True)

    scan_id: int = Field(foreign_key="scans.id", nullable=False, index=True)
    scan: "Scan" = Relationship(back_populates="facts")

    execution_id: int | None = Field(
        default=None, foreign_key="executions.id", nullable=True
    )
    execution: "Execution" = Relationship(back_populates="facts")

    fact_type: str = Field(
        sa_column=Column(String(32), nullable=False, index=True),
    )
    source_tool: str = Field(max_length=64, nullable=False)
    iteration: int = Field(default=0, nullable=False)

    # Stable hash of (scan_id, fact_type, canonical body) — used by the
    # drift detector for set-diff operations.
    fingerprint: str = Field(max_length=64, nullable=False)

    body: dict[str, Any] = Field(
        sa_column=Column(JSONB, nullable=False),
    )


__all__ = ["Fact"]
