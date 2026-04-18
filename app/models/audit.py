"""AuditLog — append-only record of every orchestrator decision.

``sequence`` gives a strictly monotonic ordering WITHIN a scan so the
full session can be replayed offline. Rows are immutable: no UPDATE /
DELETE are issued by any code path.
"""


from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, Column, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import TimestampMixin, ULIDMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class AuditLog(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("scan_id", "sequence", name="uq_audit_scan_sequence"),
        Index("ix_audit_event", "event"),
        Index("ix_audit_scan_event", "scan_id", "event"),
    )

    id: int | None = Field(default=None, primary_key=True)

    scan_id: int | None = Field(default=None, foreign_key="scans.id", nullable=True)
    # Relationship annotation is a bare string — SQLModel/SQLAlchemy can't
    # parse ``"Scan | None"`` or ``Optional["Scan"]``. FK nullability
    # (above) is what controls whether the attribute can be None.
    scan: "Scan" = Relationship(back_populates="audit_entries")

    sequence: int = Field(
        sa_column=Column(BigInteger, nullable=False),
    )

    event: str = Field(
        sa_column=Column(String(48), nullable=False),
    )

    persona: str | None = Field(default=None, max_length=16, nullable=True)
    actor: str = Field(default="system", max_length=128)

    # Dotted rule id + version, if relevant.
    rule_id: str | None = Field(default=None, max_length=128, nullable=True)

    # Full structured body of the event. Never shadowed — this is the
    # source of truth for replay.
    payload: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )


__all__ = ["AuditLog"]
