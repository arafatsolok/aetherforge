"""Finding — a human-reviewable vulnerability/weakness raised by the engine."""


from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, Column, Index, Numeric, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import TimestampMixin, ULIDMixin
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.scan import Scan


class Finding(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_cve", "cve_id"),
        CheckConstraint("cvss_score >= 0 AND cvss_score <= 10", name="ck_findings_cvss"),
    )

    id: int | None = Field(default=None, primary_key=True)

    scan_id: int = Field(foreign_key="scans.id", nullable=False, index=True)
    scan: "Scan" = Relationship(back_populates="findings")

    rule_id: str = Field(max_length=128, nullable=False, index=True)
    tool: str = Field(max_length=64, nullable=False)
    title: str = Field(max_length=512, nullable=False)
    description: str = Field(default="", max_length=8192)

    severity: str = Field(
        default=Severity.INFO.value,
        sa_column=Column(String(16), nullable=False),
    )
    cvss_score: float | None = Field(
        default=None,
        sa_column=Column(Numeric(3, 1), nullable=True),
    )
    cve_id: str | None = Field(default=None, max_length=32, nullable=True)

    # Exact artefact / endpoint / port / URL that triggered the finding.
    affected: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    # Free-form structured evidence (request/response snippets, PoC…).
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    # Operator-facing remediation hint (from the knowledge base).
    remediation: str = Field(default="", max_length=4096)

    # Lifecycle — status ∈ open | triaged | false_positive | fixed | wontfix
    status: str = Field(default="open", max_length=16)
    confirmed: bool = Field(default=False, nullable=False)
    triaged_by: str | None = Field(default=None, max_length=128, nullable=True)
    triage_notes: str = Field(default="", max_length=4096)

    @property
    def severity_enum(self) -> Severity:
        return Severity(self.severity)


__all__ = ["Finding"]
