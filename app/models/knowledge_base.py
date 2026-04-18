"""Knowledge base tables — CVE / CPE / Nuclei template catalogue.

Seeded by ``scripts/seed_knowledge_base.py``. Read-only at runtime.
"""


from typing import Any

from sqlalchemy import ARRAY, Column, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

from app.models.base import TimestampMixin


class CveEntry(SQLModel, TimestampMixin, table=True):
    __tablename__ = "kb_cve"
    __table_args__ = (
        Index("ix_kb_cve_severity", "severity"),
        Index("ix_kb_cve_cpes", "cpes", postgresql_using="gin"),
    )

    cve_id: str = Field(
        max_length=32,
        sa_column=Column(String(32), primary_key=True),
    )
    published: str | None = Field(default=None, max_length=32, nullable=True)
    last_modified: str | None = Field(default=None, max_length=32, nullable=True)
    summary: str = Field(default="", sa_column=Column(Text, nullable=False))
    severity: str = Field(default="info", max_length=16)
    cvss_score: float | None = Field(
        default=None,
        sa_column=Column(Numeric(3, 1), nullable=True),
    )
    cvss_vector: str | None = Field(default=None, max_length=128, nullable=True)

    cpes: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(256)), nullable=False, server_default="{}"),
    )

    references: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSONB, nullable=False, server_default="[]"),
    )

    raw: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )


class CpeEntry(SQLModel, TimestampMixin, table=True):
    __tablename__ = "kb_cpe"

    cpe23: str = Field(
        max_length=256,
        sa_column=Column(String(256), primary_key=True),
    )
    vendor: str = Field(max_length=128, nullable=False, index=True)
    product: str = Field(max_length=128, nullable=False, index=True)
    version: str | None = Field(default=None, max_length=64, nullable=True)
    title: str = Field(default="", max_length=512)


class NucleiTemplate(SQLModel, TimestampMixin, table=True):
    __tablename__ = "kb_nuclei_templates"
    __table_args__ = (
        Index("ix_nuclei_tags", "tags", postgresql_using="gin"),
        Index("ix_nuclei_severity", "severity"),
    )

    template_id: str = Field(
        max_length=128,
        sa_column=Column(String(128), primary_key=True),
    )
    name: str = Field(max_length=512, nullable=False)
    severity: str = Field(default="info", max_length=16)
    author: str = Field(default="", max_length=256)
    description: str = Field(default="", sa_column=Column(Text, nullable=False))

    tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(64)), nullable=False, server_default="{}"),
    )
    cves: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(32)), nullable=False, server_default="{}"),
    )

    raw: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )


__all__ = ["CpeEntry", "CveEntry", "NucleiTemplate"]
