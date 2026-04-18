"""Rule model — versioned rule definitions.

Rules authored as YAML on disk are hot-loaded into this table. The
``body`` JSONB column stores the parsed `when:` / `then:` DSL so the
rule engine never re-reads disk after boot.
"""


from typing import Any

from sqlalchemy import ARRAY, CheckConstraint, Column, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

from app.models.base import TimestampMixin, ULIDMixin


class Rule(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "rules"
    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_rules_id_version"),
        CheckConstraint("priority >= 0 AND priority <= 1000", name="ck_rules_priority"),
        Index("ix_rules_phase", "phase"),
        Index("ix_rules_body", "body", postgresql_using="gin"),
    )

    id: int | None = Field(default=None, primary_key=True)

    # Dotted, stable id ("r.recon.subfinder.seed"). Combined with ``version``
    # this is what the audit log references — never mutate an existing pair.
    rule_id: str = Field(max_length=128, nullable=False, index=True)
    version: int = Field(default=1, nullable=False)

    description: str = Field(default="", max_length=1024)
    phase: str = Field(max_length=32, nullable=False)
    priority: int = Field(default=50, nullable=False)

    # Which personas may fire this rule. Stored as text[] for cheap ANY(...).
    personas: list[str] = Field(
        sa_column=Column(ARRAY(String(16)), nullable=False),
    )

    enabled: bool = Field(default=True, nullable=False, index=True)

    # Source provenance — which file on disk this came from and its sha256.
    source_path: str | None = Field(default=None, max_length=512, nullable=True)
    source_sha256: str | None = Field(default=None, max_length=64, nullable=True)

    # The parsed DSL: { "when": ..., "then": ..., "metadata": ... }.
    body: dict[str, Any] = Field(
        sa_column=Column(JSONB, nullable=False),
    )


__all__ = ["Rule"]
