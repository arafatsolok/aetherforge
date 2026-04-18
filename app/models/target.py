"""Target model — anything AetherForge is authorised to probe.

A Target is the SCOPE of a scan. It has:
  * a list of CIDRs and/or domains
  * a set of personas it accepts (e.g. replica accepts ``black``,
    production only accepts ``white``)
  * an owner for provenance + incident escalation
"""


from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import ARRAY, Column, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from app.config import Persona
from app.models.base import TimestampMixin, ULIDMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class Target(SQLModel, TimestampMixin, ULIDMixin, table=True):
    """A scope envelope that scans run against."""

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_targets_slug"),
        Index("ix_targets_tags", "tags", postgresql_using="gin"),
    )

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(max_length=64, index=True)
    description: str = Field(default="", max_length=1024)
    owner: str = Field(default="", max_length=256)

    # Scope: explicit CIDR + domain lists. Queries on these happen at the
    # command-generator layer. Stored as Postgres arrays so we can use
    # simple SQL containment queries.
    cidrs: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(64)), nullable=False, server_default="{}"),
    )
    domains: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(253)), nullable=False, server_default="{}"),
    )

    # Which personas this target accepts. A scan requesting a persona not in
    # this list is rejected at API ingress.
    allowed_personas: list[str] = Field(
        default_factory=lambda: [Persona.WHITE.value],
        sa_column=Column(ARRAY(String(16)), nullable=False),
    )

    tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(64)), nullable=False, server_default="{}"),
    )
    notes: str = Field(default="", max_length=8192)

    # Free-form operational metadata (e.g. replica ID, env name, cloud acct).
    meta: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    active: bool = Field(default=True, nullable=False)

    # SAFETY GATE — black persona REFUSES any target without this set.
    # Operators must explicitly mark lab/replica targets as `replica_only`
    # to enable full kill-chain exploitation. Default False = production-safe.
    replica_only: bool = Field(default=False, nullable=False)

    last_scanned_at: datetime | None = Field(default=None, nullable=True)

    scans: list["Scan"] = Relationship(
        back_populates="target",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )

    # -- Helpers --------------------------------------------------------------
    def accepts_persona(self, persona: Persona) -> bool:
        """True iff the target permits the given persona.

        Black persona has the additional ``replica_only`` requirement so
        full-kill-chain runs can NEVER hit a production target by
        accident, even if it's listed in ``allowed_personas``.
        """
        if persona.value not in self.allowed_personas:
            return False
        return not (persona == Persona.BLACK and not self.replica_only)


__all__ = ["Target"]
