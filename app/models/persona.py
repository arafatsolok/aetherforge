"""PersonaDefinition — DB-backed per-environment persona overrides.

configs/personas.yaml is the source of truth at boot; rows here let an
operator carve out per-target or time-windowed exceptions at runtime
without redeploying the orchestrator.
"""


from typing import Any

from sqlalchemy import ARRAY, Column, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

from app.models.base import TimestampMixin, ULIDMixin


class PersonaDefinition(SQLModel, TimestampMixin, ULIDMixin, table=True):
    __tablename__ = "persona_definitions"
    __table_args__ = (UniqueConstraint("name", name="uq_persona_name"),)

    id: int | None = Field(default=None, primary_key=True)

    name: str = Field(max_length=16, nullable=False, index=True)
    description: str = Field(default="", max_length=1024)

    rate_limit_rps: int = Field(default=2, nullable=False)

    allowed_phases: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(32)), nullable=False, server_default="{}"),
    )

    capabilities: dict[str, bool] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )

    # Optional target scoping — if non-null this persona definition only
    # applies to matching targets.
    scoped_target_tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String(64)), nullable=False, server_default="{}"),
    )

    meta: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, server_default="{}"),
    )


__all__ = ["PersonaDefinition"]
