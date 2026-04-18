"""Rule schemas + DSL shape definitions for the public API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.config import Persona
from app.models.enums import RulePhase


class RuleBody(BaseModel):
    """Parsed DSL body. Stored verbatim in the ``rules.body`` JSONB."""

    model_config = ConfigDict(extra="forbid")

    when: dict[str, Any]
    then: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleBase(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    version: int = Field(default=1, ge=1)
    description: str = Field(default="", max_length=1024)
    phase: RulePhase
    priority: int = Field(default=50, ge=0, le=1000)
    personas: list[Persona] = Field(min_length=1)
    enabled: bool = True


class RuleCreate(RuleBase):
    body: RuleBody


class RuleRead(RuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ulid: str
    source_path: str | None = None
    source_sha256: str | None = None
    created_at: datetime
    updated_at: datetime
    body: dict[str, Any]


class RuleValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    rule_id: str | None = None


__all__ = [
    "RuleBase",
    "RuleBody",
    "RuleCreate",
    "RuleRead",
    "RuleValidationResult",
]
