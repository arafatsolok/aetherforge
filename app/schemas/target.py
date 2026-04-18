"""Target request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import Persona
from app.utils.security import is_cidr_forbidden
from app.utils.validators import is_valid_hostname


class TargetBase(BaseModel):
    slug: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    description: str = Field(default="", max_length=1024)
    owner: str = Field(default="", max_length=256)
    cidrs: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    allowed_personas: list[Persona] = Field(
        default_factory=lambda: [Persona.WHITE],
        min_length=1,
    )
    tags: list[str] = Field(default_factory=list, max_length=32)
    notes: str = Field(default="", max_length=8192)
    meta: dict[str, Any] = Field(default_factory=dict)
    active: bool = True
    # Black-persona safety gate. Default False = production-safe.
    replica_only: bool = False

    @field_validator("cidrs")
    @classmethod
    def _validate_cidrs(cls, v: list[str]) -> list[str]:
        import ipaddress

        for c in v:
            ipaddress.ip_network(c, strict=False)  # raises ValueError on bad input
            if is_cidr_forbidden(c, ["0.0.0.0/0"]):
                # Allow private/lab CIDRs; reject anything covering the whole net.
                if c == "0.0.0.0/0":
                    raise ValueError("CIDR 0.0.0.0/0 is forbidden")
        return v

    @field_validator("domains")
    @classmethod
    def _validate_domains(cls, v: list[str]) -> list[str]:
        for d in v:
            if not is_valid_hostname(d):
                raise ValueError(f"invalid hostname: {d!r}")
        return v


class TargetCreate(TargetBase):
    """Request body for POST /api/v1/targets."""


class TargetUpdate(BaseModel):
    """Partial update — every field optional."""

    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, max_length=1024)
    owner: str | None = Field(default=None, max_length=256)
    cidrs: list[str] | None = None
    domains: list[str] | None = None
    allowed_personas: list[Persona] | None = None
    tags: list[str] | None = None
    notes: str | None = None
    meta: dict[str, Any] | None = None
    active: bool | None = None
    replica_only: bool | None = None


class TargetRead(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ulid: str
    created_at: datetime
    updated_at: datetime
    last_scanned_at: datetime | None = None


__all__ = ["TargetBase", "TargetCreate", "TargetRead", "TargetUpdate"]
