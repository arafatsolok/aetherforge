"""Scan request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.config import Persona
from app.models.enums import ScanState


class ScanCreate(BaseModel):
    target_slug: str = Field(min_length=1, max_length=64)
    persona: Persona
    overrides: dict[str, Any] = Field(default_factory=dict)
    started_by: str = Field(default="api", max_length=128)


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ulid: str
    target_id: int
    persona: Persona
    state: ScanState
    workflow_id: str | None = None
    run_id: str | None = None
    started_by: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    iterations: int
    executions_total: int
    facts_total: int
    findings_total: int
    terminal_reason: str | None = None
    created_at: datetime
    updated_at: datetime


__all__ = ["ScanCreate", "ScanRead"]
