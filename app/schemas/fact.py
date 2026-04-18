"""Fact response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import FactType


class FactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ulid: str
    scan_id: int
    execution_id: int | None = None
    fact_type: FactType
    source_tool: str
    iteration: int
    fingerprint: str
    body: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


__all__ = ["FactRead"]
