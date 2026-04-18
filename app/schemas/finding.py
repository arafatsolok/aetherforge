"""Finding response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Severity


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ulid: str
    scan_id: int
    rule_id: str
    tool: str
    title: str
    description: str
    severity: Severity
    cvss_score: float | None = None
    cve_id: str | None = None
    affected: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str
    status: str
    confirmed: bool
    triaged_by: str | None = None
    triage_notes: str = ""
    created_at: datetime
    updated_at: datetime


__all__ = ["FindingRead"]
