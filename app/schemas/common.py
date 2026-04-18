"""Common response envelopes reused across the API."""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Envelope[T](BaseModel):
    """Single-item response envelope."""

    model_config = ConfigDict(from_attributes=True)

    data: T


class PageMeta(BaseModel):
    page: int = Field(default=1, ge=1)
    size: int = Field(default=25, ge=1, le=500)
    total: int = Field(default=0, ge=0)
    has_next: bool = False


class Page[T](BaseModel):
    """Paginated response envelope."""

    model_config = ConfigDict(from_attributes=True)

    items: list[T] = Field(default_factory=list)
    meta: PageMeta = Field(default_factory=PageMeta)


class ErrorBody(BaseModel):
    type: str
    detail: str | dict[str, object] | list[object]


class ErrorResponse(BaseModel):
    error: ErrorBody


__all__ = ["Envelope", "ErrorBody", "ErrorResponse", "Page", "PageMeta"]
