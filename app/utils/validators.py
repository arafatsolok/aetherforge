"""Reusable pydantic-friendly validators."""

from __future__ import annotations

import re
from typing import Final

_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.fullmatch(value))


def is_valid_port(value: int) -> bool:
    return 0 < value < 65536


__all__ = ["is_valid_hostname", "is_valid_port"]
