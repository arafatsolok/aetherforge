"""Generic output-parser helpers reused across tool wrappers (Phase 2+)."""

from __future__ import annotations

import json
import re
from typing import Any

import orjson
from defusedxml import ElementTree as SafeET

ANSI_ESCAPE_RE = re.compile(rb"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(blob: bytes) -> bytes:
    """Strip ANSI colour codes from a tool's stdout before persistence."""
    return ANSI_ESCAPE_RE.sub(b"", blob)


def try_json(blob: bytes) -> Any | None:
    """Attempt a fast JSON parse; return ``None`` on failure (no exceptions)."""
    try:
        return orjson.loads(blob)
    except (orjson.JSONDecodeError, TypeError, ValueError):
        try:
            return json.loads(blob.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


def try_xml(blob: bytes) -> SafeET.Element | None:
    """Attempt a safe XML parse (defusedxml) of a tool output blob."""
    try:
        return SafeET.fromstring(blob)
    except (SafeET.ParseError, ValueError):
        return None


__all__ = ["strip_ansi", "try_json", "try_xml"]
