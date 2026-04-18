"""Shared top-level exceptions.

Keep this module dependency-free so any layer can import without cycles.
"""

from __future__ import annotations


class AetherForgeError(Exception):
    """Base for every domain-level exception."""


class ConfigurationError(AetherForgeError):
    """Invalid / missing configuration."""


class ScopeViolation(AetherForgeError):
    """Attempted to act against a target outside the declared scope."""


class ToolExecutionError(AetherForgeError):
    """Tool container exited non-zero or timed out."""


class ParserError(AetherForgeError):
    """Tool output could not be parsed into facts."""


class NotReady(AetherForgeError):
    """Component invoked before init."""


__all__ = [
    "AetherForgeError",
    "ConfigurationError",
    "NotReady",
    "ParserError",
    "ScopeViolation",
    "ToolExecutionError",
]
