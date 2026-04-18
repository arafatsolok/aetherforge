"""Repository layer — stateless CRUD classes that take a Session.

Kept deliberately thin (no business logic). Services compose them.
"""

from __future__ import annotations

from app.repositories.rule import RuleRepository
from app.repositories.target import TargetRepository

__all__ = ["RuleRepository", "TargetRepository"]
