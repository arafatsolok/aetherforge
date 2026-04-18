"""Universal tool wrapper framework.

Each integrated security tool ships as:
  * a ``ToolWrapper`` subclass  (this package)
  * a Dockerfile                (``docker/tools/<tool>/``)
  * one or more rule YAMLs      (``rules/<persona>/<tool>/``)

Phase 2 fills in every wrapper + the registry autoloader.
"""

from __future__ import annotations

from app.tools.base import ToolCategory, ToolSpec, ToolWrapper
from app.tools.registry import ToolRegistry

__all__ = ["ToolCategory", "ToolRegistry", "ToolSpec", "ToolWrapper"]
