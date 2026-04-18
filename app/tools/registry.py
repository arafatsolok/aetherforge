"""Tool registry.

Phase 0 ships an empty registry with the lookup API. Phase 2 adds
auto-discovery of subclasses in ``app.tools.wrappers.*``.
"""

from __future__ import annotations

from app.tools.base import ToolSpec, ToolWrapper


class ToolRegistry:
    """Dict-like store of ``ToolWrapper`` instances keyed by tool name."""

    def __init__(self) -> None:
        self._wrappers: dict[str, ToolWrapper] = {}

    # -- Lifecycle ---------------------------------------------------------
    def register(self, wrapper: ToolWrapper) -> None:
        if not isinstance(wrapper.spec, ToolSpec):
            raise TypeError(f"{type(wrapper).__name__} missing ToolSpec")
        if wrapper.spec.name in self._wrappers:
            raise ValueError(f"tool already registered: {wrapper.spec.name!r}")
        self._wrappers[wrapper.spec.name] = wrapper

    def unregister(self, name: str) -> None:
        self._wrappers.pop(name, None)

    # -- Lookup ------------------------------------------------------------
    def get(self, name: str) -> ToolWrapper:
        try:
            return self._wrappers[name]
        except KeyError as err:
            raise KeyError(f"unknown tool: {name!r}") from err

    def has(self, name: str) -> bool:
        return name in self._wrappers

    def all(self) -> list[ToolWrapper]:
        return list(self._wrappers.values())

    def names(self) -> list[str]:
        return sorted(self._wrappers)


registry = ToolRegistry()


__all__ = ["ToolRegistry", "registry"]
