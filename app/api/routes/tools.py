"""Tool registry introspection — read-only."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.api.dependencies import SettingsDep
from app.tools.registry import ToolRegistry
from app.tools.registry_loader import bootstrap_registry

router = APIRouter()


@lru_cache(maxsize=1)
def _registry_for(configs_dir_str: str) -> ToolRegistry:
    """Cache the registry by configs_dir (str for hashability)."""
    return bootstrap_registry(configs_dir=Path(configs_dir_str))


def _get_registry(settings) -> ToolRegistry:               # type: ignore[no-untyped-def]
    return _registry_for(str(settings.configs_dir))


@router.get("", summary="List registered tools")
async def list_tools(settings: SettingsDep) -> dict[str, object]:
    reg = _get_registry(settings)
    return {
        "tools": [
            {
                "name": w.spec.name,
                "image": w.spec.image,
                "category": w.spec.category.value,
                "description": w.spec.description,
                "cap_add": list(w.spec.required_caps),
                "default_timeout_seconds": w.spec.default_timeout_seconds,
                "default_memory_bytes": w.spec.default_memory_bytes,
                "supports_json_output": w.spec.supports_json_output,
                "min_persona_ordinal": w.spec.min_persona_ordinal,
                "version": w.spec.version,
                "labels": list(w.spec.labels),
            }
            for w in reg.all()
        ],
        "count": len(reg.all()),
    }


@router.get("/{name}", summary="Inspect a single tool")
async def get_tool(name: str, settings: SettingsDep) -> dict[str, object]:
    reg = _get_registry(settings)
    if not reg.has(name):
        raise HTTPException(status_code=404, detail=f"tool not found: {name}")
    w = reg.get(name)
    return {
        "name": w.spec.name,
        "image": w.spec.image,
        "category": w.spec.category.value,
        "description": w.spec.description,
        "cap_add": list(w.spec.required_caps),
        "default_timeout_seconds": w.spec.default_timeout_seconds,
        "default_memory_bytes": w.spec.default_memory_bytes,
        "supports_json_output": w.spec.supports_json_output,
        "min_persona_ordinal": w.spec.min_persona_ordinal,
        "version": w.spec.version,
        "labels": list(w.spec.labels),
    }
