"""Auto-discover and register every ``ToolWrapper`` subclass.

Called once at worker boot:

  1. Load ``configs/tools.yaml`` -> per-tool overrides (image tag,
     memory cap, cpu shares, caps).
  2. Walk ``app.tools.wrappers`` — import every submodule so wrapper
     classes are registered side-effect-style.
  3. Instantiate each wrapper with its overlay-merged ``ToolSpec``.
  4. Return the populated registry.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Any

import yaml

from app.logging_config import get_logger
from app.tools.base import ToolCategory, ToolSpec, ToolWrapper
from app.tools.registry import ToolRegistry

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------
def load_tools_overlay(yaml_path: Path) -> dict[str, dict[str, Any]]:
    if not yaml_path.exists():
        return {}
    with yaml_path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return dict(doc.get("tools") or {})


def merge_spec(base: ToolSpec, overlay: dict[str, Any]) -> ToolSpec:
    """Overlay-merge YAML values onto a class-declared ``ToolSpec``."""
    if not overlay:
        return base

    # Only replace fields actually present in the YAML.
    def _pick(key: str, default: Any) -> Any:
        return overlay.get(key, default)

    category = base.category
    if "category" in overlay:
        try:
            category = ToolCategory(overlay["category"])
        except ValueError:
            log.warning("tools.overlay.unknown_category",
                        tool=base.name, category=overlay["category"])

    return ToolSpec(
        name=base.name,
        image=_pick("image", base.image),
        category=category,
        description=base.description,
        required_caps=tuple(_pick("cap_add", list(base.required_caps))),
        default_timeout_seconds=int(_pick("default_timeout_seconds", base.default_timeout_seconds)),
        default_memory_bytes=int(_pick("memory_bytes", base.default_memory_bytes)),
        default_uid=base.default_uid,
        supports_json_output=bool(_pick("supports_json_output", base.supports_json_output)),
        min_persona_ordinal=int(_pick("min_persona_ordinal", base.min_persona_ordinal)),
        version=str(_pick("version", base.version)),
        labels=tuple(_pick("labels", list(base.labels))),
    )


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------
def discover_wrapper_classes() -> list[type[ToolWrapper]]:
    """Walk ``app.tools.wrappers`` and return every concrete subclass."""
    import app.tools.wrappers as pkg

    classes: list[type[ToolWrapper]] = []
    for info in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        mod = importlib.import_module(info.name)
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, ToolWrapper)
                and attr is not ToolWrapper
                and getattr(attr, "__abstractmethods__", None) == frozenset()
            ):
                classes.append(attr)

    # Deterministic order — test stability + reproducible seeding.
    classes.sort(key=lambda c: c.__module__ + "." + c.__name__)
    return classes


def bootstrap_registry(*, configs_dir: Path) -> ToolRegistry:
    """Load every wrapper + overlay + populate the registry."""
    overlay = load_tools_overlay(configs_dir / "tools.yaml")
    registry = ToolRegistry()

    for cls in discover_wrapper_classes():
        wrapper = cls()
        merged = merge_spec(wrapper.spec, overlay.get(wrapper.spec.name, {}))
        # Replace the class-level spec with the overlay-merged one.
        object.__setattr__(wrapper, "spec", merged)
        registry.register(wrapper)

    log.info("tools.registry.bootstrapped", tools=registry.names())
    return registry


__all__ = [
    "bootstrap_registry",
    "discover_wrapper_classes",
    "load_tools_overlay",
    "merge_spec",
]
