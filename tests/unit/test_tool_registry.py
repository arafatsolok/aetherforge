"""Unit tests for the tool registry + bootstrap loader."""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.tools.base import ToolCategory, ToolSpec
from app.tools.registry_loader import (
    bootstrap_registry,
    discover_wrapper_classes,
    merge_spec,
)


@pytest.mark.unit
class TestRegistryBootstrap:
    def test_discovers_all_13_wrappers(self) -> None:
        classes = discover_wrapper_classes()
        names = {c.__name__ for c in classes}
        assert {
            "AmassWrapper", "FfufWrapper", "HttpxWrapper", "MasscanWrapper",
            "MetasploitWrapper", "NettackerWrapper", "NiktoWrapper",
            "NmapWrapper", "NucleiWrapper", "OpenvasWrapper",
            "SqlmapWrapper", "SubfinderWrapper", "WapitiWrapper",
        } <= names

    def test_bootstrap_yields_complete_registry(self) -> None:
        s = get_settings()
        reg = bootstrap_registry(configs_dir=s.configs_dir)
        names = reg.names()
        assert {"nmap", "nuclei", "subfinder", "httpx", "ffuf",
                "sqlmap", "nikto", "wapiti", "amass", "masscan",
                "metasploit", "openvas", "nettacker"} <= set(names)
        assert len(names) == 13


@pytest.mark.unit
class TestSpecMerge:
    def test_overlay_replaces_image(self) -> None:
        base = ToolSpec(
            name="x", image="default:1", category=ToolCategory.RECON_PASSIVE,
            description="", required_caps=(), default_timeout_seconds=60,
            default_memory_bytes=1024, default_uid=1000,
        )
        merged = merge_spec(base, {"image": "custom:2", "memory_bytes": 4096})
        assert merged.image == "custom:2"
        assert merged.default_memory_bytes == 4096

    def test_overlay_unknown_category_keeps_base(self) -> None:
        base = ToolSpec(
            name="x", image="i", category=ToolCategory.RECON_PASSIVE,
            description="", required_caps=(), default_timeout_seconds=60,
            default_memory_bytes=1024, default_uid=1000,
        )
        merged = merge_spec(base, {"category": "nonsense"})
        assert merged.category == ToolCategory.RECON_PASSIVE
