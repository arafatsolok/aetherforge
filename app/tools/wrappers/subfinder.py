"""subfinder — passive subdomain enumeration."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.subfinder import parse_subfinder
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class SubfinderWrapper(ToolWrapper):
    spec = ToolSpec(
        name="subfinder",
        image="aetherforge/subfinder:latest",
        category=ToolCategory.RECON_PASSIVE,
        description="Fast passive subdomain enumeration.",
        required_caps=(),
        default_timeout_seconds=600,
        default_memory_bytes=256 * 1024 * 1024,
        default_uid=10107,
        supports_json_output=True,
        min_persona_ordinal=0,
        version="2.6.8",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("subfinder params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or [])
        if not any(f in flags for f in ("-json", "-jsonl")):
            flags.append("-json")
        if "-silent" not in flags:
            flags.append("-silent")
        argv = ["-d", target, *flags]
        return InvocationPlan(argv=tuple(argv), json_output=True)

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        return parse_subfinder(stdout, scan_id=scan_id, iteration=iteration)


__all__ = ["SubfinderWrapper"]
