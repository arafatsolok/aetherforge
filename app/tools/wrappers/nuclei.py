"""nuclei — ProjectDiscovery template-driven vulnerability scanner."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.nuclei_jsonl import parse_nuclei_jsonl
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class NucleiWrapper(ToolWrapper):
    spec = ToolSpec(
        name="nuclei",
        image="aetherforge/nuclei:latest",
        category=ToolCategory.VULN_SCAN,
        description="Template-driven vulnerability scanner.",
        required_caps=(),
        default_timeout_seconds=3600,
        default_memory_bytes=1024 * 1024 * 1024,
        default_uid=10112,            # `scanner` user added by our Dockerfile
        supports_json_output=True,
        min_persona_ordinal=1,
        version="3.3.5",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("nuclei params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or [])

        argv: list[str] = ["-target", target, "-silent"]
        # Always emit JSONL unless the rule overrode it.
        if not any(f in flags for f in ("-json", "-jsonl", "-silent-json")):
            argv.append("-jsonl")
        argv += flags
        return InvocationPlan(argv=tuple(argv), json_output=True)

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        return parse_nuclei_jsonl(stdout, scan_id=scan_id, iteration=iteration)


__all__ = ["NucleiWrapper"]
