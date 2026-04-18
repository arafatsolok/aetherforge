"""nikto — legacy-style web vulnerability scanner."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.generic_text import parse_nikto_text
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class NiktoWrapper(ToolWrapper):
    spec = ToolSpec(
        name="nikto",
        image="aetherforge/nikto:latest",
        category=ToolCategory.VULN_SCAN,
        description="Legacy web vulnerability scanner.",
        required_caps=(),
        default_timeout_seconds=1800,
        default_memory_bytes=256 * 1024 * 1024,
        default_uid=10105,
        supports_json_output=False,
        min_persona_ordinal=1,
        version="2.5.0",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("nikto params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or [])
        argv = ["-h", target, "-nointeractive", *flags]
        return InvocationPlan(argv=tuple(argv))

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        return parse_nikto_text(
            stdout, scan_id=scan_id, iteration=iteration, target_url=""
        )


__all__ = ["NiktoWrapper"]
