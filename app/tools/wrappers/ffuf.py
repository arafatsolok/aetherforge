"""ffuf — fast web content fuzzer."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.ffuf_json import parse_ffuf_json
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class FfufWrapper(ToolWrapper):
    spec = ToolSpec(
        name="ffuf",
        image="aetherforge/ffuf:latest",
        category=ToolCategory.ENUMERATION,
        description="Fast web content / directory / parameter fuzzer.",
        required_caps=(),
        default_timeout_seconds=1800,
        default_memory_bytes=256 * 1024 * 1024,
        default_uid=10110,
        supports_json_output=True,
        min_persona_ordinal=1,
        version="2.1.0",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        target = params.get("target")
        if not target or "FUZZ" not in str(target):
            raise ValueError("ffuf params.target must include the FUZZ marker")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"])
        flags: list[str] = list(params.get("flags") or [])
        argv = ["-u", target, *flags]
        if "-o" not in argv:
            argv += ["-o", "/tmp/ffuf.json", "-of", "json"]
        return InvocationPlan(argv=tuple(argv),
                              expected_output_file="/tmp/ffuf.json",
                              json_output=True)

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        return parse_ffuf_json(stdout, scan_id=scan_id, iteration=iteration)


__all__ = ["FfufWrapper"]
