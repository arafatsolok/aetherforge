"""httpx — HTTP probe + tech detect + TLS grabber."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.httpx_jsonl import parse_httpx_jsonl
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class HttpxWrapper(ToolWrapper):
    spec = ToolSpec(
        name="httpx",
        image="aetherforge/httpx:latest",
        category=ToolCategory.RECON_ACTIVE,
        description="HTTP probe + tech / TLS / title fingerprinting.",
        required_caps=(),
        default_timeout_seconds=600,
        default_memory_bytes=256 * 1024 * 1024,
        default_uid=10109,
        supports_json_output=True,
        min_persona_ordinal=1,
        version="1.6.9",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("httpx params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or [])

        argv: list[str] = ["-u", target]
        if not any(f in flags for f in ("-json", "-jsonl")):
            flags.append("-json")
        if "-silent" not in flags:
            flags.append("-silent")
        argv += flags
        return InvocationPlan(argv=tuple(argv), json_output=True)

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        return parse_httpx_jsonl(stdout, scan_id=scan_id, iteration=iteration)


__all__ = ["HttpxWrapper"]
