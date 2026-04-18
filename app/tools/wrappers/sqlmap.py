"""sqlmap — SQL injection detection + exploitation."""

from __future__ import annotations

import re
from typing import Any

from app.core.rule_engine import Fact
from app.parsers.generic_text import parse_sqlmap_text
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class SqlmapWrapper(ToolWrapper):
    spec = ToolSpec(
        name="sqlmap",
        image="aetherforge/sqlmap:latest",
        category=ToolCategory.EXPLOIT,
        description="SQLi detection + DB dump + OS shell.",
        required_caps=(),
        default_timeout_seconds=1800,
        default_memory_bytes=512 * 1024 * 1024,
        default_uid=10104,
        supports_json_output=False,
        min_persona_ordinal=1,
        version="1.8.12",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("sqlmap params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or [])

        argv = ["-u", target, "--batch"]
        # Force non-interactive, bound output dir.
        if "--output-dir" not in " ".join(flags):
            flags.append("--output-dir=/tmp/sqlmap")
        argv += [f for f in flags if f != "--batch"]
        return InvocationPlan(argv=tuple(argv))

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        # Extract the URL sqlmap is testing right out of its own banner
        # (``[*] testing URL 'http://…'``) — works without bindings.
        target_url = _extract_target_url(stdout)
        return parse_sqlmap_text(
            stdout,
            scan_id=scan_id,
            iteration=iteration,
            target_url=target_url,
        )


_URL_RE = re.compile(rb"testing URL ['\"]([^'\"]+)['\"]", re.IGNORECASE)


def _extract_target_url(stdout: bytes) -> str:
    m = _URL_RE.search(stdout)
    return m.group(1).decode("utf-8", errors="replace") if m else ""


__all__ = ["SqlmapWrapper"]
