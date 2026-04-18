"""Wapiti — web application vulnerability scanner."""

from __future__ import annotations

from typing import Any

import orjson

from app.core.rule_engine import Fact
from app.parsers import make_fact
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class WapitiWrapper(ToolWrapper):
    spec = ToolSpec(
        name="wapiti",
        image="aetherforge/wapiti:latest",
        category=ToolCategory.VULN_SCAN,
        description="Web app vulnerability scanner.",
        required_caps=(),
        default_timeout_seconds=1800,
        default_memory_bytes=512 * 1024 * 1024,
        default_uid=10106,
        supports_json_output=True,
        min_persona_ordinal=1,
        version="3.2.1",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("wapiti params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or [])
        argv = ["-u", target, "-f", "json", "-o", "/tmp/wapiti.json", *flags]
        return InvocationPlan(
            argv=tuple(argv),
            expected_output_file="/tmp/wapiti.json",
            json_output=True,
        )

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        try:
            doc = orjson.loads(stdout)
        except orjson.JSONDecodeError:
            return []

        facts: list[Fact] = []
        for category, vulns in (doc.get("vulnerabilities") or {}).items():
            for v in vulns:
                facts.append(make_fact(
                    fact_type="vuln_custom",
                    body={
                        "tool": "wapiti",
                        "category": category,
                        "url": v.get("http_request", {}).get("url", ""),
                        "method": v.get("http_request", {}).get("method", ""),
                        "info": v.get("info", ""),
                        "level": v.get("level"),
                    },
                    source_tool="wapiti",
                    scan_id=scan_id,
                    iteration=iteration,
                ))
        return facts


__all__ = ["WapitiWrapper"]
