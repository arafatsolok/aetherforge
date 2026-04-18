"""OWASP Nettacker — multi-module pentest framework."""

from __future__ import annotations

from typing import Any

import orjson

from app.core.rule_engine import Fact
from app.parsers import make_fact
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class NettackerWrapper(ToolWrapper):
    spec = ToolSpec(
        name="nettacker",
        image="aetherforge/nettacker:latest",
        category=ToolCategory.VULN_SCAN,
        description="OWASP Nettacker — multi-module network+web pentest framework.",
        required_caps=(),
        default_timeout_seconds=3600,
        default_memory_bytes=1024 * 1024 * 1024,
        default_uid=10102,
        supports_json_output=True,
        min_persona_ordinal=1,
        version="0.4.0",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("nettacker params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or ["-m", "all"])

        argv = ["-i", target, "-o", "/tmp/nettacker.json", "-g", "info", *flags]
        return InvocationPlan(
            argv=tuple(argv),
            expected_output_file="/tmp/nettacker.json",
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
        # Nettacker JSON shape varies by module — we pull the common
        # "event" list and keep free-form bodies.
        for ev in doc.get("events", []) if isinstance(doc, dict) else []:
            facts.append(make_fact(
                fact_type="vuln_custom",
                body={"tool": "nettacker", **ev},
                source_tool="nettacker",
                scan_id=scan_id,
                iteration=iteration,
            ))
        return facts


__all__ = ["NettackerWrapper"]
