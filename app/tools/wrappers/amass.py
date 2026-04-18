"""amass — OWASP subdomain enumeration + intelligence."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.subfinder import parse_subfinder
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class AmassWrapper(ToolWrapper):
    spec = ToolSpec(
        name="amass",
        image="aetherforge/amass:latest",
        category=ToolCategory.RECON_PASSIVE,
        description="Deep subdomain + DNS intel (passive by default).",
        required_caps=(),
        default_timeout_seconds=3600,
        default_memory_bytes=512 * 1024 * 1024,
        default_uid=10108,
        supports_json_output=True,
        min_persona_ordinal=0,
        version="4.2.0",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("amass params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        flags: list[str] = list(params.get("flags") or ["enum", "-passive"])

        argv = list(flags)
        if "-d" not in argv:
            argv += ["-d", target]
        if not any(f in argv for f in ("-json", "-silent")):
            argv += ["-silent"]
        return InvocationPlan(argv=tuple(argv), json_output=True)

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        # amass stdout is newline-separated hosts — reuse subfinder parser.
        facts = parse_subfinder(stdout, scan_id=scan_id, iteration=iteration)
        # Re-label source_tool
        for i, f in enumerate(facts):
            facts[i] = f.__class__(
                fact_type=f.fact_type,
                body={**f.body, "source": "amass"},
                source_tool="amass",
                scan_id=f.scan_id,
                iteration=f.iteration,
                fingerprint=f.fingerprint,
            )
        return facts


__all__ = ["AmassWrapper"]
