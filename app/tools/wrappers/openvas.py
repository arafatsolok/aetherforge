"""OpenVAS / Greenbone wrapper — talks GMP, not exec.

Like Metasploit, OpenVAS is a long-running daemon. The ``build_invocation``
returns a pseudo-argv consumed by the Phase 5 GMP driver.
"""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers import make_fact
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class OpenvasWrapper(ToolWrapper):
    spec = ToolSpec(
        name="openvas",
        image="aetherforge/openvas:latest",
        category=ToolCategory.VULN_SCAN,
        description="OpenVAS / Greenbone GMP driver (Phase 5 wires protocol).",
        required_caps=(),
        default_timeout_seconds=7200,
        default_memory_bytes=2 * 1024 * 1024 * 1024,
        default_uid=1000,
        supports_json_output=True,
        min_persona_ordinal=1,
        version="22.4.41",
        labels=("rpc",),
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("openvas params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        scan_config = str(params.get("config") or "Full and fast").strip()
        argv = ["--target", target, "--config", scan_config]
        return InvocationPlan(argv=tuple(argv))

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        """Parse the JSON envelope a GMP driver should produce.

        Expected shape:
            ``{"results": [{"nvt_oid", "severity", "host", "port",
                            "description"}]}``

        Real GMP integration is an operator extension (the upstream
        ``immauss/openvas`` image speaks GMP/XML, not JSON; the driver
        layer is responsible for the translation). This parser stays
        permissive so tests + replay work with synthetic JSON inputs.
        """
        _ = stderr, exit_code
        import orjson
        facts: list[Fact] = []
        try:
            doc = orjson.loads(stdout)
        except orjson.JSONDecodeError:
            return facts
        for r in doc.get("results", []):
            facts.append(make_fact(
                fact_type="vuln_custom",
                body={
                    "tool": "openvas",
                    "nvt_oid": r.get("nvt_oid"),
                    "severity": r.get("severity"),
                    "host": r.get("host"),
                    "port": r.get("port"),
                    "description": r.get("description", ""),
                },
                source_tool="openvas",
                scan_id=scan_id,
                iteration=iteration,
            ))
        return facts


__all__ = ["OpenvasWrapper"]
