"""masscan — high-speed async TCP scanner."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers import make_fact
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class MasscanWrapper(ToolWrapper):
    spec = ToolSpec(
        name="masscan",
        image="aetherforge/masscan:latest",
        category=ToolCategory.RECON_ACTIVE,
        description="Very fast TCP port scanner.",
        required_caps=("NET_RAW", "NET_ADMIN"),
        default_timeout_seconds=900,
        default_memory_bytes=256 * 1024 * 1024,
        default_uid=10101,
        supports_json_output=True,
        min_persona_ordinal=1,
        version="1.3.2",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("masscan params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        ports = params.get("ports") or ["1-65535"]
        rate = int(params.get("rate") or 1000)
        flags: list[str] = list(params.get("flags") or [])

        argv: list[str] = [*list(flags), target, "-p", ",".join(str(p) for p in ports), "--rate", str(rate), "-oJ", "/tmp/masscan.json"]
        return InvocationPlan(argv=tuple(argv), expected_output_file="/tmp/masscan.json", json_output=True)

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        _ = stderr, exit_code
        import orjson
        facts: list[Fact] = []
        for raw in stdout.splitlines():
            line = raw.strip().rstrip(b",")
            if not line or line in (b"[", b"]"):
                continue
            try:
                doc = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            for p in doc.get("ports", []):
                facts.append(make_fact(
                    fact_type="port_open",
                    body={"host": doc.get("ip", ""), "port": int(p.get("port", 0)),
                          "protocol": p.get("proto", "tcp"), "state": "open"},
                    source_tool="masscan",
                    scan_id=scan_id,
                    iteration=iteration,
                ))
        return facts


__all__ = ["MasscanWrapper"]
