"""nmap — TCP / UDP port + service scanner."""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers.nmap_xml import parse_nmap_xml
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class NmapWrapper(ToolWrapper):
    spec = ToolSpec(
        name="nmap",
        image="aetherforge/nmap:latest",
        category=ToolCategory.RECON_ACTIVE,
        description="TCP/UDP port scanner + service / version / NSE detection.",
        required_caps=("NET_RAW",),
        default_timeout_seconds=1800,
        default_memory_bytes=512 * 1024 * 1024,
        default_uid=10100,
        supports_json_output=False,
        min_persona_ordinal=1,
        version="7.95",
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        if not params.get("target"):
            raise ValueError("nmap params.target is required")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        target = str(params["target"]).strip()
        ports = params.get("ports") or []
        flags: list[str] = list(params.get("flags") or [])

        argv: list[str] = list(flags)

        # Ensure XML output on stdout so our parser can consume it cleanly.
        if not any(f in flags for f in ("-oX", "-oA", "-oG", "-oN")):
            argv += ["-oX", "-"]

        if ports:
            port_spec = ",".join(str(int(p)) for p in ports if _is_valid_port(p))
            if port_spec:
                argv += ["-p", port_spec]

        # Safety — never allow -sO (protocol scan) under gray persona
        # without an explicit opt-in (rule metadata). Enforced earlier in
        # the command generator via argv-token sanitisation.
        argv.append(target)

        return InvocationPlan(argv=tuple(argv))

    def parse(
        self, *, stdout: bytes, stderr: bytes, exit_code: int,
        scan_id: str, iteration: int,
    ) -> list[Fact]:
        _ = stderr, exit_code
        return parse_nmap_xml(stdout, scan_id=scan_id, iteration=iteration)


def _is_valid_port(v: object) -> bool:
    try:
        p = int(v)
    except (TypeError, ValueError):
        return False
    return 0 < p < 65536


__all__ = ["NmapWrapper"]
