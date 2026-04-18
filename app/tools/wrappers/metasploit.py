"""Metasploit RPC wrapper — RPC-driven, NOT ephemeral.

Unlike the other tools, metasploit runs as a long-lived ``msfrpcd``
daemon (started by docker-compose profile ``exploit``). This wrapper's
``build_invocation`` returns an argv the Phase 5 RPC driver translates
into pymetasploit3 calls — it is NOT meant to be docker-executed.

Phase 2 provides the shape; Phase 5 wires the actual
``MetasploitRPCClient``.
"""

from __future__ import annotations

from typing import Any

from app.core.rule_engine import Fact
from app.parsers import make_fact
from app.tools.base import InvocationPlan, ToolCategory, ToolSpec, ToolWrapper


class MetasploitWrapper(ToolWrapper):
    spec = ToolSpec(
        name="metasploit",
        image="aetherforge/metasploit:latest",   # tag used only for provenance
        category=ToolCategory.EXPLOIT,
        description="Metasploit RPC driver (Phase 5 wires RPC).",
        required_caps=(),
        default_timeout_seconds=1800,
        default_memory_bytes=1024 * 1024 * 1024,
        default_uid=10103,
        supports_json_output=True,
        min_persona_ordinal=2,
        version="6.4",
        labels=("rpc",),              # flag for the executor: skip Docker spawn
    )

    def validate_params(self, params: dict[str, Any]) -> None:
        module = params.get("module")
        target = params.get("target")
        if not module or not target:
            raise ValueError("metasploit params require `module` and `target`")

    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        module = str(params["module"]).strip()
        target = str(params["target"]).strip()
        port = params.get("port")
        mode = (params.get("mode") or "check").strip()

        # argv is a *pseudo* spec the Phase 5 RPC driver consumes.
        argv: list[str] = [
            "--module", module,
            "--target", target,
            "--mode", mode,
        ]
        if port is not None:
            argv += ["--port", str(int(port))]
        if session := params.get("session"):
            argv += ["--session", str(session)]

        return InvocationPlan(argv=tuple(argv))

    def parse(self, *, stdout: bytes, stderr: bytes, exit_code: int,
              scan_id: str, iteration: int) -> list[Fact]:
        """Parse the JSON envelope written by ``MsfExecutor``.

        ``MsfExecutor`` serialises the RPC payload as
            {"module": "...", "mode": "...", "target": "...",
             "port": ..., "session": ..., "ok": bool, "payload": {...}}

        Emits ``shell_handle`` if the payload carries a session id, plus
        a ``vuln_custom`` so downstream rules' ``not_fact`` clauses
        observe completion (their dedup is by fingerprint).
        """
        _ = stderr, exit_code
        import orjson  # local: small import
        try:
            doc = orjson.loads(stdout)
        except orjson.JSONDecodeError:
            return []
        if not isinstance(doc, dict):
            return []

        payload = doc.get("payload") or {}
        module = doc.get("module") or doc.get("_module") or ""
        target = doc.get("target") or ""
        port = doc.get("port")

        session_id = (
            payload.get("session_id")
            or payload.get("SessionID")
            or doc.get("session")
        )

        facts: list[Fact] = []
        if session_id is not None:
            try:
                sid = int(session_id)
                facts.append(make_fact(
                    fact_type="shell_handle",
                    body={"source": "metasploit", "session_id": sid,
                          "module": module, "host": target, "port": port},
                    source_tool="metasploit",
                    scan_id=scan_id, iteration=iteration,
                ))
            except (TypeError, ValueError):
                pass

        # Always emit a vuln_custom for traceability + idempotency.
        facts.append(make_fact(
            fact_type="vuln_custom",
            body={
                "tool": "metasploit-portscan" if "portscan" in module else "metasploit",
                "module": module, "host": target, "port": port,
                "ok": bool(doc.get("ok")), "payload": payload,
            },
            source_tool="metasploit",
            scan_id=scan_id, iteration=iteration,
        ))
        return facts


__all__ = ["MetasploitWrapper"]
