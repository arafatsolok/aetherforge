"""``MsfExecutor`` — Metasploit RPC parallel of ``DockerExecutor``.

Same return contract (``ExecutionResult``) so the workflow doesn't
care which executor ran. The dispatcher in
``app/workflows/activities/execute.py`` picks based on
``ToolSpec.labels`` containing ``"rpc"``.

The pseudo-argv built by the metasploit wrapper looks like:
    ['--module', 'auxiliary/scanner/portscan/tcp',
     '--target', '10.77.0.5', '--mode', 'check',
     '--port', '5432', '--session', '12']
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.config import Settings
from app.core.command_generator import ToolInvocation
from app.executor.artifacts import ArtifactStore
from app.executor.docker_executor import ExecutionResult
from app.executor.sandbox import SandboxPolicy
from app.logging_config import get_logger
from app.services.metasploit_rpc import MetasploitRPC

log = get_logger(__name__)


@dataclass(slots=True)
class MsfExecutor:
    """RPC-driven executor for tools tagged ``rpc`` in their ``ToolSpec.labels``.

    The interface mirrors ``DockerExecutor.run`` so the workflow's
    activity dispatch is a one-liner.
    """

    settings: Settings
    _rpc: MetasploitRPC | None = field(default=None, init=False)
    _store: ArtifactStore = field(init=False)

    def __post_init__(self) -> None:
        self._store = ArtifactStore(settings=self.settings)

    def rpc(self) -> MetasploitRPC:
        if self._rpc is None:
            self._rpc = MetasploitRPC(settings=self.settings)
        return self._rpc

    async def close(self) -> None:
        if self._rpc is not None:
            await self._rpc.close()
            self._rpc = None

    # -------------------------------------------------------------------
    # Main entry point — same shape as DockerExecutor.run
    # -------------------------------------------------------------------
    async def run(
        self,
        *,
        invocation: ToolInvocation,
        policy: SandboxPolicy,         # honoured for timeout only
        scan_ulid: str,
        execution_ulid: str,
    ) -> ExecutionResult:
        started_at = datetime.now(UTC)
        start_mono = time.monotonic()

        # Parse the pseudo-argv that the metasploit wrapper produced.
        kv = _argv_to_kv(invocation.argv)
        module = kv.get("module")
        target = kv.get("target")
        port = int(kv["port"]) if "port" in kv else None
        mode = kv.get("mode", "check")
        session = int(kv["session"]) if "session" in kv else None

        if not module:
            return self._failure(
                invocation, scan_ulid, execution_ulid, started_at,
                start_mono, "missing --module",
            )

        log.info("msf.run", module=module, target=target, mode=mode,
                 scan=scan_ulid, execution=execution_ulid)

        rpc = self.rpc()
        try:
            result = await asyncio.wait_for(
                rpc.run_module(
                    module_name=module,
                    target=target or "",
                    port=port,
                    mode=mode,
                    options={"SESSION": session} if session is not None else None,
                ),
                timeout=policy.timeout_seconds,
            )
            timed_out = False
        except TimeoutError:
            return self._failure(
                invocation, scan_ulid, execution_ulid, started_at,
                start_mono, f"msf rpc timeout after {policy.timeout_seconds}s",
                timed_out=True,
            )
        except Exception as exc:
            return self._failure(
                invocation, scan_ulid, execution_ulid, started_at,
                start_mono, f"msf rpc error: {type(exc).__name__}: {exc}",
            )

        finished_at = datetime.now(UTC)
        duration_ms = int((time.monotonic() - start_mono) * 1000)

        # Serialise the RPC payload into stdout — Phase 2's wrapper
        # parsers consume stdout, so this keeps the contract uniform.
        stdout = json.dumps({
            "module": module, "mode": mode, "target": target, "port": port,
            "session": session, "ok": result.ok, "payload": result.payload,
        }, default=str).encode()
        stderr = (result.error or "").encode()
        exit_code = 0 if result.ok else 1

        artifact = self._store.persist(
            scan_ulid=scan_ulid, execution_ulid=execution_ulid,
            stdout=stdout, stderr=stderr, exit_code=exit_code,
            meta={
                "tool": "metasploit", "transport": "rpc",
                "module": module, "mode": mode, "target": target,
                "port": port, "session": session,
            },
        )

        return ExecutionResult(
            invocation=invocation,
            container_id=None,
            image=invocation.image,
            argv=invocation.argv,
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            stdout=stdout, stderr=stderr,
            artifact=artifact,
            timed_out=timed_out,
            error=result.error,
        )

    # -------------------------------------------------------------------
    # Failure helper
    # -------------------------------------------------------------------
    def _failure(
        self,
        invocation: ToolInvocation,
        scan_ulid: str,
        execution_ulid: str,
        started_at: datetime,
        start_mono: float,
        error: str,
        *,
        timed_out: bool = False,
    ) -> ExecutionResult:
        finished_at = datetime.now(UTC)
        duration_ms = int((time.monotonic() - start_mono) * 1000)
        artifact = self._store.persist(
            scan_ulid=scan_ulid, execution_ulid=execution_ulid,
            stdout=b"", stderr=error.encode(), exit_code=1,
            meta={"tool": "metasploit", "transport": "rpc", "error": error},
        )
        return ExecutionResult(
            invocation=invocation,
            container_id=None,
            image=invocation.image,
            argv=invocation.argv,
            exit_code=1,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            stdout=b"", stderr=error.encode(),
            artifact=artifact,
            timed_out=timed_out,
            error=error,
        )


def _argv_to_kv(argv: tuple[str, ...]) -> dict[str, str]:
    """Translate ``['--module','x','--target','y']`` -> ``{'module':'x',…}``."""
    out: dict[str, str] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("--") and i + 1 < len(argv):
            out[tok[2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return out


__all__ = ["MsfExecutor"]
