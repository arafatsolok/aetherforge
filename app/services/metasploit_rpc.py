"""Thin async wrapper over pymetasploit3.MsfRpcClient.

Phase 2 ships the connection + module-invocation contract; Phase 5 adds
the full session-management + post-exploit primitives.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any

from app.config import Settings
from app.logging_config import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class MsfRunResult:
    ok: bool
    module: str
    mode: str                # "check" | "run"
    payload: dict[str, Any]  # raw RPC return value
    error: str | None = None


class MetasploitRPC:
    """Lazy-connected MSF RPC client.

    Thread-safety: the upstream pymetasploit3 client is NOT async-safe,
    so every call is funnelled through ``asyncio.to_thread``.
    """

    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings
        self._client: Any | None = None

    async def connect(self) -> None:
        if self._client is not None:
            return
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("pymetasploit3 missing — install runtime deps") from exc

        def _connect() -> Any:
            return MsfRpcClient(
                self._settings.msf_rpc_pass.get_secret_value(),
                server=self._settings.metasploit_host,
                port=self._settings.metasploit_port,
                username=self._settings.msf_rpc_user,
                ssl=True,
            )

        self._client = await asyncio.to_thread(_connect)
        log.info("msf.rpc.connected",
                 host=self._settings.metasploit_host,
                 port=self._settings.metasploit_port)

    async def close(self) -> None:
        if self._client is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.to_thread(self._client.logout)
        self._client = None

    async def run_module(
        self,
        *,
        module_name: str,
        target: str,
        port: int | None = None,
        mode: str = "check",
        options: dict[str, Any] | None = None,
    ) -> MsfRunResult:
        """Invoke ``<module>`` against ``<target>[:port]``.

        Auxiliary scanners always run (no ``check`` semantic). Exploit /
        post modules respect ``mode`` — Phase 5 always runs ``check``
        first; Phase 6 graduates to ``run`` only after operator opt-in.
        """
        await self.connect()
        assert self._client is not None

        def _invoke() -> dict[str, Any]:
            if "/" not in module_name:
                raise ValueError(f"bad module name: {module_name!r}")
            mod_type, mod_path = module_name.split("/", 1)
            mod = self._client.modules.use(mod_type, mod_path)

            opts = dict(options or {})
            opts.setdefault("RHOSTS", target)
            if port is not None:
                opts.setdefault("RPORT", port)
            for k, v in opts.items():
                mod[k] = v

            effective_mode = mode
            if mod_type in {"auxiliary", "post"} and mode == "check":
                effective_mode = "run"

            payload = mod.check() if effective_mode == "check" else mod.execute()
            payload["_mode"] = effective_mode
            payload["_module"] = module_name
            return payload

        try:
            payload = await asyncio.to_thread(_invoke)
            return MsfRunResult(ok=True, module=module_name, mode=mode, payload=payload)
        except Exception as exc:
            log.warning("msf.rpc.error", module=module_name, mode=mode, error=str(exc))
            return MsfRunResult(
                ok=False, module=module_name, mode=mode,
                payload={}, error=f"{type(exc).__name__}: {exc}",
            )

    async def list_sessions(self) -> dict[str, Any]:
        """Return all live sessions from RPC ``session.list``."""
        await self.connect()
        assert self._client is not None
        return await asyncio.to_thread(lambda: dict(self._client.sessions.list))

    async def kill_session(self, session_id: int) -> bool:
        """Stop one open session. Idempotent — False if already gone."""
        await self.connect()
        assert self._client is not None

        def _kill() -> bool:
            try:
                self._client.sessions.session(str(session_id)).stop()
                return True
            except Exception:
                return False
        return await asyncio.to_thread(_kill)

    async def kill_all_sessions(self) -> int:
        """Cleanup helper for workflow shutdown. Returns kill count."""
        try:
            sessions = await self.list_sessions()
        except Exception:
            return 0
        killed = 0
        for sid in list(sessions):
            if await self.kill_session(int(sid)):
                killed += 1
        return killed


__all__ = ["MetasploitRPC", "MsfRunResult"]
