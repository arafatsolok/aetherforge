"""Cleanup activities — called on workflow shutdown.

Currently kills any open Metasploit sessions opened by the scan. The
RPC client is best-effort: if msfrpcd is unreachable (profile not up)
the activity returns 0 — it never blocks shutdown.
"""

from __future__ import annotations

from temporalio import activity

from app.logging_config import get_logger
from app.workflows.runtime import get_runtime

log = get_logger(__name__)


@activity.defn(name="aetherforge.cleanup.kill_msf_sessions")
async def kill_msf_sessions(scan_id: int) -> int:
    """Best-effort kill of every live MSF session. Returns kill count."""
    runtime = get_runtime()
    try:
        rpc = runtime.msf_executor.rpc()
        killed = await rpc.kill_all_sessions()
        log.info("cleanup.msf_sessions_killed", scan_id=scan_id, count=killed)
        return killed
    except Exception as exc:
        log.warning("cleanup.msf_unreachable", scan_id=scan_id, error=str(exc))
        return 0


__all__ = ["kill_msf_sessions"]
