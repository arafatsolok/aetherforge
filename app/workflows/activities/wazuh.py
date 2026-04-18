"""Wazuh integration activities — push events + ingest alerts.

Both are best-effort: if the Wazuh manager is unreachable (profile not
up) the activity returns 0 and logs a warning — never fails the scan.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.dialects.postgresql import insert
from temporalio import activity

from app.config import get_settings
from app.database import get_session_factory
from app.logging_config import get_logger
from app.models.fact import Fact
from app.parsers import make_fact
from app.services.wazuh_client import WazuhClient, WazuhUnreachable

log = get_logger(__name__)


def _client() -> WazuhClient:
    return WazuhClient(settings=get_settings())


@activity.defn(name="aetherforge.wazuh.push_command")
async def push_command_to_wazuh(
    scan_id: int,
    rule_id: str,
    tool: str,
    argv: list[str],
    exit_code: int,
    duration_ms: int,
) -> bool:
    """Push a ``command.executed`` event to Wazuh as a custom alert."""
    c = _client()
    try:
        ok = await c.push_custom_event(
            location=f"aetherforge:scan:{scan_id}",
            log_format="json",
            body={
                "scan_id": scan_id, "rule_id": rule_id, "tool": tool,
                "argv": argv, "exit_code": exit_code, "duration_ms": duration_ms,
                "source": "aetherforge",
            },
        )
        return bool(ok)
    except WazuhUnreachable as exc:
        log.info("wazuh.push.skip", reason=str(exc))
        return False
    finally:
        await c.close()


@activity.defn(name="aetherforge.wazuh.ingest_alerts")
async def ingest_wazuh_alerts(scan_id: int, limit: int = 50) -> int:
    """Pull recent Wazuh alerts and ingest as ``vuln_custom`` facts.

    Returns the number of facts inserted (deduped by fingerprint).
    """
    c = _client()
    try:
        alerts = await c.list_alerts(limit=limit)
    except WazuhUnreachable as exc:
        log.info("wazuh.ingest.skip", reason=str(exc))
        return 0
    finally:
        await c.close()

    if not alerts:
        return 0

    rows: list[dict[str, Any]] = []
    for a in alerts:
        body = {
            "tool": "wazuh",
            "host": a.get("agent", {}).get("name") or a.get("agent", {}).get("ip"),
            "rule_id": a.get("rule", {}).get("id"),
            "rule_description": a.get("rule", {}).get("description", ""),
            "level": a.get("rule", {}).get("level"),
            "groups": a.get("rule", {}).get("groups", []),
            "full_log": a.get("full_log", "")[:4096],
        }
        f = make_fact(
            fact_type="vuln_custom",
            body=body, source_tool="wazuh",
            scan_id=str(scan_id), iteration=0,
        )
        rows.append({
            "scan_id": scan_id, "execution_id": None,
            "fact_type": f.fact_type, "source_tool": f.source_tool,
            "iteration": f.iteration, "fingerprint": f.fingerprint,
            "body": f.body,
        })

    factory = get_session_factory()
    async with factory() as session, session.begin():
        stmt = insert(Fact).values(rows).on_conflict_do_nothing(
            constraint="uq_facts_scan_fingerprint",
        )
        await session.execute(stmt)
    log.info("wazuh.ingest.done", scan_id=scan_id, count=len(rows))
    return len(rows)


__all__ = ["ingest_wazuh_alerts", "push_command_to_wazuh"]
