"""Audit-log writer activity.

After each insert we issue a Postgres ``NOTIFY aetherforge_audit, '<scan_id>'``
so the SSE endpoint can wake immediately instead of polling.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, text
from sqlalchemy.sql import func
from temporalio import activity

from app.database import get_session_factory
from app.models.audit import AuditLog


@activity.defn(name="aetherforge.audit.emit")
async def emit_audit(
    scan_id: int | None,
    event: str,
    persona: str | None = None,
    actor: str = "workflow",
    rule_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> int:
    """Append a row to ``audit_log`` + NOTIFY listeners. Returns row id."""
    factory = get_session_factory()
    async with factory() as session, session.begin():
        seq_stmt = select(func.coalesce(func.max(AuditLog.sequence), 0)).where(
            AuditLog.scan_id == scan_id
        )
        next_seq = int((await session.execute(seq_stmt)).scalar_one()) + 1

        row = AuditLog(
            scan_id=scan_id,
            sequence=next_seq,
            event=event,
            persona=persona,
            actor=actor,
            rule_id=rule_id,
            payload=payload or {},
        )
        session.add(row)
        await session.flush()
        new_id = int(row.id)                                # type: ignore[arg-type]

        # Wake any LISTEN-ers (the SSE endpoint, Phase 7+).
        # The payload is just the scan_id — listeners pull the row
        # themselves so consumers can be filtered server-side.
        # Use pg_notify() rather than the NOTIFY statement so the
        # payload goes through SQLAlchemy bind parameters (NOTIFY's
        # payload position cannot be parameterised).
        if scan_id is not None:
            await session.execute(
                text("SELECT pg_notify('aetherforge_audit', :sid)"),
                {"sid": str(int(scan_id))},
            )
        return new_id


__all__ = ["emit_audit"]
