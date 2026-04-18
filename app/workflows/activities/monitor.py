"""Activities for ``ContinuousMonitorWorkflow`` — DB lookups + scan-row creation."""

from __future__ import annotations

from typing import Any

import ulid
from sqlalchemy import select
from temporalio import activity

from app.database import get_session_factory
from app.models.enums import ScanState
from app.models.scan import Scan
from app.models.target import Target


@activity.defn(name="aetherforge.monitor.lookup_target")
async def lookup_target(target_id: int) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        t = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one()
        return {
            "id": t.id, "slug": t.slug,
            "cidrs": list(t.cidrs or []),
            "domains": list(t.domains or []),
            "allowed_personas": list(t.allowed_personas or []),
            "replica_only": t.replica_only,
        }


@activity.defn(name="aetherforge.monitor.create_scan_row")
async def create_scan_row(
    target_id: int, persona: str, started_by: str
) -> dict[str, Any]:
    """Create a Scan row in PENDING state for a monitor tick."""
    scan_ulid = str(ulid.new())
    factory = get_session_factory()
    async with factory() as session, session.begin():
        scan = Scan(
            target_id=target_id,
            ulid=scan_ulid,
            persona=persona,
            state=ScanState.PENDING.value,
            started_by=started_by,
            workflow_id=f"scan-{scan_ulid}",
            task_queue="aetherforge-main",
        )
        session.add(scan)
        await session.flush()
        return {"scan_id": int(scan.id), "scan_ulid": scan_ulid}  # type: ignore[arg-type]


__all__ = ["create_scan_row", "lookup_target"]
