"""Scan lifecycle activities — state transitions + counters."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from temporalio import activity

from app.database import get_session_factory
from app.models.enums import ScanState
from app.models.scan import Scan


def _now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@activity.defn(name="aetherforge.scan.mark_running")
async def mark_scan_running(
    scan_id: int, workflow_id: str, run_id: str, task_queue: str
) -> None:
    factory = get_session_factory()
    async with factory() as session, session.begin():
        scan = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan.state = ScanState.RUNNING.value
        scan.workflow_id = workflow_id
        scan.run_id = run_id
        scan.task_queue = task_queue
        scan.started_at = _now_naive()
        session.add(scan)


@activity.defn(name="aetherforge.scan.update_progress")
async def update_scan_progress(
    scan_id: int,
    iterations: int,
    executions_total: int,
    facts_total: int,
    findings_total: int,
    persona: str,
) -> None:
    factory = get_session_factory()
    async with factory() as session, session.begin():
        scan = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan.iterations = iterations
        scan.executions_total = executions_total
        scan.facts_total = facts_total
        scan.findings_total = findings_total
        if persona and persona != scan.persona:
            scan.persona = persona
        session.add(scan)


@activity.defn(name="aetherforge.scan.mark_completed")
async def mark_scan_completed(scan_id: int, terminal_reason: str = "loop_drained") -> None:
    factory = get_session_factory()
    async with factory() as session, session.begin():
        scan = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan.state = ScanState.COMPLETED.value
        scan.terminal_reason = terminal_reason
        scan.finished_at = _now_naive()
        session.add(scan)


@activity.defn(name="aetherforge.scan.mark_failed")
async def mark_scan_failed(scan_id: int, terminal_reason: str) -> None:
    factory = get_session_factory()
    async with factory() as session, session.begin():
        scan = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan.state = ScanState.FAILED.value
        scan.terminal_reason = terminal_reason[:512]
        scan.finished_at = _now_naive()
        session.add(scan)


__all__ = [
    "mark_scan_completed",
    "mark_scan_failed",
    "mark_scan_running",
    "update_scan_progress",
]
