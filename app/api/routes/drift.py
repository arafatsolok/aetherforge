"""Drift inspection + continuous-monitor management."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select

from app.api.dependencies import SessionDep, SettingsDep
from app.config import Persona
from app.models.drift import DriftDelta, DriftSnapshot
from app.models.target import Target
from app.workflows.continuous_monitor import MonitorInput

router = APIRouter()


@router.get("/{target_id}", summary="Drift deltas for a target")
async def list_drift(
    target_id: int,
    session: SessionDep,
    limit: int = Query(20, ge=1, le=200),
) -> dict[str, Any]:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(404, detail="target not found")

    snaps = list((await session.execute(
        select(DriftSnapshot)
        .where(DriftSnapshot.target_id == target_id)
        .order_by(desc(DriftSnapshot.id)).limit(limit)
    )).scalars().all())

    deltas = list((await session.execute(
        select(DriftDelta)
        .where(DriftDelta.target_id == target_id)
        .order_by(desc(DriftDelta.id)).limit(limit)
    )).scalars().all())

    return {
        "target": {"id": target.id, "slug": target.slug},
        "snapshots": [
            {
                "id": s.id, "scan_id": s.scan_id,
                "host_count": s.host_count,
                "open_port_count": s.open_port_count,
                "finding_counts": s.finding_counts,
                "fingerprint_count": len(s.fact_fingerprints or []),
                "created_at": s.created_at.isoformat() + "Z",
            }
            for s in snaps
        ],
        "deltas": [
            {
                "id": d.id,
                "from_snapshot_id": d.from_snapshot_id,
                "to_snapshot_id":   d.to_snapshot_id,
                "added_count":      len(d.added_fingerprints or []),
                "removed_count":    len(d.removed_fingerprints or []),
                "severity_shift":   d.severity_shift,
                "created_at":       d.created_at.isoformat() + "Z",
            }
            for d in deltas
        ],
    }


class MonitorStart(BaseModel):
    target_slug: str = Field(min_length=1, max_length=64)
    persona: Persona = Persona.GRAY
    interval_seconds: int = Field(default=21_600, ge=60, le=604_800)
    started_by: str = Field(default="api", max_length=128)
    max_iterations_per_scan: int = Field(default=100, ge=1, le=10_000)


@router.post(
    "/monitor",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a ContinuousMonitorWorkflow for a target",
)
async def start_monitor(
    payload: MonitorStart, session: SessionDep, settings: SettingsDep,
) -> dict[str, Any]:
    from app.repositories.target import TargetRepository
    from app.services.temporal_orchestrator import get_orchestrator

    repo = TargetRepository(session)
    target = await repo.get_by_slug(payload.target_slug)
    if target is None:
        raise HTTPException(404, detail="target not found")
    if not target.accepts_persona(payload.persona):
        raise HTTPException(403, detail=f"target does not accept persona {payload.persona.value}")

    orch = get_orchestrator(settings)
    client = await orch.client()
    handle = await client.start_workflow(
        "ContinuousMonitorWorkflow",
        MonitorInput(
            target_id=int(target.id),                      # type: ignore[arg-type]
            persona=payload.persona.value,
            interval_seconds=payload.interval_seconds,
            started_by=payload.started_by,
            max_iterations_per_scan=payload.max_iterations_per_scan,
        ),
        id=f"monitor-{target.slug}",
        task_queue=settings.temporal_task_queue,
    )
    return {
        "workflow_id": handle.id,
        "run_id": handle.run_id,
        "target": target.slug,
        "interval_seconds": payload.interval_seconds,
    }


@router.post(
    "/monitor/{slug}/stop",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Stop a ContinuousMonitorWorkflow by target slug",
)
async def stop_monitor(slug: str, settings: SettingsDep) -> dict[str, Any]:
    from app.services.temporal_orchestrator import get_orchestrator

    orch = get_orchestrator(settings)
    client = await orch.client()
    handle = client.get_workflow_handle(f"monitor-{slug}")
    try:
        await handle.signal("stop")
    except Exception as exc:
        raise HTTPException(404, detail=f"monitor not running: {exc}") from exc
    return {"status": "stopping", "target": slug}
