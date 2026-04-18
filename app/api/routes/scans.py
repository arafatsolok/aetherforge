"""Scan lifecycle — POST starts, GET inspects, /stop + /escalate signal."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import desc, func, select
from temporalio.service import RPCError

from app.api.dependencies import SessionDep, SettingsDep
from app.config import Persona
from app.core.exceptions import ScopeViolation
from app.models.scan import Scan
from app.repositories import TargetRepository
from app.schemas.common import Page, PageMeta
from app.schemas.scan import ScanCreate, ScanRead
from app.services.temporal_orchestrator import get_orchestrator

router = APIRouter()


def _terminal_signal_or_409(exc: RPCError) -> HTTPException:
    """Map Temporal 'workflow already completed' → HTTP 409."""
    msg = str(exc).lower()
    if "already completed" in msg or "not found" in msg:
        return HTTPException(409, detail="scan workflow is already terminal")
    return HTTPException(502, detail=f"temporal upstream error: {exc}")


@router.get("", response_model=Page[ScanRead], summary="List scans (newest first)")
async def list_scans(
    session: SessionDep,
    target_id: int | None = Query(None, ge=1),
    state: str | None = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
) -> Page[ScanRead]:
    stmt = select(Scan)
    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
    if state is not None:
        stmt = stmt.where(Scan.state == state)
    rows = (await session.execute(
        stmt.order_by(desc(Scan.id)).limit(size).offset((page - 1) * size)
    )).scalars().all()
    total = (await session.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar_one()
    return Page[ScanRead](
        items=[ScanRead.model_validate(s) for s in rows],
        meta=PageMeta(page=page, size=size, total=int(total),
                      has_next=page * size < int(total)),
    )


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start an autonomous scan",
)
async def start_scan(
    payload: ScanCreate, session: SessionDep, settings: SettingsDep
) -> ScanRead:
    repo = TargetRepository(session)
    target = await repo.get_by_slug(payload.target_slug)
    if target is None:
        raise HTTPException(404, detail=f"target {payload.target_slug!r} not found")
    if not target.active:
        raise HTTPException(409, detail="target is inactive")

    orch = get_orchestrator(settings)
    try:
        scan = await orch.start_for_target(
            session=session,
            target=target,
            persona=payload.persona,
            started_by=payload.started_by,
        )
    except ScopeViolation as err:
        raise HTTPException(403, detail=str(err)) from err
    except ValueError as err:
        raise HTTPException(422, detail=str(err)) from err
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanRead, summary="Fetch a scan")
async def get_scan(scan_id: int, session: SessionDep) -> ScanRead:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, detail="scan not found")
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}/status", summary="Live workflow status (queries Temporal)")
async def scan_status(
    scan_id: int, session: SessionDep, settings: SettingsDep,
) -> dict[str, object]:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, detail="scan not found")
    if not scan.workflow_id:
        return {"workflow_id": None, "state": scan.state, "live": False}
    orch = get_orchestrator(settings)
    live = await orch.status(scan.workflow_id)
    return {
        "workflow_id": scan.workflow_id,
        "state_db": scan.state,
        "iterations_db": scan.iterations,
        "live": live,
    }


@router.post(
    "/{scan_id}/stop",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Signal a graceful stop",
)
async def stop_scan(
    scan_id: int, session: SessionDep, settings: SettingsDep,
    reason: str = Query("operator-stop", max_length=256),
) -> dict[str, object]:
    scan = await session.get(Scan, scan_id)
    if scan is None or not scan.workflow_id:
        raise HTTPException(404, detail="scan or workflow not found")
    orch = get_orchestrator(settings)
    try:
        await orch.stop(scan.workflow_id, reason=reason)
    except RPCError as exc:
        raise _terminal_signal_or_409(exc) from exc
    return {"id": scan_id, "status": "stopping", "reason": reason}


@router.post(
    "/{scan_id}/escalate",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Escalate persona mid-scan",
)
async def escalate_scan(
    scan_id: int, session: SessionDep, settings: SettingsDep,
    to: Persona = Query(...),
    authorised_by: str = Query("api"),
) -> dict[str, object]:
    scan = await session.get(Scan, scan_id)
    if scan is None or not scan.workflow_id:
        raise HTTPException(404, detail="scan or workflow not found")
    orch = get_orchestrator(settings)
    try:
        await orch.escalate_persona(scan.workflow_id, to, authorised_by=authorised_by)
    except RPCError as exc:
        raise _terminal_signal_or_409(exc) from exc
    return {"id": scan_id, "status": "escalating", "to": to.value}
