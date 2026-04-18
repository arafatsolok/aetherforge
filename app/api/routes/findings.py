"""Findings — list / inspect / triage."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, desc, func, select

from app.api.dependencies import SessionDep
from app.models.finding import Finding
from app.schemas.common import Page, PageMeta
from app.schemas.finding import FindingRead

router = APIRouter()

_ALLOWED_STATUS = {"open", "triaged", "false_positive", "fixed", "wontfix"}


class FindingTriage(BaseModel):
    status: str = Field(pattern=r"^(open|triaged|false_positive|fixed|wontfix)$")
    confirmed: bool | None = None
    triaged_by: str | None = Field(default=None, max_length=128)
    triage_notes: str | None = Field(default=None, max_length=4096)


@router.get("", response_model=Page[FindingRead], summary="List findings")
async def list_findings(
    session: SessionDep,
    severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
    status: str | None = Query(None, pattern="^(open|triaged|false_positive|fixed|wontfix)$"),
    scan_id: int | None = Query(None, ge=1),
    target_id: int | None = Query(None, ge=1),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> Page[FindingRead]:
    stmt = select(Finding)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    # severity ranking — critical first
    sev_rank_clause = case(
        (Finding.severity == "critical", 4),
        (Finding.severity == "high",     3),
        (Finding.severity == "medium",   2),
        (Finding.severity == "low",      1),
        else_=0,
    )
    stmt = stmt.order_by(sev_rank_clause.desc(), desc(Finding.created_at))

    total = (await session.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar_one()
    rows = (
        await session.execute(stmt.limit(size).offset((page - 1) * size))
    ).scalars().all()
    return Page[FindingRead](
        items=[FindingRead.model_validate(f) for f in rows],
        meta=PageMeta(page=page, size=size, total=int(total),
                      has_next=page * size < int(total)),
    )


@router.get("/{finding_id}", response_model=FindingRead, summary="Fetch a finding")
async def get_finding(finding_id: int, session: SessionDep) -> FindingRead:
    f = await session.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, detail="finding not found")
    return FindingRead.model_validate(f)


@router.patch("/{finding_id}", response_model=FindingRead, summary="Triage a finding")
async def triage_finding(
    finding_id: int, payload: FindingTriage, session: SessionDep
) -> FindingRead:
    f = await session.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, detail="finding not found")
    f.status = payload.status
    if payload.confirmed is not None:
        f.confirmed = payload.confirmed
    if payload.triaged_by is not None:
        f.triaged_by = payload.triaged_by
    if payload.triage_notes is not None:
        f.triage_notes = payload.triage_notes
    session.add(f)
    await session.flush()
    await session.refresh(f)
    return FindingRead.model_validate(f)
