"""Operator-facing metrics — totals + persona breakdown + open-finding counts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter
from sqlalchemy import case, func, select

from app.api.dependencies import SessionDep
from app.models.audit import AuditLog
from app.models.execution import Execution
from app.models.fact import Fact
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target

router = APIRouter()


@router.get("/overview", summary="Operator overview metrics")
async def overview(session: SessionDep) -> dict[str, Any]:
    sev_rank = case(
        (Finding.severity == "critical", 4),
        (Finding.severity == "high",     3),
        (Finding.severity == "medium",   2),
        (Finding.severity == "low",      1),
        else_=0,
    )

    counts = {
        "targets":   int((await session.execute(select(func.count(Target.id)))).scalar() or 0),
        "scans":     int((await session.execute(select(func.count(Scan.id)))).scalar() or 0),
        "executions":int((await session.execute(select(func.count(Execution.id)))).scalar() or 0),
        "facts":     int((await session.execute(select(func.count(Fact.id)))).scalar() or 0),
        "findings":  int((await session.execute(select(func.count(Finding.id)))).scalar() or 0),
        "audit_entries": int((await session.execute(select(func.count(AuditLog.id)))).scalar() or 0),
    }

    persona_breakdown = dict(
        (await session.execute(
            select(Scan.persona, func.count(Scan.id)).group_by(Scan.persona)
        )).all()
    )
    state_breakdown = dict(
        (await session.execute(
            select(Scan.state, func.count(Scan.id)).group_by(Scan.state)
        )).all()
    )
    severity_breakdown = dict(
        (await session.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.status == "open")
            .group_by(Finding.severity)
        )).all()
    )
    open_high_critical = int((await session.execute(
        select(func.count(Finding.id))
        .where(Finding.status == "open", sev_rank >= 3)
    )).scalar() or 0)

    # MTTD = avg seconds between scan.started_at and first vuln_* fact arrival.
    mttd_stmt = (
        select(func.avg(func.extract("epoch", Fact.created_at - Scan.started_at)))
        .select_from(Fact.__table__.join(Scan.__table__, Fact.scan_id == Scan.id))
        .where(Fact.fact_type.like("vuln_%"))
        .where(Scan.started_at.is_not(None))
    )
    mttd = (await session.execute(mttd_stmt)).scalar()
    mttd_seconds = float(mttd) if mttd is not None else None

    last_24h = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
    recent_scans = int((await session.execute(
        select(func.count(Scan.id)).where(Scan.created_at >= last_24h)
    )).scalar() or 0)

    return {
        "counts":               counts,
        "open_high_critical":   open_high_critical,
        "persona_breakdown":    persona_breakdown,
        "state_breakdown":      state_breakdown,
        "open_severity_breakdown": severity_breakdown,
        "scans_last_24h":       recent_scans,
        "mttd_seconds":         mttd_seconds,
        "generated_at":         datetime.now(UTC).isoformat(),
    }
