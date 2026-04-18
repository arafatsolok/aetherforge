"""Concrete DriftDetector — Phase 0 contract, Phase 7 implementation.

Workflow:
  1. ``snapshot(scan_id)``  → builds + persists a ``DriftSnapshot`` row from
                              the scan's facts + findings.
  2. ``compare(a, b)``      → pure: returns a ``DriftDelta`` (added /
                              removed fingerprints, severity shift).
  3. ``persist_delta(...)`` → writes the delta as a row + returns it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.drift_detector import DriftDelta as DriftDeltaContract
from app.models.drift import DriftDelta, DriftSnapshot
from app.models.fact import Fact
from app.models.finding import Finding
from app.models.scan import Scan


@dataclass(slots=True)
class PostgresDriftDetector:
    """DB-backed drift detector. Stateless — takes a session per call."""

    async def snapshot(
        self, session: AsyncSession, scan_id: int
    ) -> DriftSnapshot:
        scan = (await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )).scalar_one()

        facts = list((await session.execute(
            select(Fact).where(Fact.scan_id == scan_id)
        )).scalars().all())

        findings = list((await session.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )).scalars().all())

        sev_counter: Counter[str] = Counter(f.severity for f in findings)
        host_count = len({f.body.get("host") for f in facts
                          if f.fact_type in {"host_alive", "port_open"}
                             and f.body.get("host")})
        port_count = sum(1 for f in facts if f.fact_type == "port_open")
        fingerprints = sorted({f.fingerprint for f in facts})

        snap = DriftSnapshot(
            target_id=scan.target_id,
            scan_id=scan_id,
            host_count=host_count,
            open_port_count=port_count,
            finding_counts=dict(sev_counter),
            fact_fingerprints=fingerprints,
            summary={
                "iterations":      scan.iterations,
                "executions":      scan.executions_total,
                "facts":           len(facts),
                "findings":        len(findings),
                "terminal_reason": scan.terminal_reason or "",
            },
        )
        session.add(snap)
        await session.flush()
        await session.refresh(snap)
        return snap

    async def previous_snapshot(
        self, session: AsyncSession, target_id: int, before_id: int
    ) -> DriftSnapshot | None:
        stmt = (
            select(DriftSnapshot)
            .where(DriftSnapshot.target_id == target_id)
            .where(DriftSnapshot.id < before_id)
            .order_by(desc(DriftSnapshot.id))
            .limit(1)
        )
        return (await session.execute(stmt)).scalar_one_or_none()

    @staticmethod
    def compare(prev: DriftSnapshot, curr: DriftSnapshot) -> DriftDeltaContract:
        prev_set = set(prev.fact_fingerprints or [])
        curr_set = set(curr.fact_fingerprints or [])
        added = curr_set - prev_set
        removed = prev_set - curr_set

        sev_shift: dict[str, int] = {}
        prev_sev = dict(prev.finding_counts or {})
        curr_sev = dict(curr.finding_counts or {})
        for sev in {*prev_sev, *curr_sev}:
            delta = int(curr_sev.get(sev, 0)) - int(prev_sev.get(sev, 0))
            if delta != 0:
                sev_shift[sev] = delta

        return DriftDeltaContract(
            target_id=prev.target_id,
            from_scan_id=str(prev.scan_id),
            to_scan_id=str(curr.scan_id),
            added_fingerprints=frozenset(added),
            removed_fingerprints=frozenset(removed),
            severity_shift=sev_shift,
        )

    async def persist_delta(
        self,
        session: AsyncSession,
        prev: DriftSnapshot,
        curr: DriftSnapshot,
        delta: DriftDeltaContract,
    ) -> DriftDelta:
        row = DriftDelta(
            target_id=prev.target_id,
            from_snapshot_id=prev.id,
            to_snapshot_id=curr.id,
            added_fingerprints=sorted(delta.added_fingerprints),
            removed_fingerprints=sorted(delta.removed_fingerprints),
            severity_shift=dict(delta.severity_shift),
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return row


__all__ = ["PostgresDriftDetector"]
