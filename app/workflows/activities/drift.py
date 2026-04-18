"""Drift activities — snapshot + compare invoked from the workflow."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from temporalio import activity

from app.database import get_session_factory
from app.logging_config import get_logger
from app.models.scan import Scan
from app.services.drift_detector import PostgresDriftDetector

log = get_logger(__name__)
_detector = PostgresDriftDetector()


@activity.defn(name="aetherforge.drift.snapshot")
async def take_drift_snapshot(scan_id: int) -> int:
    """Build + persist a DriftSnapshot for a completed scan. Returns its id."""
    factory = get_session_factory()
    async with factory() as session, session.begin():
        snap = await _detector.snapshot(session, scan_id)
        log.info("drift.snapshot",
                 scan_id=scan_id, snapshot_id=snap.id,
                 fingerprints=len(snap.fact_fingerprints or []))
        return int(snap.id)  # type: ignore[arg-type]


@activity.defn(name="aetherforge.drift.compare")
async def compute_drift(scan_id: int, snapshot_id: int) -> dict[str, Any]:
    """Compare ``snapshot_id`` against the previous snapshot for the same target.

    Returns a flat dict (no DriftDelta — Temporal needs primitives):
      ``{has_drift, added_count, removed_count, severity_shift, delta_id}``
    Returns ``has_drift=False`` and ``delta_id=None`` if no previous snapshot.
    """
    factory = get_session_factory()
    async with factory() as session, session.begin():
        scan = (await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )).scalar_one()

        from app.models.drift import DriftSnapshot  # local import — avoid cycles

        curr = (await session.execute(
            select(DriftSnapshot).where(DriftSnapshot.id == snapshot_id)
        )).scalar_one()

        prev = await _detector.previous_snapshot(
            session, target_id=scan.target_id, before_id=int(curr.id),  # type: ignore[arg-type]
        )
        if prev is None:
            return {
                "has_drift": False, "added_count": 0, "removed_count": 0,
                "severity_shift": {}, "delta_id": None,
                "previous_scan_id": None,
            }

        delta_obj = _detector.compare(prev, curr)
        if not delta_obj.has_drift:
            return {
                "has_drift": False, "added_count": 0, "removed_count": 0,
                "severity_shift": {}, "delta_id": None,
                "previous_scan_id": prev.scan_id,
            }

        row = await _detector.persist_delta(session, prev, curr, delta_obj)
        log.info("drift.delta",
                 target=scan.target_id,
                 added=len(delta_obj.added_fingerprints),
                 removed=len(delta_obj.removed_fingerprints),
                 severity_shift=delta_obj.severity_shift,
                 delta_id=row.id)
        return {
            "has_drift": True,
            "added_count":   len(delta_obj.added_fingerprints),
            "removed_count": len(delta_obj.removed_fingerprints),
            "severity_shift": dict(delta_obj.severity_shift),
            "delta_id":      int(row.id),                  # type: ignore[arg-type]
            "previous_scan_id": prev.scan_id,
        }


__all__ = ["compute_drift", "take_drift_snapshot"]
