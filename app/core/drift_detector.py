"""Drift detector contract — compares scans over time.

Each completed scan produces a ``ScanSnapshot`` (set of facts + findings).
The drift detector computes the delta between consecutive snapshots for
the same target — new hosts appearing, services disappearing, CVSS
scores changing — so the continuous-monitoring mode can alert.

Phase 0: contract only. Phase 7 ships the concrete PostgreSQL-backed
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ScanSnapshot:
    target_id: int
    scan_id: str
    taken_at: datetime
    host_count: int
    open_port_count: int
    finding_count_by_severity: dict[str, int]
    fact_fingerprints: frozenset[str]  # stable hashes per fact for set-diff


@dataclass(frozen=True, slots=True)
class DriftDelta:
    target_id: int
    from_scan_id: str
    to_scan_id: str
    added_fingerprints: frozenset[str]
    removed_fingerprints: frozenset[str]
    severity_shift: dict[str, int] = field(default_factory=dict)

    @property
    def has_drift(self) -> bool:
        return bool(self.added_fingerprints or self.removed_fingerprints or self.severity_shift)


@runtime_checkable
class DriftDetector(Protocol):
    async def snapshot(self, scan_id: str) -> ScanSnapshot: ...

    async def compare(self, older: ScanSnapshot, newer: ScanSnapshot) -> DriftDelta: ...

    async def recent_drifts(self, target_id: int, limit: int = 10) -> list[DriftDelta]: ...


__all__ = ["DriftDelta", "DriftDetector", "ScanSnapshot"]
