"""Unit tests for the PostgresDriftDetector compare logic."""

from __future__ import annotations

import pytest

from app.models.drift import DriftSnapshot
from app.services.drift_detector import PostgresDriftDetector


def _snap(target_id: int, scan_id: int, *,
          fps: list[str], findings: dict[str, int]) -> DriftSnapshot:
    return DriftSnapshot(
        target_id=target_id, scan_id=scan_id,
        host_count=1, open_port_count=len(fps),
        finding_counts=findings,
        fact_fingerprints=fps,
        summary={},
    )


@pytest.mark.unit
class TestDriftCompare:
    def test_identical_snapshots_have_no_drift(self) -> None:
        a = _snap(1, 1, fps=["fpA", "fpB"], findings={"low": 1})
        b = _snap(1, 2, fps=["fpA", "fpB"], findings={"low": 1})
        delta = PostgresDriftDetector.compare(a, b)
        assert not delta.has_drift

    def test_added_fingerprints_detected(self) -> None:
        a = _snap(1, 1, fps=["fpA"], findings={})
        b = _snap(1, 2, fps=["fpA", "fpB"], findings={})
        d = PostgresDriftDetector.compare(a, b)
        assert d.has_drift
        assert d.added_fingerprints == frozenset({"fpB"})
        assert d.removed_fingerprints == frozenset()

    def test_removed_fingerprints_detected(self) -> None:
        a = _snap(1, 1, fps=["fpA", "fpB"], findings={})
        b = _snap(1, 2, fps=["fpA"], findings={})
        d = PostgresDriftDetector.compare(a, b)
        assert d.removed_fingerprints == frozenset({"fpB"})

    def test_severity_shift_picks_only_changed(self) -> None:
        a = _snap(1, 1, fps=["x"], findings={"high": 1, "low": 2})
        b = _snap(1, 2, fps=["x"], findings={"high": 3, "low": 2, "info": 1})
        d = PostgresDriftDetector.compare(a, b)
        assert d.severity_shift == {"high": 2, "info": 1}

    def test_target_id_propagated(self) -> None:
        a = _snap(7, 1, fps=[], findings={})
        b = _snap(7, 2, fps=["x"], findings={})
        d = PostgresDriftDetector.compare(a, b)
        assert d.target_id == 7
        assert d.from_scan_id == "1"
        assert d.to_scan_id == "2"
