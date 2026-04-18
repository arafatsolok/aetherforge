"""Smoke test: workflow + activities import + register without error."""

from __future__ import annotations

import pytest


@pytest.mark.unit
def test_workflow_module_imports() -> None:
    from app.workflows.autonomous_scan import AutonomousScanWorkflow

    assert AutonomousScanWorkflow.__name__ == "AutonomousScanWorkflow"


@pytest.mark.unit
def test_activities_register() -> None:
    from app.workflows.activities import ALL_ACTIVITIES

    assert len(ALL_ACTIVITIES) >= 10
    names = {getattr(a, "__temporal_activity_definition", None).name
             for a in ALL_ACTIVITIES if hasattr(a, "__temporal_activity_definition")}
    must = {
        "aetherforge.scan.mark_running",
        "aetherforge.scan.mark_completed",
        "aetherforge.scan.update_progress",
        "aetherforge.evaluate.pick_next_action",
        "aetherforge.execute.invocation",
        "aetherforge.persist.facts_and_findings",
        "aetherforge.observe.facts",
        "aetherforge.audit.emit",
    }
    assert must <= names, f"missing activities: {must - names}"
