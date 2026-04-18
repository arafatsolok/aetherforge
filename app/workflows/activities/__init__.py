"""All workflow activities — registered with the Temporal worker."""

from __future__ import annotations

from app.workflows.activities.audit import emit_audit
from app.workflows.activities.cleanup import kill_msf_sessions
from app.workflows.activities.drift import compute_drift, take_drift_snapshot
from app.workflows.activities.evaluate import pick_next_action, refresh_rule_engine
from app.workflows.activities.execute import execute_invocation
from app.workflows.activities.lifecycle import (
    mark_scan_completed,
    mark_scan_failed,
    mark_scan_running,
    update_scan_progress,
)
from app.workflows.activities.monitor import create_scan_row, lookup_target
from app.workflows.activities.observe import observe_facts, seed_initial_facts
from app.workflows.activities.persist import persist_facts_and_findings
from app.workflows.activities.wazuh import (
    ingest_wazuh_alerts,
    push_command_to_wazuh,
)

ALL_ACTIVITIES = [
    compute_drift,
    create_scan_row,
    emit_audit,
    execute_invocation,
    ingest_wazuh_alerts,
    kill_msf_sessions,
    lookup_target,
    mark_scan_completed,
    mark_scan_failed,
    mark_scan_running,
    observe_facts,
    persist_facts_and_findings,
    pick_next_action,
    push_command_to_wazuh,
    refresh_rule_engine,
    seed_initial_facts,
    take_drift_snapshot,
    update_scan_progress,
]


__all__ = ["ALL_ACTIVITIES"]
