"""``AutonomousScanWorkflow`` — the durable autonomous VAPT loop.

Activity calls use ``args=[...]`` (positional) because Temporal forbids
keyword-only activity parameters.
"""

from __future__ import annotations

import contextlib
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from app.workflows.data import (
        EscalatePersonaSignal,
        ExecutionOutcome,
        InvocationSpec,
        IterationOutcome,
        ScanInput,
        ScanResult,
        StopSignal,
    )

# Activity names used by the workflow (string lookup keeps the workflow
# free of any direct activity import — required by Temporal's strict
# determinism check).
_ACT_MARK_RUNNING    = "aetherforge.scan.mark_running"
_ACT_UPDATE_PROGRESS = "aetherforge.scan.update_progress"
_ACT_MARK_COMPLETED  = "aetherforge.scan.mark_completed"
_ACT_MARK_FAILED     = "aetherforge.scan.mark_failed"
_ACT_REFRESH_RULES   = "aetherforge.evaluate.refresh_rules"
_ACT_PICK_NEXT       = "aetherforge.evaluate.pick_next_action"
_ACT_EXECUTE         = "aetherforge.execute.invocation"
_ACT_PERSIST         = "aetherforge.persist.facts_and_findings"
_ACT_OBSERVE         = "aetherforge.observe.facts"
_ACT_SEED_FACTS      = "aetherforge.observe.seed_initial_facts"
_ACT_AUDIT           = "aetherforge.audit.emit"
_ACT_KILL_SESSIONS   = "aetherforge.cleanup.kill_msf_sessions"
_ACT_DRIFT_SNAPSHOT  = "aetherforge.drift.snapshot"
_ACT_DRIFT_COMPARE   = "aetherforge.drift.compare"
_ACT_WAZUH_PUSH      = "aetherforge.wazuh.push_command"
_ACT_WAZUH_INGEST    = "aetherforge.wazuh.ingest_alerts"

_DEFAULT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    maximum_interval=timedelta(seconds=30),
    backoff_coefficient=2.0,
    maximum_attempts=4,
)
_NO_RETRY = RetryPolicy(maximum_attempts=1)
_QUICK_TIMEOUT = timedelta(seconds=30)
_EXEC_TIMEOUT  = timedelta(minutes=70)
_ITERATIONS_BEFORE_CAN = 50


def _audit_args(
    scan_id: int,
    event: str,
    persona: str | None = None,
    actor: str = "workflow",
    rule_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> list[Any]:
    """Build the positional arg list for ``aetherforge.audit.emit``."""
    return [scan_id, event, persona, actor, rule_id, payload or {}]


@workflow.defn(name="AutonomousScanWorkflow")
class AutonomousScanWorkflow:

    def __init__(self) -> None:
        self._stop_signal: StopSignal | None = None
        self._escalate_signal: EscalatePersonaSignal | None = None
        self._executions_total = 0
        self._facts_total = 0
        self._findings_total = 0
        self._executed_rule_ids: set[str] = set()
        self._current_persona: str = "white"
        self._current_iteration: int = 0

    # -- Signals --------------------------------------------------------
    @workflow.signal
    def stop(self, signal: StopSignal) -> None:
        self._stop_signal = signal

    @workflow.signal
    def escalate_persona(self, signal: EscalatePersonaSignal) -> None:
        self._escalate_signal = signal

    # -- Queries --------------------------------------------------------
    @workflow.query
    def status(self) -> dict[str, Any]:
        return {
            "iteration": self._current_iteration,
            "persona": self._current_persona,
            "executions_total": self._executions_total,
            "facts_total": self._facts_total,
            "findings_total": self._findings_total,
            "executed_rule_ids": sorted(self._executed_rule_ids),
            "stop_requested": self._stop_signal is not None,
            "escalation_requested": self._escalate_signal is not None,
        }

    # -- Main loop ------------------------------------------------------
    @workflow.run
    async def run(self, scan_in: ScanInput) -> ScanResult:
        info = workflow.info()
        self._current_persona = scan_in.persona
        self._executed_rule_ids = set(scan_in.executed_rule_ids)
        self._current_iteration = scan_in.iterations_so_far

        if scan_in.iterations_so_far == 0:
            await workflow.execute_activity(
                _ACT_MARK_RUNNING,
                args=[scan_in.scan_id, info.workflow_id, info.run_id, info.task_queue],
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )
            await workflow.execute_activity(
                _ACT_AUDIT,
                args=_audit_args(
                    scan_in.scan_id, "scan.started",
                    persona=scan_in.persona, actor=scan_in.started_by,
                    payload={
                        "target_id": scan_in.target_id,
                        "target_slug": scan_in.target_slug,
                        "scope": scan_in.target_scope_cidrs,
                        "max_iterations": scan_in.max_iterations,
                    },
                ),
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )
            seeded = await workflow.execute_activity(
                _ACT_SEED_FACTS, args=[scan_in.scan_id, scan_in.target_id],
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )
            self._facts_total += int(seeded or 0)

        await workflow.execute_activity(
            _ACT_REFRESH_RULES, start_to_close_timeout=_QUICK_TIMEOUT,
            retry_policy=_DEFAULT_RETRY,
        )

        terminal_reason = ""

        while self._current_iteration < scan_in.max_iterations:
            self._current_iteration += 1

            if self._stop_signal is not None:
                terminal_reason = f"stopped: {self._stop_signal.reason}"
                break

            if self._escalate_signal is not None:
                from_p = self._current_persona
                self._current_persona = self._escalate_signal.to
                await workflow.execute_activity(
                    _ACT_AUDIT,
                    args=_audit_args(
                        scan_in.scan_id, "persona.changed",
                        persona=self._current_persona,
                        actor=self._escalate_signal.authorised_by,
                        payload={"from": from_p, "to": self._current_persona},
                    ),
                    start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
                )
                self._escalate_signal = None

            facts = await workflow.execute_activity(
                _ACT_OBSERVE, args=[scan_in.scan_id],
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )

            outcome_dict = await workflow.execute_activity(
                _ACT_PICK_NEXT,
                args=[
                    scan_in.scan_id, self._current_persona,
                    sorted(self._executed_rule_ids), facts,
                    scan_in.target_scope_cidrs,
                ],
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )
            inv_dict = outcome_dict.get("invocation")
            outcome = IterationOutcome(
                has_action=outcome_dict["has_action"],
                rule_id=outcome_dict.get("rule_id"),
                rejection_reason=outcome_dict.get("rejection_reason"),
                invocation=InvocationSpec(**inv_dict) if inv_dict else None,
                triggering_fact_fingerprint=outcome_dict.get("triggering_fact_fingerprint"),
            )

            if not outcome.has_action:
                if outcome.rule_id and outcome.rejection_reason:
                    self._executed_rule_ids.add(outcome.rule_id)
                    await workflow.execute_activity(
                        _ACT_AUDIT,
                        args=_audit_args(
                            scan_in.scan_id, "command.rejected",
                            persona=self._current_persona,
                            rule_id=outcome.rule_id,
                            payload={"reason": outcome.rejection_reason},
                        ),
                        start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
                    )
                    continue
                terminal_reason = "loop_drained"
                break

            assert outcome.invocation is not None
            self._executed_rule_ids.add(outcome.rule_id)  # type: ignore[arg-type]

            await workflow.execute_activity(
                _ACT_AUDIT,
                args=_audit_args(
                    scan_in.scan_id, "rule.matched",
                    persona=self._current_persona, rule_id=outcome.rule_id,
                    payload={
                        "tool": outcome.invocation.tool_name,
                        "argv": outcome.invocation.argv,
                        "trigger_fp": outcome.triggering_fact_fingerprint,
                    },
                ),
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )

            import dataclasses as _dc
            invocation_dict = _dc.asdict(outcome.invocation)
            try:
                exec_dict = await workflow.execute_activity(
                    _ACT_EXECUTE,
                    args=[scan_in.scan_id, self._current_iteration, invocation_dict],
                    start_to_close_timeout=_EXEC_TIMEOUT, retry_policy=_NO_RETRY,
                )
            except Exception as exc:
                await workflow.execute_activity(
                    _ACT_AUDIT,
                    args=_audit_args(
                        scan_in.scan_id, "scan.failed",
                        persona=self._current_persona,
                        rule_id=outcome.rule_id,
                        payload={"error": str(exc)},
                    ),
                    start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
                )
                terminal_reason = f"execution_error: {exc}"
                break

            outcome_exec = ExecutionOutcome(**exec_dict)  # flat — no nested dc
            self._executions_total += 1

            await workflow.execute_activity(
                _ACT_AUDIT,
                args=_audit_args(
                    scan_in.scan_id, "command.executed",
                    persona=self._current_persona, rule_id=outcome.rule_id,
                    payload={
                        "execution_id": outcome_exec.execution_id,
                        "exit_code": outcome_exec.exit_code,
                        "duration_ms": outcome_exec.duration_ms,
                        "timed_out": outcome_exec.timed_out,
                        "error": outcome_exec.error,
                    },
                ),
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )

            # Best-effort fan-out to Wazuh (no-op when manager is down).
            with contextlib.suppress(Exception):
                await workflow.execute_activity(
                    _ACT_WAZUH_PUSH,
                    args=[
                        scan_in.scan_id, outcome.rule_id or "",
                        outcome_exec.tool, outcome.invocation.argv,
                        outcome_exec.exit_code, outcome_exec.duration_ms,
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

            persist_res = await workflow.execute_activity(
                _ACT_PERSIST,
                args=[
                    scan_in.scan_id, outcome_exec.execution_id,
                    outcome_exec.execution_ulid, self._current_iteration,
                    outcome_exec.tool,
                ],
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )
            facts_added = int(persist_res.get("facts", 0))
            findings_added = int(persist_res.get("findings", 0))
            self._facts_total += facts_added
            self._findings_total += findings_added
            outcome_exec.facts_emitted = facts_added         # back-fill counter

            await workflow.execute_activity(
                _ACT_UPDATE_PROGRESS,
                args=[
                    scan_in.scan_id,
                    self._current_iteration,
                    self._executions_total,
                    self._facts_total,
                    self._findings_total,
                    self._current_persona,
                ],
                start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
            )

            if (self._current_iteration % _ITERATIONS_BEFORE_CAN) == 0:
                workflow.continue_as_new(ScanInput(
                    scan_id=scan_in.scan_id,
                    scan_ulid=scan_in.scan_ulid,
                    target_id=scan_in.target_id,
                    target_slug=scan_in.target_slug,
                    target_scope_cidrs=scan_in.target_scope_cidrs,
                    persona=self._current_persona,
                    started_by=scan_in.started_by,
                    initial_facts=[],
                    max_iterations=scan_in.max_iterations,
                    iterations_so_far=self._current_iteration,
                    executed_rule_ids=sorted(self._executed_rule_ids),
                ))

        if not terminal_reason:
            terminal_reason = "max_iterations_reached"

        # Cleanup hook — kill any open MSF sessions opened during the
        # scan. Best-effort; never blocks shutdown if msfrpcd is down.
        try:
            killed = await workflow.execute_activity(
                _ACT_KILL_SESSIONS, args=[scan_in.scan_id],
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
            if killed:
                await workflow.execute_activity(
                    _ACT_AUDIT,
                    args=_audit_args(
                        scan_in.scan_id, "scan.cleanup",
                        persona=self._current_persona,
                        payload={"msf_sessions_killed": int(killed)},
                    ),
                    start_to_close_timeout=_QUICK_TIMEOUT,
                    retry_policy=_DEFAULT_RETRY,
                )
        except Exception:
            pass

        # Drift — snapshot the steady state of this scan, then compare
        # to the previous one for the same target.
        try:
            snapshot_id = await workflow.execute_activity(
                _ACT_DRIFT_SNAPSHOT, args=[scan_in.scan_id],
                start_to_close_timeout=_QUICK_TIMEOUT,
                retry_policy=_DEFAULT_RETRY,
            )
            drift = await workflow.execute_activity(
                _ACT_DRIFT_COMPARE, args=[scan_in.scan_id, int(snapshot_id)],
                start_to_close_timeout=_QUICK_TIMEOUT,
                retry_policy=_DEFAULT_RETRY,
            )
            if drift and drift.get("has_drift"):
                await workflow.execute_activity(
                    _ACT_AUDIT,
                    args=_audit_args(
                        scan_in.scan_id, "drift.detected",
                        persona=self._current_persona,
                        payload=drift,
                    ),
                    start_to_close_timeout=_QUICK_TIMEOUT,
                    retry_policy=_DEFAULT_RETRY,
                )
        except Exception:
            pass

        await workflow.execute_activity(
            _ACT_MARK_COMPLETED, args=[scan_in.scan_id, terminal_reason],
            start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
        )
        await workflow.execute_activity(
            _ACT_AUDIT,
            args=_audit_args(
                scan_in.scan_id, "scan.stopped",
                persona=self._current_persona,
                payload={"reason": terminal_reason,
                         "iterations": self._current_iteration},
            ),
            start_to_close_timeout=_QUICK_TIMEOUT, retry_policy=_DEFAULT_RETRY,
        )

        return ScanResult(
            scan_id=scan_in.scan_id,
            scan_ulid=scan_in.scan_ulid,
            state="completed",
            iterations=self._current_iteration,
            executions_total=self._executions_total,
            facts_total=self._facts_total,
            findings_total=self._findings_total,
            terminal_reason=terminal_reason,
        )


__all__ = ["AutonomousScanWorkflow"]
