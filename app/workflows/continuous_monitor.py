"""``ContinuousMonitorWorkflow`` — schedules ``AutonomousScanWorkflow``
on a fixed cadence to detect drift over time.

Each tick:
  1. Resolve target by id (DB read).
  2. Start a child ``AutonomousScanWorkflow`` (fire-and-forget — drift
     captures the steady state on completion).
  3. ``workflow.sleep`` for the next interval.
  4. ``continue_as_new`` after N ticks to keep history bounded.

The first tick fires immediately on workflow start; subsequent ticks
honour ``interval_seconds``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from app.workflows.data import ScanInput

_ACT_LOOKUP_TARGET = "aetherforge.monitor.lookup_target"
_ACT_CREATE_SCAN_ROW = "aetherforge.monitor.create_scan_row"

_DEFAULT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    maximum_interval=timedelta(seconds=30),
    backoff_coefficient=2.0,
    maximum_attempts=4,
)
_TICKS_BEFORE_CAN = 24


@dataclass(slots=True)
class MonitorInput:
    target_id: int
    persona: str
    interval_seconds: int = 21_600       # 6 h
    started_by: str = "monitor"
    max_iterations_per_scan: int = 100
    ticks_so_far: int = 0


@workflow.defn(name="ContinuousMonitorWorkflow")
class ContinuousMonitorWorkflow:

    def __init__(self) -> None:
        self._stop_requested = False
        self._tick_count = 0

    @workflow.signal
    def stop(self) -> None:
        self._stop_requested = True

    @workflow.query
    def status(self) -> dict[str, Any]:
        return {"tick_count": self._tick_count, "stop_requested": self._stop_requested}

    @workflow.run
    async def run(self, mon_in: MonitorInput) -> dict[str, Any]:
        self._tick_count = mon_in.ticks_so_far

        while not self._stop_requested:
            self._tick_count += 1

            # Look up target → scan row
            target_meta = await workflow.execute_activity(
                _ACT_LOOKUP_TARGET, args=[mon_in.target_id],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=_DEFAULT_RETRY,
            )
            scan_meta = await workflow.execute_activity(
                _ACT_CREATE_SCAN_ROW,
                args=[mon_in.target_id, mon_in.persona, mon_in.started_by],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=_DEFAULT_RETRY,
            )

            scan_input = ScanInput(
                scan_id=int(scan_meta["scan_id"]),
                scan_ulid=scan_meta["scan_ulid"],
                target_id=mon_in.target_id,
                target_slug=target_meta["slug"],
                target_scope_cidrs=list(target_meta["cidrs"] or []),
                persona=mon_in.persona,
                started_by=mon_in.started_by,
                initial_facts=[],
                max_iterations=mon_in.max_iterations_per_scan,
            )

            # Schedule the child scan but don't wait for completion —
            # the loop's tick cadence comes from ``workflow.sleep`` below.
            # ``start_child_workflow`` returns once the child is
            # *scheduled* (not when it finishes), so the await here is
            # short-lived. The handle is intentionally discarded — we
            # don't poll the child's outcome from the monitor.
            await workflow.start_child_workflow(
                "AutonomousScanWorkflow",
                scan_input,
                id=f"scan-{scan_input.scan_ulid}",
                task_queue=workflow.info().task_queue,
            )

            if self._tick_count % _TICKS_BEFORE_CAN == 0:
                workflow.continue_as_new(MonitorInput(
                    target_id=mon_in.target_id,
                    persona=mon_in.persona,
                    interval_seconds=mon_in.interval_seconds,
                    started_by=mon_in.started_by,
                    max_iterations_per_scan=mon_in.max_iterations_per_scan,
                    ticks_so_far=self._tick_count,
                ))

            await workflow.sleep(mon_in.interval_seconds)

        return {"tick_count": self._tick_count, "stopped": True}


__all__ = ["ContinuousMonitorWorkflow", "MonitorInput"]
