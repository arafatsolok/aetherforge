"""Workflow / activity data transfer objects.

Everything that crosses an activity boundary MUST be JSON-serialisable
because Temporal pickles inputs / outputs to its history. We use
``dataclass`` with primitive fields (no enums-with-state, no Path, no
SecretStr) — Temporal serialises these via dataclass_json automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ScanInput:
    """Workflow input — the only thing Temporal sees on start()."""

    scan_id: int
    scan_ulid: str
    target_id: int
    target_slug: str
    target_scope_cidrs: list[str]
    persona: str                       # "white" | "gray" | "black"
    started_by: str
    initial_facts: list[dict[str, Any]] = field(default_factory=list)
    max_iterations: int = 100
    iterations_so_far: int = 0          # restored across continue-as-new
    executed_rule_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FactDTO:
    """JSON-clean wire form of ``Fact``."""

    fact_type: str
    body: dict[str, Any]
    source_tool: str
    iteration: int
    fingerprint: str


@dataclass(slots=True)
class RuleMatchSummary:
    """Just enough to drive the next two activities."""

    rule_id: str
    rule_version: int
    phase: str
    priority: int
    triggering_fact: FactDTO
    bindings: dict[str, Any]


@dataclass(slots=True)
class InvocationSpec:
    """Wire form of ``ToolInvocation`` (subset — no objects)."""

    tool_name: str
    image: str
    argv: list[str]
    cap_add: list[str]
    cap_drop: list[str]
    memory_bytes: int
    cpu_shares: int
    timeout_seconds: int
    read_only_rootfs: bool
    run_as_uid: int | None
    network: str
    rule_id: str
    persona: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ExecutionOutcome:
    """Result of one tool execution."""

    execution_id: int          # DB row id
    execution_ulid: str
    tool: str
    rule_id: str
    exit_code: int
    duration_ms: int
    timed_out: bool
    error: str | None = None
    facts_emitted: int = 0


@dataclass(slots=True)
class IterationOutcome:
    """Returned by `pick_next_action` to drive workflow control flow."""

    has_action: bool
    rule_id: str | None = None
    rejection_reason: str | None = None
    invocation: InvocationSpec | None = None
    triggering_fact_fingerprint: str | None = None


@dataclass(slots=True)
class ScanResult:
    """Final return value of the workflow."""

    scan_id: int
    scan_ulid: str
    state: str               # "completed" | "failed" | "cancelled"
    iterations: int
    executions_total: int
    facts_total: int
    findings_total: int
    terminal_reason: str = ""


# Signal payloads -----------------------------------------------------------
@dataclass(slots=True)
class StopSignal:
    reason: str
    actor: str = "operator"


@dataclass(slots=True)
class EscalatePersonaSignal:
    to: str                  # "white" | "gray" | "black"
    authorised_by: str


__all__ = [
    "EscalatePersonaSignal",
    "ExecutionOutcome",
    "FactDTO",
    "InvocationSpec",
    "IterationOutcome",
    "RuleMatchSummary",
    "ScanInput",
    "ScanResult",
    "StopSignal",
]
