"""Central orchestrator contract.

The orchestrator is the *director* that coordinates:
  Rule Engine  →  Persona Engine  →  Command Generator  →  Tool Executor  →  State Machine

Phase 0 defines the Protocol so downstream modules (API handlers, CLI,
workflows) can depend on it. Phase 3 provides the concrete Temporal-backed
``TemporalOrchestrator``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.config import Persona


@dataclass(frozen=True, slots=True)
class ScanDescriptor:
    """Immutable input to the orchestrator to start a new scan."""

    target: str
    persona: Persona
    scope_id: str | None = None
    started_by: str = "system"
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanHandle:
    """Returned from ``start`` — allows signal/stop/inspect later."""

    scan_id: str
    workflow_id: str
    run_id: str


@runtime_checkable
class Orchestrator(Protocol):
    """Contract every orchestrator implementation must honour."""

    async def start(self, descriptor: ScanDescriptor) -> ScanHandle: ...

    async def stop(self, scan_id: str, *, reason: str) -> None: ...

    async def escalate_persona(self, scan_id: str, to: Persona, *, authorised_by: str) -> None: ...

    async def status(self, scan_id: str) -> dict[str, object]: ...


class OrchestratorNotReady(RuntimeError):
    """Raised if the orchestrator is invoked before its backend is ready."""


__all__ = [
    "Orchestrator",
    "OrchestratorNotReady",
    "ScanDescriptor",
    "ScanHandle",
]
