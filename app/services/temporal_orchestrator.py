"""Concrete ``Orchestrator`` implementation backed by Temporal."""

from __future__ import annotations

from typing import Any

import ulid
from sqlalchemy.ext.asyncio import AsyncSession
from temporalio.client import Client

from app.config import Persona, Settings
from app.core.exceptions import ScopeViolation
from app.core.orchestrator import Orchestrator, ScanDescriptor, ScanHandle
from app.logging_config import get_logger
from app.models.enums import ScanState
from app.models.scan import Scan
from app.models.target import Target
from app.workflows.data import EscalatePersonaSignal, ScanInput, StopSignal

log = get_logger(__name__)


class TemporalOrchestrator(Orchestrator):
    """Wraps a Temporal client + per-scan workflow handles.

    A single instance per orchestrator process — created lazily.
    """

    _client: Client | None = None

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def client(self) -> Client:
        """Lazy-connected Temporal client. Public — used by scheduling routes."""
        if self._client is None:
            self._client = await Client.connect(
                self._settings.temporal_host,
                namespace=self._settings.temporal_namespace,
            )
        return self._client

    # Backwards-compat alias — earlier phases imported the private name.
    _ensure_client = client

    # ------------------------------------------------------------------
    # Public API (matches Orchestrator Protocol)
    # ------------------------------------------------------------------
    async def start(self, descriptor: ScanDescriptor) -> ScanHandle:
        """Protocol-compatible entry point.

        Resolves ``descriptor.target`` to a Target row by slug (preferred)
        or by exact CIDR match, then delegates to ``start_for_target``.
        Used by the CLI / Phase 5+ scheduling hooks.
        """
        from app.database import get_session_factory  # local: avoid cycle
        from app.repositories.target import TargetRepository

        factory = get_session_factory()
        async with factory() as session, session.begin():
            repo = TargetRepository(session)
            target = await repo.get_by_slug(descriptor.target)
            if target is None:
                raise ValueError(
                    f"orchestrator.start: target {descriptor.target!r} not found"
                )
            scan = await self.start_for_target(
                session=session,
                target=target,
                persona=descriptor.persona,
                started_by=descriptor.started_by,
            )

        return ScanHandle(
            scan_id=str(scan.id),
            workflow_id=scan.workflow_id or "",
            run_id=scan.run_id or "",
        )

    async def start_for_target(
        self,
        *,
        session: AsyncSession,
        target: Target,
        persona: Persona,
        started_by: str,
        max_iterations: int = 100,
    ) -> Scan:
        if not target.accepts_persona(persona):
            if persona == Persona.BLACK and not target.replica_only:
                raise ScopeViolation(
                    f"target {target.slug!r} is not marked replica_only; "
                    "black persona is forbidden on production targets"
                )
            raise ScopeViolation(
                f"target {target.slug!r} does not accept persona {persona.value!r}"
            )

        # Persist a Scan row first so the workflow can update it.
        scan_ulid = str(ulid.new())
        scan = Scan(
            target_id=target.id,                 # type: ignore[arg-type]
            ulid=scan_ulid,
            persona=persona.value,
            state=ScanState.PENDING.value,
            started_by=started_by,
            workflow_id=f"scan-{scan_ulid}",
            task_queue=self._settings.temporal_task_queue,
        )
        session.add(scan)
        await session.flush()
        await session.refresh(scan)
        scan_id = int(scan.id)  # type: ignore[arg-type]

        scan_input = ScanInput(
            scan_id=scan_id,
            scan_ulid=scan_ulid,
            target_id=int(target.id),                          # type: ignore[arg-type]
            target_slug=target.slug,
            target_scope_cidrs=list(target.cidrs or []),
            persona=persona.value,
            started_by=started_by,
            initial_facts=[],
            max_iterations=max_iterations,
        )

        c = await self.client()
        handle = await c.start_workflow(
            "AutonomousScanWorkflow",
            scan_input,
            id=f"scan-{scan_ulid}",
            task_queue=self._settings.temporal_task_queue,
        )
        scan.run_id = handle.result_run_id or handle.run_id   # type: ignore[assignment]
        session.add(scan)
        await session.flush()

        log.info("orchestrator.scan_started", scan_id=scan_id, scan_ulid=scan_ulid,
                 workflow_id=handle.id, run_id=handle.run_id, persona=persona.value)
        return scan

    async def stop(self, scan_id: str, *, reason: str) -> None:
        c = await self.client()
        handle = c.get_workflow_handle(scan_id)   # accepts workflow_id
        await handle.signal("stop", StopSignal(reason=reason, actor="api"))
        log.info("orchestrator.stop_signalled", workflow_id=scan_id, reason=reason)

    async def escalate_persona(
        self, scan_id: str, to: Persona, *, authorised_by: str
    ) -> None:
        c = await self.client()
        handle = c.get_workflow_handle(scan_id)
        await handle.signal(
            "escalate_persona",
            EscalatePersonaSignal(to=to.value, authorised_by=authorised_by),
        )
        log.info("orchestrator.persona_escalated",
                 workflow_id=scan_id, to=to.value, by=authorised_by)

    async def status(self, scan_id: str) -> dict[str, Any]:
        c = await self.client()
        handle = c.get_workflow_handle(scan_id)
        try:
            return await handle.query("status")
        except Exception as exc:
            return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Module-level lazy accessor (one per process)
# ---------------------------------------------------------------------------
_singleton: TemporalOrchestrator | None = None


def get_orchestrator(settings: Settings) -> TemporalOrchestrator:
    global _singleton
    if _singleton is None:
        _singleton = TemporalOrchestrator(settings)
    return _singleton


__all__ = ["TemporalOrchestrator", "get_orchestrator"]
