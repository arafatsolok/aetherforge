"""Scan reporter — collects scan + facts + findings + audit, renders to JSON/HTML/PDF.

Produces three artefacts from one scan ID:
  * JSON  — machine-friendly, complete data dump
  * HTML  — Jinja-rendered, branded executive summary
  * PDF   — same HTML rendered by WeasyPrint

PDF generation uses the system Cairo + Pango stack already installed
in the orchestrator image.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.logging_config import get_logger
from app.models.audit import AuditLog
from app.models.execution import Execution
from app.models.fact import Fact
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target

log = get_logger(__name__)

# M5 — wall-clock cap on PDF rendering. WeasyPrint walks a CSS box
# tree which can blow up on pathological input (deep nesting, infinite
# image fetches, etc.). A 120s cap is generous for any normal scan
# (the largest test runs in <8s) but keeps a single bad scan from
# pinning a worker thread forever.
PDF_RENDER_TIMEOUT_S: float = 120.0


class PDFRenderTimeout(RuntimeError):
    """Raised when PDF generation exceeds ``PDF_RENDER_TIMEOUT_S``."""


@dataclass(slots=True)
class ScanReportPayload:
    scan: dict[str, Any]
    target: dict[str, Any]
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    facts_by_type: dict[str, int]
    audit: list[dict[str, Any]]
    executions: list[dict[str, Any]]


class ScanReporter:
    """Builds report payloads from DB rows.

    The Jinja env is constructed lazily from ``settings.templates_dir``
    so tests can swap a mock templates directory.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jinja: Environment | None = None

    def _env(self) -> Environment:
        if self._jinja is None:
            self._jinja = Environment(
                loader=FileSystemLoader(str(self._settings.templates_dir)),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            self._jinja.filters["sevcolor"] = _severity_color
        return self._jinja

    # -------------------------------------------------------------------
    # Data collection
    # -------------------------------------------------------------------
    async def collect(self, session: AsyncSession, scan_id: int) -> ScanReportPayload:
        scan = (await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )).scalar_one_or_none()
        if scan is None:
            raise LookupError(f"scan {scan_id} not found")

        target = (await session.execute(
            select(Target).where(Target.id == scan.target_id)
        )).scalar_one()

        findings = list((await session.execute(
            select(Finding).where(Finding.scan_id == scan_id)
            .order_by(Finding.severity.desc(), Finding.created_at.desc())
        )).scalars().all())

        facts = list((await session.execute(
            select(Fact).where(Fact.scan_id == scan_id)
        )).scalars().all())

        executions = list((await session.execute(
            select(Execution).where(Execution.scan_id == scan_id)
            .order_by(Execution.id)
        )).scalars().all())

        audit = list((await session.execute(
            select(AuditLog).where(AuditLog.scan_id == scan_id)
            .order_by(AuditLog.sequence)
        )).scalars().all())

        sev_counter: Counter[str] = Counter(f.severity for f in findings)
        fact_counter: Counter[str] = Counter(f.fact_type for f in facts)

        summary = {
            "iterations":        scan.iterations,
            "executions_total":  scan.executions_total,
            "facts_total":       len(facts),
            "findings_total":    len(findings),
            "severity_counts":   dict(sev_counter),
            "fact_types":        dict(fact_counter),
            "duration_ms":       _duration_ms(scan),
            "terminal_reason":   scan.terminal_reason or "—",
        }

        return ScanReportPayload(
            scan=_scan_dict(scan),
            target=_target_dict(target),
            summary=summary,
            findings=[_finding_dict(f) for f in findings],
            facts_by_type=dict(fact_counter),
            audit=[_audit_dict(a) for a in audit],
            executions=[_execution_dict(e) for e in executions],
        )

    # -------------------------------------------------------------------
    # Renderers
    # -------------------------------------------------------------------
    def render_json(self, payload: ScanReportPayload) -> dict[str, Any]:
        return {
            "scan":         payload.scan,
            "target":       payload.target,
            "summary":      payload.summary,
            "findings":     payload.findings,
            "facts_by_type": payload.facts_by_type,
            "audit":        payload.audit,
            "executions":   payload.executions,
        }

    def render_html(self, payload: ScanReportPayload) -> str:
        tpl = self._env().get_template("reports/scan_report.html")
        return tpl.render(**self.render_json(payload))

    def render_pdf(self, payload: ScanReportPayload) -> bytes:
        """Synchronous PDF render. Prefer :meth:`render_pdf_async` from
        web routes — this version blocks the event loop and has no
        timeout."""
        # Import lazily — WeasyPrint loads slow Cairo bindings.
        from weasyprint import HTML  # noqa: PLC0415

        html_str = self.render_html(payload)
        return HTML(string=html_str, base_url=str(self._settings.templates_dir)).write_pdf()

    async def render_pdf_async(
        self, payload: ScanReportPayload, *, timeout: float | None = None,
    ) -> bytes:
        """Render the PDF in a worker thread with a wall-clock cap.

        M5 — the synchronous WeasyPrint call blocks the event loop and
        can hang on pathological HTML. We dispatch to ``asyncio.to_thread``
        so other requests keep flowing, and wrap with ``wait_for`` so a
        runaway render eventually fails with HTTP 504 instead of
        starving the worker.
        """
        cap = PDF_RENDER_TIMEOUT_S if timeout is None else timeout
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.render_pdf, payload),
                timeout=cap,
            )
        except TimeoutError as err:
            log.error(
                "reporter.pdf.timeout",
                scan_id=payload.scan.get("id"), timeout_s=cap,
            )
            raise PDFRenderTimeout(
                f"PDF render exceeded {cap:.0f}s for scan "
                f"{payload.scan.get('id')!r}",
            ) from err


# ---------------------------------------------------------------------------
# Row → dict converters (kept inline so reporter stays self-contained)
# ---------------------------------------------------------------------------
def _severity_color(sev: str) -> str:
    return {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#ca8a04",
        "low":      "#65a30d",
        "info":     "#0284c7",
    }.get(sev, "#64748b")


def _duration_ms(scan: Scan) -> int | None:
    if scan.started_at and scan.finished_at:
        return int((scan.finished_at - scan.started_at).total_seconds() * 1000)
    return None


def _iso(dt: object) -> str | None:
    if dt is None:
        return None
    return f"{dt.isoformat()}Z" if hasattr(dt, "isoformat") else str(dt)


def _scan_dict(s: Scan) -> dict[str, Any]:
    return {
        "id": s.id, "ulid": s.ulid, "persona": s.persona, "state": s.state,
        "workflow_id": s.workflow_id, "started_by": s.started_by,
        "started_at": _iso(s.started_at), "finished_at": _iso(s.finished_at),
        "iterations": s.iterations, "executions_total": s.executions_total,
        "facts_total": s.facts_total, "findings_total": s.findings_total,
        "terminal_reason": s.terminal_reason,
    }


def _target_dict(t: Target) -> dict[str, Any]:
    return {
        "id": t.id, "slug": t.slug, "description": t.description,
        "owner": t.owner, "cidrs": list(t.cidrs or []),
        "domains": list(t.domains or []), "tags": list(t.tags or []),
        "replica_only": t.replica_only,
    }


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id, "ulid": f.ulid, "rule_id": f.rule_id, "tool": f.tool,
        "title": f.title, "description": f.description,
        "severity": f.severity, "cvss_score": float(f.cvss_score) if f.cvss_score is not None else None,
        "cve_id": f.cve_id, "affected": dict(f.affected or {}),
        "evidence": dict(f.evidence or {}), "remediation": f.remediation,
        "status": f.status, "confirmed": f.confirmed,
        "triaged_by": f.triaged_by, "triage_notes": f.triage_notes,
        "created_at": _iso(f.created_at),
    }


def _audit_dict(a: AuditLog) -> dict[str, Any]:
    return {
        "sequence": a.sequence, "event": a.event, "persona": a.persona,
        "actor": a.actor, "rule_id": a.rule_id,
        "payload": dict(a.payload or {}),
        "created_at": _iso(a.created_at),
    }


def _execution_dict(e: Execution) -> dict[str, Any]:
    return {
        "id": e.id, "ulid": e.ulid, "tool": e.tool, "rule_id": e.rule_id,
        "image": e.image, "argv": list(e.argv or []),
        "exit_code": e.exit_code, "duration_ms": e.duration_ms,
        "state": e.state,
        "started_at": _iso(e.started_at), "finished_at": _iso(e.finished_at),
        "stdout_bytes": e.stdout_bytes, "stderr_bytes": e.stderr_bytes,
    }


__all__ = ["ScanReportPayload", "ScanReporter"]
