"""Scan report rendering — JSON / HTML / PDF + per-scan artefact bundle."""

from __future__ import annotations

import io
import tarfile
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.api.dependencies import SessionDep, SettingsDep
from app.models.scan import Scan
from app.services.reporter import PDFRenderTimeout, ScanReporter

router = APIRouter()


@router.get("/{scan_id}", summary="Render a scan report (json|html|pdf)")
async def get_report(
    scan_id: int,
    session: SessionDep,
    settings: SettingsDep,
    fmt: str = Query("json", pattern="^(json|html|pdf)$"),
) -> Response:
    reporter = ScanReporter(settings)
    try:
        payload = await reporter.collect(session, scan_id)
    except LookupError as err:
        raise HTTPException(404, detail=str(err)) from err

    if fmt == "json":
        return JSONResponse(reporter.render_json(payload))
    if fmt == "html":
        return HTMLResponse(reporter.render_html(payload))

    try:
        pdf_bytes = await reporter.render_pdf_async(payload)
    except PDFRenderTimeout as err:
        raise HTTPException(504, detail=str(err)) from err
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="aetherforge-scan-{scan_id}.pdf"',
        },
    )


@router.get(
    "/{scan_id}/bundle",
    summary="Download a tar.gz of the scan's artefacts + JSON + PDF",
)
async def get_bundle(
    scan_id: int, session: SessionDep, settings: SettingsDep,
) -> Response:
    """Per-scan tar.gz bundle for offline replay / hand-off / archival.

    Contents:
      ``meta.json`` — scan + target metadata
      ``report.json`` / ``report.pdf`` — generated reports
      ``artifacts/<execution_ulid>/{stdout,stderr,exit_code,meta.json}``
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, detail="scan not found")

    reporter = ScanReporter(settings)
    payload = await reporter.collect(session, scan_id)
    json_bytes = JSONResponse(reporter.render_json(payload)).body
    try:
        pdf_bytes = await reporter.render_pdf_async(payload)
    except PDFRenderTimeout as err:
        raise HTTPException(504, detail=str(err)) from err

    artefact_root: Path = settings.data_dir / "artifacts" / str(scan_id)

    # Build the tar in a worker thread — `tar.add` walks a directory
    # and reads many files; that's blocking I/O that would otherwise
    # stall the event loop on large bundles.
    import asyncio
    body = await asyncio.to_thread(
        _build_bundle, artefact_root, scan, json_bytes, pdf_bytes,
    )
    return Response(
        content=body,
        media_type="application/gzip",
        headers={
            "Content-Disposition":
                f'attachment; filename="aetherforge-scan-{scan_id}.tar.gz"',
            "Content-Length": str(len(body)),
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_bundle(
    artefact_root: Path, scan: Scan, json_bytes: bytes, pdf_bytes: bytes,
) -> bytes:
    """Synchronous tar.gz assembly — invoked from a worker thread."""
    buf = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_bytes(tar, "meta.json", _scan_meta_bytes(scan), mtime=now)
        _add_bytes(tar, "report.json", json_bytes, mtime=now)
        _add_bytes(tar, "report.pdf", pdf_bytes, mtime=now)
        if artefact_root.exists():
            tar.add(str(artefact_root), arcname="artifacts", recursive=True)
    return buf.getvalue()


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, *, mtime: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = mtime
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def _scan_meta_bytes(scan: Scan) -> bytes:
    import json
    return json.dumps(
        {
            "scan_id": scan.id, "scan_ulid": scan.ulid,
            "target_id": scan.target_id, "persona": scan.persona,
            "state": scan.state, "iterations": scan.iterations,
            "executions_total": scan.executions_total,
            "facts_total": scan.facts_total,
            "findings_total": scan.findings_total,
            "started_by": scan.started_by,
            "started_at": scan.started_at.isoformat() + "Z" if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() + "Z" if scan.finished_at else None,
            "terminal_reason": scan.terminal_reason,
        },
        indent=2,
    ).encode("utf-8")
