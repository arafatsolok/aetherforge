"""HTMX dashboard — server-rendered HTML for the operator console."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import case, desc, func, select

from app import __version__
from app.api.dependencies import SessionDep, SettingsDep
from app.api.middleware.auth import constant_time_eq
from app.config import Persona
from app.logging_config import get_logger
from app.models.audit import AuditLog
from app.models.drift import DriftDelta, DriftSnapshot
from app.models.finding import Finding
from app.models.rule import Rule
from app.models.scan import Scan
from app.models.target import Target

router = APIRouter()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------
# Whitelisted login error keys → human-readable messages. The query
# parameter is constrained by ``pattern`` so the only way to get a
# message on screen is for the server itself to redirect with one of
# these keys — nothing user-controlled ever reaches the template.
_LOGIN_ERRORS: dict[str, str] = {
    "invalid_api_key":  "Invalid API key.",
    "session_expired":  "Session expired — please sign in again.",
    "missing_fields":   "API key is required.",
}


@router.get("/ui/login", response_class=HTMLResponse, include_in_schema=False)
async def page_login(
    request: Request, settings: SettingsDep,
    next: str = Query("/", max_length=512),
    error: str | None = Query(None, max_length=32,
                              pattern="^(invalid_api_key|session_expired|missing_fields)?$"),
) -> HTMLResponse:
    if settings.api_key is None:
        # Auth disabled — the form is meaningless. Return BEFORE the
        # templates lookup so apps that didn't mount Jinja can still
        # exercise this branch (e.g. unit tests).
        return HTMLResponse(
            "<h1>Login disabled</h1><p>Authentication not configured "
            "for this environment.</p><p><a href='/'>back</a></p>",
            status_code=410,
        )
    tpl = request.app.state.templates
    return tpl.TemplateResponse(
        request=request, name="pages/login.html",
        context={
            "version": __version__,
            "next": _safe_next(next),
            "error": _LOGIN_ERRORS.get(error) if error else None,
        },
    )


@router.post("/ui/login", response_class=HTMLResponse, include_in_schema=False)
async def submit_login(
    request: Request, settings: SettingsDep,
    api_key: str = Form(..., min_length=1, max_length=512),
    next: str = Form("/", max_length=512),
) -> RedirectResponse:
    if settings.api_key is None:
        return RedirectResponse("/", status_code=303)
    if not constant_time_eq(api_key, settings.api_key.get_secret_value()):
        log.warning("ui.login.failed",
                    client=request.client.host if request.client else "unknown")
        return RedirectResponse("/ui/login?error=invalid_api_key", status_code=303)

    # B1 — defeat session fixation. Starlette's SessionMiddleware stores
    # state inside the signed cookie body, so .clear() + re-populate
    # produces a fresh signed cookie value. Any pre-existing cookie
    # planted by an attacker (e.g., copy-pasted from a previous session
    # on a shared device) becomes useless because:
    #   * its keys are wiped (no carry-over of stale data), AND
    #   * the new payload includes a per-session nonce + login timestamp
    #     so identical state never produces an identical cookie value.
    request.session.clear()
    request.session["authenticated"] = True
    request.session["sid"] = secrets.token_urlsafe(16)
    request.session["login_at"] = datetime.now(UTC).isoformat()

    log.info("ui.login.success",
             client=request.client.host if request.client else "unknown")
    return RedirectResponse(_safe_next(next), status_code=303)


def _safe_next(raw: str) -> str:
    """Open-redirect guard for the ``?next=`` post-login destination.

    A naive check (``raw.startswith("/")``) is bypassable on Chrome /
    Edge because:

    * ``/\\evil.com`` — backslash gets normalised to ``/`` by the browser
      before the request leaves, so the URL effectively becomes
      ``//evil.com`` (protocol-relative → cross-origin).
    * ``/%2fevil.com``, ``/%5cevil.com`` — percent-encoded forms of the
      separators that decode AFTER the same-origin check has run.
    * ``/\\x00…`` — null bytes confuse some routers.
    * ``//evil.com`` — protocol-relative, the classic case.
    * ``http://…``, ``//evil.com``, ``javascript:…`` — any URL with a
      scheme or netloc is, by definition, off-origin.

    We collapse all of these by:
      1. Rejecting any literal ``\\``, ``%2f``, ``%5c`` (case-insensitive)
         or ``\\x00`` in the raw value.
      2. Decoding the value once and parsing it with ``urlparse``; the
         result must have NO scheme, NO netloc, AND a path that begins
         with exactly one ``/``.

    Anything that fails any check falls back to ``"/"``.
    """
    import urllib.parse as up

    if not raw:
        return "/"
    lower = raw.lower()
    if any(needle in lower for needle in ("\\", "%2f", "%5c", "%00")):
        return "/"
    if "\x00" in raw:
        return "/"
    decoded = up.unquote(raw)
    parsed = up.urlparse(decoded)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not decoded.startswith("/") or decoded.startswith("//"):
        return "/"
    return raw


@router.post("/ui/logout", response_class=HTMLResponse, include_in_schema=False)
async def submit_logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/ui/login", status_code=303)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(
    request: Request, session: SessionDep, settings: SettingsDep,
) -> HTMLResponse:
    tpl = getattr(request.app.state, "templates", None)
    if tpl is None:
        return HTMLResponse(f"<h1>AetherForge {__version__}</h1>")

    from app.api.routes.tools import _get_registry

    metrics = await _quick_metrics(session)
    try:
        tools_count = len(_get_registry(settings).all())
    except Exception:                                       # noqa: BLE001
        tools_count = 0
    return tpl.TemplateResponse(
        request=request, name="pages/index.html",
        context={"version": __version__, "tools_count": tools_count, **metrics},
    )


@router.get("/ui/scans", response_class=HTMLResponse, include_in_schema=False)
async def page_scans(
    request: Request, session: SessionDep,
) -> HTMLResponse:
    tpl = request.app.state.templates
    rows = list((await session.execute(
        select(Scan).order_by(desc(Scan.id)).limit(50)
    )).scalars().all())
    target_ids = {s.target_id for s in rows}
    slugs: dict[int, str] = {}
    if target_ids:
        slug_rows = (await session.execute(
            select(Target.id, Target.slug).where(Target.id.in_(target_ids))
        )).all()
        slugs = dict(slug_rows)
    return tpl.TemplateResponse(
        request=request, name="pages/scans.html",
        context={"version": __version__, "scans": rows, "target_slugs": slugs},
    )


@router.get("/ui/scans/new", response_class=HTMLResponse, include_in_schema=False)
async def page_scan_new(
    request: Request, session: SessionDep,
    error: str | None = Query(None, max_length=512),
) -> HTMLResponse:
    tpl = request.app.state.templates
    targets = list((await session.execute(
        select(Target).where(Target.active.is_(True)).order_by(Target.slug)
    )).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/scan_new.html",
        context={
            "version": __version__,
            "targets": targets,
            "personas": [p.value for p in Persona],
            "error": error,
        },
    )


@router.post("/ui/scans/new", response_class=HTMLResponse, include_in_schema=False)
async def submit_scan_new(
    request: Request, session: SessionDep, settings: SettingsDep,
    target_slug: str = Form(..., min_length=1, max_length=64),
    persona: str = Form(..., min_length=1, max_length=16),
) -> RedirectResponse:
    from app.core.exceptions import ScopeViolation
    from app.repositories.target import TargetRepository
    from app.services.temporal_orchestrator import get_orchestrator

    repo = TargetRepository(session)
    target = await repo.get_by_slug(target_slug)
    if target is None:
        return RedirectResponse("/ui/scans/new?error=target_not_found", status_code=303)
    try:
        persona_val = Persona(persona)
    except ValueError:
        return RedirectResponse("/ui/scans/new?error=invalid_persona", status_code=303)
    orch = get_orchestrator(settings)
    try:
        scan = await orch.start_for_target(
            session=session, target=target,
            persona=persona_val, started_by=_started_by(request),
        )
    except ScopeViolation:
        return RedirectResponse("/ui/scans/new?error=scope_violation", status_code=303)
    except ValueError:
        return RedirectResponse("/ui/scans/new?error=invalid_request", status_code=303)
    return RedirectResponse(f"/ui/scans/{scan.id}", status_code=303)


def _started_by(request: Request) -> str:
    """Return a server-controlled actor string for audit attribution.

    Never trust an operator-controlled Form field for this — an attacker
    who reaches the form (already authenticated) could otherwise spoof
    arbitrary actor names in the audit log. ``ui:<sid>`` ties every
    UI-driven action to the *session that produced it*, which the
    server set at login time.
    """
    sess = getattr(request, "session", None)
    if isinstance(sess, dict):
        sid = sess.get("sid")
        if sid:
            return f"ui:{sid}"
    return "ui"


@router.get("/ui/findings", response_class=HTMLResponse, include_in_schema=False)
async def page_findings(
    request: Request, session: SessionDep,
    severity: str | None = Query(None, max_length=16,
                                  pattern="^(critical|high|medium|low|info)?$"),
    status: str | None = Query(None, max_length=16,
                               pattern="^(open|triaged|false_positive|fixed|wontfix)?$"),
    page: int = Query(1, ge=1, le=10_000),
    size: int = Query(50, ge=1, le=200),
) -> HTMLResponse:
    tpl = request.app.state.templates
    stmt = select(Finding)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar_one())
    sev_rank = case(
        (Finding.severity == "critical", 4),
        (Finding.severity == "high",     3),
        (Finding.severity == "medium",   2),
        (Finding.severity == "low",      1),
        else_=0,
    )
    stmt = stmt.order_by(sev_rank.desc(), desc(Finding.created_at)) \
               .limit(size).offset((page - 1) * size)
    rows = list((await session.execute(stmt)).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/findings.html",
        context={
            "version": __version__, "findings": rows,
            "filter_severity": severity or "",
            "filter_status": status or "",
            **_pagination(page=page, size=size, total=total,
                          base_path="/ui/findings",
                          extra={"severity": severity or "",
                                 "status": status or ""}),
        },
    )


@router.get("/ui/targets", response_class=HTMLResponse, include_in_schema=False)
async def page_targets(
    request: Request, session: SessionDep,
    page: int = Query(1, ge=1, le=10_000),
    size: int = Query(50, ge=1, le=200),
) -> HTMLResponse:
    tpl = request.app.state.templates
    total = int((await session.execute(
        select(func.count()).select_from(select(Target).subquery())
    )).scalar_one())
    rows = list((await session.execute(
        select(Target).order_by(desc(Target.id))
        .limit(size).offset((page - 1) * size)
    )).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/targets.html",
        context={
            "version": __version__, "targets": rows,
            **_pagination(page=page, size=size, total=total,
                          base_path="/ui/targets", extra={}),
        },
    )


def _pagination(*, page: int, size: int, total: int,
                base_path: str, extra: dict[str, str]) -> dict[str, object]:
    """Return a small dict the list templates can render Prev/Next from."""
    import urllib.parse as up
    extra_pairs = [(k, v) for k, v in extra.items() if v not in ("", None)]
    pages = max(1, (total + size - 1) // size)
    page = min(page, pages)

    def _link(p: int) -> str:
        qs = up.urlencode([*extra_pairs, ("page", p), ("size", size)])
        return f"{base_path}?{qs}"

    return {
        "page": page,
        "size": size,
        "total": total,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_url": _link(page - 1) if page > 1 else "",
        "next_url": _link(page + 1) if page < pages else "",
    }


@router.get("/ui/targets/new", response_class=HTMLResponse, include_in_schema=False)
async def page_target_new(
    request: Request,
    error: str | None = Query(None, max_length=512),
) -> HTMLResponse:
    tpl = request.app.state.templates
    return tpl.TemplateResponse(
        request=request, name="pages/target_new.html",
        context={
            "version": __version__,
            "personas": [p.value for p in Persona],
            "error": error,
        },
    )


@router.post("/ui/targets/new", response_class=HTMLResponse, include_in_schema=False)
async def submit_target_new(
    session: SessionDep,
    slug: str = Form(..., min_length=1, max_length=64),
    description: str = Form("", max_length=1024),
    owner: str = Form("", max_length=256),
    cidrs: str = Form("", max_length=4096),
    domains: str = Form("", max_length=4096),
    allowed_personas: list[str] = Form(default_factory=lambda: ["white"]),
    tags: str = Form("", max_length=2048),
    notes: str = Form("", max_length=8192),
    replica_only: bool = Form(False),
) -> RedirectResponse:
    from app.repositories.target import TargetRepository
    from app.schemas.target import TargetCreate

    def _split(s: str) -> list[str]:
        return [tok.strip() for tok in s.replace("\n", ",").split(",") if tok.strip()]

    try:
        payload = TargetCreate(
            slug=slug,
            description=description or "",
            owner=owner or "",
            cidrs=_split(cidrs),
            domains=_split(domains),
            allowed_personas=[Persona(p) for p in allowed_personas if p],
            tags=_split(tags),
            notes=notes or "",
            replica_only=bool(replica_only),
        )
    except Exception as err:  # noqa: BLE001 — surface validation back to user
        return RedirectResponse(
            f"/ui/targets/new?error={str(err).replace(' ', '+')[:480]}",
            status_code=303,
        )

    repo = TargetRepository(session)
    if await repo.get_by_slug(payload.slug) is not None:
        return RedirectResponse(
            f"/ui/targets/new?error=slug+{payload.slug}+already+exists",
            status_code=303,
        )
    entity = Target(
        slug=payload.slug,
        description=payload.description,
        owner=payload.owner,
        cidrs=list(payload.cidrs),
        domains=list(payload.domains),
        allowed_personas=[p.value for p in payload.allowed_personas],
        tags=list(payload.tags),
        notes=payload.notes,
        meta=dict(payload.meta),
        active=payload.active,
        replica_only=payload.replica_only,
    )
    await repo.create(entity)
    return RedirectResponse("/ui/targets", status_code=303)


@router.get("/ui/scans/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
async def page_scan_detail(
    scan_id: int, request: Request, session: SessionDep,
) -> HTMLResponse:
    tpl = request.app.state.templates
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return HTMLResponse("Scan not found", status_code=404)
    audit = list((await session.execute(
        select(AuditLog).where(AuditLog.scan_id == scan_id)
        .order_by(AuditLog.sequence)
    )).scalars().all())
    findings = list((await session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(desc(Finding.created_at))
    )).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/scan_detail.html",
        context={"version": __version__, "scan": scan,
                 "audit": audit, "findings": findings},
    )


# ---------------------------------------------------------------------------
# Rules page
# ---------------------------------------------------------------------------
@router.get("/ui/rules", response_class=HTMLResponse, include_in_schema=False)
async def page_rules(
    request: Request, session: SessionDep,
    phase: str | None = Query(None, max_length=32, pattern="^[a-z._]*$"),
    persona: str | None = Query(None, pattern="^(white|gray|black)?$"),
    enabled: str | None = Query(None, pattern="^(true|false)?$"),
    page: int = Query(1, ge=1, le=10_000),
    size: int = Query(50, ge=1, le=200),
) -> HTMLResponse:
    tpl = request.app.state.templates
    stmt = select(Rule)
    if phase:
        stmt = stmt.where(Rule.phase == phase)
    if persona:
        stmt = stmt.where(Rule.personas.any(persona))   # type: ignore[attr-defined]
    if enabled:
        stmt = stmt.where(Rule.enabled.is_(enabled == "true"))
    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar_one())
    stmt = stmt.order_by(Rule.priority.desc(), Rule.rule_id) \
               .limit(size).offset((page - 1) * size)
    rows = list((await session.execute(stmt)).scalars().all())

    # P2 — cap the dropdown source to keep the response small even on
    # exotic deployments with thousands of distinct phases.
    phases = [r[0] for r in (await session.execute(
        select(Rule.phase).distinct().order_by(Rule.phase).limit(200)
    )).all()]

    return tpl.TemplateResponse(
        request=request, name="pages/rules.html",
        context={
            "version": __version__,
            "rules": rows,
            "phases": phases,
            "filter_phase": phase or "",
            "filter_persona": persona or "",
            "filter_enabled": enabled or "",
            **_pagination(page=page, size=size, total=total,
                          base_path="/ui/rules",
                          extra={"phase": phase or "",
                                 "persona": persona or "",
                                 "enabled": enabled or ""}),
        },
    )


@router.get("/ui/rules/{rule_id}", response_class=HTMLResponse, include_in_schema=False)
async def page_rule_detail(
    rule_id: str, request: Request, session: SessionDep,
) -> HTMLResponse:
    tpl = request.app.state.templates
    row = (await session.execute(
        select(Rule).where(Rule.rule_id == rule_id)
        .order_by(Rule.version.desc()).limit(1)
    )).scalar_one_or_none()
    if row is None:
        return HTMLResponse("Rule not found", status_code=404)
    versions = list((await session.execute(
        select(Rule).where(Rule.rule_id == rule_id)
        .order_by(Rule.version.desc())
    )).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/rule_detail.html",
        context={"version": __version__, "rule": row, "versions": versions},
    )


# ---------------------------------------------------------------------------
# Tools page
# ---------------------------------------------------------------------------
@router.get("/ui/tools", response_class=HTMLResponse, include_in_schema=False)
async def page_tools(
    request: Request, settings: SettingsDep,
) -> HTMLResponse:
    from app.api.routes.tools import _get_registry

    tpl = request.app.state.templates
    reg = _get_registry(settings)
    tools = sorted(
        ({
            "name": w.spec.name,
            "image": w.spec.image,
            "category": w.spec.category.value,
            "description": w.spec.description,
            "cap_add": list(w.spec.required_caps),
            "default_timeout_seconds": w.spec.default_timeout_seconds,
            "default_memory_bytes": w.spec.default_memory_bytes,
            "supports_json_output": w.spec.supports_json_output,
            "min_persona_ordinal": w.spec.min_persona_ordinal,
            "version": w.spec.version,
            "labels": list(w.spec.labels),
        } for w in reg.all()),
        key=lambda t: (t["category"], t["name"]),
    )
    persona_labels = {0: "white", 1: "gray", 2: "black"}
    return tpl.TemplateResponse(
        request=request, name="pages/tools.html",
        context={
            "version": __version__,
            "tools": tools,
            "persona_labels": persona_labels,
        },
    )


# ---------------------------------------------------------------------------
# Audit page
# ---------------------------------------------------------------------------
@router.get("/ui/audit", response_class=HTMLResponse, include_in_schema=False)
async def page_audit(
    request: Request, session: SessionDep,
    scan_id: int | None = Query(None, ge=1),
    event: str | None = Query(None, max_length=64),
    persona: str | None = Query(None, pattern="^(white|gray|black)$"),
    limit: int = Query(200, ge=1, le=2000),
) -> HTMLResponse:
    tpl = request.app.state.templates
    stmt = select(AuditLog)
    if scan_id is not None:
        stmt = stmt.where(AuditLog.scan_id == scan_id)
    if event:
        stmt = stmt.where(AuditLog.event == event)
    if persona:
        stmt = stmt.where(AuditLog.persona == persona)
    stmt = stmt.order_by(desc(AuditLog.id)).limit(limit)
    rows = list((await session.execute(stmt)).scalars().all())

    # P2 — bounded so a runaway scan with 10k unique events doesn't
    # blow up the filter dropdown.
    events = [r[0] for r in (await session.execute(
        select(AuditLog.event).distinct().order_by(AuditLog.event).limit(200)
    )).all()]

    return tpl.TemplateResponse(
        request=request, name="pages/audit.html",
        context={
            "version": __version__,
            "entries": rows,
            "events": events,
            "filter_scan_id": scan_id or "",
            "filter_event": event or "",
            "filter_persona": persona or "",
            "filter_limit": limit,
        },
    )


# ---------------------------------------------------------------------------
# Drift page (target list + per-target detail)
# ---------------------------------------------------------------------------
@router.get("/ui/drift", response_class=HTMLResponse, include_in_schema=False)
async def page_drift(
    request: Request, session: SessionDep,
) -> HTMLResponse:
    tpl = request.app.state.templates
    snap_counts = dict((await session.execute(
        select(DriftSnapshot.target_id, func.count(DriftSnapshot.id))
        .group_by(DriftSnapshot.target_id)
    )).all())
    delta_counts = dict((await session.execute(
        select(DriftDelta.target_id, func.count(DriftDelta.id))
        .group_by(DriftDelta.target_id)
    )).all())
    last_snapshot = dict((await session.execute(
        select(DriftSnapshot.target_id, func.max(DriftSnapshot.created_at))
        .group_by(DriftSnapshot.target_id)
    )).all())
    targets = list((await session.execute(
        select(Target).order_by(Target.slug)
    )).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/drift.html",
        context={
            "version": __version__,
            "targets": targets,
            "snap_counts": snap_counts,
            "delta_counts": delta_counts,
            "last_snapshot": last_snapshot,
        },
    )


@router.get("/ui/drift/{target_id}", response_class=HTMLResponse, include_in_schema=False)
async def page_drift_detail(
    target_id: int, request: Request, session: SessionDep,
) -> HTMLResponse:
    tpl = request.app.state.templates
    target = await session.get(Target, target_id)
    if target is None:
        return HTMLResponse("Target not found", status_code=404)
    snaps = list((await session.execute(
        select(DriftSnapshot).where(DriftSnapshot.target_id == target_id)
        .order_by(desc(DriftSnapshot.id)).limit(50)
    )).scalars().all())
    deltas = list((await session.execute(
        select(DriftDelta).where(DriftDelta.target_id == target_id)
        .order_by(desc(DriftDelta.id)).limit(50)
    )).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="pages/drift_detail.html",
        context={
            "version": __version__,
            "target": target,
            "snapshots": snaps,
            "deltas": deltas,
            "personas": [p.value for p in Persona],
        },
    )


@router.post("/ui/drift/{target_id}/monitor", response_class=HTMLResponse, include_in_schema=False)
async def submit_drift_monitor(
    target_id: int, request: Request, session: SessionDep, settings: SettingsDep,
    persona: str = Form("gray", min_length=1, max_length=16),
    # Bounds match the JSON API in app/api/routes/drift.py:73 — 60s ≤ x ≤ 7d.
    interval_seconds: int = Form(21_600, ge=60, le=604_800),
) -> RedirectResponse:
    from app.services.temporal_orchestrator import get_orchestrator
    from app.workflows.continuous_monitor import MonitorInput

    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(404, detail="target not found")
    try:
        persona_val = Persona(persona)
    except ValueError:
        raise HTTPException(422, detail=f"invalid persona {persona!r}") from None
    if not target.accepts_persona(persona_val):
        raise HTTPException(403, detail=f"target rejects persona {persona}")

    orch = get_orchestrator(settings)
    client = await orch.client()
    await client.start_workflow(
        "ContinuousMonitorWorkflow",
        MonitorInput(
            target_id=int(target.id),                       # type: ignore[arg-type]
            persona=persona_val.value,
            interval_seconds=int(interval_seconds),
            started_by=_started_by(request),
        ),
        id=f"monitor-{target.slug}",
        task_queue=settings.temporal_task_queue,
    )
    return RedirectResponse(f"/ui/drift/{target_id}", status_code=303)


@router.post("/ui/drift/{target_id}/monitor/stop", response_class=HTMLResponse, include_in_schema=False)
async def submit_drift_monitor_stop(
    target_id: int, session: SessionDep, settings: SettingsDep,
) -> RedirectResponse:
    from app.services.temporal_orchestrator import get_orchestrator

    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(404, detail="target not found")
    orch = get_orchestrator(settings)
    client = await orch.client()
    handle = client.get_workflow_handle(f"monitor-{target.slug}")
    try:
        await handle.signal("stop")
    except Exception as exc:                                # noqa: BLE001
        # Already-stopped or never-started — UX stays idempotent (303), but
        # we LOG so an operator can see why a "Stop" click was a no-op.
        log.warning("ui.drift.monitor.stop_failed",
                    target=target.slug, error=str(exc))
    return RedirectResponse(f"/ui/drift/{target_id}", status_code=303)


# ---------------------------------------------------------------------------
# HTMX partials (returned naked HTML for swap-in)
# ---------------------------------------------------------------------------
@router.get("/ui/_partials/scans_rows", response_class=HTMLResponse, include_in_schema=False)
async def partial_scans_rows(request: Request, session: SessionDep) -> HTMLResponse:
    tpl = request.app.state.templates
    rows = list((await session.execute(
        select(Scan).order_by(desc(Scan.id)).limit(50)
    )).scalars().all())
    # Pre-load target slugs so the row template can show a name, not an FK.
    target_ids = {s.target_id for s in rows}
    slugs: dict[int, str] = {}
    if target_ids:
        slug_rows = (await session.execute(
            select(Target.id, Target.slug).where(Target.id.in_(target_ids))
        )).all()
        slugs = dict(slug_rows)
    return tpl.TemplateResponse(
        request=request, name="partials/scans_rows.html",
        context={"scans": rows, "target_slugs": slugs},
    )


@router.get("/ui/_partials/metrics", response_class=HTMLResponse, include_in_schema=False)
async def partial_metrics(request: Request, session: SessionDep) -> HTMLResponse:
    tpl = request.app.state.templates
    metrics = await _quick_metrics(session)
    return tpl.TemplateResponse(
        request=request, name="partials/metrics.html",
        context=metrics,
    )


@router.get("/ui/_partials/audit_rows", response_class=HTMLResponse, include_in_schema=False)
async def partial_audit_rows(
    request: Request, session: SessionDep,
    scan_id: int | None = Query(None, ge=1),
    event: str | None = Query(None, max_length=64),
    persona: str | None = Query(None, pattern="^(white|gray|black)$"),
    limit: int = Query(200, ge=1, le=2000),
) -> HTMLResponse:
    tpl = request.app.state.templates
    stmt = select(AuditLog)
    if scan_id is not None:
        stmt = stmt.where(AuditLog.scan_id == scan_id)
    if event:
        stmt = stmt.where(AuditLog.event == event)
    if persona:
        stmt = stmt.where(AuditLog.persona == persona)
    stmt = stmt.order_by(desc(AuditLog.id)).limit(limit)
    rows = list((await session.execute(stmt)).scalars().all())
    return tpl.TemplateResponse(
        request=request, name="partials/audit_rows.html",
        context={"entries": rows},
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
async def _quick_metrics(session) -> dict[str, object]:  # type: ignore[no-untyped-def]
    counts: dict[str, int] = {}
    for label, model in [("targets", Target), ("scans", Scan), ("findings", Finding)]:
        counts[label] = int((await session.execute(
            select(func.count(model.id))
        )).scalar() or 0)

    open_critical = int((await session.execute(
        select(func.count(Finding.id))
        .where(Finding.status == "open", Finding.severity.in_(["critical", "high"]))
    )).scalar() or 0)

    states = dict((await session.execute(
        select(Scan.state, func.count(Scan.id)).group_by(Scan.state)
    )).all())

    personas = dict((await session.execute(
        select(Scan.persona, func.count(Scan.id)).group_by(Scan.persona)
    )).all())

    return {
        "counts": counts,
        "open_critical": open_critical,
        "scan_states": states,
        "scan_personas": personas,
    }


__all__: list[str] = ["router"]
