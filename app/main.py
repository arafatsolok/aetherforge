"""FastAPI entry point.

Run modes:
  * ``AETHERFORGE_MODE=api``    — HTTP API + HTMX dashboard
  * ``AETHERFORGE_MODE=worker`` — Temporal + RQ worker (see app.workflows.worker)

The ``api`` factory below is the importable ASGI app. Gunicorn/uvicorn
uses ``app.main:app``.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.api.middleware import APIKeyAuthMiddleware, APIRateLimit, CSRFMiddleware
from app.api.routes import (
    audit,
    dashboard,
    drift,
    findings,
    health,
    metrics,
    personas,
    reports,
    rules,
    scans,
    targets,
    tools,
)
from app.config import get_settings
from app.database import dispose_db, init_db
from app.logging_config import configure_logging, get_logger
from app.utils.secrets import check_env_file_permissions

settings = get_settings()
configure_logging(settings)
log = get_logger(__name__)


# -----------------------------------------------------------------------------
# Lifespan — startup + shutdown hooks
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info(
        "app.startup",
        version=__version__,
        env=settings.env,
        mode=settings.mode.value,
        persona=settings.default_persona.value,
    )
    # Phase 8 — refuse to boot in production with a world-readable .env.
    from pathlib import Path
    check_env_file_permissions(Path(".env"), settings)
    await init_db()
    # Phase 1+: rule engine hot-load, Phase 3+: Temporal client bootstrap.
    try:
        yield
    finally:
        log.info("app.shutdown")
        await dispose_db()


# -----------------------------------------------------------------------------
# App factory
# -----------------------------------------------------------------------------
def create_app() -> FastAPI:
    app = FastAPI(
        title="AetherForge — Autonomous VAPT Orchestrator",
        description=(
            "Zero-AI, deterministic, rule-based autonomous VAPT platform. "
            "Three personas (white/gray/black). Temporal-backed loop. "
            "Every generated command is audited."
        ),
        version=__version__,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    _install_middleware(app)
    _install_exception_handlers(app)
    _install_routes(app)
    _install_static_and_templates(app)

    return app


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------
def _install_middleware(app: FastAPI) -> None:
    """Install middleware in *reverse* execution order.

    Starlette wraps each middleware around the previous one, so the LAST
    one added is the OUTERMOST — i.e. it runs FIRST on the inbound side
    and LAST on the outbound side. Desired inbound order is:

        Session → RateLimit → APIKeyAuth → CSRF → GZip → CORS → handler

    so we add them in the *reverse* of that order below.
    """
    # Innermost: CORS, then GZip (closest to the handler).
    if settings.api_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(o) for o in settings.api_cors_origins],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # CSRF — opt-out via env for legacy CI runs only. Enabled by default.
    csrf_enabled = os.environ.get("AETHERFORGE_CSRF_ENABLED", "1") != "0"
    app.add_middleware(CSRFMiddleware, enabled=csrf_enabled)

    # API-key gate (no-op when AETHERFORGE_API_KEY is unset).
    app.add_middleware(APIKeyAuthMiddleware, settings=settings)

    # Per-IP token-bucket rate limit. 60 req/min default; tune via env.
    rate_capacity = int(os.environ.get("AETHERFORGE_API_RATE_LIMIT", "60"))
    rate_refill = max(1.0, rate_capacity / 60.0)
    app.add_middleware(
        APIRateLimit,
        capacity=float(rate_capacity),
        refill_per_s=rate_refill,
    )

    # Session cookie powers the /ui/login flow. Added LAST so it is the
    # outermost wrapper — request.session is populated before any
    # middleware downstream tries to read it.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.get_secret_value(),
        session_cookie="aetherforge_session",
        same_site="strict",
        https_only=settings.is_production,
        max_age=60 * 60 * 8,
    )

    if settings.is_production:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])


# -----------------------------------------------------------------------------
# Exception handlers
# -----------------------------------------------------------------------------
def _install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_req: Request, exc: StarletteHTTPException) -> JSONResponse:
        log.warning("http.error", status=exc.status_code, detail=exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"type": "http_error", "detail": exc.detail}},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _req: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "type": "validation_error",
                    "detail": jsonable_encoder(exc.errors(), exclude={"ctx"}),
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_req: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled", exc_type=type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"error": {"type": "internal_error", "detail": "internal server error"}},
        )


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
def _install_routes(app: FastAPI) -> None:
    # Infra
    app.include_router(health.router, tags=["health"])

    # API v1
    prefix = "/api/v1"
    app.include_router(targets.router, prefix=f"{prefix}/targets", tags=["targets"])
    app.include_router(scans.router, prefix=f"{prefix}/scans", tags=["scans"])
    app.include_router(rules.router, prefix=f"{prefix}/rules", tags=["rules"])
    app.include_router(personas.router, prefix=f"{prefix}/personas", tags=["personas"])
    app.include_router(findings.router, prefix=f"{prefix}/findings", tags=["findings"])
    app.include_router(reports.router, prefix=f"{prefix}/reports", tags=["reports"])
    app.include_router(tools.router, prefix=f"{prefix}/tools", tags=["tools"])
    app.include_router(audit.router, prefix=f"{prefix}/audit", tags=["audit"])
    app.include_router(metrics.router, prefix=f"{prefix}/metrics", tags=["metrics"])
    app.include_router(drift.router, prefix=f"{prefix}/drift", tags=["drift"])

    # HTMX dashboard (HTML)
    app.include_router(dashboard.router, tags=["ui"])


# -----------------------------------------------------------------------------
# Static + templates
# -----------------------------------------------------------------------------
def _install_static_and_templates(app: FastAPI) -> None:
    static_dir: Path = settings.static_dir
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    templates_dir: Path = settings.templates_dir
    if templates_dir.exists():
        templates = Jinja2Templates(directory=str(templates_dir))
        # Make the CSRF helper available to every template so forms can
        # render <input name="_csrf" value="{{ csrf_token(request) }}">
        # without each route having to pass it explicitly.
        from app.api.middleware import csrf_token_for
        templates.env.globals["csrf_token"] = csrf_token_for
        app.state.templates = templates


# Exposed WSGI/ASGI callable
app = create_app()
