"""API-key + session authentication middleware.

Three modes, controlled by ``Settings.api_key``:

1. **api_key unset** — auth is **disabled** (development / tests). Every
   request passes. The login page (`/ui/login`) returns 410 in this
   mode so operators don't paste keys into a useless form.
2. **api_key set, /api/v1/* request** — header ``X-API-Key`` must equal
   the configured value. Constant-time compare. 401 + JSON error on
   mismatch.
3. **api_key set, /ui/* request** — session cookie must contain
   ``authenticated=True`` (set by the login form). Browsers without a
   session are redirected to ``/ui/login?next=<original>``.

Always-public paths (regardless of mode):
- ``/health``, ``/ready``, ``/metrics``
- ``/static/*``, ``/openapi.json``, ``/docs``, ``/redoc``
- ``/ui/login`` (the login form itself)

Non-mutating ``GET`` traffic to ``/ui/*`` is **also** required to be
authenticated so the audit log + finding triage UI aren't world-readable.
That's the threat model — the HTML pages reflect sensitive scan output.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from app.config import Settings
from app.logging_config import get_logger

log = get_logger(__name__)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Enforce ``Settings.api_key`` on every protected route."""

    PUBLIC_PREFIXES = (
        "/health", "/ready", "/metrics",
        "/static/", "/openapi.json", "/docs", "/redoc",
        "/ui/login", "/ui/logout",
        # Browsers auto-probe this regardless of the <link rel="icon">.
        # Keep it public so we never emit an auth.api.denied for a UA
        # artefact request.
        "/favicon.ico",
    )

    def __init__(self, app, *, settings: Settings) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._settings = settings

    @property
    def _api_key(self) -> str | None:
        if self._settings.api_key is None:
            return None
        return self._settings.api_key.get_secret_value()

    async def dispatch(  # type: ignore[no-untyped-def]
        self, request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        api_key = self._api_key
        if api_key is None:                                 # dev mode: pass-through
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in self.PUBLIC_PREFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        method = request.method

        # Browser routes: session cookie OR X-API-Key (machine-driven HTMX).
        if path.startswith("/ui") or path == "/":
            if _session_authenticated(request) or _header_matches(request, api_key):
                return await call_next(request)
            log.warning(
                "auth.ui.denied",
                path=path, method=method, client=client_ip,
                reason="no session and no valid X-API-Key",
            )
            target = f"/ui/login?next={request.url.path}"
            return RedirectResponse(target, status_code=303)

        # API routes:
        #
        # * UNSAFE methods (POST/PATCH/PUT/DELETE) — X-API-Key REQUIRED.
        #   These come from machine clients; they MUST present the
        #   header so a stolen browser session can never trigger
        #   side-effects on the API.
        #
        # * SAFE methods (GET/HEAD) — accept either X-API-Key OR a
        #   logged-in session cookie. This is what makes the
        #   <a href="/api/v1/reports/3?fmt=pdf"> link in the dashboard
        #   actually load when clicked, and what lets EventSource
        #   subscribe to /api/v1/audit/scans/{id}/sse from the
        #   browser. Cross-origin protection is provided by the
        #   session cookie's ``SameSite=Strict`` attribute.
        if path.startswith("/api/"):
            safe = method in ("GET", "HEAD", "OPTIONS")
            if _header_matches(request, api_key):
                return await call_next(request)
            if safe and _session_authenticated(request):
                return await call_next(request)
            log.warning(
                "auth.api.denied",
                path=path, method=method, client=client_ip,
                reason=("invalid X-API-Key" if request.headers.get("x-api-key")
                        else "missing X-API-Key"),
            )
            return JSONResponse(
                status_code=401,
                content={"error": {"type": "unauthorized",
                                   "detail": "missing or invalid X-API-Key header"}},
                headers={"WWW-Authenticate": "ApiKey realm=AetherForge"},
            )

        # Anything else (unknown prefix): require the same.
        if _header_matches(request, api_key):
            return await call_next(request)
        log.warning(
            "auth.unknown.denied",
            path=path, method=method, client=client_ip,
        )
        return JSONResponse(
            status_code=401,
            content={"error": {"type": "unauthorized", "detail": "auth required"}},
        )


def _session_authenticated(request: Request) -> bool:
    """True if the Starlette session cookie marks this request authenticated."""
    sess = getattr(request, "session", None)
    if not isinstance(sess, dict):
        return False
    return bool(sess.get("authenticated", False))


def _header_matches(request: Request, expected: str) -> bool:
    presented = request.headers.get("x-api-key", "")
    if not presented:
        return False
    # Constant-time comparison guards against timing-based key recovery.
    return hmac.compare_digest(presented, expected)


def constant_time_eq(a: str, b: str) -> bool:
    """Re-export for handlers that need a CT compare without recreating the helper."""
    return hmac.compare_digest(a, b)


def new_session_token() -> str:
    """Cryptographic random token, used for CSRF + session ids."""
    return secrets.token_urlsafe(32)


__all__ = ["APIKeyAuthMiddleware", "constant_time_eq", "new_session_token"]
