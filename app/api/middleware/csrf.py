"""Double-submit-cookie CSRF middleware (ASGI-native).

On every safe request (``GET``/``HEAD``/``OPTIONS``) we ensure the client
holds a ``aetherforge_csrf`` cookie. On every unsafe request the cookie
must match either the ``X-CSRF-Token`` header or the ``_csrf`` form
field. Mismatch → ``403``.

Implemented at the ASGI level (rather than as a Starlette
``BaseHTTPMiddleware``) because we may need to read the request body to
inspect the form field — and ``BaseHTTPMiddleware`` doesn't replay a
consumed body to the downstream handler. The pattern below buffers the
body once and re-emits it from a wrapper ``receive`` callable.

Exempt prefixes (no CSRF check; cookie still set on safe responses):
- ``/api/v1/*`` — protected by ``X-API-Key`` instead. CSRF is a
  browser-cookie attack; non-browser API clients are out of scope.
- ``/health``, ``/ready``, ``/metrics``, ``/static/``, ``/openapi.json``,
  ``/docs``, ``/redoc``.

Browsers calling HTMX ``hx-post`` get the cookie automatically — the
``base.html`` template wires htmx to copy the cookie into the
``X-CSRF-Token`` header on every request, so no per-form change is
required (forms still have a hidden ``_csrf`` input as belt-and-braces).
"""

from __future__ import annotations

import json
import secrets
import urllib.parse as up
from collections.abc import Awaitable, Callable
from http.cookies import SimpleCookie

COOKIE_NAME = "aetherforge_csrf"
HEADER_NAME = "x-csrf-token"
FIELD_NAME = "_csrf"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# M1 — body-size cap. Any unsafe POST larger than this is rejected with
# 413 BEFORE the buffer is allocated, so an attacker cannot exhaust
# worker RAM by streaming a huge body to a CSRF-protected endpoint.
# 10 MiB easily covers any legitimate form (target lists, notes, scan
# overrides) — file uploads, when introduced, should bypass CSRF the
# same way /api/* already does (X-API-Key on machine clients).
MAX_BODY_BYTES = 10 * 1024 * 1024

EXEMPT_PREFIXES = (
    "/api/", "/health", "/ready", "/metrics",
    "/static/", "/openapi.json", "/docs", "/redoc",
)

ASGIApp = Callable[..., Awaitable[None]]


class CSRFMiddleware:
    """Pure ASGI middleware — does NOT inherit from BaseHTTPMiddleware."""

    def __init__(self, app: ASGIApp, *, enabled: bool = True) -> None:
        self.app = app
        self.enabled = enabled

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        if any(path.startswith(p) for p in EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        cookies = _parse_cookies(scope.get("headers", []))
        cookie_token = cookies.get(COOKIE_NAME)

        if method in SAFE_METHODS:
            await self._safe_dispatch(scope, receive, send, cookie_token)
            return

        # Unsafe verb — body MUST be inspected if no header is present.
        header_token = _header(scope, HEADER_NAME)
        if header_token and cookie_token and \
                secrets.compare_digest(header_token, cookie_token):
            # Header path — no need to touch the body.
            await self.app(scope, receive, send)
            return

        # Either no header, or header didn't match — fall back to the
        # form field. Buffer the body so the downstream handler can
        # re-read it from the wrapped receive callable.
        try:
            body = await _read_body(receive, MAX_BODY_BYTES)
        except _BodyTooLarge:
            await _reject_413(send)
            return
        form_token = await _form_field(
            scope, body, FIELD_NAME,
        )

        if (not cookie_token) or (not form_token) or \
                not secrets.compare_digest(cookie_token, form_token):
            await _reject_403(send)
            return

        await self.app(scope, _replay_receive(body), send)

    async def _safe_dispatch(
        self, scope: dict, receive: Callable, send: Callable,
        cookie_token: str | None,
    ) -> None:
        """Wrap ``send`` so we can attach a Set-Cookie when the client
        doesn't yet hold a token, AND surface the token to the route
        handler via ``request.state.csrf_token`` so the template can
        embed it in this same response — without that, the very first
        page load would render an empty <meta name="csrf-token"> and
        any HTMX call on the freshly-loaded page would 403."""
        # Pre-populate scope state so handlers / Jinja can read the token
        # from THIS request, even if the cookie is being issued for the
        # first time on the response.
        if "state" not in scope:
            scope["state"] = {}
        if cookie_token is not None:
            scope["state"]["csrf_token"] = cookie_token
            await self.app(scope, receive, send)
            return

        new_token = secrets.token_urlsafe(32)
        scope["state"]["csrf_token"] = new_token

        # HttpOnly: Browser JS cannot read this cookie, so an XSS payload
        # cannot exfiltrate the token. The HTML page exposes the same
        # value via <meta name="csrf-token" content="…"> for HTMX to copy
        # into the X-CSRF-Token header — meta-tag content is only
        # accessible if the page itself rendered it, which requires the
        # attacker to already control the page (in which case CSRF is
        # the wrong threat model anyway).
        cookie_header = (
            f"{COOKIE_NAME}={new_token}; Path=/; Max-Age=28800; "
            "SameSite=Strict; HttpOnly"
        ).encode()

        async def wrapped_send(msg: dict) -> None:
            if msg["type"] == "http.response.start":
                headers = list(msg.get("headers", []))
                headers.append((b"set-cookie", cookie_header))
                msg = {**msg, "headers": headers}
            await send(msg)

        await self.app(scope, receive, wrapped_send)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _BodyTooLarge(Exception):
    """Internal sentinel — raised when the buffered body exceeds MAX_BODY_BYTES."""


def _parse_cookies(headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    """Parse the FIRST Cookie header only.

    M3 — RFC 6265 §5.4 says a UA MUST send a single Cookie header. Some
    proxies / load balancers append additional ones; concatenating and
    re-parsing means a malicious header injected later could shadow the
    legitimate token (last-wins in SimpleCookie). We mirror what
    Starlette does internally and trust only the first header.
    """
    raw = next((v for k, v in headers if k == b"cookie"), b"").decode("latin-1")
    if not raw:
        return {}
    jar = SimpleCookie()
    jar.load(raw)
    return {k: morsel.value for k, morsel in jar.items()}


def _header(scope: dict, name: str) -> str | None:
    needle = name.lower().encode()
    for k, v in scope.get("headers", []):
        if k == needle:
            return v.decode("latin-1")
    return None


async def _read_body(receive: Callable, cap: int) -> bytes:
    """Buffer the request body, raising ``_BodyTooLarge`` if it exceeds
    ``cap`` bytes — *without* draining the rest of the stream.

    M1 — drain-and-reject would still accept the full upload before the
    413 is returned, defeating the purpose. We bail at the first chunk
    that pushes total past the cap, which lets the framework close the
    connection and stop receiving further bytes.
    """
    chunks: list[bytes] = []
    total = 0
    more = True
    while more:
        msg = await receive()
        if msg["type"] == "http.disconnect":
            break
        chunk = msg.get("body", b"") or b""
        total += len(chunk)
        if total > cap:
            raise _BodyTooLarge(total)
        chunks.append(chunk)
        more = msg.get("more_body", False)
    return b"".join(chunks)


def _replay_receive(body: bytes) -> Callable:
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _form_field(scope: dict, body: bytes, field: str) -> str | None:
    """Extract one field from a urlencoded, multipart, or JSON body.

    M2 — multipart is delegated to Starlette's ``Request.form()``, which
    in turn uses python-multipart (already a transitive FastAPI
    dependency). The previous hand-rolled ``body.split(boundary)``
    mis-handled file uploads where binary data legitimately contains
    the boundary substring — Starlette's parser is the same one the
    downstream handler will use, so the result here is guaranteed
    consistent.
    """
    ctype = _header(scope, "content-type") or ""
    ctype_lc = ctype.lower()

    if ctype_lc.startswith("application/x-www-form-urlencoded"):
        try:
            parsed = up.parse_qs(body.decode("latin-1"), keep_blank_values=True)
        except Exception:                                  # noqa: BLE001
            return None
        values = parsed.get(field, [])
        return values[0] if values else None

    if ctype_lc.startswith("multipart/form-data"):
        return await _multipart_field(scope, body, field)

    if ctype_lc.startswith("application/json"):
        try:
            parsed = json.loads(body or b"{}")
        except Exception:                                  # noqa: BLE001
            return None
        if isinstance(parsed, dict):
            v = parsed.get(field)
            return str(v) if v is not None else None
        return None

    return None


async def _multipart_field(scope: dict, body: bytes, field: str) -> str | None:
    """Use Starlette's well-tested form parser for multipart bodies.

    We construct an isolated ``Request`` over a one-shot replay of the
    buffered body. The buffered ``body`` is reused unchanged for the
    downstream handler via :func:`_replay_receive`, so reading it here
    has no observable effect on the next stage.
    """
    from starlette.requests import Request  # local import keeps cold-start cheap

    sent = False

    async def _replay():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    req = Request(scope, _replay)
    try:
        form = await req.form()
    except Exception:                                      # noqa: BLE001
        return None
    val = form.get(field)
    if isinstance(val, str):
        return val
    # An UploadFile or similar slipped in — not a valid CSRF token.
    return None


async def _reject_403(send: Callable) -> None:
    body = b'{"error":{"type":"csrf_failed","detail":"missing or invalid CSRF token"}}'
    await send({
        "type": "http.response.start", "status": 403,
        "headers": [(b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _reject_413(send: Callable) -> None:
    body = (
        b'{"error":{"type":"payload_too_large","detail":"request body exceeds '
        b'CSRF inspection cap of 10 MiB"}}'
    )
    await send({
        "type": "http.response.start", "status": 413,
        "headers": [(b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


def csrf_token_for(request) -> str:                        # type: ignore[no-untyped-def]
    """Return the current CSRF token for embedding in a Jinja form.

    Prefers the value the middleware stashed in ``request.state`` for
    THIS request (handles the first-load case where the cookie is being
    issued for the very first time on the same response). Falls back to
    the incoming cookie for subsequent requests that already had one.
    """
    state_token = getattr(request.state, "csrf_token", None)
    if state_token:
        return state_token
    return request.cookies.get(COOKIE_NAME, "")


__all__ = ["COOKIE_NAME", "FIELD_NAME", "HEADER_NAME", "CSRFMiddleware", "csrf_token_for"]
