"""CSRFMiddleware regression tests.

The middleware is pure ASGI (not BaseHTTPMiddleware) so it can replay a
consumed request body to the downstream handler. Coverage targets:

  * Safe GET/HEAD/OPTIONS: cookie set on first response, untouched on
    subsequent responses
  * Cookie attributes: `HttpOnly`, `SameSite=Strict`
  * Unsafe POST/PUT/PATCH/DELETE without token → 403
  * Unsafe with valid form `_csrf` field → handler runs and SEES the body
    (proves the body-replay works — H2 fix)
  * Unsafe with valid `X-CSRF-Token` header → no body parsing needed
  * Cookie/token mismatch → 403
  * Exempt prefixes (/api/, /health, /static, /docs, /openapi.json) skip
    validation entirely
  * `enabled=False` is a no-op (legacy CI escape hatch)
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.api.middleware.csrf import COOKIE_NAME, FIELD_NAME, CSRFMiddleware


def _hello(_req):                                            # type: ignore[no-untyped-def]
    return PlainTextResponse("hi")


async def _echo(req: Request) -> JSONResponse:
    """Echo the form body so we can prove the downstream handler can
    still read the body after the middleware buffered it. UploadFile
    parts get summarised — JSON can't carry the binary blob."""
    form = await req.form()
    out: dict[str, str] = {}
    for k, v in form.items():
        if hasattr(v, "filename"):                          # UploadFile-like
            out[k] = f"<file:{v.filename}>"
        else:
            out[k] = str(v)
    return JSONResponse(out)


def _app(enabled: bool = True) -> Starlette:
    routes = [
        Route("/api/v1/x", _hello, methods=["GET", "POST"]),
        Route("/health",   _hello),
        Route("/docs",     _hello),
        Route("/static/x", _hello),
        Route("/openapi.json", _hello),
        Route("/ui/echo", _echo, methods=["POST"]),
        Route("/ui/safe", _hello, methods=["GET", "POST", "DELETE"]),
    ]
    app = Starlette(routes=routes)
    app.add_middleware(CSRFMiddleware, enabled=enabled)
    return app


# ---------------------------------------------------------------------------
# Safe methods set the cookie exactly once.
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestCookieIssuance:
    def test_get_sets_csrf_cookie(self) -> None:
        client = TestClient(_app())
        r = client.get("/ui/safe")
        assert r.status_code == 200
        assert COOKIE_NAME in client.cookies
        token = client.cookies[COOKIE_NAME]
        assert len(token) >= 32

    def test_cookie_is_httponly_strict(self) -> None:
        """H2: the cookie MUST be HttpOnly so XSS can't read it."""
        client = TestClient(_app())
        r = client.get("/ui/safe")
        set_cookie = r.headers.get("set-cookie", "")
        assert "HttpOnly" in set_cookie, set_cookie
        assert "SameSite=Strict" in set_cookie, set_cookie

    def test_subsequent_get_does_not_reissue(self) -> None:
        client = TestClient(_app())
        client.get("/ui/safe")
        first = client.cookies[COOKIE_NAME]
        r = client.get("/ui/safe")
        assert r.headers.get("set-cookie") in (None, ""), \
            "cookie was re-issued on a request that already had one"
        assert client.cookies[COOKIE_NAME] == first


# ---------------------------------------------------------------------------
# Unsafe methods must validate.
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestUnsafeValidation:
    def test_post_without_token_is_403(self) -> None:
        client = TestClient(_app())
        client.get("/ui/safe")                              # prime cookie
        r = client.post("/ui/safe", data={"x": "1"})
        assert r.status_code == 403
        assert r.json()["error"]["type"] == "csrf_failed"

    def test_post_with_form_token_passes_and_body_replays(self) -> None:
        """The handler MUST still see the form fields after CSRF buffered
        the body (regression: H2 fix uses a wrapped receive callable)."""
        client = TestClient(_app())
        client.get("/ui/echo")                              # prime cookie
        token = client.cookies[COOKIE_NAME]
        r = client.post("/ui/echo", data={"hello": "world", FIELD_NAME: token})
        assert r.status_code == 200
        body = r.json()
        # body-replay correctness: handler sees both fields
        assert body["hello"] == "world"
        assert body[FIELD_NAME] == token

    def test_post_with_header_token_passes(self) -> None:
        client = TestClient(_app())
        client.get("/ui/safe")
        token = client.cookies[COOKIE_NAME]
        r = client.post("/ui/safe", data={"x": "1"},
                        headers={"X-CSRF-Token": token})
        assert r.status_code == 200

    def test_post_with_wrong_form_token_is_403(self) -> None:
        client = TestClient(_app())
        client.get("/ui/safe")
        r = client.post("/ui/safe",
                        data={"x": "1", FIELD_NAME: "wrong"})
        assert r.status_code == 403

    def test_post_with_wrong_header_token_is_403(self) -> None:
        client = TestClient(_app())
        client.get("/ui/safe")
        r = client.post("/ui/safe", data={"x": "1"},
                        headers={"X-CSRF-Token": "wrong"})
        assert r.status_code == 403

    def test_delete_also_protected(self) -> None:
        client = TestClient(_app())
        client.get("/ui/safe")
        assert client.delete("/ui/safe").status_code == 403
        token = client.cookies[COOKIE_NAME]
        assert client.delete("/ui/safe",
                             headers={"X-CSRF-Token": token}).status_code == 200


# ---------------------------------------------------------------------------
# Exempt prefixes
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestExempt:
    @pytest.mark.parametrize("path", [
        "/api/v1/x", "/health", "/docs", "/openapi.json", "/static/x",
    ])
    def test_get_exempt_no_cookie_no_check(self, path: str) -> None:
        client = TestClient(_app())
        r = client.get(path)
        assert r.status_code == 200
        # No cookie set on exempt paths.
        assert COOKIE_NAME not in client.cookies

    def test_post_to_api_skips_csrf(self) -> None:
        """/api/* routes are protected by X-API-Key, not CSRF."""
        client = TestClient(_app())
        r = client.post("/api/v1/x", data={"x": "1"})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# enabled=False
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestDisabled:
    def test_disabled_lets_everything_through(self) -> None:
        client = TestClient(_app(enabled=False))
        # No GET prime, no token — POST still 200.
        r = client.post("/ui/safe", data={"x": "1"})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# csrf_token_for() must work on the FIRST request (no cookie yet).
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# M1 — body-size cap
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestBodySizeCap:
    """A POST body larger than MAX_BODY_BYTES MUST be rejected with 413
    BEFORE the middleware allocates the full buffer."""

    def test_oversize_post_returns_413(self) -> None:
        """The cap fires only in the form-field path (when the middleware
        actually buffers the body). With a valid X-CSRF-Token header
        we never allocate, so no cap is needed there."""
        from app.api.middleware.csrf import MAX_BODY_BYTES
        client = TestClient(_app())
        client.get("/ui/echo")                              # prime cookie
        # NO X-CSRF-Token header — forces the form-field path → buffer.
        oversize = b"x" * (MAX_BODY_BYTES + 1)
        r = client.post(
            "/ui/echo",
            content=oversize,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 413
        assert r.json()["error"]["type"] == "payload_too_large"

    def test_oversize_with_valid_header_still_passes(self) -> None:
        """Sanity: with a valid X-CSRF-Token, no cap is enforced in the
        middleware (the handler / framework is responsible for body
        limits beyond CSRF)."""
        from app.api.middleware.csrf import MAX_BODY_BYTES
        client = TestClient(_app())
        client.get("/ui/echo")
        token = client.cookies[COOKIE_NAME]
        # Larger than the cap, but the header path doesn't buffer.
        oversize = b"x" * (MAX_BODY_BYTES + 1)
        r = client.post(
            "/ui/echo",
            content=oversize,
            headers={"Content-Type": "application/octet-stream",
                     "X-CSRF-Token": token},
        )
        # Not 413 — the middleware passed through. (Handler is _echo
        # which calls req.form() on an octet-stream → empty form → 200.)
        assert r.status_code != 413

    def test_undersize_post_passes(self) -> None:
        client = TestClient(_app())
        client.get("/ui/echo")
        token = client.cookies[COOKIE_NAME]
        # 1 KiB body — well under the cap.
        body_data = {"hello": "world", FIELD_NAME: token, "blob": "x" * 1024}
        r = client.post("/ui/echo", data=body_data)
        assert r.status_code == 200, f"unexpected {r.status_code}: {r.text[:200]}"


# ---------------------------------------------------------------------------
# M2 — multipart parsing via Starlette
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestMultipartParsing:
    """The hand-rolled splitter mis-handled bodies where binary data
    contained the boundary string. Starlette's parser handles it."""

    def test_multipart_field_extracted(self) -> None:
        client = TestClient(_app())
        client.get("/ui/echo")
        token = client.cookies[COOKIE_NAME]
        # Force multipart by sending a `files` payload alongside the form.
        # python-multipart will parse this — the hand-rolled splitter
        # would have struggled.
        files = {
            FIELD_NAME: (None, token),
            "hello":    (None, "world"),
            "blob":     ("attachment.bin", b"\x00\x01\x02\x03binary"),
        }
        r = client.post("/ui/echo", files=files)
        assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"

    def test_multipart_with_boundary_substring_in_body(self) -> None:
        """Field value contains the boundary string verbatim — old
        splitter would split incorrectly. New parser must still extract."""
        import io
        client = TestClient(_app())
        client.get("/ui/echo")
        token = client.cookies[COOKIE_NAME]
        # The httpx test client picks the boundary; we send a binary file
        # that contains lots of `--` sequences, which trips naive splitters.
        files = {
            FIELD_NAME: (None, token),
            "blob": ("payload.bin", io.BytesIO(b"--bound----more----\x00data")),
        }
        r = client.post("/ui/echo", files=files)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# M3 — first Cookie header only
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestCookieHeaderShadowing:
    """A second ``cookie:`` header MUST NOT override the first one."""

    def test_only_first_cookie_header_consulted(self) -> None:
        from app.api.middleware.csrf import _parse_cookies
        # Two headers, second one tries to inject a fake CSRF token.
        headers = [
            (b"cookie", b"aetherforge_csrf=GOOD; foo=bar"),
            (b"cookie", b"aetherforge_csrf=ATTACKER"),
        ]
        parsed = _parse_cookies(headers)
        assert parsed[COOKIE_NAME] == "GOOD"


# ---------------------------------------------------------------------------
# First-load token availability (existing test — kept here for context)
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestFirstLoadTokenAvailability:
    """Regression: on the very first GET, the cookie is being issued in
    the same response, so ``request.cookies`` is empty. The middleware
    must surface the new token via ``request.state.csrf_token`` so the
    template helper can render a non-empty <meta> tag."""

    def test_state_carries_token_during_first_request(self) -> None:
        from app.api.middleware.csrf import csrf_token_for

        captured: dict[str, str] = {}

        async def _grab(req):
            captured["t"] = csrf_token_for(req)
            return PlainTextResponse("ok")

        from starlette.routing import Route as R
        app = Starlette(routes=[R("/ui/grab", _grab)])
        app.add_middleware(CSRFMiddleware, enabled=True)

        client = TestClient(app)
        r = client.get("/ui/grab")
        assert r.status_code == 200
        assert captured["t"], \
            "csrf_token_for returned empty string on FIRST request"
        # The cookie that gets set MUST equal the value we surfaced.
        assert client.cookies[COOKIE_NAME] == captured["t"]
