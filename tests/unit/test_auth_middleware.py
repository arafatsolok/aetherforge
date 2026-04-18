"""APIKeyAuthMiddleware regression tests.

Covers:
  * dev mode (api_key=None) is pass-through
  * /api/v1/* requires X-API-Key, with constant-time compare
  * /api/v1/* missing/invalid key returns 401 + WWW-Authenticate
  * /ui/* without session redirects 303 to /ui/login?next=…
  * /ui/* with X-API-Key header is also accepted (HTMX)
  * Public prefixes (/health, /docs, /static, /ui/login, /openapi.json,
    /metrics, /ui/logout) bypass auth even when key is set
  * Failed authentications emit a structlog warning (sentinel: log captured)
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.api.middleware.auth import APIKeyAuthMiddleware
from app.config import Settings


def _hello(_req):                                            # type: ignore[no-untyped-def]
    return PlainTextResponse("hi")


# Same secret + cookie name as the SessionMiddleware mounted in _app
# below. We forge the cookie value directly so tests don't have to walk
# through /ui/login (which itself sits behind the API-key gate when auth
# is enabled).
KEY = "test-key-bcdefghijklmnopqrstuvwx"          # 28 chars, ≥10 unique
_SESSION_SECRET = "x" * 64
_SESSION_COOKIE = "aetherforge_session"


def _signed_session(payload: dict) -> str:
    import itsdangerous
    signer = itsdangerous.TimestampSigner(_SESSION_SECRET)
    import base64, json
    raw = base64.b64encode(json.dumps(payload).encode())
    return signer.sign(raw).decode()


def _settings(api_key: str | None) -> Settings:
    """Build a real Settings object — env mode 'development' so validators
    don't reject our short test key."""
    s = Settings(env="development", api_key=SecretStr(api_key) if api_key else None)
    return s


def _app(api_key: str | None) -> Starlette:
    """Wire SessionMiddleware → APIKeyAuthMiddleware → handler."""
    routes = [
        Route("/", _hello),
        Route("/health", _hello),
        Route("/docs", _hello),
        Route("/openapi.json", _hello),
        Route("/metrics", _hello),
        Route("/ui/login", _hello),
        Route("/ui/logout", _hello),
        Route("/ui/scans", _hello),
        Route("/api/v1/rules",     _hello, methods=["GET", "HEAD", "POST"]),
        Route("/api/v1/anything",  _hello, methods=["GET", "POST"]),
        Route("/static/x.css", _hello),
        Route("/wat", _hello),                               # unknown prefix
    ]
    app = Starlette(routes=routes)
    settings = _settings(api_key)
    app.add_middleware(APIKeyAuthMiddleware, settings=settings)
    app.add_middleware(
        SessionMiddleware,
        secret_key=_SESSION_SECRET,
        session_cookie=_SESSION_COOKIE,
        same_site="strict",
        https_only=False,
        max_age=3600,
    )
    return app


def _client_with_session(api_key: str = KEY) -> TestClient:
    """Return a TestClient pre-loaded with a valid signed session cookie."""
    client = TestClient(_app(api_key))
    client.cookies.set(_SESSION_COOKIE,
                       _signed_session({"authenticated": True}))
    return client


# ---------------------------------------------------------------------------
# Dev mode (no key set) — always pass through.
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestDevModePassThrough:
    def test_api_open_when_key_unset(self) -> None:
        client = TestClient(_app(api_key=None))
        for path in ("/", "/api/v1/rules", "/ui/scans", "/wat"):
            assert client.get(path).status_code == 200, path


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestApiKeyGate:
    def test_no_header_returns_401(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/api/v1/rules")
        assert r.status_code == 401
        assert r.headers.get("www-authenticate", "").startswith("ApiKey")
        assert r.json()["error"]["type"] == "unauthorized"

    def test_wrong_key_returns_401(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/api/v1/rules", headers={"X-API-Key": "wrong"})
        assert r.status_code == 401

    def test_correct_key_returns_200(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/api/v1/rules", headers={"X-API-Key": KEY})
        assert r.status_code == 200

    def test_unknown_prefix_also_protected(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/wat")
        assert r.status_code == 401


@pytest.mark.unit
class TestSafeApiViaSession:
    """A logged-in browser session can hit GET/HEAD /api/* WITHOUT
    sending X-API-Key. Unsafe verbs (POST/PATCH/DELETE) still require
    the header — this is what makes the report-download links and
    SSE audit stream work in the dashboard while keeping CSRF closed."""

    def test_get_api_with_session_only_passes(self) -> None:
        client = _client_with_session()
        # No X-API-Key header — only the session cookie.
        r = client.get("/api/v1/rules")
        assert r.status_code == 200, f"got {r.status_code}: {r.text[:120]}"

    def test_head_api_with_session_only_passes(self) -> None:
        client = _client_with_session()
        r = client.head("/api/v1/rules")
        assert r.status_code == 200

    def test_post_api_with_session_only_still_blocked(self) -> None:
        """Defense in depth — a stolen browser session must NOT be able
        to fire side-effects against the API."""
        client = _client_with_session()
        r = client.post("/api/v1/anything", data={"x": "1"})
        assert r.status_code == 401

    def test_get_without_session_or_key_still_blocked(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/api/v1/rules")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestUIGate:
    def test_unauthenticated_ui_redirects_to_login(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/ui/scans", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/ui/login")
        assert "next=/ui/scans" in r.headers["location"]

    def test_unauthenticated_root_also_redirects(self) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303

    def test_x_api_key_header_unlocks_ui(self) -> None:
        """HTMX-driven traffic can present X-API-Key instead of session."""
        client = TestClient(_app(api_key=KEY))
        r = client.get("/ui/scans", headers={"X-API-Key": KEY})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Public prefixes
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestPublicPrefixes:
    @pytest.mark.parametrize("path", [
        "/health", "/docs", "/openapi.json", "/metrics",
        "/static/x.css", "/ui/login", "/ui/logout",
    ])
    def test_public_path_no_auth(self, path: str) -> None:
        client = TestClient(_app(api_key=KEY))
        r = client.get(path)
        assert r.status_code == 200, path


# ---------------------------------------------------------------------------
# Observability — every 401 must emit a structlog warning for SOC alerting.
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestObservability:
    """Patches ``app.api.middleware.auth.log.warning`` so we can assert
    the *event name* directly. Structlog formats the event as a kwarg
    rather than embedding it in ``LogRecord.message``, so caplog's
    string-substring matching is too brittle for this assertion."""

    def _capture(self, monkeypatch) -> list[tuple]:
        """Return a list that the patched log.warning appends into."""
        calls: list[tuple] = []
        from app.api.middleware import auth as auth_mod

        def _grab(event: str, **kw):
            calls.append((event, kw))

        monkeypatch.setattr(auth_mod.log, "warning", _grab)
        return calls

    def test_api_401_emits_log(self, monkeypatch) -> None:
        calls = self._capture(monkeypatch)
        client = TestClient(_app(api_key=KEY))
        client.get("/api/v1/rules")
        events = [c[0] for c in calls]
        assert "auth.api.denied" in events, f"got {events}"
        # The event payload should include the path + method + client.
        kw = next(c[1] for c in calls if c[0] == "auth.api.denied")
        assert kw["path"] == "/api/v1/rules"
        assert kw["method"] == "GET"
        assert "client" in kw

    def test_api_401_with_wrong_header_logs_invalid(self, monkeypatch) -> None:
        calls = self._capture(monkeypatch)
        client = TestClient(_app(api_key=KEY))
        client.get("/api/v1/rules", headers={"X-API-Key": "wrong"})
        kw = next(c[1] for c in calls if c[0] == "auth.api.denied")
        assert "invalid" in kw["reason"].lower()

    def test_ui_redirect_emits_log(self, monkeypatch) -> None:
        calls = self._capture(monkeypatch)
        client = TestClient(_app(api_key=KEY))
        client.get("/ui/scans", follow_redirects=False)
        events = [c[0] for c in calls]
        assert "auth.ui.denied" in events, f"got {events}"

    def test_unknown_prefix_emits_log(self, monkeypatch) -> None:
        calls = self._capture(monkeypatch)
        client = TestClient(_app(api_key=KEY))
        client.get("/wat")
        events = [c[0] for c in calls]
        assert "auth.unknown.denied" in events, f"got {events}"
