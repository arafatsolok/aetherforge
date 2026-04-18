"""End-to-end login + open-redirect tests for /ui/login.

Pulls together the three building blocks that ship the login surface:
  * dashboard.submit_login (the handler under test)
  * SessionMiddleware (so session writes set the cookie)
  * the dependency override pattern from test_session_fixation.py

Coverage:
  * GET /ui/login when api_key is None → 410 Gone
  * Wrong password redirects with `error=invalid+api+key`
  * Correct password redirects to ?next= with rotated session
  * Open-redirect guard (H1): 11 evil values all collapse to "/"
  * Logout clears the session cookie payload
  * Failed login does NOT set the session cookie
"""

from __future__ import annotations

import base64
import json
from typing import ClassVar

import pytest
from fastapi import APIRouter, FastAPI
from pydantic import SecretStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient


def _decode_session(cookie_value: str) -> dict:
    payload = cookie_value.split(".", 1)[0]
    pad = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + pad).decode())


def _app(api_key: str | None = "test-key") -> FastAPI:
    """Stand-alone app mounting the real /ui/login + /ui/logout handlers."""
    from app.api.dependencies import settings_dep
    from app.api.routes.dashboard import (
        page_login,
        submit_login,
        submit_logout,
    )

    def _settings():
        class _S:
            pass
        s = _S()
        s.api_key = SecretStr(api_key) if api_key else None
        s.env = "development"
        return s

    router = APIRouter()
    router.get("/ui/login")(page_login)
    router.post("/ui/login")(submit_login)
    router.post("/ui/logout")(submit_logout)

    app = FastAPI()
    # /ui/login GET tries to render the template via app.state.templates;
    # we don't actually need it for any of the assertions in this file
    # (the only GET test below covers the auth=disabled branch which
    #  short-circuits BEFORE template rendering).
    app.include_router(router)
    app.dependency_overrides[settings_dep] = _settings
    app.add_middleware(
        SessionMiddleware,
        secret_key="x" * 64,
        session_cookie="aetherforge_session",
        same_site="strict",
        https_only=False,
        max_age=3600,
    )
    return app


# ---------------------------------------------------------------------------
# /ui/login GET behaviour when auth is disabled
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestLoginPageWhenAuthDisabled:
    def test_get_returns_410_when_api_key_unset(self) -> None:
        client = TestClient(_app(api_key=None))
        r = client.get("/ui/login")
        assert r.status_code == 410

    def test_410_body_does_not_leak_env_var_name(self) -> None:
        """L1 — the auth-disabled response MUST be generic; it must not
        name the AETHERFORGE_API_KEY env var (an attacker scanning the
        page could otherwise infer the deployment topology)."""
        client = TestClient(_app(api_key=None))
        r = client.get("/ui/login")
        body = r.text
        # Forbidden substrings — anything that hints at the env-var name.
        for forbidden in ("AETHERFORGE_API_KEY", "API_KEY", "api_key",
                          "AETHERFORGE_", "openssl"):
            assert forbidden not in body, \
                f"L1 regression: response body leaks {forbidden!r}"
        # And it must still be informative enough for an operator.
        assert "Login disabled" in body or "auth" in body.lower()


# ---------------------------------------------------------------------------
# /ui/login POST — credential checks
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestLoginCredential:
    def test_wrong_key_redirects_with_error(self) -> None:
        client = TestClient(_app())
        r = client.post(
            "/ui/login",
            data={"api_key": "wrong", "next": "/"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "error=invalid+api+key" in r.headers["location"]
        assert client.cookies.get("aetherforge_session", "") == ""

    def test_correct_key_sets_authenticated_session(self) -> None:
        client = TestClient(_app())
        r = client.post(
            "/ui/login",
            data={"api_key": "test-key", "next": "/ui/scans"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/scans"
        cookie = client.cookies.get("aetherforge_session", "")
        assert cookie, "no session cookie set on successful login"
        payload = _decode_session(cookie)
        assert payload["authenticated"] is True
        assert "sid" in payload
        assert "login_at" in payload

    def test_logout_clears_session(self) -> None:
        client = TestClient(_app())
        # Log in
        client.post("/ui/login", data={"api_key": "test-key", "next": "/"},
                    follow_redirects=False)
        # Log out
        r = client.post("/ui/logout", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login"
        cookie = client.cookies.get("aetherforge_session", "")
        # SessionMiddleware re-emits the cookie with an empty payload.
        if cookie:
            payload = _decode_session(cookie)
            assert payload == {}, f"expected cleared session, got {payload}"


# ---------------------------------------------------------------------------
# H1 — open-redirect guard
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestOpenRedirectGuard:
    """All these `next=` values must collapse to exactly ``/``."""

    EVIL: ClassVar[list[str]] = [
        "//evil.com/path",
        "/\\evil.com",
        "/%2fevil.com",
        "/%5cevil.com",
        "/\x00evil",
        "http://evil.com/x",
        "https://evil.com/x",
        "//evil.com\\x",
        "javascript:alert(1)",          # not / -> rejected
        "data:text/html,foo",
        "/%2F%2Fevil.com",              # double-decoded //
        "",
    ]
    SAFE: ClassVar[list[str]] = [
        "/ui/scans",
        "/ui/scans/42",
        "/ui/findings?severity=high",
        "/api/v1/rules",
        "/",
    ]

    @pytest.mark.parametrize("evil_next", EVIL)
    def test_evil_next_collapses_to_root(self, evil_next: str) -> None:
        client = TestClient(_app())
        r = client.post(
            "/ui/login",
            data={"api_key": "test-key", "next": evil_next},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/", \
            f"evil next={evil_next!r} produced redirect to {r.headers['location']!r}"

    @pytest.mark.parametrize("safe_next", SAFE)
    def test_safe_next_is_honoured(self, safe_next: str) -> None:
        client = TestClient(_app())
        r = client.post(
            "/ui/login",
            data={"api_key": "test-key", "next": safe_next},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == safe_next, \
            f"safe next={safe_next!r} got rewritten to {r.headers['location']!r}"
