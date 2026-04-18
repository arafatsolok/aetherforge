"""Regression test for the B1 session-fixation fix.

The /ui/login handler MUST rotate the signed session cookie on every
successful authentication. Two consecutive logins of the same identity
must produce two DIFFERENT cookie values, otherwise an attacker who
copied a victim's cookie value (e.g., from a shared device) could
replay it indefinitely against future logins.

The rotation is achieved by ``request.session.clear()`` plus writing a
fresh ``sid`` nonce + ``login_at`` timestamp before granting the
``authenticated`` flag.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import APIRouter, FastAPI
from pydantic import SecretStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient


def _decode_session(cookie_value: str) -> dict:
    """Decode the base64 payload that SessionMiddleware writes into the cookie.

    The cookie format is ``<base64-json>.<timestamp>.<signature>``; we
    only need the payload to compare two cookies for content equality.
    """
    payload = cookie_value.split(".", 1)[0]
    pad = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + pad).decode())


def _app(api_key: str = "test-key") -> FastAPI:
    """Build a minimal app that mounts the real ``submit_login``.

    We override the ``settings_dep`` FastAPI dependency to inject a
    settings object whose ``api_key`` matches the value the test posts.
    """
    from app.api.dependencies import settings_dep
    from app.api.routes.dashboard import submit_login
    from app.config import get_settings

    real = get_settings()

    def _settings_with_key():
        # Build a stand-in object: the route handler only touches
        # ``api_key``; everything else is unused.
        class _S:
            pass
        s = _S()
        s.api_key = SecretStr(api_key)
        # The handler also does not touch other fields, but in case
        # FastAPI auto-binds, copy a few attrs over.
        for attr in ("env",):
            setattr(s, attr, getattr(real, attr, "development"))
        return s

    router = APIRouter()
    router.post("/ui/login")(submit_login)

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[settings_dep] = _settings_with_key
    app.add_middleware(
        SessionMiddleware,
        secret_key="x" * 64,
        session_cookie="aetherforge_session",
        same_site="strict",
        https_only=False,
        max_age=3600,
    )
    return app


@pytest.mark.unit
class TestSessionRotationOnLogin:
    """Two logins → two cookie payloads with different ``sid`` values."""

    def _login(self, client: TestClient, api_key: str = "test-key") -> str:
        r = client.post(
            "/ui/login",
            data={"api_key": api_key, "next": "/"},
            follow_redirects=False,
        )
        # SessionMiddleware writes the cookie via Set-Cookie on the
        # outgoing redirect — TestClient stores it in client.cookies.
        assert r.status_code == 303, f"unexpected status {r.status_code}"
        return client.cookies.get("aetherforge_session", "")

    def test_two_logins_produce_distinct_cookies(self) -> None:
        client = TestClient(_app())
        cookie_a = self._login(client)
        client.cookies.clear()
        cookie_b = self._login(client)

        assert cookie_a, "no session cookie set on first login"
        assert cookie_b, "no session cookie set on second login"
        assert cookie_a != cookie_b, \
            "session cookie did NOT rotate between two logins (B1 regression)"

        payload_a = _decode_session(cookie_a)
        payload_b = _decode_session(cookie_b)
        for key in ("authenticated", "sid", "login_at"):
            assert key in payload_a, f"first cookie missing '{key}'"
            assert key in payload_b, f"second cookie missing '{key}'"
        assert payload_a["sid"] != payload_b["sid"], \
            "sid nonce did not change — rotation pattern broken"
        assert payload_a["authenticated"] is True
        assert payload_b["authenticated"] is True

    def test_login_clears_pre_existing_session(self) -> None:
        """Post-login session must contain ONLY the three rotation keys."""
        client = TestClient(_app())
        cookie = self._login(client)
        payload = _decode_session(cookie)
        assert set(payload.keys()) == {"authenticated", "sid", "login_at"}, \
            f"unexpected session keys after login: {sorted(payload.keys())}"

    def test_wrong_key_does_not_rotate(self) -> None:
        """A failed login must NOT touch the session at all."""
        client = TestClient(_app())
        r = client.post(
            "/ui/login",
            data={"api_key": "wrong", "next": "/"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        # Failed login should redirect with error and NOT set a session cookie.
        # (It may set the CSRF cookie via the middleware, but session is
        #  untouched.)
        assert "error=invalid_api_key" in (r.headers.get("location") or "")
        assert client.cookies.get("aetherforge_session", "") == ""
