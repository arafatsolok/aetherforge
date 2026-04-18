"""Unit tests for the per-IP API rate limit middleware."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.api.middleware.rate_limit import APIRateLimit


def _hello(_req):                         # type: ignore[no-untyped-def]
    return PlainTextResponse("hi")


def _app(capacity: float = 3.0, refill: float = 0.0) -> Starlette:
    app = Starlette(routes=[
        Route("/api/v1/x", _hello),
        Route("/health", _hello),
    ])
    app.add_middleware(APIRateLimit, capacity=capacity, refill_per_s=refill)
    return app


@pytest.mark.unit
class TestRateLimit:
    def test_under_quota_succeeds(self) -> None:
        client = TestClient(_app(capacity=5.0))
        for _ in range(3):
            assert client.get("/api/v1/x").status_code == 200

    def test_over_quota_429(self) -> None:
        client = TestClient(_app(capacity=2.0))
        client.get("/api/v1/x")
        client.get("/api/v1/x")
        r = client.get("/api/v1/x")
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_health_exempt(self) -> None:
        client = TestClient(_app(capacity=1.0))
        for _ in range(10):
            assert client.get("/health").status_code == 200

    def test_429_body_shape(self) -> None:
        client = TestClient(_app(capacity=1.0))
        client.get("/api/v1/x")
        r = client.get("/api/v1/x")
        body = r.json()
        assert body["error"]["type"] == "rate_limited"
