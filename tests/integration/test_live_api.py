"""Live-stack integration tests.

These run against a running orchestrator + worker + postgres + redis +
temporal. Invoked by the validation pass AFTER ``docker compose up -d``.

Base URL comes from env ``AETHERFORGE_TEST_BASE_URL``. Defaults to
``http://127.0.0.1:8001`` matching the port shift in the live-test .env.
"""

from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.getenv("AETHERFORGE_TEST_BASE_URL", "http://127.0.0.1:8001")


@pytest.fixture(scope="module")
def http() -> httpx.Client:
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as c:
        yield c


@pytest.mark.integration
def test_health(http: httpx.Client) -> None:
    r = http.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"]


@pytest.mark.integration
def test_ready_db_and_redis(http: httpx.Client) -> None:
    r = http.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok", body
    assert body["checks"]["postgres"]["ok"] is True, body
    assert body["checks"]["redis"]["ok"] is True, body


@pytest.mark.integration
def test_openapi(http: httpx.Client) -> None:
    r = http.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["info"]["title"].startswith("AetherForge")
    # At least the Phase 0 route set we registered.
    paths = set(spec["paths"])
    must = {
        "/health",
        "/ready",
        "/api/v1/targets",
        "/api/v1/scans",
        "/api/v1/rules",
        "/api/v1/personas",
        "/api/v1/personas/current",
        "/api/v1/findings",
    }
    missing = must - paths
    assert not missing, f"openapi missing routes: {missing}"


@pytest.mark.integration
@pytest.mark.parametrize(
    "path,expected_key",
    [
        ("/api/v1/targets",          "items"),
        ("/api/v1/scans",            "items"),
        ("/api/v1/rules",            "items"),
        ("/api/v1/findings",         "items"),
        ("/api/v1/personas",         "personas"),
        ("/api/v1/personas/current", "persona"),
    ],
)
def test_phase0_stub_routes(http: httpx.Client, path: str, expected_key: str) -> None:
    r = http.get(path)
    assert r.status_code == 200, (path, r.text)
    assert expected_key in r.json(), (path, r.json())


@pytest.mark.integration
def test_persona_header_override(http: httpx.Client) -> None:
    r = http.get(
        "/api/v1/personas/current",
        headers={"X-AetherForge-Persona": "gray"},
    )
    assert r.status_code == 200
    assert r.json()["persona"] == "gray"


@pytest.mark.integration
def test_persona_header_invalid_rejected(http: httpx.Client) -> None:
    r = http.get(
        "/api/v1/personas/current",
        headers={"X-AetherForge-Persona": "magenta"},
    )
    assert r.status_code == 400


@pytest.mark.integration
def test_dashboard_renders(http: httpx.Client) -> None:
    r = http.get("/")
    assert r.status_code == 200
    assert "AetherForge" in r.text
    assert "text/html" in r.headers["content-type"]


@pytest.mark.integration
def test_unknown_route_404(http: httpx.Client) -> None:
    r = http.get("/nonexistent/path")
    assert r.status_code == 404
