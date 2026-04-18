"""/health returns 200 and the running version."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import __version__


@pytest.mark.unit
def test_health_ok(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
