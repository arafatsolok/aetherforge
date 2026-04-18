"""Shared pytest fixtures.

Phase 0 scaffolding — provides a FastAPI TestClient + env override so
subsequent phases can write real tests without re-plumbing fixtures.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session", autouse=True)
def _test_env() -> None:
    """Inject safe test defaults into the environment BEFORE settings load."""
    os.environ.setdefault("AETHERFORGE_ENV", "development")
    os.environ.setdefault("AETHERFORGE_SECRET_KEY", "x" * 32)
    os.environ.setdefault(
        "AETHERFORGE_DATABASE_URL",
        "postgresql+asyncpg://aetherforge:aetherforge@localhost:5432/aetherforge_test",
    )
    os.environ.setdefault("AETHERFORGE_REDIS_URL", "redis://localhost:6379/1")
    # Forbid network egress by default in tests.
    os.environ.setdefault("AETHERFORGE_STRICT_SCOPE_ENFORCEMENT", "true")
    # Tests use synthetic CIDRs (10.77.x) that the production default
    # ``FORBIDDEN_CIDRS=0.0.0.0/0`` would always reject. Reset to a
    # narrow forbidden range so unit tests can scope-check freely.
    # Tests that need forbidden checks pass forbidden_cidrs_extra to
    # DeterministicCommandGenerator directly.
    os.environ.setdefault("AETHERFORGE_FORBIDDEN_CIDRS", "127.0.0.0/8")
    # Reset the lru_cached settings singleton so the env vars above land.
    from app.config import get_settings
    get_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Sync TestClient for unit-level HTTP shape assertions.

    Deliberately does NOT enter the app as a context manager — lifespan
    startup (init_db / Temporal client / rule loader) requires live infra
    and is exercised by the integration suite instead.
    """
    from app.main import create_app

    app = create_app()
    yield TestClient(app)
