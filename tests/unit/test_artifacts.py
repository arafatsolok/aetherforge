"""Unit tests for the artifact store."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.executor.artifacts import ArtifactStore


def _settings_with_data_dir(tmp: Path) -> Settings:
    """Pydantic Settings is frozen — clone with model_copy."""
    base = Settings()  # picks up env vars
    return base.model_copy(update={"data_dir": tmp})


@pytest.mark.unit
class TestArtifactStore:
    def test_persist_round_trip(self, tmp_path: Path) -> None:
        s = _settings_with_data_dir(tmp_path)
        store = ArtifactStore(settings=s)
        ptr = store.persist(
            scan_ulid="scan-X",
            execution_ulid="exec-Y",
            stdout=b"hello world\n",
            stderr=b"oops\n",
            exit_code=0,
            meta={"tool": "nmap"},
        )
        assert ptr.stdout_path.read_bytes() == b"hello world\n"
        assert ptr.stderr_path.read_bytes() == b"oops\n"
        assert ptr.stdout_bytes == 12
        assert ptr.stderr_bytes == 5
        assert len(ptr.stdout_sha256) == 64
        assert ptr.meta_path.exists()

    def test_strip_ansi_during_persist(self, tmp_path: Path) -> None:
        s = _settings_with_data_dir(tmp_path)
        store = ArtifactStore(settings=s)
        ansi = b"\x1b[31mred\x1b[0m text"
        ptr = store.persist(
            scan_ulid="x", execution_ulid="y",
            stdout=ansi, stderr=b"", exit_code=0, meta={},
        )
        assert b"\x1b" not in ptr.stdout_path.read_bytes()
