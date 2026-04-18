"""Artefact persistence — stdout, stderr, tool-native output files.

Every invocation produces a directory under ``data/artifacts/<scan>/<execution>/``:

  stdout                  raw stdout (ANSI-stripped)
  stderr                  raw stderr (ANSI-stripped)
  exit_code               plain-text exit code
  meta.json               invocation metadata (argv, timings, sandbox)
  output/                 bind-mounted /output inside the container

Each file is HMAC-signed using ``AETHERFORGE_SECRET_KEY`` so tampering
becomes detectable (Phase 8 will verify at report-time).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import Settings
from app.utils.parsers import strip_ansi


@dataclass(frozen=True, slots=True)
class ArtifactPointer:
    """Structured reference to on-disk artefact files."""

    scan_ulid: str
    execution_ulid: str
    root: Path
    stdout_path: Path
    stderr_path: Path
    meta_path: Path
    output_dir: Path
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int


class ArtifactStore:
    """Write + digest artefacts on behalf of the executor."""

    def __init__(self, *, settings: Settings) -> None:
        self._root = settings.data_dir / "artifacts"
        self._secret = settings.secret_key.get_secret_value().encode()
        self._root.mkdir(parents=True, exist_ok=True)

    # -- Writing -----------------------------------------------------------
    def prepare(self, *, scan_ulid: str, execution_ulid: str) -> Path:
        """Create the per-execution directory. Returns the root."""
        run_dir = self._root / scan_ulid / execution_ulid
        (run_dir / "output").mkdir(parents=True, exist_ok=True)
        return run_dir

    def persist(
        self,
        *,
        scan_ulid: str,
        execution_ulid: str,
        stdout: bytes,
        stderr: bytes,
        exit_code: int,
        meta: dict[str, Any],
    ) -> ArtifactPointer:
        run_dir = self.prepare(scan_ulid=scan_ulid, execution_ulid=execution_ulid)

        stdout_clean = strip_ansi(stdout)
        stderr_clean = strip_ansi(stderr)

        out_path = run_dir / "stdout"
        err_path = run_dir / "stderr"
        exit_path = run_dir / "exit_code"
        meta_path = run_dir / "meta.json"
        output_dir = run_dir / "output"

        out_path.write_bytes(stdout_clean)
        err_path.write_bytes(stderr_clean)
        exit_path.write_text(str(exit_code))

        hmac_meta = {
            **meta,
            "persisted_at": datetime.now(UTC).isoformat(),
            "stdout_hmac": self._hmac(stdout_clean),
            "stderr_hmac": self._hmac(stderr_clean),
        }
        meta_path.write_text(json.dumps(hmac_meta, indent=2, sort_keys=True, default=str))

        return ArtifactPointer(
            scan_ulid=scan_ulid,
            execution_ulid=execution_ulid,
            root=run_dir,
            stdout_path=out_path,
            stderr_path=err_path,
            meta_path=meta_path,
            output_dir=output_dir,
            stdout_sha256=hashlib.sha256(stdout_clean).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr_clean).hexdigest(),
            stdout_bytes=len(stdout_clean),
            stderr_bytes=len(stderr_clean),
        )

    # -- Reading -----------------------------------------------------------
    def load_stdout(self, ptr: ArtifactPointer) -> bytes:
        return ptr.stdout_path.read_bytes()

    def load_stderr(self, ptr: ArtifactPointer) -> bytes:
        return ptr.stderr_path.read_bytes()

    def head(self, path: Path, limit: int = 4096) -> str:
        try:
            return path.read_bytes()[:limit].decode("utf-8", errors="replace")
        except OSError:
            return ""

    # -- Helpers -----------------------------------------------------------
    def _hmac(self, blob: bytes) -> str:
        return hmac.new(self._secret, blob, hashlib.sha256).hexdigest()

    def root(self) -> Path:
        return self._root

    def used_bytes(self) -> int:
        """Walk the artefact tree. Cheap enough; callers cache."""
        total = 0
        for path, _, files in os.walk(self._root):
            for f in files:
                with contextlib.suppress(OSError):
                    total += (Path(path) / f).stat().st_size
        return total


__all__ = ["ArtifactPointer", "ArtifactStore"]
