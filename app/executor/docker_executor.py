"""Sandboxed Docker execution of tool invocations.

Given a ``ToolInvocation`` (already scope-checked by the command
generator), the executor:

  1. Pre-creates the artefact directory + bind-mount target.
  2. Calls the Docker Engine API to ``docker run --rm`` the image.
  3. Enforces the cgroup + cap + read-only rootfs policy.
  4. Tees stdout / stderr to the artefact store.
  5. Kills the container if it exceeds the sandbox timeout.
  6. Returns an ``ExecutionResult`` that the parser consumes.

All Docker interactions go through the Docker SDK ``DockerClient``,
instantiated once per worker from the bind-mounted socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from docker.errors import APIError, ContainerError, ImageNotFound
from docker.models.containers import Container

import docker
from app.config import Settings
from app.core.command_generator import ToolInvocation
from app.executor.artifacts import ArtifactPointer, ArtifactStore
from app.executor.sandbox import SandboxPolicy
from app.logging_config import get_logger

log = get_logger(__name__)


class ExecutorError(RuntimeError):
    """Raised on any non-recoverable executor failure."""


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Return value of ``DockerExecutor.run``."""

    invocation: ToolInvocation
    container_id: str | None
    image: str
    argv: tuple[str, ...]
    exit_code: int
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    stdout: bytes
    stderr: bytes
    artifact: ArtifactPointer
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and self.error is None


@dataclass(slots=True)
class DockerExecutor:
    """Docker-SDK-based tool runner."""

    settings: Settings
    artifact_store: ArtifactPointer | None = None  # injected in __post_init__
    _client: docker.DockerClient | None = field(default=None, init=False)
    _store: ArtifactStore = field(init=False)

    def __post_init__(self) -> None:
        self._store = ArtifactStore(settings=self.settings)

    # -------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def close(self) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None

    # -------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------
    async def run(
        self,
        *,
        invocation: ToolInvocation,
        policy: SandboxPolicy,
        scan_ulid: str,
        execution_ulid: str,
    ) -> ExecutionResult:
        """Execute the invocation. Raises only on unrecoverable infra errors."""
        # Blocking Docker SDK calls → run in a thread so we don't block the loop.
        return await asyncio.to_thread(
            self._run_sync,
            invocation,
            policy,
            scan_ulid,
            execution_ulid,
        )

    # -------------------------------------------------------------------
    # Synchronous core
    # -------------------------------------------------------------------
    def _run_sync(
        self,
        invocation: ToolInvocation,
        policy: SandboxPolicy,
        scan_ulid: str,
        execution_ulid: str,
    ) -> ExecutionResult:
        run_dir = self._store.prepare(scan_ulid=scan_ulid, execution_ulid=execution_ulid)

        started_at = datetime.now(UTC)
        start_mono = time.monotonic()

        log.info(
            "executor.run",
            tool=invocation.tool_name,
            image=invocation.image,
            argv=list(invocation.argv),
            scan=scan_ulid,
            execution=execution_ulid,
        )

        container: Container | None = None
        stdout: bytes = b""
        stderr: bytes = b""
        exit_code = -1
        timed_out = False
        error: str | None = None

        try:
            client = self.client()
            container = client.containers.run(
                image=invocation.image,
                command=list(invocation.argv),
                detach=True,
                remove=False,            # We remove manually after capturing logs
                stdout=True,
                stderr=True,
                network=policy.network,
                cap_drop=list(policy.cap_drop),
                cap_add=list(policy.cap_add),
                mem_limit=policy.memory_bytes,
                cpu_shares=policy.cpu_shares,
                pids_limit=policy.pids_limit,
                read_only=policy.read_only_rootfs,
                tmpfs=dict.fromkeys(policy.tmpfs_mounts, "rw,noexec,nosuid,size=128m"),
                user=str(policy.run_as_uid) if policy.run_as_uid is not None else None,
                security_opt=list(policy.security_opts),
                environment=dict(policy.env),
                volumes=_render_mounts(policy.mounts, run_dir),
                labels={
                    "aetherforge.scan": scan_ulid,
                    "aetherforge.execution": execution_ulid,
                    "aetherforge.tool": invocation.tool_name,
                    "aetherforge.rule": invocation.rule_id,
                },
            )

            exit_code, timed_out = self._wait_with_timeout(
                container, policy.timeout_seconds
            )

            stdout = container.logs(stdout=True, stderr=False) or b""
            stderr = container.logs(stdout=False, stderr=True) or b""

        except ImageNotFound as err:
            error = f"image not found: {invocation.image}"
            exit_code = 127
            log.error("executor.image_missing", image=invocation.image, error=str(err))
        except ContainerError as err:
            stdout = err.stderr or b""
            stderr = err.stderr or b""
            exit_code = err.exit_status
            error = f"container error: {err.exit_status}"
            log.warning("executor.container_error", exit=err.exit_status)
        except APIError as err:
            error = f"docker api error: {err}"
            log.error("executor.api_error", error=str(err))
        except Exception as err:
            error = f"unexpected: {type(err).__name__}: {err}"
            log.exception("executor.unexpected")
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    log.warning("executor.remove_failed")

        finished_at = datetime.now(UTC)
        duration_ms = int((time.monotonic() - start_mono) * 1000)

        meta: dict[str, Any] = {
            "tool": invocation.tool_name,
            "image": invocation.image,
            "argv": list(invocation.argv),
            "scan_ulid": scan_ulid,
            "execution_ulid": execution_ulid,
            "rule_id": invocation.rule_id,
            "persona": invocation.persona.value,
            "container_id": container.id if container else None,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "error": error,
            "sandbox": {
                "network": policy.network,
                "cap_add": list(policy.cap_add),
                "cap_drop": list(policy.cap_drop),
                "memory_bytes": policy.memory_bytes,
                "cpu_shares": policy.cpu_shares,
                "pids_limit": policy.pids_limit,
                "timeout_seconds": policy.timeout_seconds,
                "read_only_rootfs": policy.read_only_rootfs,
                "run_as_uid": policy.run_as_uid,
            },
        }

        artifact = self._store.persist(
            scan_ulid=scan_ulid,
            execution_ulid=execution_ulid,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            meta=meta,
        )

        return ExecutionResult(
            invocation=invocation,
            container_id=container.id if container else None,
            image=invocation.image,
            argv=invocation.argv,
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            artifact=artifact,
            timed_out=timed_out,
            error=error,
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------
    @staticmethod
    def _wait_with_timeout(container: Container, timeout_s: int) -> tuple[int, bool]:
        """Wait for the container to finish or kill it on timeout.

        Returns (exit_code, timed_out).
        """
        try:
            result = container.wait(timeout=timeout_s)
            return int(result.get("StatusCode", -1)), False
        except Exception:
            with contextlib.suppress(Exception):
                container.kill(signal="SIGKILL")
            return 137, True  # 128 + SIGKILL


def _render_mounts(
    mounts: tuple[tuple[str, str, str], ...], run_dir: object
) -> dict[str, dict[str, str]]:
    """Translate ``(host, container, mode)`` tuples to Docker SDK dict form."""
    _ = run_dir  # reserved for Phase 3 — per-exec bind of the artefact dir
    out: dict[str, dict[str, str]] = {}
    for host, container, mode in mounts:
        out[host] = {"bind": container, "mode": mode}
    return out


__all__ = [
    "DockerExecutor",
    "ExecutionResult",
    "ExecutorError",
]
