"""Tool-container execution layer.

Public surface:
  * ``DockerExecutor``  — runs a ``ToolInvocation`` in a sandboxed
                          throwaway container and returns an ``ExecutionResult``
  * ``ExecutionResult`` — stdout/stderr/exit + timing + artifact pointer
  * ``SandboxPolicy``   — defaults (can be overridden per-invocation)
  * ``ArtifactStore``   — on-disk artefact writer, hashes + tees stdout
  * ``RateLimiter``     — per-persona in-process token bucket
"""

from __future__ import annotations

from app.executor.artifacts import ArtifactPointer, ArtifactStore
from app.executor.docker_executor import (
    DockerExecutor,
    ExecutionResult,
    ExecutorError,
)
from app.executor.rate_limiter import RateLimiter
from app.executor.sandbox import SandboxPolicy, default_sandbox

__all__ = [
    "ArtifactPointer",
    "ArtifactStore",
    "DockerExecutor",
    "ExecutionResult",
    "ExecutorError",
    "RateLimiter",
    "SandboxPolicy",
    "default_sandbox",
]
