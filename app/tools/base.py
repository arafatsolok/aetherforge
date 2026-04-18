"""Abstract base for every tool wrapper.

A ``ToolWrapper`` subclass encapsulates three things for one CLI tool:

  1. ``spec``   — static metadata (name, image, category, required caps)
  2. ``build_invocation(params)`` — translate structured params into argv
  3. ``parse(stdout, stderr, exit_code)`` — extract ``Fact``s from output

The executor itself (Docker / cgroup / timeout) is NOT a wrapper concern.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import Any

from app.core.rule_engine import Fact


class ToolCategory(enum.StrEnum):
    RECON_PASSIVE = "recon.passive"
    RECON_ACTIVE = "recon.active"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    PERSISTENCE = "persistence"
    EXFIL_SIMULATION = "exfil_simulation"
    DEFENSE = "defense"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Static, read-only metadata for one tool."""

    name: str
    image: str
    category: ToolCategory
    description: str
    required_caps: tuple[str, ...] = ()
    default_timeout_seconds: int = 600
    default_memory_bytes: int = 536_870_912  # 512 MiB
    default_uid: int | None = None
    supports_json_output: bool = False
    min_persona_ordinal: int = 0   # 0=white, 1=gray, 2=black
    version: str = "unknown"
    labels: tuple[str, ...] = ()


@dataclass(slots=True)
class InvocationPlan:
    """Concrete argv + env + files for a single run."""

    argv: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)
    input_files: dict[str, bytes] = field(default_factory=dict)  # written to tmpfs pre-run
    expected_output_file: str | None = None
    json_output: bool = False


class ToolWrapper(abc.ABC):
    """Abstract interface implemented by every tool module.

    Subclasses are instantiated by the ``ToolRegistry`` at boot; they must
    be stateless and thread-safe.
    """

    spec: ToolSpec

    @abc.abstractmethod
    def build_invocation(self, params: dict[str, Any]) -> InvocationPlan:
        """Translate structured rule params into a concrete plan."""

    @abc.abstractmethod
    def parse(
        self,
        *,
        stdout: bytes,
        stderr: bytes,
        exit_code: int,
        scan_id: str,
        iteration: int,
    ) -> list[Fact]:
        """Parse tool output into ``Fact``s that feed the rule engine."""

    # Optional hooks -------------------------------------------------------
    def validate_params(self, params: dict[str, Any]) -> None:
        """Raise on bad params. Default: no-op. Phase 2 enforces."""

    def sanitise_stdout(self, data: bytes) -> bytes:
        """Hook to strip ANSI / truncate noisy tool output. Default: identity."""
        return data


__all__ = ["InvocationPlan", "ToolCategory", "ToolSpec", "ToolWrapper"]
