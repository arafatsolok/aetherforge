"""Container sandbox policy — defaults + per-invocation overrides.

A ``SandboxPolicy`` is the authoritative set of Docker run flags the
executor is allowed to apply. Tool wrappers declare their requirements
via ``ToolSpec`` (e.g. nmap needs ``NET_RAW``) and the policy is derived
deterministically from (spec + persona + scope) — no Docker flag is
added implicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.config import Persona, Settings

# Hard policy ceilings — wrappers can ask for less, never more.
_MAX_MEMORY_BYTES: Final[int] = 4 * 1024 * 1024 * 1024   # 4 GiB
_MAX_TIMEOUT_SEC: Final[int] = 7200                      # 2 h
_MAX_PIDS: Final[int] = 512


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Concrete Docker run config for one invocation."""

    network: str = "aetherforge_targets"
    cap_add: tuple[str, ...] = ()
    cap_drop: tuple[str, ...] = ("ALL",)
    read_only_rootfs: bool = True
    tmpfs_mounts: tuple[str, ...] = ("/tmp",)
    memory_bytes: int = 512 * 1024 * 1024     # 512 MiB
    cpu_shares: int = 512
    pids_limit: int = 256
    timeout_seconds: int = 600
    run_as_uid: int | None = 10100            # matches the wrappers' uid
    security_opts: tuple[str, ...] = (
        "no-new-privileges:true",
        "apparmor=docker-default",
    )
    # ``--env`` pairs — injected into the container. Redacted in audit.
    env: tuple[tuple[str, str], ...] = ()
    # Bind mounts — always read-only unless explicitly marked rw.
    mounts: tuple[tuple[str, str, str], ...] = ()  # (host, container, mode)

    def clamped(self) -> SandboxPolicy:
        """Return a copy with every field clamped to the hard ceilings."""
        return SandboxPolicy(
            network=self.network,
            cap_add=tuple(c for c in self.cap_add if c in _ALLOWED_CAPS),
            cap_drop=self.cap_drop or ("ALL",),
            read_only_rootfs=True,       # always enforce
            tmpfs_mounts=self.tmpfs_mounts or ("/tmp",),
            memory_bytes=min(self.memory_bytes, _MAX_MEMORY_BYTES),
            cpu_shares=max(1, min(self.cpu_shares, 4096)),
            pids_limit=max(1, min(self.pids_limit, _MAX_PIDS)),
            timeout_seconds=max(1, min(self.timeout_seconds, _MAX_TIMEOUT_SEC)),
            run_as_uid=self.run_as_uid if self.run_as_uid and self.run_as_uid >= 1000 else 10100,
            security_opts=self.security_opts or (
                "no-new-privileges:true",
                "apparmor=docker-default",
            ),
            env=self.env,
            mounts=self.mounts,
        )

    def docker_run_args(self) -> list[str]:
        """Render the policy as extra Docker SDK ``host_config`` args.

        Used by ``DockerExecutor``; returned as a list so tests can
        inspect exactly what would be passed.
        """
        parts: list[str] = []
        for cap in self.cap_add:
            parts += ["--cap-add", cap]
        for cap in self.cap_drop:
            parts += ["--cap-drop", cap]
        if self.read_only_rootfs:
            parts += ["--read-only"]
        for tm in self.tmpfs_mounts:
            parts += ["--tmpfs", f"{tm}:rw,noexec,nosuid,size=128m"]
        parts += ["--memory", str(self.memory_bytes)]
        parts += ["--cpu-shares", str(self.cpu_shares)]
        parts += ["--pids-limit", str(self.pids_limit)]
        parts += ["--network", self.network]
        if self.run_as_uid is not None:
            parts += ["--user", str(self.run_as_uid)]
        for so in self.security_opts:
            parts += ["--security-opt", so]
        for host, container, mode in self.mounts:
            parts += ["--mount", f"type=bind,source={host},target={container},readonly" if mode == "ro" else f"type=bind,source={host},target={container}"]
        for k, v in self.env:
            parts += ["-e", f"{k}={v}"]
        return parts


# Whitelist of capabilities tools are allowed to request. Any cap not in
# here is dropped even if the wrapper asks for it.
_ALLOWED_CAPS: Final[frozenset[str]] = frozenset(
    {"NET_RAW", "NET_ADMIN", "NET_BIND_SERVICE"}
)


def default_sandbox(
    *,
    settings: Settings,
    persona: Persona,
    cap_add: tuple[str, ...] = (),
    memory_bytes: int | None = None,
    cpu_shares: int | None = None,
    timeout_seconds: int | None = None,
    run_as_uid: int | None = None,
    network: str = "aetherforge_targets",
    env: tuple[tuple[str, str], ...] = (),
    mounts: tuple[tuple[str, str, str], ...] = (),
) -> SandboxPolicy:
    """Build a ``SandboxPolicy`` from (settings, persona, overrides).

    Values not provided fall back to the platform-wide defaults in
    ``settings``. The returned policy is always passed through
    ``.clamped()`` so hard ceilings apply.
    """
    policy = SandboxPolicy(
        network=network,
        cap_add=cap_add,
        memory_bytes=memory_bytes if memory_bytes is not None else settings.tool_memory_limit,
        cpu_shares=cpu_shares if cpu_shares is not None else settings.tool_cpu_shares,
        timeout_seconds=timeout_seconds if timeout_seconds is not None else settings.tool_run_timeout,
        run_as_uid=run_as_uid,
        env=env,
        mounts=mounts,
    )
    # Unused today — persona may later tighten this further (e.g. white
    # persona gets a tighter pids_limit or smaller memory).
    _ = persona
    return policy.clamped()


__all__ = ["SandboxPolicy", "default_sandbox"]
