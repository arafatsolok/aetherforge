"""Unit tests for sandbox policy clamping."""

from __future__ import annotations

import pytest

from app.config import Persona, get_settings
from app.executor.sandbox import SandboxPolicy, default_sandbox


@pytest.mark.unit
class TestSandboxClamp:
    def test_drops_non_whitelisted_caps(self) -> None:
        p = SandboxPolicy(cap_add=("SYS_ADMIN", "NET_RAW", "SYS_PTRACE"))
        assert p.clamped().cap_add == ("NET_RAW",)

    def test_memory_ceiling(self) -> None:
        p = SandboxPolicy(memory_bytes=10 * 1024 * 1024 * 1024)   # 10 GiB
        assert p.clamped().memory_bytes == 4 * 1024 * 1024 * 1024  # 4 GiB ceiling

    def test_timeout_ceiling(self) -> None:
        p = SandboxPolicy(timeout_seconds=99999)
        assert p.clamped().timeout_seconds == 7200

    def test_pids_ceiling(self) -> None:
        p = SandboxPolicy(pids_limit=999999)
        assert p.clamped().pids_limit == 512

    def test_uid_forced_above_1000(self) -> None:
        p = SandboxPolicy(run_as_uid=0)
        assert p.clamped().run_as_uid == 10100

    def test_read_only_always_true(self) -> None:
        p = SandboxPolicy(read_only_rootfs=False)
        assert p.clamped().read_only_rootfs is True

    def test_docker_run_args_include_cap_drop_all(self) -> None:
        p = SandboxPolicy(cap_add=("NET_RAW",)).clamped()
        args = p.docker_run_args()
        assert "--cap-drop" in args
        assert "ALL" in args
        assert "--cap-add" in args
        assert "NET_RAW" in args


@pytest.mark.unit
def test_default_sandbox_respects_settings_defaults() -> None:
    s = get_settings()
    p = default_sandbox(settings=s, persona=Persona.GRAY, cap_add=("NET_RAW",))
    assert p.network == "aetherforge_targets"
    assert p.cap_add == ("NET_RAW",)
    assert p.memory_bytes == s.tool_memory_limit
    assert p.cpu_shares == s.tool_cpu_shares
    assert p.timeout_seconds == s.tool_run_timeout
