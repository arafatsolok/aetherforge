"""Unit tests for the Metasploit RPC executor (no live RPC needed)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.config import Persona, Settings
from app.core.command_generator import ToolInvocation
from app.executor.msf_executor import MsfExecutor, _argv_to_kv
from app.executor.sandbox import default_sandbox
from app.services.metasploit_rpc import MsfRunResult


def _settings_with_data(tmp: Path) -> Settings:
    return Settings().model_copy(update={"data_dir": tmp})


def _invocation() -> ToolInvocation:
    return ToolInvocation(
        tool_name="metasploit",
        image="aetherforge/metasploit:latest",
        argv=("--module", "auxiliary/scanner/portscan/tcp",
              "--target", "10.77.0.5", "--port", "80", "--mode", "run"),
        env={}, workdir="/", mounts=(), network="aetherforge_targets",
        cap_add=(), cap_drop=("ALL",), memory_bytes=1024,
        cpu_shares=512, timeout_seconds=10,
        read_only_rootfs=True, run_as_uid=10103,
        rule_id="r.test", scan_id="1", persona=Persona.BLACK,
        metadata={},
    )


@pytest.mark.unit
def test_argv_to_kv_basics() -> None:
    kv = _argv_to_kv(("--module", "x/y", "--port", "80", "--mode", "run"))
    assert kv == {"module": "x/y", "port": "80", "mode": "run"}


@pytest.mark.unit
def test_argv_to_kv_skips_dangling() -> None:
    kv = _argv_to_kv(("--module", "x/y", "--leftover"))
    assert kv == {"module": "x/y"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_msf_executor_routes_through_rpc(tmp_path: Path) -> None:
    s = _settings_with_data(tmp_path)
    ex = MsfExecutor(settings=s)

    # Replace the lazy RPC with a mock — we only verify the executor
    # plumbing, not the RPC client itself.
    rpc_mock = MagicMock()
    rpc_mock.run_module = AsyncMock(return_value=MsfRunResult(
        ok=True, module="auxiliary/scanner/portscan/tcp", mode="run",
        payload={"job_id": 7, "found": [80]},
    ))
    ex._rpc = rpc_mock                                       # type: ignore[assignment]

    result = await ex.run(
        invocation=_invocation(),
        policy=default_sandbox(settings=s, persona=Persona.BLACK,
                               timeout_seconds=10),
        scan_ulid="scan1", execution_ulid="exec1",
    )
    assert result.ok
    assert result.exit_code == 0
    rpc_mock.run_module.assert_awaited_once()
    args = rpc_mock.run_module.call_args.kwargs
    assert args["module_name"] == "auxiliary/scanner/portscan/tcp"
    assert args["target"] == "10.77.0.5"
    assert args["port"] == 80
    assert args["mode"] == "run"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_msf_executor_failure_path(tmp_path: Path) -> None:
    s = _settings_with_data(tmp_path)
    ex = MsfExecutor(settings=s)
    rpc_mock = MagicMock()
    rpc_mock.run_module = AsyncMock(side_effect=RuntimeError("connection refused"))
    ex._rpc = rpc_mock                                       # type: ignore[assignment]

    result = await ex.run(
        invocation=_invocation(),
        policy=default_sandbox(settings=s, persona=Persona.BLACK,
                               timeout_seconds=10),
        scan_ulid="scan2", execution_ulid="exec2",
    )
    assert not result.ok
    assert result.exit_code == 1
    assert result.error and "connection refused" in result.error
