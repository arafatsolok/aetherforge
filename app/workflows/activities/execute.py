"""``execute_invocation`` — sandboxed Docker run of a single tool.

Persists the ``Execution`` row + the ``ExecutionResult`` artefact, and
returns the small ``ExecutionOutcome`` DTO. The actual stdout/stderr
bytes stay on disk in artefacts and in the executor return value (we do
NOT pass them through Temporal).
"""

from __future__ import annotations

from typing import Any

import ulid
from temporalio import activity

from app.config import Persona
from app.core.command_generator import ToolInvocation
from app.database import get_session_factory
from app.executor import default_sandbox
from app.models.enums import ExecutionState
from app.models.execution import Execution
from app.workflows.data import ExecutionOutcome, InvocationSpec
from app.workflows.runtime import get_runtime


@activity.defn(name="aetherforge.execute.invocation")
async def execute_invocation(
    scan_id: int,
    iteration: int,
    invocation_dto: dict[str, Any],
) -> dict[str, Any]:
    runtime = get_runtime()
    spec = InvocationSpec(**invocation_dto)
    execution_ulid = str(ulid.new())

    invocation = ToolInvocation(
        tool_name=spec.tool_name,
        image=spec.image,
        argv=tuple(spec.argv),
        env={},
        workdir="/home/scanner",
        mounts=(),
        network=spec.network,
        cap_add=tuple(spec.cap_add),
        cap_drop=tuple(spec.cap_drop),
        memory_bytes=spec.memory_bytes,
        cpu_shares=spec.cpu_shares,
        timeout_seconds=spec.timeout_seconds,
        read_only_rootfs=spec.read_only_rootfs,
        run_as_uid=spec.run_as_uid,
        rule_id=spec.rule_id,
        scan_id=str(scan_id),
        persona=Persona(spec.persona),
        metadata=dict(spec.metadata),
    )

    # Insert pending row first so we have an FK target for facts.
    factory = get_session_factory()
    async with factory() as session, session.begin():
        execution = Execution(
            scan_id=scan_id,
            ulid=execution_ulid,
            rule_id=spec.rule_id,
            iteration=iteration,
            tool=spec.tool_name,
            image=spec.image,
            argv=list(spec.argv),
            state=ExecutionState.RUNNING.value,
        )
        session.add(execution)
        await session.flush()
        execution_id = int(execution.id)  # type: ignore[arg-type]

    # Run the tool — async, no DB held.
    policy = default_sandbox(
        settings=runtime.settings,
        persona=Persona(spec.persona),
        cap_add=tuple(spec.cap_add),
        memory_bytes=spec.memory_bytes,
        cpu_shares=spec.cpu_shares,
        timeout_seconds=spec.timeout_seconds,
        run_as_uid=spec.run_as_uid,
        network=spec.network,
    )
    # Dispatch — RPC-labelled tools (metasploit, openvas) go through their
    # respective RPC executor; everything else gets a sandboxed container.
    wrapper = runtime.registry.get(spec.tool_name)
    if "rpc" in (wrapper.spec.labels or ()) and spec.tool_name == "metasploit":
        chosen = runtime.msf_executor
    else:
        chosen = runtime.executor

    result = await chosen.run(
        invocation=invocation,
        policy=policy,
        scan_ulid=str(scan_id),
        execution_ulid=execution_ulid,
    )

    # Update execution row with the outcome.
    async with factory() as session, session.begin():
        execution = await session.get(Execution, execution_id)
        assert execution is not None
        execution.exit_code = result.exit_code
        execution.duration_ms = result.duration_ms
        execution.container_id = result.container_id
        execution.stdout_bytes = result.artifact.stdout_bytes
        execution.stderr_bytes = result.artifact.stderr_bytes
        execution.artifact_meta = {
            "stdout_sha256": result.artifact.stdout_sha256,
            "stderr_sha256": result.artifact.stderr_sha256,
            "root": str(result.artifact.root),
        }
        execution.stdout_head = result.stdout[:4096].decode("utf-8", errors="replace")
        execution.stderr_head = result.stderr[:4096].decode("utf-8", errors="replace")
        execution.started_at = result.started_at.replace(tzinfo=None)
        execution.finished_at = result.finished_at.replace(tzinfo=None)
        if result.timed_out:
            execution.state = ExecutionState.TIMEOUT.value
        elif result.error or result.exit_code != 0:
            execution.state = ExecutionState.FAILED.value
        else:
            execution.state = ExecutionState.SUCCESS.value
        session.add(execution)

    import dataclasses
    return dataclasses.asdict(ExecutionOutcome(
        execution_id=execution_id,
        execution_ulid=execution_ulid,
        tool=spec.tool_name,
        rule_id=spec.rule_id,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        timed_out=result.timed_out,
        error=result.error,
        facts_emitted=0,
    ))


__all__ = ["execute_invocation"]
