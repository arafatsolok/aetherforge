"""``pick_next_action`` — evaluate rules + generate the next command.

Combined into one activity because they're cheap and atomic — splitting
would just spam the workflow history with no retry benefit.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from sqlalchemy import select
from temporalio import activity

from app.config import Persona
from app.core.command_generator import CommandRejected
from app.core.rule_engine import Fact, RuleDefinition
from app.database import get_session_factory
from app.models.rule import Rule
from app.workflows.data import InvocationSpec, IterationOutcome
from app.workflows.runtime import get_runtime


@activity.defn(name="aetherforge.evaluate.refresh_rules")
async def refresh_rule_engine() -> int:
    """Reload the rule engine from the DB. Returns the loaded rule count."""
    runtime = get_runtime()
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(Rule).where(Rule.enabled.is_(True))
        rows = (await session.execute(stmt)).scalars().all()

    definitions: list[RuleDefinition] = []
    for r in rows:
        body = r.body or {}
        definitions.append(RuleDefinition(
            id=r.rule_id,
            version=r.version,
            persona=tuple(Persona(p) for p in (r.personas or [])),
            phase=r.phase,
            priority=r.priority,
            description=r.description,
            when=body.get("when") or {},
            then=body.get("then") or {},
            metadata=body.get("metadata") or {"enabled": r.enabled},
        ))
    runtime.rule_engine.load(definitions)
    return len(definitions)


@activity.defn(name="aetherforge.evaluate.pick_next_action")
async def pick_next_action(
    scan_id: int,
    persona_value: str,
    executed_rule_ids: list[str],
    facts_dto: list[dict[str, Any]],
    target_scope_cidrs: list[str],
) -> dict[str, Any]:
    """Pick the highest-priority fireable rule and translate it to an invocation.

    Returns the dict form of ``IterationOutcome``:
      - ``has_action=False`` → loop done OR no rule fires this iteration
      - ``has_action=True`` + invocation → workflow should execute
    """
    runtime = get_runtime()

    # Lazy-load if the engine is empty (worker just booted).
    if runtime.rule_engine.count() == 0:
        await refresh_rule_engine()

    persona = Persona(persona_value)
    facts = [
        Fact(
            fact_type=f["fact_type"], body=f["body"],
            source_tool=f["source_tool"], scan_id=str(scan_id),
            iteration=int(f["iteration"]), fingerprint=f["fingerprint"],
        )
        for f in facts_dto
    ]

    matches = runtime.rule_engine.evaluate(
        facts, persona=persona, executed_rule_ids=set(executed_rule_ids)
    )
    if not matches:
        return dataclasses.asdict(IterationOutcome(has_action=False))

    top = matches[0]

    try:
        invocation = runtime.command_generator.generate(
            top, persona=persona,
            target_scope_cidrs=target_scope_cidrs,
            scan_id=str(scan_id),
        )
    except CommandRejected as err:
        return dataclasses.asdict(IterationOutcome(
            has_action=False,
            rule_id=top.rule.id,
            rejection_reason=str(err),
            triggering_fact_fingerprint=top.triggering_fact.fingerprint,
        ))

    return dataclasses.asdict(IterationOutcome(
        has_action=True,
        rule_id=top.rule.id,
        invocation=InvocationSpec(
            tool_name=invocation.tool_name,
            image=invocation.image,
            argv=list(invocation.argv),
            cap_add=list(invocation.cap_add),
            cap_drop=list(invocation.cap_drop),
            memory_bytes=invocation.memory_bytes,
            cpu_shares=invocation.cpu_shares,
            timeout_seconds=invocation.timeout_seconds,
            read_only_rootfs=invocation.read_only_rootfs,
            run_as_uid=invocation.run_as_uid,
            network=invocation.network,
            rule_id=invocation.rule_id,
            persona=invocation.persona.value,
            metadata=dict(invocation.metadata),
        ),
        triggering_fact_fingerprint=top.triggering_fact.fingerprint,
    ))


__all__ = ["pick_next_action", "refresh_rule_engine"]
