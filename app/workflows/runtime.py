"""Per-worker singletons used by activities.

Activities are stateless callables; expensive-to-build dependencies
(rule engine, tool registry, persona engine, executors) are kept here so
they're built once per worker process and reused.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from app.config import get_settings
from app.core.command_generator import DeterministicCommandGenerator
from app.core.persona_engine import PersonaEngine
from app.core.rule_engine import DeterministicRuleEngine
from app.executor import DockerExecutor
from app.executor.msf_executor import MsfExecutor
from app.tools.registry import ToolRegistry
from app.tools.registry_loader import bootstrap_registry


@dataclass(slots=True)
class WorkerRuntime:
    settings: object
    registry: ToolRegistry
    rule_engine: DeterministicRuleEngine
    persona_engine: PersonaEngine
    command_generator: DeterministicCommandGenerator
    executor: DockerExecutor
    msf_executor: MsfExecutor


@lru_cache(maxsize=1)
def get_runtime() -> WorkerRuntime:
    settings = get_settings()
    registry = bootstrap_registry(configs_dir=settings.configs_dir)
    rule_engine = DeterministicRuleEngine()
    persona_engine = PersonaEngine.from_yaml(settings.configs_dir / "personas.yaml")
    command_generator = DeterministicCommandGenerator(
        registry=registry,
        persona_engine=persona_engine,
        settings=settings,
    )
    executor = DockerExecutor(settings=settings)
    msf_executor = MsfExecutor(settings=settings)
    return WorkerRuntime(
        settings=settings,
        registry=registry,
        rule_engine=rule_engine,
        persona_engine=persona_engine,
        command_generator=command_generator,
        executor=executor,
        msf_executor=msf_executor,
    )


__all__ = ["WorkerRuntime", "get_runtime"]
