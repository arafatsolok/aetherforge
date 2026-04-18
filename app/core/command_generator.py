"""Command generator contract + concrete implementation.

The generator translates a ``RuleMatch`` into a ``ToolInvocation`` — the
deterministic specification of exactly what will be executed in a
sandboxed container. Scope + persona + forbidden-CIDR enforcement
happens HERE, before Docker sees anything. A rejected command is still
recorded (caller is responsible for writing an audit entry).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.config import Persona, Settings
from app.core.evasion import evasion_for
from app.core.persona_engine import PersonaEngine
from app.core.rule_engine.contract import RuleMatch
from app.tools.registry import ToolRegistry
from app.utils.security import (
    is_cidr_forbidden,
    is_target_in_scope,
    sanitize_argv_token,
)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """Fully-materialised specification of a tool run."""

    tool_name: str
    image: str
    argv: tuple[str, ...]
    env: dict[str, str]
    workdir: str
    mounts: tuple[tuple[str, str, str], ...]
    network: str
    cap_add: tuple[str, ...]
    cap_drop: tuple[str, ...]
    memory_bytes: int
    cpu_shares: int
    timeout_seconds: int
    read_only_rootfs: bool
    run_as_uid: int | None
    rule_id: str
    scan_id: str
    persona: Persona
    metadata: dict[str, str] = field(default_factory=dict)


class CommandRejected(ValueError):
    """Generated command was rejected by scope / persona / forbidden checks."""

    def __init__(self, reason: str, *, rule_id: str) -> None:
        super().__init__(f"rule {rule_id}: {reason}")
        self.reason = reason
        self.rule_id = rule_id


@runtime_checkable
class CommandGenerator(Protocol):
    def generate(
        self,
        match: RuleMatch,
        *,
        persona: Persona,
        target_scope_cidrs: list[str],
        scan_id: str,
    ) -> ToolInvocation: ...


# ---------------------------------------------------------------------------
# Concrete implementation
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class DeterministicCommandGenerator:
    """Scope-enforcing, persona-gated command generator.

    Everything is deterministic: given the same inputs it always returns
    the same ``ToolInvocation`` (or the same ``CommandRejected``). No
    clock reads, no randomness, no external I/O.
    """

    registry: ToolRegistry
    persona_engine: PersonaEngine
    settings: Settings
    forbidden_cidrs_extra: tuple[str, ...] = ()

    # -------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------
    def generate(
        self,
        match: RuleMatch,
        *,
        persona: Persona,
        target_scope_cidrs: list[str],
        scan_id: str,
    ) -> ToolInvocation:
        rule = match.rule

        # 1. Persona guard -------------------------------------------------
        if persona not in rule.persona:
            raise CommandRejected(
                f"persona {persona.value!r} not in rule personas {[p.value for p in rule.persona]!r}",
                rule_id=rule.id,
            )
        self.persona_engine.require(persona, phase=rule.phase)

        # 2. Extract the action block --------------------------------------
        action = rule.then.get("action")
        if action != "execute_tool":
            raise CommandRejected(
                f"unsupported action {action!r} (Phase 2 only handles execute_tool)",
                rule_id=rule.id,
            )

        tool_name = rule.then.get("tool")
        if not tool_name:
            raise CommandRejected("missing tool name in `then.tool`", rule_id=rule.id)

        if not self.registry.has(tool_name):
            raise CommandRejected(f"unknown tool: {tool_name!r}", rule_id=rule.id)

        wrapper = self.registry.get(tool_name)

        # 3. Resolve $fact.X references in params --------------------------
        raw_params: dict[str, Any] = rule.then.get("params") or {}
        resolved = {k: _resolve(v, match.bindings) for k, v in raw_params.items()}

        # 4. Scope check — target must be in scope + not forbidden ---------
        target = _as_str(resolved.get("target"))
        if target is None:
            raise CommandRejected("rule produced no `target` param", rule_id=rule.id)

        forbidden = list(self.settings.forbidden_cidrs) + list(self.forbidden_cidrs_extra)
        # If the target carries an IP/CIDR (raw or inside a URL), scope-check
        # the IP. URL with hostname → upstream layer must resolve first.
        scope_check_target = _host_of_target(target)
        if scope_check_target:
            if is_cidr_forbidden(scope_check_target, forbidden):
                raise CommandRejected(
                    f"target {target!r} falls inside forbidden CIDR",
                    rule_id=rule.id,
                )
            if self.settings.strict_scope_enforcement and not is_target_in_scope(
                scope_check_target, target_scope_cidrs
            ):
                raise CommandRejected(
                    f"target {target!r} out of scope "
                    f"(allowed: {target_scope_cidrs})",
                    rule_id=rule.id,
                )
        # Hostnames are resolved upstream; command-gen only sees IPs/URLs.
        # For URL params we still extract the host and scope-check it.

        # 5. Delegate to the wrapper to produce argv ----------------------
        wrapper.validate_params(resolved)
        plan = wrapper.build_invocation(resolved)

        # 5b. Apply per-persona evasion extras --------------------------
        evasion = evasion_for(persona, rule_id=rule.id)
        extras = {
            "nmap":   evasion.nmap_extra,
            "nuclei": evasion.nuclei_extra,
            "ffuf":   evasion.ffuf_extra,
            "httpx":  evasion.httpx_extra,
        }.get(tool_name, ())
        argv_with_evasion = list(plan.argv) + list(extras)

        # 6. Sanitize every argv token ------------------------------------
        safe_argv: list[str] = []
        for tok in argv_with_evasion:
            try:
                safe_argv.append(sanitize_argv_token(str(tok)))
            except ValueError as err:
                raise CommandRejected(
                    f"unsafe argv token {tok!r}: {err}", rule_id=rule.id
                ) from err

        # 7. Assemble the final ``ToolInvocation`` ------------------------
        spec = wrapper.spec
        return ToolInvocation(
            tool_name=spec.name,
            image=spec.image,
            argv=tuple(safe_argv),
            env=dict(plan.env),
            workdir="/home/scanner",
            mounts=(),               # per-exec artefact mount added by executor
            network="aetherforge_targets",
            cap_add=tuple(spec.required_caps),
            cap_drop=("ALL",),
            memory_bytes=spec.default_memory_bytes,
            cpu_shares=self.settings.tool_cpu_shares,
            timeout_seconds=spec.default_timeout_seconds,
            read_only_rootfs=True,
            run_as_uid=spec.default_uid,
            rule_id=rule.id,
            scan_id=scan_id,
            persona=persona,
            metadata={"phase": rule.phase, "priority": str(rule.priority)},
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# A bare reference covering the entire string. Returns the bound value as-is.
_FACT_REF_RE = re.compile(r"^\$[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*$")
# An embedded reference inside a longer string ("$fact.url/FUZZ"). Substituted
# string-style — only safe characters (alnum/.-_:/) survive the argv
# sanitiser later, so injection attempts can't slip through.
_FACT_INTERP_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*)")


def _resolve(value: Any, bindings: dict[str, Any]) -> Any:
    """Recursively resolve ``$fact.X`` references in rule params.

    Whole-string refs ("$fact.url") return the bound value directly.
    Embedded refs ("$fact.url/FUZZ") are interpolated as strings so
    rules can append literal suffixes. ``"$(curl evil)"`` is left
    untouched so the argv sanitiser rejects it.
    """
    if isinstance(value, str):
        if _FACT_REF_RE.match(value):
            parts = value[1:].split(".")
            cursor: Any = bindings
            for p in parts:
                if isinstance(cursor, dict) and p in cursor:
                    cursor = cursor[p]
                else:
                    return None
            return cursor
        if "$" in value and _FACT_INTERP_RE.search(value):
            return _FACT_INTERP_RE.sub(
                lambda m: str(_lookup(m.group(1), bindings) or ""),
                value,
            )
    if isinstance(value, list):
        return [_resolve(v, bindings) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, bindings) for k, v in value.items()}
    return value


def _lookup(path: str, bindings: dict[str, Any]) -> Any:
    cursor: Any = bindings
    for p in path.split("."):
        if isinstance(cursor, dict) and p in cursor:
            cursor = cursor[p]
        else:
            return None
    return cursor


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    # URLs / hostnames arrive as strings; lists get flattened to strings
    # in wrapper-specific ways. We only stringify when it's a simple scalar.
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _looks_like_ip_or_cidr(value: str) -> bool:
    """True if ``value`` is a bare IP or CIDR (NOT a URL containing slashes)."""
    stripped = value.strip()
    if "://" in stripped:
        return False
    if "/" in stripped:
        ip_part, _, mask = stripped.partition("/")
        return bool(mask.isdigit() and all(c.isdigit() or c in ".:" for c in ip_part))
    return bool(stripped) and all(c.isdigit() or c in ".:" for c in stripped)


def _host_of_target(target: str) -> str | None:
    """Extract the host portion of an IP/CIDR/URL — None for hostnames."""
    if "://" in target:
        try:
            host_part = target.split("://", 1)[1].split("/", 1)[0]
            host_part = host_part.split(":", 1)[0]
            return host_part if all(c.isdigit() or c in ".:" for c in host_part) else None
        except IndexError:
            return None
    if _looks_like_ip_or_cidr(target):
        return target
    return None


__all__ = [
    "CommandGenerator",
    "CommandRejected",
    "DeterministicCommandGenerator",
    "ToolInvocation",
]
