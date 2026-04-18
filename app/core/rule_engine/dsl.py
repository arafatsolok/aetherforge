"""Rule DSL evaluator.

Inputs:
  * A parsed ``when:`` predicate (dict straight from YAML)
  * A list of ``Fact``s representing current world state

Output:
  * A list of ``PredicateMatch`` — each match carries the triggering fact
    and the ``$fact.X`` variable bindings. Empty list means no match.

Semantics (all deterministic, no I/O):
  ``fact_type: X``   → yields one match per existing fact with that type;
                       ``$fact`` binds to that fact's body.
  ``all: [a, b, c]`` → cross-product of child matches, with bindings
                       merged. Variable bindings must be consistent
                       across children; incompatible combos are pruned.
  ``any: [a, b, c]`` → union of child matches.
  ``not_fact: {…}``  → matches ONCE (producing a null-fact match) iff no
                       fact satisfies the inner predicate. When nested
                       inside ``all`` under an outer ``fact_type``, the
                       ``where`` clause may reference ``$fact`` values
                       bound by that outer match.
  ``where: {…}``     → attached to ``fact_type`` / ``not_fact`` — filters
                       facts whose body matches every key/value pair.
                       Values may be scalars or ``$fact.X`` references or
                       op dicts like ``{in: [...]}``, ``{matches: '^ssh'}``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.core.rule_engine.contract import Fact


class DslError(ValueError):
    """Raised for malformed DSL not caught by the JSONSchema layer."""


@dataclass(frozen=True, slots=True)
class PredicateMatch:
    """One consistent assignment of facts to predicate variables.

    ``bindings`` includes ``$fact``, plus any scoped bindings introduced
    by parent predicates (e.g. an outer ``fact_type`` that set
    ``$fact.port``).
    """

    triggering_fact: Fact | None   # None for `not_fact`-only matches
    bindings: dict[str, Any]


@dataclass(slots=True)
class EvalContext:
    """Everything ``evaluate_when`` needs beyond the predicate itself."""

    facts: list[Fact]
    # Variable bindings inherited from the enclosing scope. The top-level
    # caller passes {} and the evaluator recurses with merged copies.
    bindings: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def evaluate_when(when: dict[str, Any], facts: list[Fact]) -> list[PredicateMatch]:
    """Evaluate a rule's ``when:`` block against the current fact set."""
    ctx = EvalContext(facts=facts)
    return _eval_predicate(when, ctx)


# ---------------------------------------------------------------------------
# Recursive dispatch
# ---------------------------------------------------------------------------
def _eval_predicate(pred: dict[str, Any], ctx: EvalContext) -> list[PredicateMatch]:
    if not isinstance(pred, dict) or not pred:
        raise DslError(f"predicate must be a non-empty dict, got {type(pred).__name__}")

    if "all" in pred:
        return _eval_all(pred["all"], ctx)
    if "any" in pred:
        return _eval_any(pred["any"], ctx)
    if "fact_type" in pred:
        return _eval_fact_type(pred["fact_type"], pred.get("where"), ctx)
    if "not_fact" in pred:
        return _eval_not_fact(pred["not_fact"], ctx)

    raise DslError(f"unknown predicate shape: keys={sorted(pred)}")


# ---------------------------------------------------------------------------
# Combinators
# ---------------------------------------------------------------------------
def _eval_all(children: list[dict[str, Any]], ctx: EvalContext) -> list[PredicateMatch]:
    if not children:
        raise DslError("`all` requires at least one predicate")

    # Fold: start with the first child's matches, then for each subsequent
    # child, combine by cross-product + binding-consistency check.
    current: list[PredicateMatch] = _eval_predicate(children[0], ctx)

    for child in children[1:]:
        next_matches: list[PredicateMatch] = []
        for left in current:
            child_ctx = EvalContext(facts=ctx.facts, bindings=dict(left.bindings))
            for right in _eval_predicate(child, child_ctx):
                merged = _merge_bindings(left.bindings, right.bindings)
                if merged is None:
                    continue  # incompatible -> prune
                next_matches.append(
                    PredicateMatch(
                        triggering_fact=right.triggering_fact or left.triggering_fact,
                        bindings=merged,
                    )
                )
        current = next_matches
        if not current:
            return []
    return current


def _eval_any(children: list[dict[str, Any]], ctx: EvalContext) -> list[PredicateMatch]:
    out: list[PredicateMatch] = []
    for child in children:
        out.extend(_eval_predicate(child, ctx))
    return _dedupe(out)


# ---------------------------------------------------------------------------
# Leaf predicates
# ---------------------------------------------------------------------------
def _eval_fact_type(
    fact_type: str, where: dict[str, Any] | None, ctx: EvalContext
) -> list[PredicateMatch]:
    """Match facts of ``fact_type``.

    Binding semantics: the FIRST ``fact_type`` encountered in any match
    path binds ``$fact``. Subsequent ``fact_type`` predicates (e.g. in an
    enclosing ``all:``) correlate via ``where:`` clauses that reference
    ``$fact.X``; they never rebind ``$fact`` — the outer fact is the
    triggering fact for the whole rule.
    """
    matches: list[PredicateMatch] = []
    inherited_fact = "fact" in ctx.bindings

    for f in ctx.facts:
        if f.fact_type != fact_type:
            continue
        if where and not _where_matches(where, f.body, ctx.bindings):
            continue

        new_bindings = dict(ctx.bindings)
        if not inherited_fact:
            new_bindings["fact"] = f.body
            new_bindings["source_tool"] = f.source_tool

        matches.append(PredicateMatch(triggering_fact=f, bindings=new_bindings))
    return matches


def _eval_not_fact(spec: dict[str, Any], ctx: EvalContext) -> list[PredicateMatch]:
    fact_type = spec.get("fact_type")
    if not fact_type:
        raise DslError("`not_fact` requires `fact_type`")
    where = spec.get("where")

    for f in ctx.facts:
        if f.fact_type != fact_type:
            continue
        if where is None or _where_matches(where, f.body, ctx.bindings):
            # Matching fact exists -> predicate is FALSE -> no matches.
            return []

    # No matching fact exists -> predicate is TRUE. Produce exactly one
    # match carrying the inherited bindings (no new $fact binding).
    return [PredicateMatch(triggering_fact=None, bindings=dict(ctx.bindings))]


# ---------------------------------------------------------------------------
# `where:` clause
# ---------------------------------------------------------------------------
def _where_matches(
    where: dict[str, Any], body: dict[str, Any], bindings: dict[str, Any]
) -> bool:
    for key, expected in where.items():
        actual = body.get(key)
        if not _value_matches(expected, actual, bindings):
            return False
    return True


def _value_matches(expected: Any, actual: Any, bindings: dict[str, Any]) -> bool:
    # Scalar with $fact.X reference resolution
    if isinstance(expected, str) and expected.startswith("$"):
        expected = _resolve_ref(expected, bindings)
        return expected == actual

    # Operator dict: {eq|ne|in|contains|matches|gt|lt|gte|lte: value}
    if isinstance(expected, dict) and len(expected) == 1:
        (op, val), = expected.items()
        if isinstance(val, str) and val.startswith("$"):
            val = _resolve_ref(val, bindings)
        return _apply_op(op, actual, val)

    # Scalar literal
    return expected == actual


def _apply_op(op: str, actual: Any, val: Any) -> bool:
    try:
        match op:
            case "eq":       return actual == val
            case "ne":       return actual != val
            case "in":       return actual in val
            case "contains": return isinstance(actual, str) and isinstance(val, str) and val in actual
            case "matches":  return isinstance(actual, str) and isinstance(val, str) and re.search(val, actual) is not None
            case "gt":       return actual is not None and actual > val
            case "lt":       return actual is not None and actual < val
            case "gte":      return actual is not None and actual >= val
            case "lte":      return actual is not None and actual <= val
            case _:          raise DslError(f"unknown where-op: {op!r}")
    except TypeError:
        # Incompatible comparison types count as non-match, not a crash.
        return False


def _resolve_ref(ref: str, bindings: dict[str, Any]) -> Any:
    """Resolve `$fact.port` against the current bindings. Unknown → None."""
    if not ref.startswith("$"):
        return ref
    parts = ref[1:].split(".")
    cursor: Any = bindings
    for p in parts:
        if isinstance(cursor, dict) and p in cursor:
            cursor = cursor[p]
        else:
            return None
    return cursor


# ---------------------------------------------------------------------------
# Bookkeeping
# ---------------------------------------------------------------------------
def _merge_bindings(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any] | None:
    """Merge two binding dicts; return None on incompatible overlap."""
    out = dict(a)
    for k, v in b.items():
        if k in out and out[k] != v:
            return None
        out[k] = v
    return out


def _dedupe(matches: list[PredicateMatch]) -> list[PredicateMatch]:
    seen: set[tuple[int | None, Any]] = set()
    out: list[PredicateMatch] = []
    for m in matches:
        key_id = id(m.triggering_fact) if m.triggering_fact else None
        key_b = _freeze(m.bindings)     # already a canonical nested tuple
        if (key_id, key_b) in seen:
            continue
        seen.add((key_id, key_b))
        out.append(m)
    return out


def _freeze(v: Any) -> Any:
    if isinstance(v, dict):
        return tuple(sorted((k, _freeze(vv)) for k, vv in v.items()))
    if isinstance(v, list):
        return tuple(_freeze(x) for x in v)
    return v


__all__ = ["DslError", "EvalContext", "PredicateMatch", "evaluate_when"]
