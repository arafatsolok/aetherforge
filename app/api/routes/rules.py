"""Rule CRUD — DB-backed + live validation."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import SessionDep
from app.core.rule_engine import RuleValidationError, parse_rule_document
from app.core.rule_engine.schema import validate_rule_payload
from app.models.rule import Rule
from app.repositories import RuleRepository
from app.schemas.common import Page, PageMeta
from app.schemas.rule import RuleCreate, RuleRead, RuleValidationResult

router = APIRouter()


@router.get("", response_model=Page[RuleRead], summary="List rules")
async def list_rules(
    session: SessionDep,
    enabled: bool | None = Query(None),
    phase: str | None = Query(None),
    persona: str | None = Query(None, pattern="^(white|gray|black)$"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
) -> Page[RuleRead]:
    repo = RuleRepository(session)
    items, total = await repo.list_(
        enabled=enabled,
        phase=phase,
        persona=persona,
        limit=size,
        offset=(page - 1) * size,
    )
    return Page[RuleRead](
        items=[RuleRead.model_validate(r) for r in items],
        meta=PageMeta(page=page, size=size, total=total, has_next=page * size < total),
    )


@router.post(
    "",
    response_model=RuleRead,
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a rule by (id, version)",
)
async def create_rule(payload: RuleCreate, session: SessionDep) -> RuleRead:
    doc = _to_rule_doc(payload)
    try:
        parse_rule_document(doc)  # re-validate against the same schema as YAMLs
    except RuleValidationError as err:
        raise HTTPException(status_code=422, detail=str(err)) from err

    row = Rule(
        rule_id=payload.rule_id,
        version=payload.version,
        description=payload.description,
        phase=payload.phase.value,
        priority=payload.priority,
        personas=[p.value for p in payload.personas],
        enabled=payload.enabled,
        body=payload.body.model_dump(),
    )
    session.add(row)
    await session.flush()
    await session.refresh(row)
    return RuleRead.model_validate(row)


@router.post("/validate", response_model=RuleValidationResult, summary="Validate without persisting")
async def validate_rule(payload: dict[str, Any]) -> RuleValidationResult:
    issues = validate_rule_payload(payload)
    return RuleValidationResult(
        valid=not issues,
        errors=[f"{i.path}: {i.message}" for i in issues],
        rule_id=str(payload.get("id") or "") or None,
    )


@router.get("/{rule_id}", response_model=RuleRead, summary="Fetch a rule")
async def get_rule(
    rule_id: str, session: SessionDep, version: int | None = Query(None, ge=1)
) -> RuleRead:
    repo = RuleRepository(session)
    row = await repo.get(rule_id, version=version)
    if row is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return RuleRead.model_validate(row)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _to_rule_doc(payload: RuleCreate) -> dict[str, Any]:
    return {
        "id": payload.rule_id,
        "version": payload.version,
        "description": payload.description,
        "phase": payload.phase.value,
        "priority": payload.priority,
        "persona": [p.value for p in payload.personas],
        "enabled": payload.enabled,
        "when": payload.body.when,
        "then": payload.body.then,
        "metadata": payload.body.metadata,
    }
