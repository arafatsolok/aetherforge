"""Target CRUD — DB-backed."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import SessionDep
from app.models.target import Target
from app.repositories import TargetRepository
from app.schemas.common import Page, PageMeta
from app.schemas.target import TargetCreate, TargetRead, TargetUpdate

router = APIRouter()


@router.get("", response_model=Page[TargetRead], summary="List targets")
async def list_targets(
    session: SessionDep,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
) -> Page[TargetRead]:
    repo = TargetRepository(session)
    items, total = await repo.list_(limit=size, offset=(page - 1) * size)
    return Page[TargetRead](
        items=[TargetRead.model_validate(t) for t in items],
        meta=PageMeta(page=page, size=size, total=total, has_next=page * size < total),
    )


@router.post(
    "",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a target",
)
async def create_target(payload: TargetCreate, session: SessionDep) -> TargetRead:
    repo = TargetRepository(session)
    if await repo.get_by_slug(payload.slug) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"target slug {payload.slug!r} already exists",
        )
    entity = Target(
        slug=payload.slug,
        description=payload.description,
        owner=payload.owner,
        cidrs=list(payload.cidrs),
        domains=list(payload.domains),
        allowed_personas=[p.value for p in payload.allowed_personas],
        tags=list(payload.tags),
        notes=payload.notes,
        meta=dict(payload.meta),
        active=payload.active,
        replica_only=payload.replica_only,
    )
    created = await repo.create(entity)
    return TargetRead.model_validate(created)


@router.get("/{target_id}", response_model=TargetRead, summary="Fetch a target")
async def get_target(target_id: int, session: SessionDep) -> TargetRead:
    repo = TargetRepository(session)
    target = await repo.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    return TargetRead.model_validate(target)


@router.get("/slug/{slug}", response_model=TargetRead, summary="Fetch by slug")
async def get_target_by_slug(slug: str, session: SessionDep) -> TargetRead:
    repo = TargetRepository(session)
    target = await repo.get_by_slug(slug)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    return TargetRead.model_validate(target)


@router.patch("/{target_id}", response_model=TargetRead, summary="Partial update")
async def patch_target(
    target_id: int, payload: TargetUpdate, session: SessionDep
) -> TargetRead:
    repo = TargetRepository(session)
    target = await repo.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")

    updates = payload.model_dump(exclude_unset=True)
    if "allowed_personas" in updates and updates["allowed_personas"] is not None:
        updates["allowed_personas"] = [p.value for p in updates["allowed_personas"]]
    updated = await repo.update(target, **updates)
    return TargetRead.model_validate(updated)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, session: SessionDep) -> None:
    repo = TargetRepository(session)
    target = await repo.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    await repo.delete(target)
