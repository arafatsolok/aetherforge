"""CRUD for Target."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.target import Target


@dataclass(slots=True)
class TargetRepository:
    session: AsyncSession

    async def list_(self, *, limit: int = 50, offset: int = 0) -> tuple[list[Target], int]:
        total_stmt = select(func.count()).select_from(Target)
        total = (await self.session.execute(total_stmt)).scalar_one()
        stmt = select(Target).order_by(Target.id.desc()).limit(limit).offset(offset)
        rows = (await self.session.execute(stmt)).scalars().all()
        return list(rows), int(total)

    async def get(self, target_id: int) -> Target | None:
        return await self.session.get(Target, target_id)

    async def get_by_slug(self, slug: str) -> Target | None:
        stmt = select(Target).where(Target.slug == slug).limit(1)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def get_by_ulid(self, ulid_value: str) -> Target | None:
        stmt = select(Target).where(Target.ulid == ulid_value).limit(1)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def create(self, target: Target) -> Target:
        self.session.add(target)
        await self.session.flush()
        await self.session.refresh(target)
        return target

    async def update(self, target: Target, **fields: object) -> Target:
        for k, v in fields.items():
            if v is not None:
                setattr(target, k, v)
        self.session.add(target)
        await self.session.flush()
        await self.session.refresh(target)
        return target

    async def delete(self, target: Target) -> None:
        await self.session.delete(target)
        await self.session.flush()


__all__ = ["TargetRepository"]
