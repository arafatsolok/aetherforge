"""CRUD for Rule, with bulk upsert from the YAML loader."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule import Rule


@dataclass(slots=True)
class RuleRepository:
    session: AsyncSession

    async def list_(
        self,
        *,
        enabled: bool | None = None,
        phase: str | None = None,
        persona: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[Rule], int]:
        base = select(Rule)
        if enabled is not None:
            base = base.where(Rule.enabled == enabled)
        if phase is not None:
            base = base.where(Rule.phase == phase)
        if persona is not None:
            base = base.where(Rule.personas.any(persona))  # type: ignore[attr-defined]

        total = (await self.session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
        rows = (
            await self.session.execute(
                base.order_by(Rule.priority.desc(), Rule.rule_id).limit(limit).offset(offset)
            )
        ).scalars().all()
        return list(rows), int(total)

    async def get(self, rule_id: str, version: int | None = None) -> Rule | None:
        stmt = select(Rule).where(Rule.rule_id == rule_id)
        if version is not None:
            stmt = stmt.where(Rule.version == version)
        stmt = stmt.order_by(Rule.version.desc()).limit(1)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def all_enabled(self) -> list[Rule]:
        stmt = select(Rule).where(Rule.enabled.is_(True))
        return list((await self.session.execute(stmt)).scalars().all())

    async def upsert_many(self, rows: list[dict[str, Any]]) -> int:
        """Bulk upsert by (rule_id, version). Used by the YAML loader."""
        if not rows:
            return 0
        stmt = insert(Rule).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["rule_id", "version"],
            set_={
                "description": stmt.excluded.description,
                "phase":       stmt.excluded.phase,
                "priority":    stmt.excluded.priority,
                "personas":    stmt.excluded.personas,
                "enabled":     stmt.excluded.enabled,
                "source_path": stmt.excluded.source_path,
                "source_sha256": stmt.excluded.source_sha256,
                "body":        stmt.excluded.body,
                "updated_at":  stmt.excluded.updated_at,
            },
        )
        await self.session.execute(stmt)
        await self.session.flush()
        return len(rows)


__all__ = ["RuleRepository"]
