"""Read-side helpers for the knowledge base."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge_base import CveEntry, NucleiTemplate


@dataclass(slots=True)
class KBLookup:
    session: AsyncSession

    async def cve(self, cve_id: str) -> CveEntry | None:
        return await self.session.get(CveEntry, cve_id)

    async def cves_for_cpe(self, cpe23: str, *, limit: int = 25) -> list[CveEntry]:
        stmt = (
            select(CveEntry)
            .where(CveEntry.cpes.any(cpe23))  # type: ignore[attr-defined]
            .order_by(CveEntry.cvss_score.desc().nullslast())
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def nuclei_templates_for_tag(
        self, tag: str, *, limit: int = 25
    ) -> list[NucleiTemplate]:
        stmt = (
            select(NucleiTemplate)
            .where(NucleiTemplate.tags.any(tag))  # type: ignore[attr-defined]
            .order_by(NucleiTemplate.template_id)
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())


__all__ = ["KBLookup"]
