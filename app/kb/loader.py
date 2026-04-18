"""Bulk KB seeders.

Accepts any of:
  * NVD CVE 1.1 JSON feed
  * CPE dictionary XML / JSON
  * Nuclei template tree (walk of .yaml files)

For offline operation we ship a small built-in catalogue (in
``app.kb.builtin``) with ~30 high-profile CVEs + common CPEs + a
handful of Nuclei templates. ``seed_builtin_catalogue`` seeds exactly
those. Operators replace it via the full seeders for production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.kb import builtin
from app.models.knowledge_base import CpeEntry, CveEntry, NucleiTemplate


@dataclass(frozen=True, slots=True)
class KBSeedResult:
    cves: int
    cpes: int
    nuclei: int

    def total(self) -> int:
        return self.cves + self.cpes + self.nuclei


async def seed_cves(session: AsyncSession, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    stmt = insert(CveEntry).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["cve_id"],
        set_={c: stmt.excluded[c] for c in (
            "published", "last_modified", "summary", "severity",
            "cvss_score", "cvss_vector", "cpes", "references", "raw",
            "updated_at",
        )},
    )
    await session.execute(stmt)
    await session.flush()
    return len(rows)


async def seed_cpes(session: AsyncSession, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    stmt = insert(CpeEntry).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["cpe23"],
        set_={c: stmt.excluded[c] for c in ("vendor", "product", "version", "title", "updated_at")},
    )
    await session.execute(stmt)
    await session.flush()
    return len(rows)


async def seed_nuclei_templates(
    session: AsyncSession, rows: list[dict[str, Any]]
) -> int:
    if not rows:
        return 0
    stmt = insert(NucleiTemplate).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["template_id"],
        set_={c: stmt.excluded[c] for c in (
            "name", "severity", "author", "description",
            "tags", "cves", "raw", "updated_at",
        )},
    )
    await session.execute(stmt)
    await session.flush()
    return len(rows)


async def seed_builtin_catalogue(session: AsyncSession) -> KBSeedResult:
    """Seed the small built-in catalogue that ships with AetherForge."""
    cves = await seed_cves(session, builtin.BUILTIN_CVES)
    cpes = await seed_cpes(session, builtin.BUILTIN_CPES)
    nuclei = await seed_nuclei_templates(session, builtin.BUILTIN_NUCLEI_TEMPLATES)
    return KBSeedResult(cves=cves, cpes=cpes, nuclei=nuclei)


__all__ = [
    "KBSeedResult",
    "seed_builtin_catalogue",
    "seed_cpes",
    "seed_cves",
    "seed_nuclei_templates",
]
