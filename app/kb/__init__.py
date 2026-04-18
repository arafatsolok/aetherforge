"""Knowledge base — CVE / CPE / Nuclei template catalogue.

Read-only at runtime. Seeded by ``scripts/seed_knowledge_base.py``.
"""

from __future__ import annotations

from app.kb.loader import (
    KBSeedResult,
    seed_builtin_catalogue,
    seed_cpes,
    seed_cves,
    seed_nuclei_templates,
)
from app.kb.lookup import KBLookup

__all__ = [
    "KBLookup",
    "KBSeedResult",
    "seed_builtin_catalogue",
    "seed_cpes",
    "seed_cves",
    "seed_nuclei_templates",
]
