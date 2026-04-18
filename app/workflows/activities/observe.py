"""``observe_facts`` — read the world state for the current iteration.

Plus ``seed_initial_facts`` — emit the synthetic ``host_alive`` fact for
each scope CIDR/host so the recon rules have something to fire on.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import Any

from sqlalchemy import select
from temporalio import activity

from app.database import get_session_factory
from app.models.fact import Fact
from app.models.target import Target
from app.parsers import make_fact
from app.workflows.data import FactDTO


@activity.defn(name="aetherforge.observe.facts")
async def observe_facts(scan_id: int) -> list[dict[str, Any]]:
    """Return every persisted fact for this scan, oldest-first."""
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(Fact).where(Fact.scan_id == scan_id).order_by(Fact.id)
        rows = (await session.execute(stmt)).scalars().all()
        return [
            dataclasses.asdict(FactDTO(
                fact_type=f.fact_type,
                body=dict(f.body),
                source_tool=f.source_tool,
                iteration=f.iteration,
                fingerprint=f.fingerprint,
            ))
            for f in rows
        ]


@activity.defn(name="aetherforge.observe.seed_initial_facts")
async def seed_initial_facts(scan_id: int, target_id: int) -> int:
    """Emit ``host_alive`` for each /32 inside the target's CIDRs (capped).

    Caps at 256 hosts per CIDR to avoid runaway expansion when an
    operator adds an over-broad scope. Real recon rules then take over.
    """
    factory = get_session_factory()
    async with factory() as session, session.begin():
        target = (
            await session.execute(select(Target).where(Target.id == target_id))
        ).scalar_one()

        emitted = 0
        for cidr in target.cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            for i, host_ip in enumerate(net.hosts()):
                if i >= 256:
                    break
                fact = make_fact(
                    fact_type="host_alive",
                    body={"host": str(host_ip), "status": "seeded"},
                    source_tool="seeder",
                    scan_id=str(scan_id),
                    iteration=0,
                )
                session.add(Fact(
                    scan_id=scan_id,
                    fact_type=fact.fact_type,
                    source_tool=fact.source_tool,
                    iteration=fact.iteration,
                    fingerprint=fact.fingerprint,
                    body=fact.body,
                ))
                emitted += 1

        for domain in target.domains:
            fact = make_fact(
                fact_type="host_alive",
                body={"host": domain, "status": "seeded"},
                source_tool="seeder",
                scan_id=str(scan_id),
                iteration=0,
            )
            session.add(Fact(
                scan_id=scan_id,
                fact_type=fact.fact_type,
                source_tool=fact.source_tool,
                iteration=fact.iteration,
                fingerprint=fact.fingerprint,
                body=fact.body,
            ))
            emitted += 1

        return emitted


__all__ = ["observe_facts", "seed_initial_facts"]
