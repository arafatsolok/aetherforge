"""Parse subfinder output → ``subdomain`` facts.

subfinder with ``-json`` emits one JSON doc per line; with ``-silent``
plain mode, one hostname per line. Handle both.
"""

from __future__ import annotations

import orjson

from app.core.rule_engine import Fact
from app.parsers import make_fact


def parse_subfinder(
    blob: bytes, *, scan_id: str, iteration: int
) -> list[Fact]:
    facts: list[Fact] = []
    seen: set[str] = set()

    for raw in blob.splitlines():
        line = raw.strip()
        if not line:
            continue

        host: str | None = None
        source: str | None = None

        # JSON first
        try:
            doc = orjson.loads(line)
            if isinstance(doc, dict):
                host = doc.get("host") or doc.get("name")
                source = doc.get("source")
        except orjson.JSONDecodeError:
            host = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else str(line)

        if not host or host in seen:
            continue
        seen.add(host)

        facts.append(
            make_fact(
                fact_type="subdomain",
                body={"host": host, "source": source or "subfinder"},
                source_tool="subfinder",
                scan_id=scan_id,
                iteration=iteration,
            )
        )
    return facts


__all__ = ["parse_subfinder"]
