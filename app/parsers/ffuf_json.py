"""Parse ffuf JSON → ``web_endpoint`` facts."""

from __future__ import annotations

import orjson

from app.core.rule_engine import Fact
from app.parsers import make_fact


def parse_ffuf_json(
    blob: bytes, *, scan_id: str, iteration: int
) -> list[Fact]:
    facts: list[Fact] = []
    try:
        doc = orjson.loads(blob)
    except orjson.JSONDecodeError:
        return facts

    for result in doc.get("results", []):
        url = result.get("url") or ""
        facts.append(
            make_fact(
                fact_type="web_endpoint",
                body={
                    "url": url,
                    "host": result.get("host", ""),
                    "status": result.get("status"),
                    "length": result.get("length"),
                    "words": result.get("words"),
                    "lines": result.get("lines"),
                    "content_type": result.get("content-type", ""),
                    "input": result.get("input", {}),
                },
                source_tool="ffuf",
                scan_id=scan_id,
                iteration=iteration,
            )
        )
    return facts


__all__ = ["parse_ffuf_json"]
