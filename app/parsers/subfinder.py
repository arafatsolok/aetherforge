"""Parse subfinder output → ``subdomain`` facts.

subfinder with ``-json`` emits one JSON doc per line; with ``-silent``
plain mode, one hostname per line. Handle both — AND reject anything
that looks like a shell error (leading ``/``, spaces, or
``open ...: no such file``), which is what leaks when subfinder
failed to read its config file.
"""

from __future__ import annotations

import re

import orjson

from app.core.rule_engine import Fact
from app.logging_config import get_logger
from app.parsers import make_fact

log = get_logger(__name__)

# RFC 1123 hostname — labels of [a-z0-9-] joined by dots, 1-253 chars
# total. Case-insensitive. Used as the final sanity gate so lines like
# "open /home/scanner/.config/subfinder/config.yaml: no such file..."
# never get emitted as a fake subdomain.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)


def _is_valid_hostname(s: str) -> bool:
    return bool(s) and bool(_HOSTNAME_RE.match(s))


def parse_subfinder(
    blob: bytes, *, scan_id: str, iteration: int
) -> list[Fact]:
    facts: list[Fact] = []
    seen: set[str] = set()
    dropped_noise = 0

    for raw in blob.splitlines():
        line = raw.strip()
        if not line:
            continue

        host: str | None = None
        source: str | None = None

        # Prefer JSON (the `-json` flag).
        try:
            doc = orjson.loads(line)
            if isinstance(doc, dict):
                host = doc.get("host") or doc.get("name")
                source = doc.get("source")
        except orjson.JSONDecodeError:
            host = line.decode("utf-8", errors="replace") \
                if isinstance(line, bytes) else str(line)

        if not host:
            continue
        # Reject anything that isn't a well-formed hostname. Previously
        # any non-JSON line was emitted as a fact, so subfinder's error
        # messages became fake "subdomains" and then downstream rules
        # (e.g. r.recon.dns.a_record) fed them to httpx as URLs.
        if not _is_valid_hostname(host):
            dropped_noise += 1
            log.debug(
                "parser.subfinder.skip_non_hostname",
                scan_id=scan_id, iteration=iteration,
                snippet=host[:120],
            )
            continue
        if host in seen:
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

    if dropped_noise:
        log.warning(
            "parser.subfinder.noise_dropped",
            scan_id=scan_id, iteration=iteration,
            dropped=dropped_noise, emitted=len(facts),
        )
    return facts


__all__ = ["parse_subfinder"]
