"""Generic text-output parsers for tools without machine-readable output.

These produce loosely-typed ``vuln_custom`` facts — the finding-builder
in Phase 6 will map them to structured findings via per-tool rules.
"""

from __future__ import annotations

import re

from app.core.rule_engine import Fact
from app.parsers import make_fact

# sqlmap stamps each discovery with a line like:
#   [11:58:41] [INFO] the back-end DBMS is MySQL
# and:
#   [11:58:41] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
# we only pluck the "confirmed ... injectable" ones.
_SQLMAP_INJECTION_RE = re.compile(
    rb"Parameter[:\s]+'(?P<param>[^']+)'.*?is vulnerable\.", re.IGNORECASE | re.DOTALL,
)


def parse_sqlmap_text(
    stdout: bytes, *, scan_id: str, iteration: int, target_url: str,
) -> list[Fact]:
    facts: list[Fact] = []
    for match in _SQLMAP_INJECTION_RE.finditer(stdout):
        param = match.group("param").decode("utf-8", errors="replace")
        facts.append(
            make_fact(
                fact_type="vuln_custom",
                body={
                    "tool": "sqlmap",
                    "url": target_url,
                    "parameter": param,
                    "kind": "sqli",
                    "confirmed_sqli": True,
                },
                source_tool="sqlmap",
                scan_id=scan_id,
                iteration=iteration,
            )
        )
    return facts


def parse_nikto_text(
    stdout: bytes, *, scan_id: str, iteration: int, target_url: str,
) -> list[Fact]:
    """Nikto emits ``+ OSVDB-...: message`` lines per finding."""
    facts: list[Fact] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line.startswith(b"+ "):
            continue
        body = {
            "tool": "nikto",
            "url": target_url,
            "message": line[2:].decode("utf-8", errors="replace"),
        }
        facts.append(
            make_fact(
                fact_type="vuln_custom",
                body=body,
                source_tool="nikto",
                scan_id=scan_id,
                iteration=iteration,
            )
        )
    return facts


__all__ = ["parse_nikto_text", "parse_sqlmap_text"]
