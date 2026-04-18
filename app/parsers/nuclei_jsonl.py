"""Parse Nuclei JSONL → ``vuln_nuclei`` facts (with CVSS-mapped severity)."""

from __future__ import annotations

from typing import Final

import orjson

from app.core.rule_engine import Fact
from app.logging_config import get_logger
from app.parsers import make_fact

log = get_logger(__name__)

# Severity → CVSS-3 base-score estimate when nuclei doesn't supply one
# directly. Aligned with FIRST.org severity bands.
_SEVERITY_CVSS_DEFAULT: Final[dict[str, float]] = {
    "info":     0.0,
    "unknown":  0.0,
    "low":      3.5,
    "medium":   5.5,
    "high":     7.5,
    "critical": 9.5,
}


def parse_nuclei_jsonl(
    blob: bytes, *, scan_id: str, iteration: int
) -> list[Fact]:
    facts: list[Fact] = []
    bad_lines = 0
    skipped_non_objects = 0

    for line_no, raw_line in enumerate(blob.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            doc = orjson.loads(line)
        except orjson.JSONDecodeError as exc:
            # M4 — silent ``continue`` was masking truncated nuclei
            # output (e.g. when the tool was killed by the sandbox
            # timeout mid-line). Surface every drop so the operator
            # can correlate against executor exit codes.
            bad_lines += 1
            log.warning(
                "parser.nuclei.bad_line",
                scan_id=scan_id, iteration=iteration,
                line_no=line_no, error=str(exc),
                # Snip the bad line to ~120 chars — keeps the structured
                # log small but preserves enough to diagnose.
                snippet=line[:120].decode("utf-8", errors="replace"),
            )
            continue
        if not isinstance(doc, dict):
            skipped_non_objects += 1
            log.warning(
                "parser.nuclei.not_an_object",
                scan_id=scan_id, iteration=iteration,
                line_no=line_no, type=type(doc).__name__,
            )
            continue

        info = doc.get("info") or {}
        severity = str(info.get("severity", "info")).lower()
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]

        cvss = (
            classification.get("cvss-score")
            or classification.get("cvss_score")
            or _SEVERITY_CVSS_DEFAULT.get(severity, 0.0)
        )
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = _SEVERITY_CVSS_DEFAULT.get(severity, 0.0)

        body = {
            "template_id":     doc.get("template-id") or doc.get("templateID") or "",
            "template_path":   doc.get("template-path") or "",
            "name":            info.get("name", ""),
            "description":     info.get("description", ""),
            "severity":        severity,
            "cvss_score":      cvss,
            "cvss_vector":     classification.get("cvss-metrics", ""),
            "cwe":             classification.get("cwe-id") or [],
            "tags":            info.get("tags") or [],
            "cves":            cve_ids,
            "host":            doc.get("host", ""),
            "port":            _extract_port(doc),
            "url":             doc.get("matched-at") or doc.get("url") or "",
            "matcher_name":    doc.get("matcher-name", ""),
            "extracted_results": doc.get("extracted-results") or [],
            "reference":       info.get("reference") or [],
        }
        facts.append(
            make_fact(
                fact_type="vuln_nuclei",
                body=body,
                source_tool="nuclei",
                scan_id=scan_id,
                iteration=iteration,
            )
        )

    if bad_lines or skipped_non_objects:
        log.warning(
            "parser.nuclei.summary",
            scan_id=scan_id, iteration=iteration,
            facts_emitted=len(facts),
            bad_lines=bad_lines,
            non_object_lines=skipped_non_objects,
        )
    return facts


def _extract_port(doc: dict[str, object]) -> int | None:
    p = doc.get("port")
    if isinstance(p, int):
        return p
    if isinstance(p, str) and p.isdigit():
        return int(p)
    url = doc.get("matched-at") or doc.get("url")
    if isinstance(url, str) and "://" in url:
        try:
            host_part = url.split("://", 1)[1].split("/", 1)[0]
            if ":" in host_part:
                return int(host_part.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            pass
    return None


__all__ = ["parse_nuclei_jsonl"]
