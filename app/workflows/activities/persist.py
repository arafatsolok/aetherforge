"""``persist_facts_and_findings`` — parse the artefact and write Facts.

Reads the on-disk artefact (cheap — same node as the executor), invokes
the wrapper's parser, then bulk-inserts ``Fact`` rows + emits a
``Finding`` for every parsed vuln_* fact.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.dialects.postgresql import insert
from temporalio import activity

from app.database import get_session_factory
from app.executor.artifacts import ArtifactStore
from app.kb.msf_modules import msf_module_for_cve
from app.models.enums import Severity
from app.models.fact import Fact
from app.models.finding import Finding
from app.parsers import make_fact
from app.workflows.runtime import get_runtime

# Maps Nuclei severity → our Severity enum.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.INFO,
}


@activity.defn(name="aetherforge.persist.facts_and_findings")
async def persist_facts_and_findings(
    scan_id: int,
    execution_id: int,
    execution_ulid: str,
    iteration: int,
    tool: str,
) -> dict[str, int]:
    """Parse the persisted artefact and write Facts + Findings."""
    runtime = get_runtime()
    store = ArtifactStore(settings=runtime.settings)

    # Read raw stdout/stderr from disk.
    root = store.root() / str(scan_id) / execution_ulid
    stdout_path = root / "stdout"
    stderr_path = root / "stderr"
    exit_path = root / "exit_code"
    stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
    try:
        exit_code = int(exit_path.read_text()) if exit_path.exists() else 0
    except ValueError:
        exit_code = 0

    if not runtime.registry.has(tool):
        return {"facts": 0, "findings": 0}

    wrapper = runtime.registry.get(tool)
    facts = wrapper.parse(
        stdout=stdout, stderr=stderr, exit_code=exit_code,
        scan_id=str(scan_id), iteration=iteration,
    )
    if not facts:
        return {"facts": 0, "findings": 0}

    fact_rows: list[dict[str, Any]] = []
    finding_rows: list[dict[str, Any]] = []

    for f in facts:
        fact_rows.append({
            "scan_id":      scan_id,
            "execution_id": execution_id,
            "fact_type":    f.fact_type,
            "source_tool":  f.source_tool,
            "iteration":    f.iteration,
            "fingerprint":  f.fingerprint,
            "body":         f.body,
        })

        # Auto-emit findings for vuln_* facts (severity carried in body).
        if f.fact_type.startswith("vuln_"):
            severity = _SEVERITY_MAP.get(
                str(f.body.get("severity", "info")).lower(), Severity.INFO,
            )
            cve_ids = f.body.get("cves") or []
            cve_id = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else None
            finding_rows.append({
                "scan_id": scan_id,
                "rule_id": f.body.get("template_id") or f.fact_type,
                "tool": f.source_tool,
                "title": str(f.body.get("name") or f.fact_type)[:512],
                "description": str(f.body.get("description") or "")[:8192],
                "severity": severity.value,
                "cvss_score": f.body.get("cvss_score"),
                "cve_id": cve_id,
                "affected": {"host": f.body.get("host"), "port": f.body.get("port"),
                             "url": f.body.get("url")},
                "evidence": dict(f.body),
                "remediation": "",
                "status": "open",
                "confirmed": False,
            })

    # CVE enrichment — for every vuln_* fact whose body lists CVE IDs we
    # look up known MSF modules and emit a ``cve_match`` fact so
    # exploit-tier rules can fire on it.
    cve_match_rows: list[dict[str, Any]] = []
    for f in facts:
        if not f.fact_type.startswith("vuln_"):
            continue
        for cve_id in (f.body.get("cves") or []):
            if not isinstance(cve_id, str):
                continue
            module = msf_module_for_cve(cve_id)
            if not module:
                continue
            cve_fact = make_fact(
                fact_type="cve_match",
                body={
                    "cve_id":             cve_id,
                    "host":               f.body.get("host"),
                    "port":               f.body.get("port"),
                    "url":                f.body.get("url"),
                    "metasploit_module":  module,
                    "discovered_via":     f.source_tool,
                    "severity":           f.body.get("severity", "info"),
                },
                source_tool="kb",
                scan_id=str(scan_id),
                iteration=iteration,
            )
            cve_match_rows.append({
                "scan_id":      scan_id,
                "execution_id": execution_id,
                "fact_type":    cve_fact.fact_type,
                "source_tool":  cve_fact.source_tool,
                "iteration":    cve_fact.iteration,
                "fingerprint":  cve_fact.fingerprint,
                "body":         cve_fact.body,
            })

    factory = get_session_factory()
    async with factory() as session, session.begin():
        if fact_rows:
            stmt = insert(Fact).values(fact_rows)
            stmt = stmt.on_conflict_do_nothing(
                constraint="uq_facts_scan_fingerprint",
            )
            await session.execute(stmt)
        if cve_match_rows:
            stmt = insert(Fact).values(cve_match_rows)
            stmt = stmt.on_conflict_do_nothing(
                constraint="uq_facts_scan_fingerprint",
            )
            await session.execute(stmt)
        if finding_rows:
            await session.execute(insert(Finding).values(finding_rows))

    return {
        "facts": len(fact_rows) + len(cve_match_rows),
        "findings": len(finding_rows),
    }


__all__ = ["persist_facts_and_findings"]
