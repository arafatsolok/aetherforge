"""Reporter rendering tests — JSON shape + HTML smoke + PDF byte-prefix."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.services.reporter import ScanReporter, ScanReportPayload


def _payload() -> ScanReportPayload:
    return ScanReportPayload(
        scan={
            "id": 1, "ulid": "01ABC", "persona": "gray", "state": "completed",
            "workflow_id": "scan-x", "started_by": "test",
            "started_at": "2026-04-18T03:00:00Z", "finished_at": "2026-04-18T03:00:10Z",
            "iterations": 3, "executions_total": 3,
            "facts_total": 7, "findings_total": 1,
            "terminal_reason": "loop_drained",
        },
        target={
            "id": 2, "slug": "lab", "description": "lab",
            "owner": "qa", "cidrs": ["10.77.0.0/24"],
            "domains": [], "tags": ["demo"], "replica_only": False,
        },
        summary={
            "iterations": 3, "executions_total": 3,
            "facts_total": 7, "findings_total": 1,
            "severity_counts": {"high": 1, "info": 6},
            "fact_types": {"port_open": 1, "host_alive": 6},
            "duration_ms": 10000, "terminal_reason": "loop_drained",
        },
        findings=[{
            "id": 11, "ulid": "01F", "rule_id": "r.test",
            "tool": "nuclei", "title": "Test finding",
            "description": "demo", "severity": "high",
            "cvss_score": 7.5, "cve_id": "CVE-2021-44228",
            "affected": {"host": "10.77.0.5", "port": 443},
            "evidence": {}, "remediation": "patch it", "status": "open",
            "confirmed": False, "triaged_by": None, "triage_notes": "",
            "created_at": "2026-04-18T03:00:05Z",
        }],
        facts_by_type={"port_open": 1, "host_alive": 6},
        audit=[{"sequence": 1, "event": "scan.started", "rule_id": None,
                "persona": "gray", "actor": "test", "payload": {},
                "created_at": "2026-04-18T03:00:00Z"}],
        executions=[],
    )


def _settings() -> Settings:
    # Use the real templates directory so the report template loads.
    repo_root = Path(__file__).resolve().parents[2]
    return Settings().model_copy(update={"templates_dir": repo_root / "templates"})


@pytest.mark.unit
class TestReporter:
    def test_render_json_round_trips(self) -> None:
        r = ScanReporter(_settings())
        payload = _payload()
        out = r.render_json(payload)
        assert out["scan"]["ulid"] == "01ABC"
        assert out["summary"]["findings_total"] == 1
        assert out["findings"][0]["cve_id"] == "CVE-2021-44228"

    def test_render_html_includes_finding_title(self) -> None:
        r = ScanReporter(_settings())
        html = r.render_html(_payload())
        assert "AetherForge Scan Report" in html
        assert "Test finding" in html
        assert "CVE-2021-44228" in html
        assert "loop_drained" in html

    def test_render_html_severity_pill_present(self) -> None:
        r = ScanReporter(_settings())
        html = r.render_html(_payload())
        # Severity pill HTML class shows up
        assert 'class="pill high"' in html or 'pill high' in html


# ---------------------------------------------------------------------------
# M5 — async PDF render with timeout
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestPdfTimeout:
    """A pathological / slow PDF render must surface as PDFRenderTimeout
    rather than hanging the worker forever."""

    @pytest.mark.asyncio
    async def test_render_pdf_async_raises_on_timeout(self, monkeypatch) -> None:
        from app.services.reporter import PDFRenderTimeout, ScanReporter

        r = ScanReporter(_settings())

        # Replace the real sync renderer with one that sleeps past the cap.
        import time
        def _slow(_payload):
            time.sleep(2.0)
            return b"%PDF-1.4 fake"
        monkeypatch.setattr(r, "render_pdf", _slow)

        with pytest.raises(PDFRenderTimeout):
            await r.render_pdf_async(_payload(), timeout=0.05)

    @pytest.mark.asyncio
    async def test_render_pdf_async_fast_path_returns_bytes(
        self, monkeypatch,
    ) -> None:
        from app.services.reporter import ScanReporter
        r = ScanReporter(_settings())
        monkeypatch.setattr(r, "render_pdf",
                            lambda _p: b"%PDF-1.4 stub bytes")
        out = await r.render_pdf_async(_payload(), timeout=2.0)
        assert out == b"%PDF-1.4 stub bytes"
