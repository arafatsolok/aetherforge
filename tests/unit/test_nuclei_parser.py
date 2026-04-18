"""Unit tests for the nuclei JSONL parser."""

from __future__ import annotations

import pytest

from app.parsers.nuclei_jsonl import parse_nuclei_jsonl

NUCLEI_BLOB = (
    b'{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell",'
    b'"severity":"critical","tags":["cve","rce","oast","log4j"],'
    b'"classification":{"cve-id":["CVE-2021-44228"]}},'
    b'"host":"10.77.10.5","port":"8080","matched-at":"http://10.77.10.5:8080/api"}\n'
    b'{"template-id":"ssh-auth-methods","info":{"name":"SSH auth methods",'
    b'"severity":"info","tags":["ssh"]},"host":"10.77.10.5","port":22,'
    b'"matched-at":"10.77.10.5:22"}\n'
)


@pytest.mark.unit
class TestNucleiParser:
    def test_returns_one_fact_per_line(self) -> None:
        facts = parse_nuclei_jsonl(NUCLEI_BLOB, scan_id="s1", iteration=0)
        assert len(facts) == 2
        for f in facts:
            assert f.fact_type == "vuln_nuclei"

    def test_log4shell_details(self) -> None:
        facts = parse_nuclei_jsonl(NUCLEI_BLOB, scan_id="s1", iteration=0)
        log4 = facts[0]
        assert log4.body["severity"] == "critical"
        assert log4.body["cves"] == ["CVE-2021-44228"]
        assert log4.body["port"] == 8080
        assert log4.body["url"].startswith("http://10.77.10.5:8080")

    def test_port_extraction_from_url(self) -> None:
        blob = (
            b'{"template-id":"x","info":{"severity":"low"},'
            b'"host":"1.2.3.4","matched-at":"http://1.2.3.4:9443/path"}'
        )
        facts = parse_nuclei_jsonl(blob, scan_id="s1", iteration=0)
        assert facts[0].body["port"] == 9443

    def test_malformed_line_skipped_and_logged(self, monkeypatch) -> None:
        """M4 — bad lines are skipped AND logged so silent drops can no
        longer mask truncated nuclei output."""
        from app.parsers import nuclei_jsonl as mod

        events: list[tuple] = []
        monkeypatch.setattr(mod.log, "warning",
                            lambda evt, **kw: events.append((evt, kw)))

        blob = b"{not-json-at-all}\n" + NUCLEI_BLOB
        facts = parse_nuclei_jsonl(blob, scan_id="s1", iteration=0)
        # Same 2 facts — bad line is dropped
        assert len(facts) == 2
        # AND the drop emitted a structured warning + a summary
        names = [e[0] for e in events]
        assert "parser.nuclei.bad_line" in names, names
        assert "parser.nuclei.summary" in names, names
        # The bad-line event must include the offending snippet for triage.
        bad = next(e for e in events if e[0] == "parser.nuclei.bad_line")
        assert "snippet" in bad[1]
        assert bad[1]["scan_id"] == "s1"
        assert bad[1]["line_no"] == 1

    def test_non_dict_top_level_logged(self, monkeypatch) -> None:
        """A JSON line that's an array/string/etc must also be flagged."""
        from app.parsers import nuclei_jsonl as mod
        events: list[tuple] = []
        monkeypatch.setattr(mod.log, "warning",
                            lambda evt, **kw: events.append((evt, kw)))

        blob = b'["just", "an", "array"]\n' + NUCLEI_BLOB
        facts = parse_nuclei_jsonl(blob, scan_id="s2", iteration=3)
        assert len(facts) == 2
        assert any(e[0] == "parser.nuclei.not_an_object" for e in events)

    def test_empty_blob_returns_nothing(self) -> None:
        assert parse_nuclei_jsonl(b"", scan_id="s1", iteration=0) == []

    def test_cvss_default_for_critical(self) -> None:
        blob = b'{"template-id":"x","info":{"severity":"critical"},"host":"a","matched-at":"a"}'
        f = parse_nuclei_jsonl(blob, scan_id="s1", iteration=0)[0]
        assert f.body["cvss_score"] == 9.5
        assert f.body["severity"] == "critical"

    def test_cvss_default_for_info(self) -> None:
        blob = b'{"template-id":"x","info":{"severity":"info"},"host":"a","matched-at":"a"}'
        f = parse_nuclei_jsonl(blob, scan_id="s1", iteration=0)[0]
        assert f.body["cvss_score"] == 0.0

    def test_template_supplied_cvss_wins(self) -> None:
        blob = (
            b'{"template-id":"x","info":{"severity":"medium",'
            b'"classification":{"cvss-score":7.2}},"host":"a","matched-at":"a"}'
        )
        f = parse_nuclei_jsonl(blob, scan_id="s1", iteration=0)[0]
        assert f.body["cvss_score"] == 7.2
