"""Unit tests for the knowledge-base built-in catalogue."""

from __future__ import annotations

import pytest

from app.kb import builtin


@pytest.mark.unit
class TestBuiltin:
    def test_cve_ids_unique(self) -> None:
        ids = [c["cve_id"] for c in builtin.BUILTIN_CVES]
        assert len(ids) == len(set(ids))

    def test_cve_shape(self) -> None:
        for c in builtin.BUILTIN_CVES:
            assert c["cve_id"].startswith("CVE-")
            assert c["severity"] in {"info", "low", "medium", "high", "critical"}
            assert 0.0 <= c["cvss_score"] <= 10.0
            assert c["cpes"]
            assert c["references"]

    def test_cpes_parse(self) -> None:
        for row in builtin.BUILTIN_CPES:
            parts = row["cpe23"].split(":")
            assert parts[0] == "cpe" and parts[1] == "2.3"
            assert row["vendor"] and row["product"]

    def test_nuclei_shape(self) -> None:
        for t in builtin.BUILTIN_NUCLEI_TEMPLATES:
            assert t["template_id"]
            assert t["severity"] in {"info", "low", "medium", "high", "critical"}
            assert isinstance(t["tags"], list)
            assert isinstance(t["cves"], list)

    def test_log4shell_in_catalogue(self) -> None:
        hit = [c for c in builtin.BUILTIN_CVES if c["cve_id"] == "CVE-2021-44228"]
        assert hit
        assert hit[0]["severity"] == "critical"
