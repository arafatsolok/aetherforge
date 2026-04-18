"""Unit tests for subfinder parser (handles both JSON + plain modes)."""

from __future__ import annotations

import pytest

from app.parsers.subfinder import parse_subfinder


@pytest.mark.unit
class TestSubfinderParser:
    def test_json_mode(self) -> None:
        blob = (
            b'{"host":"a.example.test","source":"crtsh"}\n'
            b'{"host":"b.example.test","source":"hackertarget"}\n'
        )
        facts = parse_subfinder(blob, scan_id="s1", iteration=0)
        assert len(facts) == 2
        assert {f.body["host"] for f in facts} == {"a.example.test", "b.example.test"}

    def test_plain_mode(self) -> None:
        blob = b"a.example.test\nb.example.test\nc.example.test\n"
        facts = parse_subfinder(blob, scan_id="s1", iteration=0)
        assert len(facts) == 3
        for f in facts:
            assert f.fact_type == "subdomain"

    def test_dedupes_by_host(self) -> None:
        blob = b"a.example.test\na.example.test\nb.example.test\n"
        facts = parse_subfinder(blob, scan_id="s1", iteration=0)
        assert len(facts) == 2

    def test_empty(self) -> None:
        assert parse_subfinder(b"", scan_id="s1", iteration=0) == []
