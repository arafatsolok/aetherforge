"""Unit tests for the httpx JSONL parser."""

from __future__ import annotations

import pytest

from app.parsers.httpx_jsonl import parse_httpx_jsonl

HTTPX_BLOB = (
    b'{"url":"https://lab.example.test/","host":"lab.example.test",'
    b'"port":"443","status_code":200,"title":"Lab replica","webserver":"nginx",'
    b'"tech":["nginx","php"],"scheme":"https",'
    b'"tls":{"issuer_common_name":"Lets Encrypt R3","tls_version":"TLSv1.3"},'
    b'"a":["10.77.10.5"]}\n'
)


@pytest.mark.unit
class TestHttpxParser:
    def test_emits_http_tls_dns_and_banner_facts(self) -> None:
        facts = parse_httpx_jsonl(HTTPX_BLOB, scan_id="s1", iteration=0)
        kinds = sorted(f.fact_type for f in facts)
        # http_response + tls_cert + dns_record + service_banner (from tech)
        assert kinds == ["dns_record", "http_response", "service_banner", "tls_cert"]

    def test_http_body_fields(self) -> None:
        facts = parse_httpx_jsonl(HTTPX_BLOB, scan_id="s1", iteration=0)
        http_fact = next(f for f in facts if f.fact_type == "http_response")
        assert http_fact.body["status_code"] == 200
        assert http_fact.body["port"] == 443
        assert http_fact.body["tech"] == ["nginx", "php"]

    def test_tls_body_fields(self) -> None:
        facts = parse_httpx_jsonl(HTTPX_BLOB, scan_id="s1", iteration=0)
        tls = next(f for f in facts if f.fact_type == "tls_cert")
        assert tls.body["issuer"] == "Lets Encrypt R3"
        assert tls.body["tls_version"] == "TLSv1.3"
