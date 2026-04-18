"""Parse httpx JSONL → ``http_response``, ``tls_cert``, ``dns_record``."""

from __future__ import annotations

import orjson

from app.core.rule_engine import Fact
from app.parsers import make_fact


def parse_httpx_jsonl(
    blob: bytes, *, scan_id: str, iteration: int
) -> list[Fact]:
    facts: list[Fact] = []

    for raw in blob.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            doc = orjson.loads(line)
        except orjson.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue

        url = doc.get("url") or doc.get("input") or ""
        host = doc.get("host") or doc.get("input") or ""
        port = doc.get("port")

        http_body = {
            "host": host,
            "url": url,
            "port": int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None,
            "status_code": doc.get("status_code") or doc.get("status-code"),
            "title": doc.get("title", ""),
            "webserver": doc.get("webserver", ""),
            "tech": doc.get("tech") or [],
            "content_type": doc.get("content_type") or doc.get("content-type", ""),
            "content_length": doc.get("content_length") or doc.get("content-length"),
            "scheme": doc.get("scheme", ""),
        }
        facts.append(
            make_fact(
                fact_type="http_response",
                body=http_body,
                source_tool="httpx",
                scan_id=scan_id,
                iteration=iteration,
            )
        )

        tls = doc.get("tls") or doc.get("tls-grab")
        if isinstance(tls, dict):
            cert_body = {
                "host": host,
                "port": http_body["port"],
                "issuer": tls.get("issuer_common_name") or tls.get("issuer_dn", ""),
                "subject": tls.get("subject_common_name") or tls.get("subject_dn", ""),
                "subject_alt_names": tls.get("subject_an") or tls.get("subject_alt_names") or [],
                "not_before": tls.get("not_before"),
                "not_after": tls.get("not_after"),
                "tls_version": tls.get("tls_version"),
                "cipher": tls.get("cipher"),
            }
            facts.append(
                make_fact(
                    fact_type="tls_cert",
                    body=cert_body,
                    source_tool="httpx",
                    scan_id=scan_id,
                    iteration=iteration,
                )
            )

        ips = doc.get("a") or doc.get("ip")
        if isinstance(ips, str):
            ips = [ips]
        if isinstance(ips, list):
            for ip in ips:
                facts.append(
                    make_fact(
                        fact_type="dns_record",
                        body={"host": host, "type": "A", "value": ip},
                        source_tool="httpx",
                        scan_id=scan_id,
                        iteration=iteration,
                    )
                )

        # Tech-detect → ``service_banner`` so vuln-scan rules can match
        # against detected stacks (e.g. "if tech includes nginx, run X").
        tech = http_body.get("tech") or []
        if isinstance(tech, list) and tech:
            facts.append(
                make_fact(
                    fact_type="service_banner",
                    body={
                        "host":     host,
                        "port":     http_body["port"],
                        "protocol": "tcp",
                        "service":  "http",
                        "product":  http_body.get("webserver") or "",
                        "tech":     tech,
                        "title":    http_body.get("title", ""),
                        "scheme":   http_body.get("scheme", ""),
                    },
                    source_tool="httpx",
                    scan_id=scan_id,
                    iteration=iteration,
                )
            )

    return facts


__all__ = ["parse_httpx_jsonl"]
