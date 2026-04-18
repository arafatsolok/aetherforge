"""Parse Nmap XML → ``port_open`` / ``service_banner`` / ``host_alive`` facts."""

from __future__ import annotations

from typing import Any

from defusedxml import ElementTree as SafeET

from app.core.rule_engine import Fact
from app.parsers import make_fact


def parse_nmap_xml(
    xml_blob: bytes, *, scan_id: str, iteration: int
) -> list[Fact]:
    facts: list[Fact] = []

    if not xml_blob.strip():
        return facts

    try:
        root = SafeET.fromstring(xml_blob)
    except SafeET.ParseError:
        return facts

    for host in root.iter("host"):
        addr = _first_attr(host, "address", "addr")
        if not addr:
            continue
        status = _first_attr(host, "status", "state") or "unknown"

        # Emit host_alive for every up host.
        if status == "up":
            facts.append(
                make_fact(
                    fact_type="host_alive",
                    body={"host": addr, "status": status},
                    source_tool="nmap",
                    scan_id=scan_id,
                    iteration=iteration,
                )
            )

        for port_el in host.iter("port"):
            portid = port_el.get("portid")
            protocol = port_el.get("protocol")
            if not portid or not protocol:
                continue
            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else "unknown")
            if state != "open":
                continue

            body: dict[str, Any] = {
                "host": addr,
                "port": int(portid),
                "protocol": protocol,
                "state": state,
            }
            facts.append(
                make_fact(
                    fact_type="port_open",
                    body=body,
                    source_tool="nmap",
                    scan_id=scan_id,
                    iteration=iteration,
                )
            )

            service_el = port_el.find("service")
            if service_el is not None:
                banner = {
                    "host": addr,
                    "port": int(portid),
                    "protocol": protocol,
                    "service": service_el.get("name", ""),
                    "product": service_el.get("product", ""),
                    "version": service_el.get("version", ""),
                    "extrainfo": service_el.get("extrainfo", ""),
                    "cpe": [cpe.text for cpe in service_el.iter("cpe") if cpe.text],
                    "banner": service_el.get("banner", ""),
                    "tunnel": service_el.get("tunnel", ""),
                }
                facts.append(
                    make_fact(
                        fact_type="service_banner",
                        body=banner,
                        source_tool="nmap",
                        scan_id=scan_id,
                        iteration=iteration,
                    )
                )

    return facts


def _first_attr(parent: SafeET.Element, tag: str, attr: str) -> str | None:
    el = parent.find(tag)
    if el is None:
        return None
    return el.get(attr)


__all__ = ["parse_nmap_xml"]
