"""Unit tests for the nmap XML parser."""

from __future__ import annotations

import pytest

from app.parsers.nmap_xml import parse_nmap_xml

NMAP_XML_HAPPY = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.77.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.7p1">
          <cpe>cpe:/a:openbsd:openssh:9.7p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.27"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.mark.unit
class TestNmapParser:
    def test_happy_path(self) -> None:
        facts = parse_nmap_xml(NMAP_XML_HAPPY, scan_id="s1", iteration=0)

        # 1 host_alive + 2 port_open + 2 service_banner (closed port is skipped)
        kinds = [f.fact_type for f in facts]
        assert kinds.count("host_alive") == 1
        assert kinds.count("port_open") == 2
        assert kinds.count("service_banner") == 2

    def test_ports_closed_not_emitted(self) -> None:
        facts = parse_nmap_xml(NMAP_XML_HAPPY, scan_id="s1", iteration=0)
        ports = [f.body["port"] for f in facts if f.fact_type == "port_open"]
        assert 81 not in ports
        assert {22, 80} <= set(ports)

    def test_empty_blob(self) -> None:
        assert parse_nmap_xml(b"", scan_id="s1", iteration=0) == []

    def test_malformed_xml(self) -> None:
        assert parse_nmap_xml(b"not xml at all", scan_id="s1", iteration=0) == []

    def test_fingerprints_unique(self) -> None:
        facts = parse_nmap_xml(NMAP_XML_HAPPY, scan_id="s1", iteration=0)
        fps = [f.fingerprint for f in facts]
        assert len(fps) == len(set(fps))

    def test_service_banner_includes_cpe(self) -> None:
        facts = parse_nmap_xml(NMAP_XML_HAPPY, scan_id="s1", iteration=0)
        ssh = next(f for f in facts
                   if f.fact_type == "service_banner" and f.body["port"] == 22)
        assert ssh.body["cpe"] == ["cpe:/a:openbsd:openssh:9.7p1"]
        assert ssh.body["product"] == "OpenSSH"
