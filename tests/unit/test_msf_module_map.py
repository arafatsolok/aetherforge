"""Unit tests for the CVE → MSF module knowledge-base lookup."""

from __future__ import annotations

import pytest

from app.kb.msf_modules import CVE_TO_MSF_MODULE, msf_module_for_cve


@pytest.mark.unit
class TestModuleMap:
    def test_known_cves_resolve(self) -> None:
        assert msf_module_for_cve("CVE-2021-44228") == \
            "exploit/multi/http/log4shell_header_injection"
        assert msf_module_for_cve("CVE-2017-5638") == \
            "exploit/multi/http/struts2_content_type_ognl"

    def test_case_insensitive_lookup(self) -> None:
        assert msf_module_for_cve("cve-2021-44228") == \
            CVE_TO_MSF_MODULE["CVE-2021-44228"]

    def test_unknown_cve_returns_none(self) -> None:
        assert msf_module_for_cve("CVE-9999-99999") is None

    def test_modules_are_well_formed(self) -> None:
        for cve, mod in CVE_TO_MSF_MODULE.items():
            assert cve.startswith("CVE-")
            assert "/" in mod
            kind = mod.split("/", 1)[0]
            assert kind in {"exploit", "auxiliary", "post"}, mod
