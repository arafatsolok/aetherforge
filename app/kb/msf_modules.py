"""CVE → Metasploit module lookup table.

Hand-curated mapping of high-profile CVEs to their canonical MSF
modules. Used by ``r.exploit.metasploit.auto`` (rule body reads
``$fact.metasploit_module``); the persist activity enriches every
``cve_match`` fact with this lookup.

Last updated: 2026-04-18.
"""

from __future__ import annotations

from typing import Final

CVE_TO_MSF_MODULE: Final[dict[str, str]] = {
    "CVE-2021-44228":   "exploit/multi/http/log4shell_header_injection",
    "CVE-2021-41773":   "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2017-5638":    "exploit/multi/http/struts2_content_type_ognl",
    "CVE-2014-0160":    "auxiliary/scanner/ssl/openssl_heartbleed",
    "CVE-2020-14882":   "exploit/multi/http/weblogic_admin_handle_rce",
    "CVE-2022-22965":   "exploit/multi/http/spring_framework_rce_spring4shell",
    "CVE-2019-19781":   "exploit/linux/http/citrix_dir_traversal_rce",
    "CVE-2017-12615":   "exploit/multi/http/tomcat_jsp_upload_bypass",
    "CVE-2023-46604":   "exploit/multi/misc/activemq_openwire_rce",
    "CVE-2024-3400":    "exploit/linux/http/panos_globalprotect_command_injection",
    # Aux scanners — safe to run in check/run mode without exploitation:
    "CVE-2017-0144":    "auxiliary/scanner/smb/smb_ms17_010",
    "CVE-2023-22515":   "auxiliary/scanner/http/confluence_admin_create",
}


def msf_module_for_cve(cve_id: str) -> str | None:
    return CVE_TO_MSF_MODULE.get(cve_id.upper())


__all__ = ["CVE_TO_MSF_MODULE", "msf_module_for_cve"]
