"""Small built-in knowledge-base catalogue.

Hand-curated: real CVE IDs + CPEs + Nuclei template refs. Just enough to
exercise lookups during unit tests and to give a useful baseline for
lab / CTF deployments. Replace with full NVD + pd-nuclei-templates for
production use.

Last updated: 2026-04-17 — refresh before prod deployments.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# CVEs (subset of high-profile, Nuclei-covered advisories)
# ---------------------------------------------------------------------------
BUILTIN_CVES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228",   # Log4Shell
        "published": "2021-12-10",
        "last_modified": "2024-01-15",
        "summary": (
            "Apache Log4j2 JNDI lookup feature allows remote attackers to execute "
            "arbitrary code via crafted requests (Log4Shell)."
        ),
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cpes": [
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
        ],
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
        "raw": {},
    },
    {
        "cve_id": "CVE-2021-41773",   # Apache path traversal
        "published": "2021-10-05",
        "last_modified": "2023-11-07",
        "summary": "Apache HTTP Server 2.4.49 path traversal & RCE via crafted URL.",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
        "references": ["https://httpd.apache.org/security/vulnerabilities_24.html"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2023-46604",   # ActiveMQ RCE
        "published": "2023-10-27",
        "last_modified": "2024-07-03",
        "summary": "Apache ActiveMQ allows remote code execution via OpenWire protocol.",
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:apache:activemq:5.18.2:*:*:*:*:*:*:*"],
        "references": ["https://activemq.apache.org/security-advisories"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2017-5638",    # Struts 2 OGNL
        "published": "2017-03-11",
        "last_modified": "2023-02-28",
        "summary": "Apache Struts 2 Jakarta Multipart parser OGNL injection / RCE.",
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:apache:struts:2.3.31:*:*:*:*:*:*:*"],
        "references": ["https://cwiki.apache.org/confluence/display/WW/S2-045"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2014-0160",    # Heartbleed
        "published": "2014-04-07",
        "last_modified": "2023-11-07",
        "summary": "OpenSSL TLS heartbeat read overrun discloses 64 KiB of memory.",
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cpes": ["cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*"],
        "references": ["https://heartbleed.com"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2020-14882",   # WebLogic console RCE
        "published": "2020-10-21",
        "last_modified": "2022-05-03",
        "summary": "Oracle WebLogic Server RCE via unauthenticated console path bypass.",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:oracle:weblogic_server:12.2.1.4.0:*:*:*:*:*:*:*"],
        "references": ["https://www.oracle.com/security-alerts/cpuoct2020.html"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2022-22965",   # Spring4Shell
        "published": "2022-04-01",
        "last_modified": "2023-02-28",
        "summary": "Spring Core RCE via ClassLoader on JDK 9+ (Spring4Shell).",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*"],
        "references": ["https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2019-19781",   # Citrix ADC path traversal
        "published": "2019-12-27",
        "last_modified": "2023-08-15",
        "summary": "Citrix ADC / Gateway path traversal -> RCE (Shitrix).",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:citrix:application_delivery_controller_firmware:13.0:*:*:*:*:*:*:*"],
        "references": ["https://support.citrix.com/article/CTX267027"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2017-12615",   # Tomcat PUT JSP
        "published": "2017-09-19",
        "last_modified": "2022-11-18",
        "summary": "Apache Tomcat JSP upload via HTTP PUT when readonly init-param is false.",
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:a:apache:tomcat:7.0.81:*:*:*:*:*:*:*"],
        "references": ["https://tomcat.apache.org/security-7.html"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2022-0847",    # Dirty Pipe
        "published": "2022-03-07",
        "last_modified": "2023-02-01",
        "summary": "Linux kernel Dirty Pipe — unprivileged local privilege escalation.",
        "severity": "high",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:o:linux:linux_kernel:5.8:*:*:*:*:*:*:*"],
        "references": ["https://dirtypipe.cm4all.com"],
        "raw": {},
    },
    {
        "cve_id": "CVE-2024-3400",    # PAN-OS GlobalProtect
        "published": "2024-04-12",
        "last_modified": "2024-07-10",
        "summary": "Palo Alto PAN-OS GlobalProtect command injection (pre-auth).",
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cpes": ["cpe:2.3:o:paloaltonetworks:pan-os:11.1.2:*:*:*:*:*:*:*"],
        "references": ["https://security.paloaltonetworks.com/CVE-2024-3400"],
        "raw": {},
    },
]

# ---------------------------------------------------------------------------
# CPEs (representative vendor/product rows)
# ---------------------------------------------------------------------------
BUILTIN_CPES: list[dict[str, Any]] = [
    {"cpe23": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",              "vendor": "apache",  "product": "log4j",         "version": "2.14.1", "title": "Apache Log4j 2.14.1"},
    {"cpe23": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",        "vendor": "apache",  "product": "http_server",   "version": "2.4.49", "title": "Apache HTTP Server 2.4.49"},
    {"cpe23": "cpe:2.3:a:apache:tomcat:7.0.81:*:*:*:*:*:*:*",             "vendor": "apache",  "product": "tomcat",        "version": "7.0.81", "title": "Apache Tomcat 7.0.81"},
    {"cpe23": "cpe:2.3:a:apache:activemq:5.18.2:*:*:*:*:*:*:*",           "vendor": "apache",  "product": "activemq",      "version": "5.18.2", "title": "Apache ActiveMQ 5.18.2"},
    {"cpe23": "cpe:2.3:a:apache:struts:2.3.31:*:*:*:*:*:*:*",             "vendor": "apache",  "product": "struts",        "version": "2.3.31", "title": "Apache Struts 2.3.31"},
    {"cpe23": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",            "vendor": "openssl", "product": "openssl",       "version": "1.0.1",  "title": "OpenSSL 1.0.1"},
    {"cpe23": "cpe:2.3:a:oracle:weblogic_server:12.2.1.4.0:*:*:*:*:*:*:*","vendor": "oracle",  "product": "weblogic_server","version": "12.2.1.4.0","title": "Oracle WebLogic 12.2.1.4"},
    {"cpe23": "cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*",   "vendor": "vmware",  "product": "spring_framework","version": "5.3.17","title": "Spring Framework 5.3.17"},
    {"cpe23": "cpe:2.3:a:citrix:application_delivery_controller_firmware:13.0:*:*:*:*:*:*:*","vendor": "citrix","product": "application_delivery_controller_firmware","version": "13.0","title": "Citrix ADC 13.0"},
    {"cpe23": "cpe:2.3:o:linux:linux_kernel:5.8:*:*:*:*:*:*:*",           "vendor": "linux",   "product": "linux_kernel",  "version": "5.8",    "title": "Linux kernel 5.8"},
    {"cpe23": "cpe:2.3:o:paloaltonetworks:pan-os:11.1.2:*:*:*:*:*:*:*",   "vendor": "paloaltonetworks","product": "pan-os","version": "11.1.2","title": "Palo Alto PAN-OS 11.1.2"},
]

# ---------------------------------------------------------------------------
# Nuclei template catalogue (a useful subset)
# ---------------------------------------------------------------------------
BUILTIN_NUCLEI_TEMPLATES: list[dict[str, Any]] = [
    {"template_id": "CVE-2021-44228", "name": "Log4Shell (Apache Log4j RCE)", "severity": "critical",
     "author": "projectdiscovery", "description": "JNDI lookup RCE in Apache Log4j.",
     "tags": ["cve", "rce", "oast", "log4j"], "cves": ["CVE-2021-44228"], "raw": {}},

    {"template_id": "CVE-2021-41773", "name": "Apache HTTP Server Path Traversal", "severity": "critical",
     "author": "projectdiscovery", "description": "Apache 2.4.49 path traversal + RCE.",
     "tags": ["cve", "apache", "lfi", "traversal"], "cves": ["CVE-2021-41773"], "raw": {}},

    {"template_id": "CVE-2023-46604", "name": "ActiveMQ OpenWire RCE", "severity": "critical",
     "author": "projectdiscovery", "description": "RCE via OpenWire marshaller.",
     "tags": ["cve", "rce", "activemq"], "cves": ["CVE-2023-46604"], "raw": {}},

    {"template_id": "CVE-2017-5638", "name": "Struts 2 OGNL RCE", "severity": "critical",
     "author": "projectdiscovery", "description": "Jakarta Multipart parser OGNL injection.",
     "tags": ["cve", "struts", "rce"], "cves": ["CVE-2017-5638"], "raw": {}},

    {"template_id": "ssh-auth-methods", "name": "SSH authentication methods", "severity": "info",
     "author": "projectdiscovery", "description": "Enumerate SSH auth methods offered by the server.",
     "tags": ["ssh", "enum", "network"], "cves": [], "raw": {}},

    {"template_id": "tls-version", "name": "TLS version detection", "severity": "info",
     "author": "projectdiscovery", "description": "Detect TLS protocol versions.",
     "tags": ["tls", "ssl", "info"], "cves": [], "raw": {}},

    {"template_id": "wordpress-version", "name": "WordPress version detection", "severity": "info",
     "author": "projectdiscovery", "description": "Detect exposed WordPress version.",
     "tags": ["wordpress", "tech", "wp"], "cves": [], "raw": {}},

    {"template_id": "CVE-2024-3400", "name": "PAN-OS GlobalProtect Command Injection", "severity": "critical",
     "author": "projectdiscovery", "description": "Unauthenticated command injection in GlobalProtect.",
     "tags": ["cve", "rce", "panos"], "cves": ["CVE-2024-3400"], "raw": {}},
]


__all__ = ["BUILTIN_CPES", "BUILTIN_CVES", "BUILTIN_NUCLEI_TEMPLATES"]
