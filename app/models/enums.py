"""Shared enums used by ORM models AND wire schemas.

Kept in one module so a schema change doesn't drift between the two.
"""


import enum


class Severity(enum.StrEnum):
    """CVSS-aligned severity bands."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def ordinal(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class FactType(enum.StrEnum):
    """Observations the rule engine's DSL can match on.

    Adding a type here = every layer that persists it (facts table,
    rule-DSL ``fact_type:`` clauses, parsers) must handle it.
    """

    HOST_ALIVE = "host_alive"
    PORT_OPEN = "port_open"
    SERVICE_BANNER = "service_banner"
    HTTP_RESPONSE = "http_response"
    TLS_CERT = "tls_cert"
    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    CVE_MATCH = "cve_match"
    VULN_NUCLEI = "vuln_nuclei"
    VULN_CUSTOM = "vuln_custom"
    WEB_ENDPOINT = "web_endpoint"
    FORM_FIELD = "form_field"
    INJECTION_POINT = "injection_point"
    CREDENTIAL = "credential"
    SESSION = "session"
    SHELL_HANDLE = "shell_handle"
    EXFIL_CHANNEL = "exfil_channel"


class ScanState(enum.StrEnum):
    """See also app.core.state_machine.ScanState — kept in sync manually."""

    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ESCALATING = "escalating"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecutionState(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    TIMEOUT = "timeout"
    FAILED = "failed"
    REJECTED = "rejected"       # scope/persona check refused the command


class AuditEvent(enum.StrEnum):
    SCAN_STARTED = "scan.started"
    SCAN_STOPPED = "scan.stopped"
    SCAN_FAILED = "scan.failed"
    PERSONA_CHANGED = "persona.changed"
    RULE_MATCHED = "rule.matched"
    COMMAND_GENERATED = "command.generated"
    COMMAND_REJECTED = "command.rejected"
    COMMAND_EXECUTED = "command.executed"
    FACT_EMITTED = "fact.emitted"
    FINDING_EMITTED = "finding.emitted"
    DRIFT_DETECTED = "drift.detected"


class RulePhase(enum.StrEnum):
    """Canonical phase strings used by both rules and personas."""

    RECON_PASSIVE = "recon.passive"
    RECON_ACTIVE = "recon.active"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    EXPLOIT_SAFE = "exploit.safe"
    EXPLOIT_FULL = "exploit.full"
    POST_EXPLOIT = "post_exploit"
    PERSISTENCE = "persistence"
    PIVOTING = "pivoting"
    EXFIL_SIMULATION = "exfil_simulation"


__all__ = [
    "AuditEvent",
    "ExecutionState",
    "FactType",
    "RulePhase",
    "ScanState",
    "Severity",
]
