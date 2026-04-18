"""SQLModel ORM models.

Importing this package registers every model on ``SQLModel.metadata`` —
Alembic autogenerate picks them up there.
"""


# Force SQLAlchemy to resolve every forward-reference relationship NOW that
# every model class is imported. Without this, lazy mapper configuration at
# first-query time can race with module imports and raise
# ``InvalidRequestError: expression '"ClassName"' failed to locate a name``.
from sqlalchemy.orm import configure_mappers as _configure_mappers

from app.models.audit import AuditLog
from app.models.base import TimestampMixin, ULIDMixin
from app.models.drift import DriftDelta, DriftSnapshot
from app.models.enums import (
    AuditEvent,
    ExecutionState,
    FactType,
    RulePhase,
    ScanState,
    Severity,
)
from app.models.execution import Execution
from app.models.fact import Fact
from app.models.finding import Finding
from app.models.knowledge_base import CpeEntry, CveEntry, NucleiTemplate
from app.models.persona import PersonaDefinition
from app.models.rule import Rule
from app.models.scan import Scan
from app.models.target import Target

_configure_mappers()


__all__ = [
    "AuditEvent",
    "AuditLog",
    "CpeEntry",
    "CveEntry",
    "DriftDelta",
    "DriftSnapshot",
    "Execution",
    "ExecutionState",
    "Fact",
    "FactType",
    "Finding",
    "NucleiTemplate",
    "PersonaDefinition",
    "Rule",
    "RulePhase",
    "Scan",
    "ScanState",
    "Severity",
    "Target",
    "TimestampMixin",
    "ULIDMixin",
]
