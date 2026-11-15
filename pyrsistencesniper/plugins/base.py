"""Base class and shared helpers for persistence detection plugins."""

from __future__ import annotations

from typing import ClassVar

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    TimeEvidence,
)
from pyrsistencesniper.detection.engine import execute_definition

# Plugins filter at two levels, and the split is load-bearing.
#   run(): reject values that are not valid findings at all - garbage data,
#     non-executable flags, wrong value types. This is data quality, and nothing
#     dropped here can be recovered with --min-severity.
#   Detection profile allow/block rules: suppress values that are valid
#     persistence entries but known-good defaults (explorer.exe for
#     winlogon_shell). This is policy, and --min-severity info shows it again.
# Suppress inside run() only when no evidence could make the value a finding.


class PersistencePlugin:
    """Base class for persistence detection plugins."""

    definition: ClassVar[CheckDefinition]

    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.registry = context.registry
        self.filesystem = context.filesystem

    def _make_finding(
        self,
        path: str,
        value: str,
        access: AccessLevel,
        *,
        description: str = "",
        resolve_target: str = "",
        time_evidence: tuple[TimeEvidence, ...] = (),
    ) -> Finding:
        """Create a Finding populated with this plugin's definition metadata."""
        check = self.definition
        return Finding(
            path=path,
            value=value,
            technique=check.technique,
            mitre_id=check.mitre_id,
            description=description or check.description,
            access_gained=access,
            hostname=self.context.hostname,
            check_id=check.id,
            references=check.reference_links,
            resolve_target=resolve_target,
            time_evidence=time_evidence,
        )

    def run(self) -> list[Finding]:
        """Run the declarative engine; override for detection it cannot express."""
        return execute_definition(
            self.definition,
            self.context,
            self._make_finding,
        )
