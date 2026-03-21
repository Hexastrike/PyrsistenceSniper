"""Base class and shared helpers for persistence detection plugins."""

from __future__ import annotations

from typing import ClassVar

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import AccessLevel, CheckDefinition, Finding
from pyrsistencesniper.core.registry import HiveOps, execute_definition


class PersistencePlugin:
    """Base class for persistence detection plugins.

    Subclasses provide a CheckDefinition and either rely on the built-in
    declarative engine or override run() for custom detection logic.
    """

    definition: ClassVar[CheckDefinition]

    def __init__(
        self, context: AnalysisContext, *, include_defaults: bool = False
    ) -> None:
        self.context = context
        self.registry = context.registry
        self.filesystem = context.filesystem
        self.profile = context.profile
        self._include_defaults = include_defaults
        self.hive_ops = HiveOps(context)

    def _make_finding(
        self,
        path: str,
        value: str,
        access: AccessLevel,
        *,
        description: str = "",
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
            references=check.references,
        )

    def run(self) -> list[Finding]:
        """Execute the check. Override in subclasses for custom detection.

        Filtering convention -- plugins filter at two levels:

        * **In run()**: reject values that are not valid findings (garbage
          data, non-executable flags, wrong value types).  These are data
          quality checks and apply even when ``--raw`` is used.
        * **FilterRule (allow/block)**: suppress values that *are* valid
          persistence entries but are known-good defaults (e.g.
          ``explorer.exe`` for ``winlogon_shell``).  These are policy
          decisions and are bypassed by ``--min-severity info``.
        """
        return execute_definition(
            self.definition,
            self.registry,
            self.context.hive_path,
            self.context.active_controlset,
            self.context.user_profiles,
            self._make_finding,
        )
