"""Detection for ErrorHandler.cmd Persistence."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ErrorHandlerCmd(PersistencePlugin):
    """Detects ErrorHandler.cmd Persistence persistence entries."""

    definition = CheckDefinition(
        id="error_handler_cmd",
        technique="ErrorHandler.cmd Persistence",
        mitre_id="T1546",
        description=(
            "ErrorHandler.cmd in System32 is executed by Windows Error Reporting on "
            "certain crashes. The file does not exist by default."
        ),
    )

    def run(self) -> list[Finding]:
        """Report ErrorHandler.cmd, which Windows does not ship."""
        path = r"Windows\System32\ErrorHandler.cmd"
        if not self.filesystem.exists(path):
            return []

        return [
            self._make_finding(
                path=path,
                value=path,
                access=AccessLevel.SYSTEM,
            )
        ]
