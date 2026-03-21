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
    definition = CheckDefinition(
        id="error_handler_cmd",
        technique="ErrorHandler.cmd Persistence",
        mitre_id="T1546",
        description=(
            "ErrorHandler.cmd in System32 is executed by Windows Error "
            "Reporting on certain crashes. The file does not exist by "
            "default; its presence indicates persistence or tampering."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
    )

    def run(self) -> list[Finding]:
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
