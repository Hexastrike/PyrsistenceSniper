from __future__ import annotations

import logging
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)


@register_plugin
class PowerAutomate(PersistencePlugin):
    definition = CheckDefinition(
        id="power_automate",
        technique="Power Automate Desktop Flows",
        mitre_id="T1546",
        description=(
            "Power Automate Desktop stores flow definitions and scripts "
            "under the user's AppData. Both the Flows and Scripts "
            "directories are checked for automation-based persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile in self.context.user_profiles:
            pa_base = (
                self.filesystem.image_root
                / "Users"
                / profile.username
                / "AppData"
                / "Local"
                / "Microsoft"
                / "Power Automate Desktop"
            )

            self._scan_directory(pa_base / "Flows", findings)
            self._scan_directory(pa_base / "Scripts", findings)

        return findings

    def _scan_directory(self, directory: Path, findings: list[Finding]) -> None:
        if not directory.is_dir():
            return
        try:
            findings.extend(
                self._make_finding(
                    path=str(
                        PureWindowsPath(entry.relative_to(self.filesystem.image_root))
                    ),
                    value=entry.name,
                    access=AccessLevel.USER,
                )
                for entry in directory.iterdir()
                if entry.is_dir()
            )
        except PermissionError:
            logger.debug(
                "Permission denied reading directory: %s",
                directory,
                exc_info=True,
            )
