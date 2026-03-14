from __future__ import annotations

import logging
from pathlib import PureWindowsPath

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

logger = logging.getLogger(__name__)


@register_plugin
class PowerAutomate(PersistencePlugin):
    definition = CheckDefinition(
        id="power_automate",
        technique="Power Automate Desktop Flows",
        mitre_id="T1546",
        description=(
            "Power Automate Desktop stores flow definitions as directories "
            "under the user's AppData. The presence of custom flows may "
            "indicate automation-based persistence or lateral movement."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile in self.context.user_profiles:
            flows_dir = (
                self.filesystem.image_root
                / "Users"
                / profile.username
                / "AppData"
                / "Local"
                / "Microsoft"
                / "Power Automate Desktop"
                / "Flows"
            )
            if not flows_dir.is_dir():
                continue

            try:
                entries = list(flows_dir.iterdir())
            except PermissionError:
                logger.debug(
                    "Permission denied reading flows directory: %s",
                    flows_dir,
                    exc_info=True,
                )
                continue

            findings.extend(
                self._make_finding(
                    path=str(
                        PureWindowsPath(entry.relative_to(self.filesystem.image_root))
                    ),
                    value=entry.name,
                    access=AccessLevel.USER,
                )
                for entry in entries
                if entry.is_dir()
            )

        return findings
