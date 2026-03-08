from __future__ import annotations

from pathlib import PureWindowsPath
from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding


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

        for profile in self.image.user_profiles:
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
                continue

            for entry in entries:
                if entry.is_dir():
                    findings.append(
                        self._make_finding(
                            path=str(
                                PureWindowsPath(
                                    entry.relative_to(self.filesystem.image_root)
                                )
                            ),
                            value=entry.name,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
