"""Detection for Power Automate Desktop Flows."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.filesystem import safe_is_dir, safe_iterdir
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class PowerAutomate(PersistencePlugin):
    """Detects Power Automate Desktop Flows persistence entries."""

    definition = CheckDefinition(
        id="power_automate",
        technique="Power Automate Desktop Flows",
        mitre_id="T1546",
        description=(
            "Power Automate Desktop stores flow definitions and scripts in the Flows "
            "and Scripts folders under the user's AppData, and a flow runs the actions "
            "it defines as that user."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
    )

    def run(self) -> list[Finding]:
        """Report every desktop flow and script stored under a user's profile."""
        findings: list[Finding] = []

        for profile in self.context.user_profiles:
            power_automate_root = (
                self.filesystem.image_root
                / "Users"
                / profile.username
                / "AppData"
                / "Local"
                / "Microsoft"
                / "Power Automate Desktop"
            )

            self._scan_directory(power_automate_root / "Flows", findings)
            self._scan_directory(power_automate_root / "Scripts", findings)

        return findings

    def _scan_directory(self, directory: Path, findings: list[Finding]) -> None:
        """Report every subdirectory of one Power Automate store."""
        if not safe_is_dir(directory):
            return
        findings.extend(
            self._make_finding(
                path=str(
                    PureWindowsPath(entry.relative_to(self.filesystem.image_root))
                ),
                value=entry.name,
                access=AccessLevel.USER,
            )
            for entry in safe_iterdir(directory)
            if safe_is_dir(entry)
        )
