from __future__ import annotations

import logging
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

import defusedxml.ElementTree as ET

from pyrsistencesniper.models.finding import AccessLevel, FilterRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

logger = logging.getLogger(__name__)

_TASKS_DIR = r"Windows\System32\Tasks"
_MAX_DEPTH = 50


@register_plugin
class ScheduledTaskFiles(PersistencePlugin):
    definition = CheckDefinition(
        id="scheduled_task_files",
        technique="Scheduled Task (XML Files)",
        mitre_id="T1053.005",
        description=(
            "Scheduled task XML files under System32\\Tasks define actions "
            "executed on triggers. All Exec actions are extracted and "
            "reported; non-OS executables and scripts are typical "
            "indicators of persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1053/005/",),
        allow=(
            FilterRule(
                reason="Microsoft-signed scheduled task",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Parse scheduled task XML files and extract Exec action command lines."""
        findings: list[Finding] = []

        tasks_dir = self.filesystem.image_root / "Windows" / "System32" / "Tasks"
        if not tasks_dir.is_dir():
            return findings

        self._walk_tasks(tasks_dir, findings)
        return findings

    def _walk_tasks(
        self,
        directory: Path,
        findings: list[Finding],
        depth: int = 0,
    ) -> None:
        """Recursively traverse the Tasks directory, parsing each XML file found."""
        if depth >= _MAX_DEPTH:
            return

        try:
            entries = list(directory.iterdir())
        except PermissionError:
            logger.debug(
                "Permission denied reading directory: %s",
                directory,
                exc_info=True,
            )
            return

        for entry in entries:
            if entry.is_dir():
                self._walk_tasks(entry, findings, depth + 1)
            elif entry.is_file():
                self._parse_task_xml(entry, findings)

    def _parse_task_xml(
        self,
        path: Path,
        findings: list[Finding],
    ) -> None:
        """Extract Command and Arguments from each Exec element in a task XML file."""
        try:
            tree = ET.parse(path)
        except Exception:
            logger.debug("Failed to parse task XML: %s", path, exc_info=True)
            return

        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        for exec_elem in root.iter(f"{ns}Exec"):
            command = exec_elem.findtext(f"{ns}Command", "")
            args = exec_elem.findtext(f"{ns}Arguments", "")
            if not command:
                continue

            task_name = str(
                PureWindowsPath(
                    path.relative_to(
                        self.filesystem.image_root / "Windows" / "System32" / "Tasks"
                    )
                )
            )
            value = f"{command} {args}".strip() if args else command

            findings.append(
                self._make_finding(
                    path=f"{_TASKS_DIR}\\{task_name}",
                    value=value,
                    access=AccessLevel.SYSTEM,
                )
            )
