"""Detect persistence via Office default templates and global template folders."""

from __future__ import annotations

import logging
from pathlib import Path

from pyrsistencesniper.core.filesystem import safe_is_dir, safe_is_file, safe_iterdir
from pyrsistencesniper.core.ledger import record_artifact_failure
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

_USER_TEMPLATE_FILES: tuple[str, ...] = (
    r"AppData\Roaming\Microsoft\Templates\Normal.dotm",
    r"AppData\Roaming\Microsoft\Templates\NormalEmail.dotm",
)

_USER_TEMPLATE_FOLDERS: tuple[str, ...] = (
    r"AppData\Roaming\Microsoft\Word\STARTUP",
    r"AppData\Roaming\Microsoft\Excel\XLSTART",
)

_OFFICE_INSTALL_ROOTS: tuple[str, ...] = (
    r"Program Files\Microsoft Office",
    r"Program Files (x86)\Microsoft Office",
)

_CLICK_TO_RUN_DIRECTORY = "root"

_MACHINE_TEMPLATE_FOLDERS: tuple[str, ...] = ("STARTUP", "XLSTART")

_IGNORED_FILE_NAME = "desktop.ini"

# Word loads every file in STARTUP and Excel opens every file in XLSTART, so the
# folders are enumerated instead of probed by name. A real install holds a
# handful of vendor add-ins there, so this bound is an order of magnitude above
# any legitimate folder and still refuses to hash one an attacker filled.
_MAX_ENTRIES_PER_FOLDER = 128


@register_plugin
class OfficeTemplates(PersistencePlugin):
    """Detects Office Default Templates persistence entries."""

    definition = CheckDefinition(
        id="office_templates",
        technique="Office Default Templates",
        mitre_id="T1137.001",
        description=(
            "Normal.dotm (Word) and every file in the Word STARTUP and Excel "
            "XLSTART global template folders load automatically on application "
            "start, so a macro embedded in one runs every time the application "
            "opens."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the templates and startup-folder files Office loads at launch."""
        findings: list[Finding] = []
        reported: set[str] = set()

        for folder in self._machine_template_folders():
            self._scan_folder(folder, AccessLevel.SYSTEM, findings, reported)

        for profile in self.context.user_profiles:
            for template_relative in _USER_TEMPLATE_FILES:
                artifact = f"Users\\{profile.username}\\{template_relative}"
                if self.filesystem.exists(artifact):
                    self._add(artifact, AccessLevel.USER, findings, reported)
            for folder_relative in _USER_TEMPLATE_FOLDERS:
                folder = self.filesystem.resolve(
                    f"Users\\{profile.username}\\{folder_relative}"
                )
                self._scan_folder(folder, AccessLevel.USER, findings, reported)

        return findings

    # Click-to-Run nests the program directory under "root" while the MSI layout
    # does not, and the version folder is named per release, so the install roots
    # are walked rather than named.
    def _machine_template_folders(self) -> list[Path]:
        """Locate the STARTUP and XLSTART folders of every Office install."""
        folders: list[Path] = []
        for install_root in _OFFICE_INSTALL_ROOTS:
            base = self.filesystem.resolve(install_root)
            for parent in (base, base / _CLICK_TO_RUN_DIRECTORY):
                if not safe_is_dir(parent):
                    continue
                for program_directory in safe_iterdir(parent):
                    if not safe_is_dir(program_directory):
                        continue
                    folders.extend(
                        program_directory / folder_name
                        for folder_name in _MACHINE_TEMPLATE_FOLDERS
                    )
        return folders

    def _scan_folder(
        self,
        folder: Path,
        access: AccessLevel,
        findings: list[Finding],
        reported: set[str],
    ) -> None:
        """Report every file in a folder Office loads wholesale on application start."""
        if not safe_is_dir(folder):
            return
        for entry in self._bounded_entries(folder):
            self._add(self.filesystem.image_relative(entry), access, findings, reported)

    def _bounded_entries(self, folder: Path) -> list[Path]:
        """List the files to examine, capping an overfilled folder and saying so."""
        entries = sorted(
            (
                entry
                for entry in safe_iterdir(folder)
                if safe_is_file(entry) and entry.name.lower() != _IGNORED_FILE_NAME
            ),
            key=lambda entry: entry.name.lower(),
        )
        if len(entries) <= _MAX_ENTRIES_PER_FOLDER:
            return entries
        record_artifact_failure(
            self.definition.id,
            folder,
            f"folder holds {len(entries)} files, only the first "
            f"{_MAX_ENTRIES_PER_FOLDER} were examined; an Office global "
            f"template folder this large is itself an anomaly",
        )
        return entries[:_MAX_ENTRIES_PER_FOLDER]

    # Users\Default User is a junction onto Users\Default on every modern
    # Windows install, so path resolution lands two discovered profiles on the
    # same file; without the reported set one artifact would be counted twice.
    def _add(
        self,
        artifact: str,
        access: AccessLevel,
        findings: list[Finding],
        reported: set[str],
    ) -> None:
        """Record one template, skipping a file two profile paths both reach."""
        key = artifact.casefold()
        if key in reported:
            return
        reported.add(key)
        findings.append(
            self._make_finding(
                path=artifact,
                value=artifact,
                access=access,
                resolve_target=artifact,
            )
        )
