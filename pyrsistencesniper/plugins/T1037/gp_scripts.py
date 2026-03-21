"""Detect Group Policy script persistence via scripts.ini and psscripts.ini (T1037.001).

Group Policy scripts.ini and psscripts.ini define startup/shutdown and
logon/logoff scripts.  Malicious CmdLine entries provide boot-level or
logon-level persistence through the Group Policy infrastructure.
"""

from __future__ import annotations

import configparser
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

_GP_DIR = Path("Windows") / "System32" / "GroupPolicy"
_SCRIPT_FILES: tuple[tuple[Path, str], ...] = (
    (Path("Machine") / "Scripts" / "scripts.ini", "Machine"),
    (Path("Machine") / "Scripts" / "psscripts.ini", "Machine (PowerShell)"),
    (Path("User") / "Scripts" / "scripts.ini", "User"),
    (Path("User") / "Scripts" / "psscripts.ini", "User (PowerShell)"),
)


@register_plugin
class GpScripts(PersistencePlugin):
    """Scan Group Policy script INI files for CmdLine persistence entries."""

    definition = CheckDefinition(
        id="gp_scripts",
        technique="Group Policy Scripts",
        mitre_id="T1037.001",
        description=(
            "Group Policy scripts.ini and psscripts.ini define "
            "startup/shutdown and logon/logoff scripts. Malicious CmdLine "
            "entries provide boot-level or logon-level persistence via "
            "the GP infrastructure."
        ),
        references=("https://attack.mitre.org/techniques/T1037/001/",),
    )

    def run(self) -> list[Finding]:
        """Scan Group Policy scripts.ini and psscripts.ini for CmdLine entries."""
        findings: list[Finding] = []

        group_policy_dir = self.filesystem.image_root / _GP_DIR
        if not group_policy_dir.is_dir():
            return findings

        for relative_path, scope_label in _SCRIPT_FILES:
            ini_file_path = group_policy_dir / relative_path
            if not ini_file_path.is_file():
                continue

            self._parse_ini_file(ini_file_path, relative_path, scope_label, findings)

        return findings

    def _parse_ini_file(
        self,
        ini_file_path: Path,
        relative_path: Path,
        scope_label: str,
        findings: list[Finding],
    ) -> None:
        """Parse a single INI file and append any CmdLine findings."""
        config = configparser.ConfigParser(interpolation=None)

        for encoding in ("utf-16", "utf-8-sig", "utf-8"):
            try:
                config.read(str(ini_file_path), encoding=encoding)
                break
            except Exception:
                logger.debug(
                    "Failed to read INI with %s encoding: %s",
                    encoding,
                    ini_file_path,
                    exc_info=True,
                )
                config.clear()
        else:
            logger.debug("All encoding attempts failed for INI file: %s", ini_file_path)
            return

        for section_name in config.sections():
            self._extract_cmdline_entries(
                config, section_name, relative_path, scope_label, findings
            )

    def _extract_cmdline_entries(
        self,
        config: configparser.ConfigParser,
        section_name: str,
        relative_path: Path,
        scope_label: str,
        findings: list[Finding],
    ) -> None:
        """Extract CmdLine entries from an INI section."""
        try:
            section_items = list(config.items(section_name))
        except Exception:
            logger.debug(
                "Failed to read INI section %s",
                section_name,
                exc_info=True,
            )
            return

        key_value_map = {key.lower(): value for key, value in section_items}

        for key_name, raw_value in section_items:
            key_lower = key_name.lower()
            if not key_lower.endswith("cmdline") or not raw_value.strip():
                continue

            index_prefix = key_lower[: -len("cmdline")]
            parameters = key_value_map.get(f"{index_prefix}parameters", "").strip()
            command_line = raw_value.strip()
            full_command = (
                f"{command_line} {parameters}".strip() if parameters else command_line
            )

            access_level = (
                AccessLevel.SYSTEM
                if scope_label.startswith("Machine")
                else AccessLevel.USER
            )
            findings.append(
                self._make_finding(
                    path=str(PureWindowsPath(_GP_DIR / relative_path)),
                    value=full_command,
                    access=access_level,
                    description=(
                        f"{self.definition.description} (scope: {scope_label})"
                    ),
                )
            )
