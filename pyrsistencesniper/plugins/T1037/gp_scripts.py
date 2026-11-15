"""Detect Group Policy script persistence via scripts.ini and psscripts.ini."""

from __future__ import annotations

import codecs
import re
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.filesystem import (
    safe_is_dir,
    safe_is_file,
    safe_iterdir,
)
from pyrsistencesniper.core.ledger import record_artifact_failure
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.windows import read_bounded
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_GP_DIR = Path("Windows") / "System32" / "GroupPolicy"
_GP_USERS_DIR = Path("Windows") / "System32" / "GroupPolicyUsers"

_MAX_INI_BYTES = 1 << 20

_PER_USER_SCRIPT_FILES: tuple[tuple[Path, str, AccessLevel], ...] = (
    (Path("User") / "Scripts" / "scripts.ini", "User", AccessLevel.USER),
    (Path("User") / "Scripts" / "psscripts.ini", "User (PowerShell)", AccessLevel.USER),
)

_SCRIPT_FILES: tuple[tuple[Path, str, AccessLevel], ...] = (
    (Path("Machine") / "Scripts" / "scripts.ini", "Machine", AccessLevel.SYSTEM),
    (
        Path("Machine") / "Scripts" / "psscripts.ini",
        "Machine (PowerShell)",
        AccessLevel.SYSTEM,
    ),
    *_PER_USER_SCRIPT_FILES,
)

_SECTION_PATTERN = re.compile(r"^\[(?P<name>[^\]]*)\]")
_COMMENT_PREFIXES: tuple[str, ...] = (";", "#")


def _decode_ini_text(raw_bytes: bytes) -> str:
    """Decode INI bytes the way Windows' own profile parser tolerates them."""
    if raw_bytes.startswith(codecs.BOM_UTF8):
        return raw_bytes.decode("utf-8-sig")
    if raw_bytes.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw_bytes.decode("utf-16")
    if b"\x00" in raw_bytes:
        return raw_bytes.decode("utf-16", errors="replace")
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes.decode("cp1252", errors="replace")


def _parse_ini_text(text: str) -> tuple[dict[str, list[tuple[str, str]]], list[int]]:
    """Split INI text into per-section pairs, naming the lines that would not parse."""
    sections: dict[str, list[tuple[str, str]]] = {}
    unreadable_lines: list[int] = []
    current_section: list[tuple[str, str]] | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue
        section_match = _SECTION_PATTERN.match(line)
        if section_match is not None:
            current_section = sections.setdefault(
                section_match.group("name").strip(), []
            )
            continue
        key_name, separator, raw_value = line.partition("=")
        if not separator or not key_name.strip() or current_section is None:
            unreadable_lines.append(line_number)
            continue
        current_section.append((key_name.strip(), raw_value.strip()))

    return sections, unreadable_lines


@register_plugin
class GpScripts(PersistencePlugin):
    """Scan Group Policy script INI files for CmdLine persistence entries."""

    definition = CheckDefinition(
        id="gp_scripts",
        technique="Group Policy Scripts",
        mitre_id="T1037.001",
        description=(
            "Group Policy scripts.ini and psscripts.ini define startup/shutdown and "
            "logon/logoff scripts, so a CmdLine entry runs at boot or at logon."
        ),
    )

    def run(self) -> list[Finding]:
        """Scan the machine and per-user local GPO script files for CmdLine entries."""
        findings: list[Finding] = []

        if safe_is_dir(self.filesystem.image_root / _GP_DIR):
            for relative_path, scope_label, access in _SCRIPT_FILES:
                self._scan_ini_file(
                    _GP_DIR / relative_path, scope_label, access, findings
                )

        for account_sid in self._local_gpo_accounts():
            for relative_path, scope_label, access in _PER_USER_SCRIPT_FILES:
                self._scan_ini_file(
                    _GP_USERS_DIR / account_sid / relative_path,
                    f"{scope_label}, local GPO for {account_sid}",
                    access,
                    findings,
                )

        return findings

    def _local_gpo_accounts(self) -> list[str]:
        """Return the account each per-user local GPO directory is named after."""
        gp_users_dir = self.filesystem.image_root / _GP_USERS_DIR
        if not safe_is_dir(gp_users_dir):
            return []
        return sorted(
            entry.name for entry in safe_iterdir(gp_users_dir) if safe_is_dir(entry)
        )

    def _scan_ini_file(
        self,
        relative_path: Path,
        scope_label: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """Parse one Group Policy INI file and append the CmdLine entries it holds."""
        ini_file_path = self.filesystem.image_root / relative_path
        if not safe_is_file(ini_file_path):
            return

        try:
            raw_bytes = read_bounded(ini_file_path, _MAX_INI_BYTES)
        except (OSError, ValueError) as error:
            record_artifact_failure(self.definition.id, ini_file_path, error)
            return

        sections, unreadable_lines = _parse_ini_text(_decode_ini_text(raw_bytes))
        if unreadable_lines:
            record_artifact_failure(
                self.definition.id,
                ini_file_path,
                "no key=value pair could be read from line(s) "
                + ", ".join(str(number) for number in unreadable_lines),
            )

        for section_items in sections.values():
            self._extract_cmdline_entries(
                section_items, relative_path, scope_label, access, findings
            )

    def _extract_cmdline_entries(
        self,
        section_items: list[tuple[str, str]],
        relative_path: Path,
        scope_label: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """Extract CmdLine entries from an INI section."""
        key_value_map: dict[str, str] = {}
        for key_name, raw_value in section_items:
            key_value_map.setdefault(key_name.lower(), raw_value)

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

            findings.append(
                self._make_finding(
                    path=str(PureWindowsPath(relative_path)),
                    value=full_command,
                    access=access,
                    description=(
                        f"{self.definition.description} (scope: {scope_label})"
                    ),
                )
            )
