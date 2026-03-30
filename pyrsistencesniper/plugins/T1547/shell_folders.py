from __future__ import annotations

import logging
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.filesystem import safe_iterdir
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.core.winutil import canonicalize_windows_path, expand_env_vars
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

_SHELL_FOLDERS_KEY = r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
_USER_SHELL_FOLDERS_KEY = (
    r"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)

_DEFAULT_USER_STARTUP = (
    r"Users\{username}\AppData\Roaming"
    r"\Microsoft\Windows\Start Menu\Programs\Startup"
)
_DEFAULT_COMMON_STARTUP = r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"


def _normalize_for_compare(path: str) -> str:
    return canonicalize_windows_path(path).lower()


@register_plugin
class ShellFoldersStartup(PersistencePlugin):
    definition = CheckDefinition(
        id="shell_folders_startup",
        technique="Shell Folders Startup Redirect",
        mitre_id="T1547.001",
        description=(
            "Shell Folders and User Shell Folders Startup values define "
            "the startup folder path. Redirecting to a non-default "
            "directory lets an attacker populate it with arbitrary "
            "executables that run at logon."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is not None:
            self._check_startup_value(
                hive=hive,
                key_path=_USER_SHELL_FOLDERS_KEY,
                value_name="Common Startup",
                canonical_prefix=r"HKLM\SOFTWARE",
                expected_default=_DEFAULT_COMMON_STARTUP,
                username="",
                access=AccessLevel.SYSTEM,
                findings=findings,
            )

        for profile, hive in self.hive_ops.iter_user_hives():
            expected = _DEFAULT_USER_STARTUP.replace("{username}", profile.username)
            for key_suffix in (_SHELL_FOLDERS_KEY, _USER_SHELL_FOLDERS_KEY):
                self._check_startup_value(
                    hive=hive,
                    key_path=f"Software\\{key_suffix}",
                    value_name="Startup",
                    canonical_prefix=f"HKU\\{profile.username}",
                    expected_default=expected,
                    username=profile.username,
                    access=AccessLevel.USER,
                    findings=findings,
                )

        return findings

    def _check_startup_value(
        self,
        *,
        hive: HiveProtocol,
        key_path: str,
        value_name: str,
        canonical_prefix: str,
        expected_default: str,
        username: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """Flag non-default Startup paths and scan the resolved folder for files."""
        node = self.registry.load_subtree(hive, key_path)
        raw_value = node.get(value_name) if node else None
        if raw_value is None:
            return
        value_str = str(raw_value)

        expanded = expand_env_vars(value_str, username)
        reg_path = f"{canonical_prefix}\\{key_path}\\{value_name}"

        if _normalize_for_compare(expanded) != _normalize_for_compare(expected_default):
            findings.append(
                self._make_finding(
                    path=reg_path,
                    value=value_str,
                    access=access,
                    description=(
                        f"Startup folder redirected to non-default path: {value_str}"
                    ),
                )
            )

        resolved = self.filesystem.resolve(expanded)
        self._scan_folder(resolved, access, findings)

    def _scan_folder(
        self,
        folder: Path,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """List files in the startup folder, excluding desktop.ini."""
        if not folder.is_dir():
            return
        findings.extend(
            self._make_finding(
                path=str(
                    PureWindowsPath(entry.relative_to(self.filesystem.image_root))
                ),
                value=entry.name,
                access=access,
            )
            for entry in safe_iterdir(folder)
            if entry.is_file() and entry.name.lower() != "desktop.ini"
        )
