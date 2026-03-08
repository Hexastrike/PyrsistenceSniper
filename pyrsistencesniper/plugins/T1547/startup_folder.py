from __future__ import annotations

import logging
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from pyrsistencesniper.core.normalize import expand_env_vars
from pyrsistencesniper.models.finding import AccessLevel, FilterRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

logger = logging.getLogger(__name__)

_SHELL_FOLDERS_KEY = r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
_USER_SHELL_FOLDERS_KEY = (
    r"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)

_DEFAULT_SYSTEM_STARTUP = r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
_DEFAULT_USER_STARTUP = (
    r"Users\{username}\AppData\Roaming"
    r"\Microsoft\Windows\Start Menu\Programs\Startup"
)


@register_plugin
class StartupFolder(PersistencePlugin):
    definition = CheckDefinition(
        id="startup_folder",
        technique="Startup Folder",
        mitre_id="T1547.001",
        description=(
            "Programs and shortcuts placed in per-user or system-wide "
            "Startup folders execute automatically at logon, providing "
            "simple file-drop persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        allow=(
            FilterRule(
                reason="Microsoft-signed startup item",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        system_startup = self._resolve_startup_path(
            hive_name="SOFTWARE",
            value_name="Common Startup",
            default=_DEFAULT_SYSTEM_STARTUP,
        )
        self._scan_folder(system_startup, AccessLevel.SYSTEM, findings)

        for profile, hive in self._iter_user_hives():
            user_startup = self._resolve_startup_path(
                hive_name="",
                value_name="Startup",
                default=_DEFAULT_USER_STARTUP.replace("{username}", profile.username),
                hive_override=hive,
                username=profile.username,
            )
            self._scan_folder(user_startup, AccessLevel.USER, findings)

        return findings

    def _resolve_startup_path(
        self,
        hive_name: str,
        value_name: str,
        default: str,
        hive_override: object | None = None,
        username: str = "",
    ) -> Path:
        """Resolve the Startup folder path from the registry."""
        hive = hive_override or self._open_hive(hive_name)
        if hive is not None:
            for key in (_USER_SHELL_FOLDERS_KEY, _SHELL_FOLDERS_KEY):
                node = self.registry.load_subtree(hive, key)
                if node is None:
                    continue
                val = node.get(value_name)
                if val and str(val).strip():
                    expanded = expand_env_vars(str(val), username)
                    return self.filesystem.resolve(expanded)

        return self.filesystem.image_root / Path(default)

    def _scan_folder(
        self,
        folder: Path,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        if not folder.is_dir():
            return
        try:
            entries = list(folder.iterdir())
        except PermissionError:
            logger.debug("Permission denied reading folder: %s", folder, exc_info=True)
            return
        for entry in entries:
            if entry.is_file() and entry.name.lower() != "desktop.ini":
                try:
                    rel = str(
                        PureWindowsPath(entry.relative_to(self.filesystem.image_root))
                    )
                except ValueError:
                    logger.debug(
                        "Path not relative to image root: %s",
                        entry,
                        exc_info=True,
                    )
                    rel = str(entry)
                findings.append(
                    self._make_finding(
                        path=rel,
                        value=entry.name,
                        access=access,
                    )
                )
