"""Detection for Startup Folder."""

from __future__ import annotations

import logging
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
    HiveProtocol,
)
from pyrsistencesniper.core.shortcut import (
    describe_shortcut_entry,
    resolve_shortcut_target,
)
from pyrsistencesniper.core.windows import expand_env_vars
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

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

# A redirect turns every file in the target directory into a hashed, PE-parsed
# finding. The densest Start Menu folder measured on a loaded workstation holds
# 24 files, so 256 clears any real Startup folder by an order of magnitude and
# still refuses to walk a 4,609-file redirect.
_MAX_ENTRIES_PER_FOLDER = 256


@register_plugin
class StartupFolder(PersistencePlugin):
    """Detects Startup Folder persistence entries."""

    definition = CheckDefinition(
        id="startup_folder",
        technique="Startup Folder",
        mitre_id="T1547.001",
        description=(
            "Programs and shortcuts in the per-user and system-wide Startup folders "
            "run automatically at logon."
        ),
    )

    def run(self) -> list[Finding]:
        """Scan the machine-wide Startup folder, then each user's own."""
        findings: list[Finding] = []

        system_startup = self._resolve_startup_path(
            hive_name="SOFTWARE",
            value_name="Common Startup",
            default=_DEFAULT_SYSTEM_STARTUP,
        )
        self._scan_folder(system_startup, AccessLevel.SYSTEM, findings)

        for profile, hive in self.context.iter_user_hives():
            user_startup = self._resolve_startup_path(
                hive_name="",
                value_name="Startup",
                default=_DEFAULT_USER_STARTUP.replace("{username}", profile.username),
                hive_override=hive,
                username=profile.username,
            )
            self._scan_folder(
                user_startup,
                AccessLevel.USER,
                findings,
                username=profile.username,
            )

        return findings

    def _resolve_startup_path(
        self,
        hive_name: str,
        value_name: str,
        default: str,
        hive_override: HiveProtocol | None = None,
        username: str = "",
    ) -> Path:
        """Resolve the Startup folder path from the registry."""
        hive = hive_override or self.context.open_hive_by_name(hive_name)
        if hive is not None:
            for key in (_USER_SHELL_FOLDERS_KEY, _SHELL_FOLDERS_KEY):
                lookup_key = f"Software\\{key}" if hive_override is not None else key
                node = self.registry.load_subtree(hive, lookup_key)
                if node is None:
                    continue
                val = node.get(value_name)
                if val and str(val).strip():
                    expanded = expand_env_vars(str(val), username)
                    return self.filesystem.resolve(expanded)

        return self.filesystem.image_root / Path(*PureWindowsPath(default).parts)

    def _scan_folder(
        self,
        folder: Path,
        access: AccessLevel,
        findings: list[Finding],
        username: str = "",
    ) -> None:
        """Report every file in the Startup folder as an entry that runs at logon."""
        # resolve() folds an unusable value to the image root, and an
        # attacker controls this one: enumerating the root would report
        # bootmgr and pagefile.sys as logon persistence.
        if folder == self.filesystem.image_root:
            return
        if not safe_is_dir(folder):
            return
        for entry in self._bounded_entries(folder):
            artifact = self.filesystem.image_relative(entry)
            target, arguments = resolve_shortcut_target(
                self.definition.id, entry, artifact, username
            )
            findings.append(
                self._make_finding(
                    path=artifact,
                    value=describe_shortcut_entry(entry, target, arguments),
                    access=access,
                    resolve_target=target or artifact,
                )
            )

    def _bounded_entries(self, folder: Path) -> list[Path]:
        """List the files to examine, capping a redirected folder and saying so."""
        entries = sorted(
            (
                entry
                for entry in safe_iterdir(folder)
                if safe_is_file(entry) and entry.name.lower() != "desktop.ini"
            ),
            key=lambda entry: entry.name.lower(),
        )
        if len(entries) <= _MAX_ENTRIES_PER_FOLDER:
            return entries
        record_artifact_failure(
            self.definition.id,
            folder,
            f"folder holds {len(entries)} files, only the first "
            f"{_MAX_ENTRIES_PER_FOLDER} were examined; a Startup folder this "
            f"large is itself evidence the shell folder was redirected",
        )
        return entries[:_MAX_ENTRIES_PER_FOLDER]
