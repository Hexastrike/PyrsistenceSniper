"""Detection for Shell Folders Startup Redirect."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.filesystem import (
    safe_is_dir,
    safe_is_file,
    safe_iterdir,
)
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
from pyrsistencesniper.core.windows import (
    canonicalize_windows_path,
    expand_env_vars,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

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
    """Return a Windows path in the canonical lowercase form comparisons use."""
    return canonicalize_windows_path(path).lower()


@register_plugin
class ShellFoldersStartup(PersistencePlugin):
    """Detects Shell Folders Startup Redirect persistence entries."""

    definition = CheckDefinition(
        id="shell_folders_startup",
        technique="Shell Folders Startup Redirect",
        mitre_id="T1547.001",
        description=(
            "The Startup values under Shell Folders and User Shell Folders name the "
            "Startup folder, so redirecting one makes every file in the new directory "
            "run at logon."
        ),
    )

    def run(self) -> list[Finding]:
        """Report a redirected Startup folder and everything inside it."""
        findings: list[Finding] = []

        hive = self.context.open_hive_by_name("SOFTWARE")
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

        for profile, hive in self.context.iter_user_hives():
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
        """Flag a redirected Startup path and scan the folder it points at."""
        node = self.registry.load_subtree(hive, key_path)
        raw_value = node.get(value_name) if node else None
        if raw_value is None:
            return
        value_str = str(raw_value)

        # Deduplication stays inside a check, so scanning a Startup value still
        # at its default would report every file startup_folder already reports.
        # This check owns the redirect; the defaults belong to startup_folder.
        expanded = expand_env_vars(value_str, username)
        if _normalize_for_compare(expanded) == _normalize_for_compare(expected_default):
            return

        findings.append(
            self._make_finding(
                path=f"{canonical_prefix}\\{key_path}\\{value_name}",
                value=value_str,
                access=access,
                description=(
                    f"Startup folder redirected to non-default path: {value_str}"
                ),
            )
        )
        self._scan_folder(self.filesystem.resolve(expanded), access, findings, username)

    def _scan_folder(
        self,
        folder: Path,
        access: AccessLevel,
        findings: list[Finding],
        username: str = "",
    ) -> None:
        """List files in the startup folder, excluding desktop.ini."""
        # resolve() folds an unusable value to the image root, and an
        # attacker controls this one: enumerating the root would report
        # bootmgr and pagefile.sys as logon persistence.
        if folder == self.filesystem.image_root:
            return
        if not safe_is_dir(folder):
            return
        for entry in safe_iterdir(folder):
            if not safe_is_file(entry) or entry.name.lower() == "desktop.ini":
                continue
            artifact = str(
                PureWindowsPath(entry.relative_to(self.filesystem.image_root))
            )
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
